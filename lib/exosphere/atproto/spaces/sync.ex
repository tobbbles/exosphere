defmodule Exosphere.ATProto.Spaces.Sync do
  @moduledoc """
  Space sync (atproto proposal 0016, the November 12 alpha): keep a local copy
  of a space's repos in step with their repo hosts, authenticated end to end —
  and the host-side halves of the same exchanges, for consumers that host.

  Sync runs over dedicated XRPC with LtHash commit digests. A syncer keeps a
  running set hash per repo; when its digest equals the latest commit's
  `data`, the local copy is fully synced **and authenticated**. Recover from
  divergence with a full STAR archive (`get_repo/5`, verified through
  `Spaces.Repo.verify/4`).

  Oplog entries (`list_repo_ops/5`, applied by `sync_repo/6`) are a transport
  optimisation, never a source of truth: hosts may compact them, and they
  reset on account migration.

  ## The writer set and its lifecycle

  `list_writers/4` reads the space host's writer set. Each entry is either a
  `com.atproto.space.defs#repoWrite` (the repo's latest revision and commit
  `data`) or a `#repoRemoved` (the repo left the writer set: stop treating it
  as part of the space). A later write re-adds a removed repo with a new
  `repoWrite`.

  ## Notifications

  A syncer registers for notifications by passing `notify:` to
  `Spaces.Credential.authorize_space_sync/4`, and keeps the registration alive
  by reauthorizing before each credential expires. The space host then calls
  two methods on the syncer's endpoint, neither carrying service auth (the
  registration token in the body authenticates them):

    * `com.atproto.space.confirmRegistration`, before a new registration:
      `decode_confirm_registration/1`, check the token is one you issued for
      that space (`token_matches?/2`), answer `confirm_registration_response/1`.
      The space host's side is `confirm_registration/4`.
    * `com.atproto.space.notifySpaceUpdate`, for each update:
      `decode_space_update/1`, check the token likewise, then act on the
      update (see `decode_space_update/1`). The space host's side is
      `notify_space_update/5`.

  Repo hosts tell the space host about writes with
  `com.atproto.space.notifyRepoUpdate` (`notify_repo_update/4`, service auth
  from the repo's account); the space host reads it with
  `decode_notify_repo_update/1` and `check_repo_update_auth/2`.

  Serving those endpoints stays in the consumer's process tree: this module
  shapes and checks the bodies, and leaves the HTTP to the app.

  ## Authorization

  Syncer reads are credential-authed: the space credential travels as
  `Authorization: Atproto-Space-Credential <jwt>` with an
  `Atproto-Space-Audience` header and an RFC 9421 HTTP Message Signature by
  the credential's bound key (`Spaces.HttpSignature`). The audience is the
  repo owner's DID for repo-host methods and the space authority's DID for
  `list_writers/4`. Pass `:http` to substitute an `HTTP.Behaviour` mock.

  ## Authenticity: the commit and record MACs

  Commits carry no signature. Methods that return a commit or record —
  `get_latest_commit/5`, `list_repo_ops/5`, `get_repo/5`, `get_record/7` —
  need the author's `#atproto_kem` public key, passed as `kem_key:` (a P-256
  key or `did:key`; resolve it with `Identity.Document.get_kem_key/1`). For
  every request — retries and each page included — the client derives a fresh
  HPKE secret (`Spaces.Kem.encapsulate/2`), asks for a MAC with
  `Accept-Signature` (`Spaces.Mac.request_headers/2`), and verifies the
  HTTP-signature MAC the host answers with: the commit profile for commits,
  the record profile for records.

  `kem_key:` may also be a function `fn refresh? -> {:ok, key} | {:error, _}
  end`. It is called with `false` first; if verification then fails, it is
  called again with `true` — re-resolve the author's DID document, since the
  KEM key may have rotated — and the request is retried once with a new key
  share. With a plain key there is no retry, and a failure is returned for
  the caller to handle the same way.

  A missing `kem_key:` is `{:error, :missing_kem_key}`. A MAC that fails is
  `{:error, {:invalid_space_mac, reason}}` (`Spaces.Mac`). A host that cannot
  use the request answers `InvalidSpaceMac`, returned as
  `{:error, :invalid_space_mac}`.

  ## Error surface

  Transport errors come back as-is, and HTTP errors as
  `{:error, {:http_error, status}}`, except these:

  | XRPC error | returned |
  |---|---|
  | `RepoNotFound` | `{:error, :repo_not_found}`: the repo was never written, or was emptied and collected; treat it as an empty repo |
  | `RepoTakendown` | `{:error, :repo_takendown}` |
  | `RepoDeactivated` | `{:error, :repo_deactivated}` |
  | `RepoSuspended` | `{:error, :repo_suspended}` |
  | `InvalidSpaceMac` | `{:error, :invalid_space_mac}` |
  | `InvalidCursor` | `{:error, :invalid_cursor}` |
  | `SinceOutOfBounds` (400) | `{:error, {:since_out_of_bounds, floor}}` |

  The reference PDS does not emit `SinceOutOfBounds`; it is typed for hosts
  that follow the proposal's "cannot find its since revision" guidance, with
  the oldest retained rev parsed out of the message when the host gives it.

  This replaces the November 5 surface: `registerNotify`/`unregisterNotify`,
  forwarded `notifyWrite` and `notifySpaceStatus`/`notifySpaceDeleted` are
  gone, as are the `Atproto-Space-Want-Mac`/`Atproto-Space-Mac` headers.
  """

  alias Exosphere.ATProto.{AtUri, CID, HTTP, TID}
  alias Exosphere.ATProto.CBOR, as: DagCbor
  alias Exosphere.ATProto.Identity.DID

  alias Exosphere.ATProto.Spaces.{
    Commit,
    Credential,
    HttpSignature,
    Kem,
    Lthash,
    Mac,
    Token,
    XRPC
  }

  alias Exosphere.ATProto.Spaces.Repo, as: SpaceRepo

  @repo_write "com.atproto.space.defs#repoWrite"
  @repo_removed "com.atproto.space.defs#repoRemoved"
  @space_deleted "com.atproto.space.notifySpaceUpdate#spaceDeleted"
  @registration_expired "com.atproto.space.notifySpaceUpdate#registrationExpired"

  # The lexicon bound on notify tokens and challenges.
  @max_token_bytes 512
  # The reference space host gives a syncer's endpoint 10 seconds.
  @notify_timeout 10_000

  @typedoc "A space credential and its bound key (`Spaces.Credential.authorize_space_sync/4`)."
  @type credential :: Credential.t()

  @typedoc """
  The author's KEM public key (a P-256 point or `did:key`), or a function
  resolving it: called with `false`, then with `true` to re-resolve after a
  failed verification.
  """
  @type kem_key ::
          binary()
          | (boolean() -> {:ok, binary()} | {:error, term()})

  @typedoc "A `com.atproto.space.defs#repoWrite`: a repo advanced to a new revision."
  @type repo_write :: %{
          required(:type) => :repo_write,
          required(:repo) => String.t(),
          required(:repo_rev) => String.t(),
          required(:data) => binary(),
          required(:space_rev) => String.t(),
          optional(:prev_space_rev) => String.t() | nil
        }

  @typedoc "A `com.atproto.space.defs#repoRemoved`: a repo left the writer set."
  @type repo_removed :: %{
          required(:type) => :repo_removed,
          required(:repo) => String.t(),
          required(:space_rev) => String.t(),
          optional(:prev_space_rev) => String.t() | nil
        }

  @typedoc "A writer set entry, as `list_writers/4` returns it."
  @type writer :: repo_write() | repo_removed()

  @typedoc """
  A `notifySpaceUpdate` update: a writer set change (with `prev_space_rev`),
  `%{type: :space_deleted}`, `%{type: :registration_expired, space_rev:}`, or
  `%{type: :unknown, value: map}` for an update type this library does not
  know.
  """
  @type space_update ::
          repo_write()
          | repo_removed()
          | %{type: :space_deleted}
          | %{type: :registration_expired, space_rev: String.t()}
          | %{type: :unknown, value: map()}

  @typedoc "A `notifyRepoUpdate` body: the repo's new revision and commit `data`."
  @type repo_update :: %{
          space: String.t(),
          repo: String.t(),
          repo_rev: String.t(),
          data: binary()
        }

  # -- the writer set -----------------------------------------------------------

  @doc """
  A page of the space host's writer set (`com.atproto.space.listWriters`),
  ordered by `space_rev`, ascending.

  Returns `{:ok, %{repos: [writer()], cursor: cursor | nil}}`, each entry
  either `%{type: :repo_write, repo:, repo_rev:, data:, space_rev:}` (`data`
  the repo's commit digest, decoded from the lexicon `bytes` form) or
  `%{type: :repo_removed, repo:, space_rev:}`. Entries of a union type this
  library does not know are skipped, as the reference client does. An entry
  that is malformed is `{:error, :invalid_writer}`.

  ## Two revisions

    * `repo_rev` is **the repo's** revision: the TID of the author's latest
      commit, the `since:` that `list_repo_ops/5` takes. It is only ever
      compared within one repo.
    * `space_rev` is **the space host's** sequence number for the change:
      every accepted write or removal advances one per-space sequence. It is
      what the listing is ordered by, and what the cursor is.

  `cursor:` is "repos updated after this space revision", so a syncer that
  remembers the last `space_rev` it processed — from a page, a notification,
  or `authorize_space_sync/4`'s `space_rev` — asks only for what moved since.
  A non-empty page carries a cursor and an empty page ends the walk. A repo
  can appear twice across pages if it moved while you paged; its last entry
  is current.

  Removed repos may be garbage collected after 72 hours, so a syncer whose
  last seen space revision is older should list the whole writer set (no
  cursor) and drop any repo that is missing or removed.
  """
  @spec list_writers(String.t(), String.t(), credential(), keyword()) ::
          {:ok, %{repos: [writer()], cursor: String.t() | nil}} | {:error, term()}
  def list_writers(space_host, space_ref, cred, opts \\ []) do
    params =
      %{space: space_ref}
      |> maybe_put("limit", Keyword.get(opts, :limit))
      |> maybe_put("cursor", Keyword.get(opts, :cursor))

    url = xrpc_url(space_host, "com.atproto.space.listWriters", params)

    with {:ok, %{body: body}} <- get_json(url, cred, authority(space_ref), [], opts),
         {:ok, repos} <- decode_writers(body["repos"]),
         {:ok, cursor} <- optional_string(body["cursor"]) do
      {:ok, %{repos: repos, cursor: cursor}}
    end
  end

  @doc """
  A writer set entry in wire form (`$type` included), for a space host
  serving `listWriters`. `prev_space_rev` is not part of a listing and is
  left out.
  """
  @spec encode_writer(writer()) :: map()
  def encode_writer(writer), do: encode_entry(Map.delete(writer, :prev_space_rev))

  @doc """
  A `listWriters` output for `writers` (ordered by `space_rev`): the encoded
  entries, and the last entry's `space_rev` as the cursor — none on an empty
  page, which is how a syncer knows the walk is over.
  """
  @spec list_writers_output([writer()]) :: map()
  def list_writers_output(writers) when is_list(writers) do
    %{"repos" => Enum.map(writers, &encode_writer/1)}
    |> maybe_put("cursor", writers |> List.last() |> then(&(&1 && &1.space_rev)))
  end

  # -- repo reads (MAC-verified) --------------------------------------------------

  @doc """
  A repo's current commit (`com.atproto.space.getLatestCommit`), from its
  repo host, verified against the commit MAC (see "Authenticity" above;
  requires `kem_key:`). Its `data` is the digest a fully-synced running set
  hash must equal (`synced?/2`).
  """
  @spec get_latest_commit(String.t(), String.t(), String.t(), credential(), keyword()) ::
          {:ok, Commit.t()} | {:error, term()}
  def get_latest_commit(repo_host, space_ref, repo_did, cred, opts \\ []) do
    url =
      xrpc_url(repo_host, "com.atproto.space.getLatestCommit", %{space: space_ref, repo: repo_did})

    ctx = %{space: space_ref, repo: repo_did}

    with_kem(opts, fn kem_key ->
      with {:ok, kem} <- Kem.encapsulate(kem_key),
           {:ok, %{body: body, headers: headers}} <-
             get_json(url, cred, repo_did, Mac.request_headers(:commit, kem.key_share), opts),
           {:ok, commit} <- decode_commit(body["commit"]),
           :ok <- Commit.verify(commit, ctx, kem, headers) do
        {:ok, commit}
      end
    end)
  end

  @doc """
  One page of a repo's oplog (`com.atproto.space.listRepoOps`) after `since`
  (the local sync position). Records are inlined by default;
  `exclude_values: true` fetches metadata only. Ops sharing a `rev` belong to
  one commit. Requires `kem_key:`.

  Returns `{:ok, %{ops: [map()], commit: Commit.t(), cursor: String.t() | nil}}`.
  Every page carries the repo's current commit, verified against that page's
  MAC. A page has a `cursor` whenever it is full, so the last page may be
  empty; page until there is no cursor, then compare the last page's commit
  `data` with your running set hash — `sync_repo/6` does all of that.

  A repo that was never written is `{:error, :repo_not_found}`. When the
  host answers that `since` falls outside its retained window, the error is
  `{:error, {:since_out_of_bounds, floor}}` — the cue to recover via
  `get_repo/5`.
  """
  @spec list_repo_ops(String.t(), String.t(), String.t(), credential(), keyword()) ::
          {:ok, %{ops: [map()], commit: Commit.t(), cursor: String.t() | nil}}
          | {:error, term()}
  def list_repo_ops(repo_host, space_ref, repo_did, cred, opts \\ []) do
    params =
      %{space: space_ref, repo: repo_did}
      |> maybe_put("since", Keyword.get(opts, :since))
      |> maybe_put("cursor", Keyword.get(opts, :cursor))
      |> maybe_put("limit", Keyword.get(opts, :limit))
      |> maybe_put("excludeValues", Keyword.get(opts, :exclude_values))

    url = xrpc_url(repo_host, "com.atproto.space.listRepoOps", params)
    ctx = %{space: space_ref, repo: repo_did}

    with_kem(opts, fn kem_key ->
      with {:ok, kem} <- Kem.encapsulate(kem_key),
           {:ok, %{body: body, headers: headers}} <-
             get_json(url, cred, repo_did, Mac.request_headers(:commit, kem.key_share), opts),
           {:ok, ops} <- decode_ops(body["ops"]),
           {:ok, commit} <- decode_commit(body["commit"]),
           {:ok, cursor} <- optional_string(body["cursor"]),
           :ok <- Commit.verify(commit, ctx, kem, headers) do
        {:ok, %{ops: ops, commit: commit, cursor: cursor}}
      end
    end)
  end

  @doc """
  Bring a known state of a repo up to date from its oplog: page through
  `list_repo_ops/5` from `head.rev` (each page with a fresh MAC secret), fold
  every op into `head.lthash`, and once a page has no cursor, require the
  result to equal that page's commit `data`.

  Ops must come in revision order, after `head.rev`, and any inlined value
  must encode to its op's `cid`. Options pass through to `list_repo_ops/5`
  (`:kem_key` is required; `:limit`, `:exclude_values`, `:http`, …).

  Returns `{:ok, %{commit:, lthash:, rev:, ops:}}` — the authenticated state
  to continue from (`rev` is the commit's) and every op applied, in order.
  `{:error, {:diverged, commit}}` (the ops do not lead to the commit) and
  `{:error, :ops_out_of_order}` mean the oplog cannot be applied to this
  state: recover with `get_repo/5`, as for `{:since_out_of_bounds, _}`.
  `{:error, :repo_not_found}` means the host no longer has the repo: treat it
  as empty.
  """
  @spec sync_repo(
          String.t(),
          String.t(),
          String.t(),
          credential(),
          %{rev: String.t(), lthash: Lthash.t()},
          keyword()
        ) ::
          {:ok, %{commit: Commit.t(), lthash: Lthash.t(), rev: String.t(), ops: [map()]}}
          | {:error, term()}
  def sync_repo(repo_host, space_ref, repo_did, cred, head, opts \\ [])

  def sync_repo(
        repo_host,
        space_ref,
        repo_did,
        cred,
        %{rev: since, lthash: %Lthash{} = hash},
        opts
      )
      when is_binary(since) do
    opts = opts |> Keyword.delete(:cursor) |> Keyword.put(:since, since)
    state = %{since: since, last_rev: since, lthash: hash, ops: [], cursor: nil}
    sync_pages({repo_host, space_ref, repo_did, cred}, opts, state)
  end

  defp sync_pages({repo_host, space_ref, repo_did, cred} = target, opts, state) do
    page_opts = if state.cursor, do: Keyword.put(opts, :cursor, state.cursor), else: opts

    with {:ok, %{ops: ops, commit: commit, cursor: cursor}} <-
           list_repo_ops(repo_host, space_ref, repo_did, cred, page_opts),
         {:ok, last_rev, hash} <- apply_page(ops, state) do
      applied = Enum.reverse(ops, state.ops)

      cond do
        is_nil(cursor) ->
          if Commit.matches?(hash, commit),
            do:
              {:ok,
               %{commit: commit, lthash: hash, rev: commit["rev"], ops: Enum.reverse(applied)}},
            else: {:error, {:diverged, commit}}

        # A host answering with the same cursor would page forever.
        cursor == state.cursor ->
          {:error, :repeated_cursor}

        true ->
          sync_pages(target, opts, %{
            state
            | cursor: cursor,
              last_rev: last_rev,
              lthash: hash,
              ops: applied
          })
      end
    end
  end

  defp apply_page(ops, state) do
    Enum.reduce_while(ops, {:ok, state.last_rev, state.lthash}, fn op, {:ok, last, hash} ->
      with {:ok, rev} <- check_op_order(op, state.since, last),
           :ok <- check_op_value(op) do
        {:cont, {:ok, rev, Commit.apply_op(hash, op)}}
      else
        error -> {:halt, error}
      end
    end)
  end

  # Ops sharing a revision were applied atomically; none may precede `since`
  # or an op already applied.
  defp check_op_order(%{"rev" => rev}, since, last) when is_binary(rev) do
    if rev > since and rev >= last, do: {:ok, rev}, else: {:error, :ops_out_of_order}
  end

  defp check_op_order(_op, _since, _last), do: {:error, :invalid_op}

  defp check_op_value(%{"value" => value} = op) when not is_nil(value) do
    path = "#{op["collection"]}/#{op["rkey"]}"

    with cid when is_binary(cid) <- op["cid"],
         {:ok, cid} <- CID.decode(cid),
         {:ok, ^cid} <- value_cid(value) do
      :ok
    else
      _ -> {:error, {:record_cid_mismatch, path}}
    end
  end

  defp check_op_value(_op), do: :ok

  @doc """
  A repo's records (`com.atproto.space.listRecords`), page by page. Options:
  `:collection` (omit to list across all collections), `:cursor`, `:limit`,
  and `:exclude_values` (metadata only — collection, rkey, cid — for diffing
  a lightly diverged copy). A cursor the host cannot read is
  `{:error, :invalid_cursor}`.

  Listing carries no MAC: verify the result through the set hash, or fetch
  individual records with `get_record/7`.
  """
  @spec list_records(String.t(), String.t(), String.t(), credential(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def list_records(repo_host, space_ref, repo_did, cred, opts \\ []) do
    params =
      %{space: space_ref, repo: repo_did}
      |> maybe_put("collection", Keyword.get(opts, :collection))
      |> maybe_put("cursor", Keyword.get(opts, :cursor))
      |> maybe_put("limit", Keyword.get(opts, :limit))
      |> maybe_put("excludeValues", Keyword.get(opts, :exclude_values))

    url = xrpc_url(repo_host, "com.atproto.space.listRecords", params)

    with {:ok, %{body: body}} <- get_json(url, cred, repo_did, [], opts), do: {:ok, body}
  end

  @doc """
  A single record (`com.atproto.space.getRecord`), verified against the
  record MAC (requires `kem_key:`): the response must be the record that was
  requested (its `uri` is the space record URI
  `at://{authority}/space/{type}/{skey}/{repo}/{collection}/{rkey}`), the
  `Atproto-Space-Record` header the MAC covers must name that URI and the
  record's CID, and the value must encode to that CID.

  Returns `{:ok, %{"uri" => …, "cid" => …, "value" => …}}`. Errors:
  `:record_uri_mismatch`, `:record_cid_mismatch`, `:invalid_record`, and
  `{:invalid_space_mac, reason}`.
  """
  @spec get_record(
          String.t(),
          String.t(),
          String.t(),
          String.t(),
          String.t(),
          credential(),
          keyword()
        ) ::
          {:ok, map()} | {:error, term()}
  def get_record(repo_host, space_ref, repo_did, collection, rkey, cred, opts \\ []) do
    params = %{space: space_ref, repo: repo_did, collection: collection, rkey: rkey}
    url = xrpc_url(repo_host, "com.atproto.space.getRecord", params)

    with {:ok, uri} <- record_uri(space_ref, repo_did, collection, rkey) do
      with_kem(opts, fn kem_key ->
        with {:ok, kem} <- Kem.encapsulate(kem_key),
             {:ok, %{body: body, headers: headers}} <-
               get_json(url, cred, repo_did, Mac.request_headers(:record, kem.key_share), opts),
             :ok <- verify_record(body, uri, kem, headers) do
          {:ok, body}
        end
      end)
    end
  end

  @doc """
  The full repo (`com.atproto.space.getRepo`) as a STAR archive
  (`application/vnd.dasl.star`), verified end to end through
  `Spaces.Repo.verify/4`: the archive's commit names the requested repo and
  space, the commit MAC verifies and the `Atproto-Space-Commit` header it
  covers matches the archive's commit, and every record folds into a set hash
  equal to the commit's `data`. Requires `kem_key:`.

  On success the returned set hash is the authenticated running hash to
  continue syncing from (`sync_repo/6` with `%{rev: verified.rev, lthash:
  verified.lthash}`). A response whose content type is not STAR is
  `{:error, {:unexpected_content_type, content_type}}`. A repo its host does
  not have is `{:error, :repo_not_found}`: treat it as empty.
  """
  @spec get_repo(String.t(), String.t(), String.t(), credential(), keyword()) ::
          {:ok, SpaceRepo.verified()} | {:error, term()}
  def get_repo(repo_host, space_ref, repo_did, cred, opts \\ []) do
    http = Keyword.get(opts, :http, HTTP)
    url = xrpc_url(repo_host, "com.atproto.space.getRepo", %{space: space_ref, repo: repo_did})
    ctx = %{space: space_ref, repo: repo_did}

    with_kem(opts, fn kem_key ->
      with {:ok, kem} <- Kem.encapsulate(kem_key) do
        mac_request = Mac.request_headers(:commit, kem.key_share)

        case signed_request(http, url, opts, cred, repo_did, mac_request) do
          {:ok, %{status: 200, body: star, headers: headers}} when is_binary(star) ->
            with :ok <- check_star_content_type(headers),
                 do: SpaceRepo.verify(star, ctx, kem, headers)

          {:ok, response} ->
            classify_error(response)

          error ->
            error
        end
      end
    end)
  end

  # -- confirmRegistration --------------------------------------------------------

  @doc """
  Space host side: confirm a new notify registration before storing it, by
  calling `com.atproto.space.confirmRegistration` on the syncer's `endpoint`
  with `{space, token, challenge}` and checking that it echoes the challenge.

  Returns `:ok`, or `{:error, :registration_not_confirmed}` for any failure —
  a refusal, a wrong echo, a timeout — which `authorizeSpaceSync` answers as
  `RegistrationNotConfirmed`. The call carries no auth. The endpoint is the
  requester's choice: fetch it as an untrusted URL (HTTPS, public address).
  Options: `:challenge` pins the challenge (tests only; it is random by
  default), `:timeout` (10 seconds by default, as the reference), `:http`.
  """
  @spec confirm_registration(String.t(), String.t(), String.t(), keyword()) ::
          :ok | {:error, :registration_not_confirmed}
  def confirm_registration(endpoint, space_ref, token, opts \\ []) do
    challenge = Keyword.get_lazy(opts, :challenge, &new_challenge/0)
    body = %{"space" => space_ref, "token" => token, "challenge" => challenge}
    opts = Keyword.put_new(opts, :timeout, @notify_timeout)

    case XRPC.procedure(
           endpoint,
           "com.atproto.space.confirmRegistration",
           body,
           [headers: []],
           opts
         ) do
      {:ok, %{"challenge" => ^challenge}} -> :ok
      _ -> {:error, :registration_not_confirmed}
    end
  end

  @doc """
  Syncer side: read a `confirmRegistration` request into
  `{:ok, %{space:, token:, challenge:}}`, or `{:error, :invalid_request}`.

  Then check that `token` is the one you passed as `notify:` for `space`
  (`token_matches?/2`), refuse otherwise (an XRPC error), and answer
  `confirm_registration_response/1`.
  """
  @spec decode_confirm_registration(map()) ::
          {:ok, %{space: String.t(), token: String.t(), challenge: String.t()}}
          | {:error, :invalid_request}
  def decode_confirm_registration(%{"space" => space, "token" => token, "challenge" => challenge}) do
    if XRPC.space_ref?(space) and token?(token) and token?(challenge),
      do: {:ok, %{space: space, token: token, challenge: challenge}},
      else: {:error, :invalid_request}
  end

  def decode_confirm_registration(_), do: {:error, :invalid_request}

  @doc """
  The `confirmRegistration` output echoing the challenge, from the decoded
  request or the challenge itself.
  """
  @spec confirm_registration_response(%{challenge: String.t()} | String.t()) :: map()
  def confirm_registration_response(%{challenge: challenge}),
    do: confirm_registration_response(challenge)

  def confirm_registration_response(challenge) when is_binary(challenge),
    do: %{"challenge" => challenge}

  @doc """
  Whether a token received in `confirmRegistration` or `notifySpaceUpdate`
  is the one issued for the space, compared in constant time (the token is
  the only thing authenticating those calls).
  """
  @spec token_matches?(String.t(), term()) :: boolean()
  def token_matches?(issued, received) when is_binary(issued),
    do: Mac.equal?(issued, received)

  # -- notifySpaceUpdate -----------------------------------------------------------

  @doc """
  Space host side: send a `com.atproto.space.notifySpaceUpdate` to a
  registered syncer's `endpoint`, with the registration's `token` and the
  `update` (see `t:space_update/0`; `:unknown` cannot be sent).

  Returns `:ok`, or the XRPC error (`{:error, {:http_error, status, name}}`
  and so on) for the caller's retry policy: `repoWrite` and `repoRemoved`
  are best effort, while expiry and deletion notices are retried with backoff
  (1 minute up to 12 hours, for at least 72 hours), and a syncer that rejects
  an expiry notice with a non-retryable error (e.g. 400) has unregistered.
  The call carries no auth; fetch the endpoint as an untrusted URL. Options:
  `:timeout` (10 seconds by default), `:http`.
  """
  @spec notify_space_update(String.t(), String.t(), String.t(), space_update(), keyword()) ::
          :ok | {:error, term()}
  def notify_space_update(endpoint, space_ref, token, update, opts \\ []) do
    with {:ok, body} <- encode_space_update(space_ref, token, update) do
      opts = Keyword.put_new(opts, :timeout, @notify_timeout)

      case XRPC.procedure(
             endpoint,
             "com.atproto.space.notifySpaceUpdate",
             body,
             [headers: []],
             opts
           ) do
        {:ok, _} -> :ok
        error -> error
      end
    end
  end

  @doc """
  The `notifySpaceUpdate` input for `update`, `$type`s in full. A writer set
  change includes `prevSpaceRev` when it has one.
  """
  @spec encode_space_update(String.t(), String.t(), space_update()) ::
          {:ok, map()} | {:error, :invalid_update}
  def encode_space_update(space_ref, token, update) when is_binary(space_ref) do
    if token?(token) do
      case encode_entry(update) do
        nil -> {:error, :invalid_update}
        entry -> {:ok, %{"space" => space_ref, "token" => token, "update" => entry}}
      end
    else
      {:error, :invalid_update}
    end
  end

  @doc """
  Syncer side: read a `notifySpaceUpdate` request into
  `{:ok, %{space:, token:, update:}}`. Check `token` against the one issued
  for `space` (`token_matches?/2`) and reject anything else.

  `update` is matched on its `$type` in full:

  | `$type` | decoded | syncer action |
  |---|---|---|
  | `com.atproto.space.defs#repoWrite` | `%{type: :repo_write, repo:, repo_rev:, data:, space_rev:, prev_space_rev:}` | sync the repo from its host |
  | `com.atproto.space.defs#repoRemoved` | `%{type: :repo_removed, repo:, space_rev:, prev_space_rev:}` | stop treating the repo as part of the space |
  | `com.atproto.space.notifySpaceUpdate#spaceDeleted` | `%{type: :space_deleted}` | reauthorize; only a `SpaceDeleted` answer confirms the deletion |
  | `com.atproto.space.notifySpaceUpdate#registrationExpired` | `%{type: :registration_expired, space_rev:}` | reauthorize with `notify:` and catch up through `list_writers/4`; or reject with a 400 to unregister |
  | anything else | `%{type: :unknown, value: map}` | acknowledge and ignore |

  Writer set changes are best effort: a `prev_space_rev` that is not the last
  `space_rev` you processed means updates were missed — catch up with
  `list_writers/4`'s `cursor:` set to the last one you did process.
  A malformed body is `{:error, :invalid_request}`; a malformed update of a
  known type is `{:error, :invalid_update}`.
  """
  @spec decode_space_update(map()) ::
          {:ok, %{space: String.t(), token: String.t(), update: space_update()}}
          | {:error, :invalid_request | :invalid_update}
  def decode_space_update(%{"space" => space, "token" => token, "update" => update}) do
    if XRPC.space_ref?(space) and token?(token) do
      with {:ok, update} <- decode_update(update),
           do: {:ok, %{space: space, token: token, update: update}}
    else
      {:error, :invalid_request}
    end
  end

  def decode_space_update(_), do: {:error, :invalid_request}

  defp decode_update(%{"$type" => type} = update) when type in [@repo_write, @repo_removed] do
    with {:ok, entry} <- decode_entry(update),
         prev = update["prevSpaceRev"],
         true <- is_nil(prev) or TID.valid?(prev) do
      {:ok, Map.put(entry, :prev_space_rev, prev)}
    else
      _ -> {:error, :invalid_update}
    end
  end

  defp decode_update(%{"$type" => @space_deleted}), do: {:ok, %{type: :space_deleted}}

  defp decode_update(%{"$type" => @registration_expired} = update) do
    case update["spaceRev"] do
      rev when is_binary(rev) ->
        if TID.valid?(rev),
          do: {:ok, %{type: :registration_expired, space_rev: rev}},
          else: {:error, :invalid_update}

      _ ->
        {:error, :invalid_update}
    end
  end

  defp decode_update(%{"$type" => type} = update) when is_binary(type),
    do: {:ok, %{type: :unknown, value: update}}

  defp decode_update(_), do: {:error, :invalid_update}

  # -- notifyRepoUpdate -------------------------------------------------------------

  @doc """
  Repo host side: tell the space host a space repo advanced
  (`com.atproto.space.notifyRepoUpdate`), with `update`'s `space`, `repo`,
  `repo_rev` and commit `data` (32 bytes).

  Authenticated with service auth from the repo's account. `auth` is one of:

    * `[service_auth: [key: repo_signing_jwk]]` — minted per request:
      `iss` defaults to the repo DID, `aud` to the space authority's space
      host (`Token.space_host_aud/1`, `{authority}#atproto_pds`), and `lxm`
      is `com.atproto.space.notifyRepoUpdate`; `:iss`, `:aud`, `:kid` and
      `:expires_in` may be given to override.
    * `[headers: [{"authorization", "Bearer " <> jwt}]]` — minted elsewhere.

  Delivery is retried by the repo host until it succeeds; the space host
  answers `UpstreamFailure` when a managing app cannot be reached, which is
  also a reason to retry rather than drop. Errors come back as XRPC errors
  (`{:error, {:http_error, status, name}}`, e.g. `FutureRev`).
  """
  @spec notify_repo_update(String.t(), repo_update(), keyword(), keyword()) ::
          :ok | {:error, term()}
  def notify_repo_update(space_host, update, auth, opts \\ [])

  def notify_repo_update(
        space_host,
        %{space: space, repo: repo, repo_rev: repo_rev, data: data},
        auth,
        opts
      )
      when is_binary(data) do
    with {:ok, auth} <- repo_update_auth(auth, space, repo) do
      body = %{
        "space" => space,
        "repo" => repo,
        "repoRev" => repo_rev,
        "data" => encode_bytes(data)
      }

      case XRPC.procedure(space_host, "com.atproto.space.notifyRepoUpdate", body, auth, opts) do
        {:ok, _} -> :ok
        error -> error
      end
    end
  end

  defp repo_update_auth([service_auth: sa], space, repo) when is_list(sa) do
    sa =
      sa
      |> Keyword.put_new(:iss, repo)
      |> Keyword.put_new_lazy(:aud, fn -> Token.space_host_aud(authority(space)) end)

    {:ok, [service_auth: sa]}
  end

  defp repo_update_auth([headers: headers] = auth, _space, _repo) when is_list(headers),
    do: {:ok, auth}

  defp repo_update_auth(_, _, _), do: {:error, :invalid_auth}

  @doc """
  Space host side: read a `notifyRepoUpdate` body into
  `{:ok, %{space:, repo:, repo_rev:, data:}}` (`data` decoded from the
  lexicon `bytes` form), or `{:error, :invalid_request}`.

  Verify the request's service auth first (`XRPC.ServiceAuth.verify/3` with
  `lxm: "com.atproto.space.notifyRepoUpdate"`), then `check_repo_update_auth/2`
  against the decoded body. Since the November 12 alpha the body carries no
  `spaceRev`: the space host sequences the update itself.
  """
  @spec decode_notify_repo_update(map()) :: {:ok, repo_update()} | {:error, :invalid_request}
  def decode_notify_repo_update(%{"space" => space, "repo" => repo, "repoRev" => rev} = body) do
    with true <- XRPC.space_ref?(space) and did?(repo) and tid?(rev),
         {:ok, data} when is_binary(data) <- decode_field(body, "data") do
      {:ok, %{space: space, repo: repo, repo_rev: rev, data: data}}
    else
      _ -> {:error, :invalid_request}
    end
  end

  def decode_notify_repo_update(_), do: {:error, :invalid_request}

  @doc """
  Space host side: check a verified `notifyRepoUpdate` service auth payload
  against the decoded body, as the reference does: `iss` must be the repo (so
  a repo host cannot notify on another account's behalf), and `aud` the space
  authority, bare or as `{authority}#atproto_pds` (a host answers for many
  authorities, so the audience is only knowable from the body).

  Returns `:ok`, `{:error, :iss_mismatch}` or `{:error, :aud_mismatch}`
  (both answered as `Forbidden`).
  """
  @spec check_repo_update_auth(map(), repo_update()) ::
          :ok | {:error, :iss_mismatch | :aud_mismatch}
  def check_repo_update_auth(%{} = payload, %{space: space, repo: repo}) do
    authority = authority(space)

    cond do
      payload["iss"] != repo ->
        {:error, :iss_mismatch}

      payload["aud"] not in [authority, Token.space_host_aud(authority)] ->
        {:error, :aud_mismatch}

      true ->
        :ok
    end
  end

  # -- the set hash -----------------------------------------------------------------

  @doc """
  Fold a page of oplog ops into the running set hash (remove `prev`, add
  `cid` — deletes carry `cid: null`). Ops are maps in the wire shape with
  string keys. `sync_repo/6` does this with the ordering and value checks.
  """
  @spec apply_ops(Lthash.t(), [map()]) :: Lthash.t()
  def apply_ops(%Lthash{} = hash, ops) when is_list(ops),
    do: Enum.reduce(ops, hash, &Commit.apply_op(&2, &1))

  @doc """
  The authenticated-sync check: the running set hash's digest equals the
  head commit's `data` (a verified commit, or the raw 32-byte digest). When
  this holds, the local copy is fully synced — and what the author's repo
  host vouched for, not merely what some host served.
  """
  @spec synced?(Lthash.t(), binary() | map()) :: boolean()
  def synced?(%Lthash{} = hash, data) when is_binary(data),
    do: Mac.equal?(Lthash.digest(hash), data)

  def synced?(%Lthash{} = hash, %{"data" => data}), do: synced?(hash, data)
  def synced?(%Lthash{}, _), do: false

  # -- requests ---------------------------------------------------------------------

  defp get_json(url, cred, audience, extra_headers, opts) do
    http = Keyword.get(opts, :http, HTTP)

    case signed_request(http, url, opts, cred, audience, extra_headers) do
      {:ok, %{status: 200, body: body} = response} when is_map(body) -> {:ok, response}
      {:ok, response} -> classify_error(response)
      error -> error
    end
  end

  # Every credential-authed request: the credential, its audience, and the
  # signature over both. The signature binds neither method nor URI. Every
  # sync read is a GET.
  defp signed_request(http, url, opts, cred, audience, extra_headers) do
    {:ok, headers} = Credential.presentation_headers(cred, audience)
    request_opts = Keyword.put(HTTP.take_request_opts(opts), :headers, headers ++ extra_headers)
    http.request(:get, url, request_opts)
  end

  # The audience for space-host methods: the authority DID of the space ref.
  defp authority(space_ref) do
    case AtUri.parse(space_ref) do
      {:ok, %AtUri{authority: authority}} when is_binary(authority) -> authority
      _ -> raise ArgumentError, "not a space reference: #{inspect(space_ref)}"
    end
  end

  defp xrpc_url(host, nsid, params) do
    query = URI.encode_query(params)
    "#{String.trim_trailing(host, "/")}/xrpc/#{nsid}?#{query}"
  end

  # The media type, without parameters, when the response names one.
  defp check_star_content_type(headers) do
    case HttpSignature.normalize_headers(headers)["content-type"] do
      nil ->
        :ok

      content_type ->
        media_type =
          content_type
          |> String.split(";", parts: 2)
          |> hd()
          |> String.trim()
          |> String.downcase()

        if media_type == XRPC.star_content_type(),
          do: :ok,
          else: {:error, {:unexpected_content_type, content_type}}
    end
  end

  defp new_challenge,
    do: :crypto.strong_rand_bytes(16) |> Base.encode32(case: :lower, padding: false)

  # -- MACs and the KEM key -----------------------------------------------------------

  # Run a MAC'd request with the author's KEM key. `attempt` encapsulates
  # afresh, so a retry never reuses a key share. A failed verification is
  # retried once with a re-resolved key, when the caller gave a resolver.
  defp with_kem(opts, attempt) do
    with {:ok, kem_key} <- resolve_kem_key(opts, false) do
      case attempt.(kem_key) do
        {:error, reason} = error ->
          if is_function(Keyword.get(opts, :kem_key), 1) and verification_error?(reason) do
            with {:ok, kem_key} <- resolve_kem_key(opts, true), do: attempt.(kem_key)
          else
            error
          end

        result ->
          result
      end
    end
  end

  defp resolve_kem_key(opts, refresh?) do
    case Keyword.get(opts, :kem_key) do
      nil ->
        {:error, :missing_kem_key}

      resolve when is_function(resolve, 1) ->
        case resolve.(refresh?) do
          {:ok, key} when is_binary(key) -> {:ok, key}
          {:error, _} = error -> error
          _ -> {:error, :invalid_kem_key}
        end

      key when is_binary(key) ->
        {:ok, key}

      _ ->
        {:error, :invalid_kem_key}
    end
  end

  # What the reference retries with a refreshed KEM key: a MAC that fails, or
  # a response that fails verification against it.
  @verification_errors [
    :invalid_commit,
    :repo_mismatch,
    :space_mismatch,
    :records_do_not_match_commit,
    :wrong_star_type,
    :invalid_record,
    :record_uri_mismatch,
    :record_cid_mismatch
  ]

  defp verification_error?({:invalid_space_mac, _}), do: true
  defp verification_error?({:unsupported_commit_version, _}), do: true
  defp verification_error?({:records_out_of_order, _}), do: true
  defp verification_error?({:invalid_record_path, _}), do: true
  defp verification_error?(reason), do: reason in @verification_errors

  # The reference's order: the record requested, a CID, the MAC over both,
  # then the value against the CID.
  defp verify_record(%{"uri" => uri, "cid" => cid_string, "value" => value}, uri, kem, headers)
       when is_binary(cid_string) do
    with {:ok, cid} <- decode_cid(cid_string),
         :ok <- Mac.verify_record(uri, cid, kem, headers),
         {:ok, value_cid} <- value_cid(value) do
      if value_cid == cid, do: :ok, else: {:error, :record_cid_mismatch}
    end
  end

  defp verify_record(%{"uri" => other}, uri, _kem, _headers) when other != uri,
    do: {:error, :record_uri_mismatch}

  defp verify_record(_, _, _, _), do: {:error, :invalid_record}

  defp decode_cid(string) do
    case CID.decode(string) do
      {:ok, cid} -> {:ok, cid}
      _ -> {:error, :invalid_record}
    end
  end

  defp record_uri(space_ref, repo_did, collection, rkey) do
    with {:ok, %AtUri{authority: authority, space_type: type, skey: skey}} when is_binary(type) <-
           AtUri.parse(space_ref),
         {:ok, uri} <- AtUri.make_space(authority, type, skey, repo_did, collection, rkey) do
      {:ok, AtUri.to_string(uri)}
    else
      _ -> {:error, :invalid_space_ref}
    end
  end

  # The CID of a JSON record value: back to the data model ($link → CID,
  # $bytes → byte string), DRISL-encoded, sha256.
  defp value_cid(value) do
    with {:ok, bytes} <- DagCbor.encode(from_json(value)) do
      {:ok, %CID{version: 1, codec: :dag_cbor, hash: :crypto.hash(:sha256, bytes)}}
    end
  rescue
    _ -> {:error, :invalid_record}
  end

  defp from_json(%{"$link" => link} = map) when map_size(map) == 1, do: CID.decode!(link)

  defp from_json(%{"$bytes" => b64} = map) when map_size(map) == 1,
    do: %CBOR.Tag{tag: :bytes, value: Base.decode64!(b64, padding: false)}

  defp from_json(map) when is_map(map), do: Map.new(map, fn {k, v} -> {k, from_json(v)} end)
  defp from_json(list) when is_list(list), do: Enum.map(list, &from_json/1)
  defp from_json(float) when is_float(float) and float == trunc(float), do: trunc(float)
  defp from_json(other), do: other

  # -- errors -------------------------------------------------------------------------

  @typed_errors %{
    "RepoNotFound" => :repo_not_found,
    "RepoTakendown" => :repo_takendown,
    "RepoDeactivated" => :repo_deactivated,
    "RepoSuspended" => :repo_suspended,
    "InvalidSpaceMac" => :invalid_space_mac,
    "InvalidCursor" => :invalid_cursor
  }

  # XRPC error bodies are {"error": code, "message": msg}. The sync-recovery
  # signal is typed rather than left as a bare 400: a caller of list_repo_ops/5
  # gets a named match to route to the full-archive recovery, not a
  # string-match.
  defp classify_error(%{status: 400, body: %{"error" => "SinceOutOfBounds"} = body}) do
    {:error, {:since_out_of_bounds, floor_from_message(body["message"])}}
  end

  defp classify_error(%{body: %{"error" => code}}) when is_map_key(@typed_errors, code),
    do: {:error, Map.fetch!(@typed_errors, code)}

  defp classify_error(%{status: status}), do: {:error, {:http_error, status}}

  # "...the oldest retained rev is 3kbcq3p7ad2c2 — recover with a full getRepo":
  # pull the floor out when the host words it that way; nil otherwise (the
  # message is host prose, not a lexicon field).
  @floor_pattern ~r/oldest retained rev is ([0-9a-z]{13})/

  defp floor_from_message(message) when is_binary(message) do
    with [_, candidate] <- Regex.run(@floor_pattern, message),
         true <- TID.valid?(candidate) do
      candidate
    else
      _ -> nil
    end
  end

  defp floor_from_message(_), do: nil

  # -- decoding -----------------------------------------------------------------------

  # A defs#commit carries one lexicon `bytes` field, `data`. Every response
  # that carries one must carry it (listRepoOps on every page since the
  # November 12 alpha).
  defp decode_commit(%{} = commit) do
    with {:ok, %{"data" => data}} <- decode_fields(commit, ["data"]) do
      {:ok, Map.put(commit, "data", data)}
    end
  end

  defp decode_commit(nil), do: {:error, :missing_commit}
  defp decode_commit(_), do: {:error, :invalid_commit}

  defp decode_ops(ops) when is_list(ops) do
    if Enum.all?(ops, &is_map/1), do: {:ok, ops}, else: {:error, :invalid_op}
  end

  defp decode_ops(_), do: {:error, :invalid_response}

  defp optional_string(nil), do: {:ok, nil}
  defp optional_string(value) when is_binary(value), do: {:ok, value}
  defp optional_string(_), do: {:error, :invalid_response}

  defp decode_writers(repos) when is_list(repos) do
    repos
    |> Enum.reduce_while({:ok, []}, fn
      %{"$type" => type} = entry, {:ok, acc} when type in [@repo_write, @repo_removed] ->
        case decode_entry(entry) do
          {:ok, writer} -> {:cont, {:ok, [writer | acc]}}
          {:error, {:invalid_bytes, _}} = error -> {:halt, error}
          {:error, _} -> {:halt, {:error, :invalid_writer}}
        end

      # An open union: a member type this library does not know is skipped.
      %{"$type" => type}, acc when is_binary(type) ->
        {:cont, acc}

      _, _ ->
        {:halt, {:error, :invalid_writer}}
    end)
    |> case do
      {:ok, decoded} -> {:ok, Enum.reverse(decoded)}
      {:error, _} = error -> error
    end
  end

  defp decode_writers(_), do: {:error, :invalid_response}

  # A defs#repoWrite or defs#repoRemoved, without prevSpaceRev.
  defp decode_entry(%{"$type" => @repo_write} = entry) do
    with {:ok, data} <- decode_field(entry, "data"),
         true <-
           (did?(entry["repo"]) and tid?(entry["repoRev"]) and tid?(entry["spaceRev"]) and
              is_binary(data)) || {:error, :invalid} do
      {:ok,
       %{
         type: :repo_write,
         repo: entry["repo"],
         repo_rev: entry["repoRev"],
         data: data,
         space_rev: entry["spaceRev"]
       }}
    end
  end

  defp decode_entry(%{"$type" => @repo_removed} = entry) do
    if did?(entry["repo"]) and tid?(entry["spaceRev"]),
      do: {:ok, %{type: :repo_removed, repo: entry["repo"], space_rev: entry["spaceRev"]}},
      else: {:error, :invalid}
  end

  # The wire form of a writer set entry or notifySpaceUpdate update; nil for
  # anything else.
  defp encode_entry(
         %{type: :repo_write, repo: repo, repo_rev: rev, data: data, space_rev: srev} = u
       )
       when is_binary(data) do
    %{
      "$type" => @repo_write,
      "repo" => repo,
      "repoRev" => rev,
      "data" => encode_bytes(data),
      "spaceRev" => srev
    }
    |> maybe_put("prevSpaceRev", Map.get(u, :prev_space_rev))
  end

  defp encode_entry(%{type: :repo_removed, repo: repo, space_rev: srev} = u) do
    %{"$type" => @repo_removed, "repo" => repo, "spaceRev" => srev}
    |> maybe_put("prevSpaceRev", Map.get(u, :prev_space_rev))
  end

  defp encode_entry(%{type: :space_deleted}), do: %{"$type" => @space_deleted}

  defp encode_entry(%{type: :registration_expired, space_rev: srev}) when is_binary(srev),
    do: %{"$type" => @registration_expired, "spaceRev" => srev}

  defp encode_entry(_), do: nil

  # Lexicon `bytes` in JSON: {"$bytes": b64}, standard alphabet, unpadded.
  defp encode_bytes(binary), do: %{"$bytes" => Base.encode64(binary, padding: false)}

  # Lexicon `bytes` travel in JSON as {"$bytes": b64} — the standard RFC 4648
  # §4 alphabet (not URL-safe), `=` padding optional (atproto data model
  # spec). Anything else is an error rather than a silent pass-through, so a
  # malformed value can never pose as a decoded one.
  defp decode_bytes(%{"$bytes" => b64}) when is_binary(b64), do: decode_bytes(b64)
  defp decode_bytes(b64) when is_binary(b64), do: Base.decode64(b64, padding: false)
  defp decode_bytes(_other), do: :error

  defp decode_fields(map, fields) do
    Enum.reduce_while(fields, {:ok, %{}}, fn field, {:ok, acc} ->
      case decode_field(map, field) do
        {:ok, decoded} -> {:cont, {:ok, Map.put(acc, field, decoded)}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  # An absent field decodes to nil; a present-but-undecodable one is an error.
  defp decode_field(map, field) do
    case Map.fetch(map, field) do
      :error ->
        {:ok, nil}

      {:ok, wire} ->
        case decode_bytes(wire) do
          {:ok, bin} -> {:ok, bin}
          :error -> {:error, {:invalid_bytes, field}}
        end
    end
  end

  defp did?(value), do: is_binary(value) and DID.valid?(value)
  defp tid?(value), do: is_binary(value) and TID.valid?(value)
  defp token?(value), do: is_binary(value) and byte_size(value) <= @max_token_bytes

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
