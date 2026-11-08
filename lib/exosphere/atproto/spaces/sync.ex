defmodule Exosphere.ATProto.Spaces.Sync do
  @moduledoc """
  The space sync client (atproto proposal 0016): keep a local copy of a
  member's permissioned repo in step with its repo host, authenticated end to
  end.

  Sync runs over dedicated XRPC with LtHash commit digests. The client
  maintains a running set hash; when its digest equals the latest commit's
  `data`, the local copy is fully synced **and authenticated**. On
  divergence, recover via a full STAR archive (`get_repo/5`, verified through
  `Spaces.Repo.verify/4`) or `get_latest_commit/5` plus a records diff.

  Oplog entries (`list_repo_ops/5`) are a transport optimisation, never a
  source of truth: hosts may compact them, and they reset on account
  migration — hence `list_repo_ops/5` returns the retained window, and
  divergence falls back to the full archive.

  Notify registration (`register_notify/5`) subscribes a syncer to write
  notifications at a space host; delivery of `notifyWrite` stays in the
  consumer's process tree — this module exposes registration and
  `decode_notify_write/1`, and leaves receiving to the app.

  ## Authorization

  All requests are credential-authed: the space credential travels as
  `Authorization: Atproto-Space-Credential <jwt>` with an
  `Atproto-Space-Audience` header and an RFC 9421 HTTP Message Signature by
  the credential's bound key (`Spaces.HttpSignature`). The audience is the
  repo owner's DID for repo-host methods and the space authority's DID for
  space-host methods (`list_repos/4`, `register_notify/5`,
  `unregister_notify/5`). Pass `:http` to substitute an `HTTP.Behaviour` mock.

  ## Authenticity: the commit and record MACs

  Commits carry no signature (atproto `5791385`). Methods that return a
  commit or record — `get_latest_commit/5`, `list_repo_ops/5`, `get_repo/5`,
  `get_record/7` — need the author's `#atproto_kem` public key, passed as
  `kem_key:` (a compressed P-256 key or `did:key`; resolve it with
  `Identity.Document.get_kem_key/1`). For each request the client derives a
  fresh shared secret (`Spaces.Kem.encapsulate/1`), sends its key share in
  `Atproto-Space-Want-Mac`, and verifies the `Atproto-Space-Mac` the host
  answers with (`Spaces.Mac`) — so what comes back is authenticated to the
  author's repo host, and deniable to everyone else. A missing `kem_key:` is
  `{:error, :missing_kem_key}`; a MAC that fails is `{:error, :invalid_mac}`,
  on which the proposal advises refreshing the author's DID document before
  retrying.

  ## Error surface

  Failures come back typed: transport errors as-is, and HTTP errors as
  `{:error, {:http_error, status}}` — except the sync-recovery signal. When a
  host answers `listRepoOps`'s `since` with `400 SinceOutOfBounds` (the `since`
  predates the retained oplog window, or names a position the oplog never
  covered), the client returns `{:error, {:since_out_of_bounds, floor}}` with
  the window's oldest retained rev parsed out of the message when the host
  carries it — the position a full `get_repo/5` recovery starts from.
  """

  alias Exosphere.ATProto.{AtUri, CID, HTTP, TID}
  alias Exosphere.ATProto.CBOR, as: DagCbor
  alias Exosphere.ATProto.Spaces.{Commit, Credential, Kem, Lthash, Mac}
  alias Exosphere.ATProto.Spaces.Repo, as: SpaceRepo

  @typedoc "A minted credential and its bound key (`Spaces.Credential.mint/4`)."
  @type credential :: Credential.t()

  @doc """
  The space host's writer set (`com.atproto.space.listRepos`): each member
  repo with its current `repo_rev` and commit `data` (the sha256 of its
  LtHash state) as last reported to the authority, and the `space_rev` at
  which the host last saw it move. The authority may lag the repo hosts,
  which are the source of truth.

  Returns `{:ok, %{repos: [%{did:, repo_rev:, space_rev:, data:}], cursor:
  cursor | nil}}`. The `data` values are base64-decoded from the lexicon
  `bytes` wire form (`{"$bytes": …}`). The wire field was `hash` until atproto
  `5791385` (2026-10-27) renamed it alongside the commit's own digest field;
  a pre-rename host's `hash` is not read across (`data` decodes to `nil`).

  ## Two revisions, and why they are not the same thing

  Until atproto `357c4cee9` (2026-09-30) a repo entry carried one `rev`. It
  now carries two, and they answer different questions:

    * `repo_rev` (wire `repoRev`) is **the repo's** revision — the TID of the
      author's latest commit, the same number `list_repo_ops/5`'s `since:`
      takes. It is per-repo and only ever compared within one repo.
    * `space_rev` (wire `spaceRev`) is **the space host's** sequence number
      for the update: every accepted `notifyWrite` advances one per-space
      sequence, and the repo's entry is stamped with where it landed. It is
      what the listing is *ordered by*, ascending, and what the cursor is.

  The second is what makes the writer set resumable rather than merely
  pageable: `cursor:` is "repos updated after this space revision
  (exclusive)", so a syncer that remembers the last `space_rev` it processed
  — from a page, or from a forwarded `notifyWrite`'s `spaceRev` — can ask for
  only what moved since, and a gap in a forwarded notification's
  `prevSpaceRev` chain is recovered by exactly that call. A repo can appear
  twice across pages if it moved while you paged; that is the lexicon's
  stated behaviour, not a host bug.

  The cursor rule changed with it: a **non-empty** page carries a cursor
  (its last entry's `spaceRev`), and an empty page omits it. So the end of
  the walk is an empty page, one round trip later than "a short page" was.
  """
  @spec list_repos(String.t(), String.t(), credential(), keyword()) ::
          {:ok, %{repos: [map()], cursor: String.t() | nil}} | {:error, term()}
  def list_repos(space_host, space_ref, cred, opts \\ []) do
    params =
      %{space: space_ref}
      |> maybe_put("limit", Keyword.get(opts, :limit))
      |> maybe_put("cursor", Keyword.get(opts, :cursor))

    url = xrpc_url(space_host, "com.atproto.space.listRepos", params)

    with {:ok, %{body: body}} <- get_json(url, cred, authority(space_ref), [], opts),
         {:ok, repos} <- decode_repos(body["repos"]) do
      {:ok, %{repos: repos, cursor: body["cursor"]}}
    end
  end

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

    with {:ok, kem} <- encapsulate(opts),
         {:ok, %{body: body, headers: headers}} <-
           get_json(url, cred, repo_did, want_mac(:commit, kem), opts),
         {:ok, commit} <- decode_commit(body["commit"]),
         :ok <- require_present(commit, :missing_commit),
         :ok <- verify_commit(commit, headers, space_ref, repo_did, kem) do
      {:ok, commit}
    end
  end

  @doc """
  A repo's oplog (`com.atproto.space.listRepoOps`) after `since` (the local
  sync position). Records are inlined by default; `exclude_values: true`
  fetches metadata only. Ops sharing a `rev` belong to one batch. Requires
  `kem_key:`.

  Returns `{:ok, %{ops: [map()], commit: map() | nil, cursor: String.t() | nil}}`
  — the head `commit` is present when the response reaches the oplog head
  (and is then verified against the response's MAC), and `cursor` is present
  when it does not (page until it disappears). A page without a commit has no
  MAC: its ops are checked when the final page's commit `data` is compared
  against your running set hash.

  When the host answers that `since` predates (or falls outside) its retained
  window, the error is `{:error, {:since_out_of_bounds, floor}}` with the
  window floor when the host names one — the cue to recover via `get_repo/5`.
  """
  @spec list_repo_ops(String.t(), String.t(), String.t(), credential(), keyword()) ::
          {:ok, %{ops: [map()], commit: map() | nil, cursor: String.t() | nil}}
          | {:error, term()}
  def list_repo_ops(repo_host, space_ref, repo_did, cred, opts \\ []) do
    params =
      %{space: space_ref, repo: repo_did}
      |> maybe_put("since", Keyword.get(opts, :since))
      |> maybe_put("cursor", Keyword.get(opts, :cursor))
      |> maybe_put("limit", Keyword.get(opts, :limit))
      |> maybe_put("excludeValues", Keyword.get(opts, :exclude_values))

    url = xrpc_url(repo_host, "com.atproto.space.listRepoOps", params)

    with {:ok, kem} <- encapsulate(opts),
         {:ok, %{body: body, headers: headers}} <-
           get_json(url, cred, repo_did, want_mac(:commit, kem), opts),
         {:ok, commit} <- decode_commit(body["commit"]),
         :ok <- maybe_verify_commit(commit, headers, space_ref, repo_did, kem) do
      {:ok, %{ops: body["ops"] || [], commit: commit, cursor: body["cursor"]}}
    end
  end

  @doc """
  A repo's records (`com.atproto.space.listRecords`), page by page. Options:
  `:collection` (omit to list across all collections), `:cursor`, `:limit`,
  `:reverse`, and `:exclude_values` (metadata only — collection, rkey, cid —
  for diffing a lightly diverged copy).

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
      |> maybe_put("reverse", Keyword.get(opts, :reverse))
      |> maybe_put("excludeValues", Keyword.get(opts, :exclude_values))

    url = xrpc_url(repo_host, "com.atproto.space.listRecords", params)

    with {:ok, %{body: body}} <- get_json(url, cred, repo_did, [], opts), do: {:ok, body}
  end

  @doc """
  A single record (`com.atproto.space.getRecord`), verified against the
  record MAC (requires `kem_key:`): the response must be the record that was
  requested (its `uri` is the space record URI
  `at://{authority}/space/{type}/{skey}/{repo}/{collection}/{rkey}`), the MAC
  must cover that URI and the record's CID, and the value must encode to that
  CID.

  Returns `{:ok, %{"uri" => …, "cid" => …, "value" => …}}`.
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

    with {:ok, uri} <- record_uri(space_ref, repo_did, collection, rkey),
         {:ok, kem} <- encapsulate(opts),
         {:ok, %{body: body, headers: headers}} <-
           get_json(url, cred, repo_did, want_mac(:record, kem), opts),
         :ok <- verify_record(body, headers, uri, kem) do
      {:ok, body}
    end
  end

  @doc """
  The full repo (`com.atproto.space.getRepo`) as a STAR archive, verified end
  to end through `Spaces.Repo.verify/4`: the archive's commit names the
  requested repo and space, its MAC verifies, and every record folds into a
  set hash equal to the commit's `data`. Requires `kem_key:`.

  On success the returned set hash is the authenticated running hash to
  continue syncing from (`list_repo_ops/5` with `since: verified.rev`).
  """
  @spec get_repo(String.t(), String.t(), String.t(), credential(), keyword()) ::
          {:ok, SpaceRepo.verified()} | {:error, term()}
  def get_repo(repo_host, space_ref, repo_did, cred, opts \\ []) do
    http = Keyword.get(opts, :http, HTTP)
    url = xrpc_url(repo_host, "com.atproto.space.getRepo", %{space: space_ref, repo: repo_did})

    with {:ok, kem} <- encapsulate(opts) do
      case signed_request(http, :get, url, [], cred, repo_did, want_mac(:commit, kem)) do
        {:ok, %{status: 200, body: star, headers: headers}} when is_binary(star) ->
          with {:ok, mac} <- response_mac(headers, :commit) do
            SpaceRepo.verify(star, %{space: space_ref, repo: repo_did}, kem.shared_secret, mac)
          end

        {:ok, response} ->
          classify_error(response)

        error ->
          error
      end
    end
  end

  @doc """
  Subscribe to write notifications for the space (`com.atproto.space.registerNotify`,
  a procedure on the space host). The subscriber is named by `service` — a
  service identifier (a DID with an optional service fragment), not a bare
  URL, because `notifyWrite` is delivered with service auth addressed to that
  identifier. Re-registering replaces the registration and extends the
  expiry, which may outlive the credential's own — renew before then.
  """
  @spec register_notify(String.t(), String.t(), String.t(), credential(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def register_notify(space_host, space_ref, service, cred, opts \\ []) do
    notify_procedure(space_host, "registerNotify", space_ref, service, cred, opts)
  end

  @doc """
  Withdraw a notify registration (`com.atproto.space.unregisterNotify`),
  passing the same `service` identifier it was registered under.
  Registrations may also simply be left to expire.
  """
  @spec unregister_notify(String.t(), String.t(), String.t(), credential(), keyword()) ::
          :ok | {:error, term()}
  def unregister_notify(space_host, space_ref, service, cred, opts \\ []) do
    case notify_procedure(space_host, "unregisterNotify", space_ref, service, cred, opts) do
      {:ok, _} -> :ok
      error -> error
    end
  end

  @doc """
  Decode a forwarded write notification (`com.atproto.space.notifyWrite`, the
  JSON body a space host POSTs to a registered syncer) into
  `%{space:, repo:, repo_rev:, data:, space_rev:, prev_space_rev:}`.

  `data` is the repo's commit digest after the write, base64-decoded from the
  lexicon `bytes` form (the field was `hash` until atproto `5791385`).
  `space_rev`/`prev_space_rev` sequence the space: a `prev_space_rev` that is
  not the last `space_rev` you processed means notifications were missed —
  recover with `list_repos/4`'s `cursor:` set to the last one you did
  process. The notification carries no record data and authenticates
  nothing about the repo: sync the repo itself from its host.

  Receiving the POST (and checking its service auth) is the app's job; this
  only gives the body a shape. Missing required fields are
  `{:error, {:missing_field, name}}`.
  """
  @spec decode_notify_write(map()) :: {:ok, map()} | {:error, term()}
  def decode_notify_write(%{} = body) do
    with :ok <- require_fields(body, ~w(space repo repoRev data)),
         {:ok, data} <- decode_field(body, "data") do
      {:ok,
       %{
         space: body["space"],
         repo: body["repo"],
         repo_rev: body["repoRev"],
         data: data,
         space_rev: body["spaceRev"],
         prev_space_rev: body["prevSpaceRev"]
       }}
    end
  end

  @doc """
  Fold a page of oplog ops into the running set hash (remove `prev`, add
  `cid` — deletes carry `cid: null`). Ops are maps in the wire shape with
  string keys.
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

  # -- requests -------------------------------------------------------------

  defp get_json(url, cred, audience, extra_headers, opts) do
    http = Keyword.get(opts, :http, HTTP)

    case signed_request(http, :get, url, [], cred, audience, extra_headers) do
      {:ok, %{status: 200, body: body} = response} when is_map(body) -> {:ok, response}
      {:ok, response} -> classify_error(response)
      error -> error
    end
  end

  defp notify_procedure(space_host, method, space_ref, service, cred, opts) do
    http = Keyword.get(opts, :http, HTTP)
    url = "#{String.trim_trailing(space_host, "/")}/xrpc/com.atproto.space.#{method}"
    body = [json: %{"space" => space_ref, "service" => service}]

    case signed_request(http, :post, url, body, cred, authority(space_ref), []) do
      {:ok, %{status: 200, body: body}} when is_map(body) -> {:ok, body}
      {:ok, %{status: 200}} -> {:ok, %{}}
      {:ok, response} -> classify_error(response)
      error -> error
    end
  end

  # Every credential-authed request: the credential, its audience, and the
  # signature over both. The signature binds neither method nor URI.
  defp signed_request(http, method, url, request_opts, cred, audience, extra_headers) do
    {:ok, headers} = Credential.presentation_headers(cred, audience)
    http.request(method, url, Keyword.put(request_opts, :headers, headers ++ extra_headers))
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

  # -- MACs -------------------------------------------------------------------

  # A fresh key share per request (retries and pages included).
  defp encapsulate(opts) do
    case Keyword.get(opts, :kem_key) do
      nil -> {:error, :missing_kem_key}
      kem_key -> Kem.encapsulate(kem_key)
    end
  end

  defp want_mac(type, kem),
    do: [{Mac.want_mac_header_name(), Mac.want_mac_header(type, kem.key_share)}]

  defp response_mac(headers, type) do
    headers
    |> header(Mac.mac_header_name())
    |> Mac.parse_mac_header(type)
  end

  defp verify_commit(commit, headers, space_ref, repo_did, kem) do
    with {:ok, mac} <- response_mac(headers, :commit) do
      Commit.verify(commit, %{space: space_ref, repo: repo_did}, kem.shared_secret, mac)
    end
  end

  defp maybe_verify_commit(nil, _headers, _space, _repo, _kem), do: :ok

  defp maybe_verify_commit(commit, headers, space, repo, kem),
    do: verify_commit(commit, headers, space, repo, kem)

  defp verify_record(%{"uri" => uri, "cid" => cid_string, "value" => value}, headers, uri, kem)
       when is_binary(cid_string) do
    with {:ok, mac} <- response_mac(headers, :record),
         {:ok, cid} <- CID.decode(cid_string),
         true <-
           Mac.equal?(Mac.record_mac(kem.shared_secret, uri, CID.to_bytes(cid)), mac) || :mac,
         {:ok, value_cid} <- value_cid(value),
         true <- value_cid == cid || :cid do
      :ok
    else
      :mac -> {:error, :invalid_mac}
      :cid -> {:error, :record_cid_mismatch}
      {:error, {:bad_space_mac, _}} = error -> error
      {:error, _} -> {:error, :invalid_record}
    end
  end

  defp verify_record(%{"uri" => other}, _headers, uri, _kem) when other != uri,
    do: {:error, :record_uri_mismatch}

  defp verify_record(_, _, _, _), do: {:error, :invalid_record}

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

  defp header(headers, name) when is_list(headers) do
    Enum.find_value(headers, fn {k, v} -> if String.downcase(k) == name, do: v end)
  end

  defp header(_, _), do: nil

  # -- errors -----------------------------------------------------------------

  # XRPC error bodies are {"error": code, "message": msg}. The sync-recovery
  # signal is typed rather than left as a bare 400: a caller of list_repo_ops/5
  # gets a named match to route to the full-archive recovery, not a
  # string-match. The reference PDS does not emit this code — its lexicon
  # declares no such error and its reader serves the retained window silently
  # — so this classifies hosts that follow the proposal's "cannot find its
  # since revision" guidance with an explicit signal.
  defp classify_error(%{status: 400, body: %{"error" => "SinceOutOfBounds"} = body}) do
    {:error, {:since_out_of_bounds, floor_from_message(body["message"])}}
  end

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

  # -- decoding -------------------------------------------------------------

  # A defs#commit carries one lexicon `bytes` field, `data`.
  defp decode_commit(nil), do: {:ok, nil}

  defp decode_commit(%{} = commit) do
    with {:ok, %{"data" => data}} <- decode_fields(commit, ["data"]) do
      {:ok, Map.put(commit, "data", data)}
    end
  end

  defp decode_commit(_), do: {:error, :invalid_commit}

  defp require_present(nil, error), do: {:error, error}
  defp require_present(_, _), do: :ok

  defp require_fields(body, fields) do
    case Enum.find(fields, &(not Map.has_key?(body, &1))) do
      nil -> :ok
      missing -> {:error, {:missing_field, missing}}
    end
  end

  # Lexicon `bytes` travel in JSON as {"$bytes": b64} — the standard RFC 4648
  # §4 alphabet (not URL-safe), `=` padding optional (atproto data model
  # spec). A bare string stays readable for hosts predating the wrapper;
  # anything else is an error rather than a silent pass-through, so a
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

  defp decode_repos(repos) when is_list(repos) do
    Enum.reduce_while(repos, {:ok, []}, fn repo, {:ok, acc} ->
      case decode_field(repo, "data") do
        {:ok, data} -> {:cont, {:ok, [decode_repo(repo, data) | acc]}}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, decoded} -> {:ok, Enum.reverse(decoded)}
      {:error, _} = error -> error
    end
  end

  defp decode_repos(_), do: {:error, :invalid_response}

  # The current field names only. A host still on the pre-`357c4cee9` lexicon
  # sends `rev` and no `spaceRev`, and both decode to `nil` here rather than
  # being read across: guessing that a field means what its successor means
  # is how a client ends up agreeing with one stale host and nobody else.
  defp decode_repo(repo, data) do
    %{did: repo["did"], repo_rev: repo["repoRev"], space_rev: repo["spaceRev"], data: data}
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
