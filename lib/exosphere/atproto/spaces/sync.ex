defmodule Exosphere.ATProto.Spaces.Sync do
  @moduledoc """
  The space sync client (atproto proposal 0016): keep a local copy of a
  member's permissioned repo in step with its repo host, authenticated end to
  end.

  Sync runs over dedicated XRPC with LtHash commit digests. The client
  maintains a running set hash; when the running hash equals the latest
  commit's hash, the local copy is fully synced **and authenticated**. On
  divergence, recover via a full CAR (`get_repo/4`, verified through
  `Spaces.Repo.verify_car/5`) or `get_latest_commit/3` plus a records diff.

  Oplog entries (`list_repo_ops/3`) are a transport optimisation, never a
  source of truth: hosts may compact them, and they reset on account
  migration — hence `list_repo_ops/3` returns the retained window, and
  divergence falls back to the full CAR.

  Notify registration (`register_notify/3`) subscribes a syncer to write
  notifications at a space host; websocket delivery of `notifyWrite` stays in
  the consumer's process tree (model on `Exosphere.Firehose.Consumer`'s
  reconnect discipline) — this module exposes registration and leaves
  receiving to the app.

  All requests are credential-authed: the space credential travels as the
  DPoP-scheme access token with a per-request proof carrying its `ath`
  (through `Exosphere.ATProto.OAuth.Request.authorized/6`, including nonce
  retries). Pass `:http` to substitute an `HTTP.Behaviour` mock.
  """

  alias Exosphere.ATProto.HTTP
  alias Exosphere.ATProto.OAuth.Request
  alias Exosphere.ATProto.Spaces.Commit
  alias Exosphere.ATProto.Spaces.Lthash
  alias Exosphere.ATProto.Spaces.Repo, as: SpaceRepo

  @type credential :: %{credential: String.t(), dpop_key: map()}

  @doc """
  The space host's writer set (`com.atproto.space.listRepos`): each member
  repo with its current `rev` and commit `hash` as last reported to the
  authority. The authority may lag the repo hosts, which are the source of
  truth.

  Returns `{:ok, %{repos: [%{did:, rev:, hash:}], cursor: cursor | nil}}`.
  The `hash` values are base64-decoded from the lexicon `bytes` wire form
  (`{"$bytes": …}`).
  """
  @spec list_repos(String.t(), String.t(), credential(), keyword()) ::
          {:ok, %{repos: [map()], cursor: String.t() | nil}} | {:error, term()}
  def list_repos(space_host, space_ref, cred, opts \\ []) do
    params =
      %{space: space_ref}
      |> maybe_put("limit", Keyword.get(opts, :limit))
      |> maybe_put("cursor", Keyword.get(opts, :cursor))

    with {:ok, body} <- get(space_host, "com.atproto.space.listRepos", params, cred, opts),
         {:ok, repos} <- decode_repos(body["repos"]) do
      {:ok, %{repos: repos, cursor: body["cursor"]}}
    end
  end

  @doc """
  A repo's current signed commit (`com.atproto.space.getLatestCommit`), from
  its repo host. The commit's `hash` is the digest a fully-synced running
  set hash must equal. Its `bytes` fields (`hash`, `ikm`, `mac`, `sig`) are
  returned decoded.
  """
  @spec get_latest_commit(String.t(), String.t(), String.t(), credential(), keyword()) ::
          {:ok, map() | nil} | {:error, term()}
  def get_latest_commit(repo_host, space_ref, repo_did, cred, opts \\ []) do
    with {:ok, body} <-
           get(
             repo_host,
             "com.atproto.space.getLatestCommit",
             %{space: space_ref, repo: repo_did},
             cred,
             opts
           ) do
      decode_commit(body["commit"])
    end
  end

  @doc """
  A repo's oplog (`com.atproto.space.listRepoOps`) after `since` (the local
  sync position). Records are inlined by default; `exclude_values: true`
  fetches metadata only. Ops sharing a `rev` belong to one batch.

  Returns `{:ok, %{ops: [map()], commit: map() | nil, cursor: String.t() | nil}}`
  — the head `commit` is present when the response reaches the oplog head,
  and `cursor` is present when it does not (page until it disappears). The
  commit's `bytes` fields arrive decoded, like `get_latest_commit/5`.
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

    with {:ok, body} <- get(repo_host, "com.atproto.space.listRepoOps", params, cred, opts),
         {:ok, commit} <- decode_commit(body["commit"]) do
      {:ok, %{ops: body["ops"] || [], commit: commit, cursor: body["cursor"]}}
    end
  end

  @doc """
  A repo's records (`com.atproto.space.listRecords`), page by page.
  """
  @spec list_records(String.t(), String.t(), String.t(), String.t(), credential(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def list_records(repo_host, space_ref, repo_did, collection, cred, opts \\ []) do
    params =
      %{space: space_ref, repo: repo_did, collection: collection}
      |> maybe_put("cursor", Keyword.get(opts, :cursor))
      |> maybe_put("limit", Keyword.get(opts, :limit))
      |> maybe_put("reverse", Keyword.get(opts, :reverse))

    get(repo_host, "com.atproto.space.listRecords", params, cred, opts)
  end

  @doc """
  A single record (`com.atproto.space.getRecord`).
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

    get(repo_host, "com.atproto.space.getRecord", params, cred, opts)
  end

  @doc """
  The full-repo CAR (`com.atproto.space.getRepo`), verified end to end
  through `Spaces.Repo.verify_car/5`: commit MAC + signature, canonical
  index folding to the commit's hash, and every record block under its index
  CID in index order.

  `ctx` supplies the space URI and author DID; `public_key`/`curve` are the
  author's account signing key. On success the returned set hash is the
  authenticated running hash to continue syncing from.
  """
  @spec get_repo(
          String.t(),
          String.t(),
          String.t(),
          map(),
          binary(),
          atom(),
          credential(),
          keyword()
        ) ::
          {:ok, SpaceRepo.verified()} | {:error, term()}
  def get_repo(repo_host, space_ref, repo_did, ctx, public_key, curve, cred, opts \\ []) do
    http = Keyword.get(opts, :http, HTTP)
    url = xrpc_url(repo_host, "com.atproto.space.getRepo", %{space: space_ref, repo: repo_did})

    case Request.authorized(http, :get, url, [], cred.dpop_key, cred.credential) do
      {:ok, %{status: 200, body: car}} when is_binary(car) ->
        SpaceRepo.verify_car(car, ctx, public_key, curve, Keyword.take(opts, [:expect_values]))

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      error ->
        error
    end
  end

  @doc """
  Subscribe to write notifications for the space (`com.atproto.space.registerNotify`,
  a procedure on the space host). The subscriber is named by `service` — a
  service identifier (a DID with an optional service fragment), not a bare
  URL, because `notifyWrite` is delivered with service auth addressed to that
  identifier. Re-registering replaces the registration and extends the
  expiry, which may outlive the credential's own — renew before then.
  Websocket delivery of `notifyWrite` stays in the consumer's process tree.
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
  Fold a page of oplog ops into the running set hash (remove `prev`, add
  `cid` — deletes carry `cid: null`). Ops are maps in the wire shape with
  string keys.
  """
  @spec apply_ops(Lthash.t(), [map()]) :: Lthash.t()
  def apply_ops(%Lthash{} = hash, ops) when is_list(ops),
    do: Enum.reduce(ops, hash, &Commit.apply_op(&2, &1))

  @doc """
  The authenticated-sync check: the running set hash's digest equals the
  head commit's hash. When this holds, the local copy is fully synced — and
  cryptographic proof that it is what the author signed, not merely what
  the host served.
  """
  @spec synced?(Lthash.t(), binary() | map()) :: boolean()
  def synced?(%Lthash{} = hash, commit_hash) when is_binary(commit_hash),
    do: Lthash.digest(hash) == commit_hash

  def synced?(%Lthash{} = hash, %{"hash" => commit_hash}),
    do: synced?(hash, commit_hash)

  defp get(host, nsid, params, cred, opts) do
    http = Keyword.get(opts, :http, HTTP)
    url = xrpc_url(host, nsid, params)

    case Request.authorized(http, :get, url, [], cred.dpop_key, cred.credential) do
      {:ok, %{status: 200, body: body}} when is_map(body) -> {:ok, body}
      {:ok, %{status: status}} -> {:error, {:http_error, status}}
      error -> error
    end
  end

  # The signedCommit carries four lexicon `bytes` fields.
  defp decode_commit(nil), do: {:ok, nil}

  defp decode_commit(%{} = commit) do
    with {:ok, decoded} <- decode_fields(commit, ~w(hash ikm mac sig)) do
      {:ok, Map.merge(commit, decoded)}
    end
  end

  defp notify_procedure(space_host, method, space_ref, service, cred, opts) do
    http = Keyword.get(opts, :http, HTTP)
    url = "#{String.trim_trailing(space_host, "/")}/xrpc/com.atproto.space.#{method}"

    case Request.authorized(
           http,
           :post,
           url,
           [json: %{"space" => space_ref, "service" => service}],
           cred.dpop_key,
           cred.credential
         ) do
      {:ok, %{status: 200, body: body}} when is_map(body) ->
        {:ok, body}

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      error ->
        error
    end
  end

  defp xrpc_url(host, nsid, params) do
    query = URI.encode_query(params)
    "#{String.trim_trailing(host, "/")}/xrpc/#{nsid}?#{query}"
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
      case decode_field(repo, "hash") do
        {:ok, hash} -> {:cont, {:ok, [%{did: repo["did"], rev: repo["rev"], hash: hash} | acc]}}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, decoded} -> {:ok, Enum.reverse(decoded)}
      {:error, _} = error -> error
    end
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
