defmodule Exosphere.ATProto.Spaces.Writes do
  @moduledoc """
  Write records into a member's permissioned repo through their own PDS
  (proposal 0016): `com.atproto.space.createRecord` / `putRecord` /
  `deleteRecord` / `applyWrites`.

  Writes always go to the user's **own** PDS under a space-scoped OAuth
  session (the `space:` scopes of `Exosphere.ATProto.OAuth.Scope`); the PDS
  routes the record into the space's permissioned repo. Credential-authed
  writes are not a thing — credentials read, sessions write.

  The authorization is the caller's. For an atproto OAuth session pass
  `session: session`: its access token is DPoP-bound, so each request carries
  `Authorization: DPoP …` plus a fresh proof, the PDS's DPoP nonce is used
  and a `use_dpop_nonce` challenge is retried once (via
  `Exosphere.ATProto.OAuth.Request`). A DPoP-bound token sent as `Bearer` is
  refused by the PDS. `headers: [...]` passes the given headers through
  verbatim, for any other authorization scheme.

  Request options (`:timeout`, `:follow_redirects`) travel in the same
  keyword list as everything else and reach the transport; see
  `Exosphere.ATProto.HTTP` on what a `:timeout` actually bounds.
  """

  alias Exosphere.ATProto.HTTP
  alias Exosphere.ATProto.OAuth.{Request, Session}
  alias Exosphere.ATProto.Spaces.XRPC

  @nsid "com.atproto.space"

  @type auth :: [headers: [{String.t(), String.t()}]] | [session: Session.t()]

  @doc """
  Create a record (`com.atproto.space.createRecord`) into the member
  `repo_did`'s permissioned repo — server-chosen rkey unless `:rkey` is
  given. `:validate` toggles Lexicon validation (unset = validate known
  Lexicons only).
  """
  @spec create_record(String.t(), String.t(), String.t(), String.t(), map(), auth(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def create_record(pds, space_ref, repo_did, collection, record, auth, opts \\ []) do
    procedure(
      pds,
      "createRecord",
      %{"space" => space_ref, "repo" => repo_did, "collection" => collection, "record" => record}
      |> maybe_put("rkey", Keyword.get(opts, :rkey))
      |> maybe_put("validate", Keyword.get(opts, :validate)),
      auth,
      opts
    )
  end

  @doc """
  Create or replace a record at a known rkey (`com.atproto.space.putRecord`).
  """
  @spec put_record(
          String.t(),
          String.t(),
          String.t(),
          String.t(),
          String.t(),
          map(),
          auth(),
          keyword()
        ) ::
          {:ok, map()} | {:error, term()}
  def put_record(pds, space_ref, repo_did, collection, rkey, record, auth, opts \\ []) do
    procedure(
      pds,
      "putRecord",
      %{
        "space" => space_ref,
        "repo" => repo_did,
        "collection" => collection,
        "rkey" => rkey,
        "record" => record
      },
      auth,
      opts
    )
  end

  @doc """
  Delete a record (`com.atproto.space.deleteRecord`).
  """
  @spec delete_record(
          String.t(),
          String.t(),
          String.t(),
          String.t(),
          String.t(),
          auth(),
          keyword()
        ) ::
          {:ok, map()} | {:error, term()}
  def delete_record(pds, space_ref, repo_did, collection, rkey, auth, opts \\ []) do
    procedure(
      pds,
      "deleteRecord",
      %{"space" => space_ref, "repo" => repo_did, "collection" => collection, "rkey" => rkey},
      auth,
      opts
    )
  end

  @doc """
  Apply a batch of writes atomically (`com.atproto.space.applyWrites`) —
  every op lands under one shared rev. Ops are `$type`-discriminated maps;
  build them with `create_op/3`, `update_op/3`, `delete_op/2`.
  """
  @spec apply_writes(String.t(), String.t(), String.t(), [map()], auth(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def apply_writes(pds, space_ref, repo_did, ops, auth, opts \\ []) when is_list(ops) do
    procedure(
      pds,
      "applyWrites",
      %{"space" => space_ref, "repo" => repo_did, "writes" => ops}
      |> maybe_put("validate", Keyword.get(opts, :validate)),
      auth,
      opts
    )
  end

  @doc """
  Delete every record in the caller's repo in the space
  (`com.atproto.space.clearRecords`, atproto `840c41e`). The repo advances to
  a new rev with the empty repo's digest and its oplog is cleared; in the
  authority's own repo the records the host publishes from the space's
  configuration (`com.atproto.space.policy`, `com.atproto.memberspace.member`)
  are kept. Succeeds whether or not there was anything to delete.
  """
  @spec clear_records(String.t(), String.t(), String.t(), auth(), keyword()) ::
          :ok | {:error, term()}
  def clear_records(pds, space_ref, repo_did, auth, opts \\ []) do
    body = %{"space" => space_ref, "repo" => repo_did}

    with {:ok, _} <- XRPC.procedure(pds, "#{@nsid}.clearRecords", body, auth, opts), do: :ok
  end

  @doc """
  Import the caller's repo in a space from a STAR archive as `getRepo` serves
  it (`com.atproto.space.importRepo`, atproto `35c0cf1`), during account
  migration, replacing whatever the host holds for that repo. The archive's
  commit names the space and must name the account as its repo; check it
  locally first with `Spaces.Repo.read/1`. If the account is the space's
  authority, import the space meta archive first
  (`Spaces.Space.import_space_meta/4`). Blobs are uploaded separately.
  Requires a `create` grant for every collection in the archive.
  """
  @spec import_repo(String.t(), binary(), auth(), keyword()) :: :ok | {:error, term()}
  def import_repo(pds, star, auth, opts \\ []) when is_binary(star) do
    with {:ok, _} <- XRPC.procedure_bytes(pds, "#{@nsid}.importRepo", star, auth, opts), do: :ok
  end

  @doc """
  A `#create` op for `apply_writes/6`, with an optional client-chosen rkey.
  """
  @spec create_op(String.t(), map(), String.t() | nil) :: map()
  def create_op(collection, record, rkey \\ nil) do
    %{"$type" => "#{@nsid}.applyWrites#create", "collection" => collection, "value" => record}
    |> maybe_put("rkey", rkey)
  end

  @doc """
  An `#update` op for `apply_writes/6`.
  """
  @spec update_op(String.t(), String.t(), map()) :: map()
  def update_op(collection, rkey, record),
    do: %{
      "$type" => "#{@nsid}.applyWrites#update",
      "collection" => collection,
      "rkey" => rkey,
      "value" => record
    }

  @doc """
  A `#delete` op for `apply_writes/6`.
  """
  @spec delete_op(String.t(), String.t()) :: map()
  def delete_op(collection, rkey),
    do: %{"$type" => "#{@nsid}.applyWrites#delete", "collection" => collection, "rkey" => rkey}

  defp procedure(pds, method, body, auth, opts) do
    http = Keyword.get(opts, :http, HTTP)
    url = "#{String.trim_trailing(pds, "/")}/xrpc/#{@nsid}.#{method}"

    case request(http, :post, url, Keyword.put(HTTP.take_request_opts(opts), :json, body), auth) do
      {:ok, %{status: 200, body: resp}} when is_map(resp) ->
        {:ok, resp}

      {:ok, %{status: status, body: resp}} when is_map(resp) ->
        {:error, {:http_error, status, resp["error"]}}

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, _} = error ->
        error
    end
  end

  defp request(http, method, url, opts, headers: headers),
    do: http.request(method, url, Keyword.put(opts, :headers, headers))

  # The shared DPoP executor: nonce store, per-request proof, and one retry
  # on a `use_dpop_nonce` challenge.
  defp request(http, method, url, opts, session: %Session{} = session),
    do: Request.authorized(http, method, url, opts, session.dpop_key, session.access_token)

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
