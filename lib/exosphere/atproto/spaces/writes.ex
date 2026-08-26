defmodule Exosphere.ATProto.Spaces.Writes do
  @moduledoc """
  Write records into a member's permissioned repo through their own PDS
  (proposal 0016): `com.atproto.space.createRecord` / `putRecord` /
  `deleteRecord` / `applyWrites`.

  Writes always go to the user's **own** PDS under a space-scoped OAuth
  session (the `space:` scopes of `Exosphere.ATProto.OAuth.Scope`); the PDS
  routes the record into the space's permissioned repo. Credential-authed
  writes are not a thing — credentials read, sessions write.

  The authorization is the caller's: pass the session's
  `headers: [{"authorization", "Bearer " <> session.access_token}]`, or pass
  `session: session` and the DPoP proof is derived per request.
  """

  alias Exosphere.ATProto.HTTP
  alias Exosphere.ATProto.OAuth.{DPoP, Session}

  @nsid "com.atproto.space"

  @type auth :: [headers: [{String.t(), String.t()}]] | [session: Session.t()]

  @doc """
  Create a record (`com.atproto.space.createRecord`) with a server-chosen
  rkey, into the member `repo_did`'s permissioned repo.
  """
  @spec create_record(String.t(), String.t(), String.t(), String.t(), map(), auth(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def create_record(pds, space_ref, repo_did, collection, record, auth, opts \\ []) do
    procedure(
      pds,
      "createRecord",
      %{"space" => space_ref, "repo" => repo_did, "collection" => collection, "record" => record},
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

    case request(http, :post, url, [json: body], auth) do
      {:ok, %{status: 200, body: resp}} when is_map(resp) ->
        {:ok, resp}

      {:ok, %{status: status, body: resp}} when is_map(resp) ->
        {:error, {:http_error, status, resp["error"]}}

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}
    end
  end

  defp request(http, method, url, opts, headers: headers),
    do: http.request(method, url, Keyword.put(opts, :headers, headers))

  defp request(http, method, url, opts, session: %Session{} = session) do
    with {:ok, proof} <-
           DPoP.proof(session.dpop_key, method_name(method), url, ath: session.access_token) do
      headers = [
        {"authorization", "DPoP " <> session.access_token},
        {"dpop", proof}
      ]

      http.request(method, url, Keyword.put(opts, :headers, headers))
    end
  end

  defp method_name(:post), do: "POST"

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
