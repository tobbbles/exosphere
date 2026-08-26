defmodule Exosphere.ATProto.Spaces.SimpleSpace do
  @moduledoc """
  Client for `com.atproto.simplespace` — the reference space
  implementation every PDS must serve (proposal 0016): spaces anchored on a
  user's own DID, administered through a handful of XRPC calls.

  Administration (`create_space/3` … `remove_member/3`, `manage=` scopes,
  OAuth-authenticated on the owner's PDS) takes the authorization as
  `headers:` (a space-scoped OAuth session's bearer token). `get_space/3`
  also accepts a `credential:` (space credential + DPoP key);
  `list_members/3` requires OAuth — the host-internal member list is not
  readable with a space credential.

  The user-access policy and app-access axes are options, not strings:

      SimpleSpace.create_space(pds, "com.example.group",
        policy: :member_list,
        app_access: {:allow_list, ["https://app.example.com/client-metadata.json"]}
      )

  `check_user_access/3` is the *managing-app* side of the
  `managing_app` policy — the call the authority makes to the managing app,
  which exosphere consumers implementing one can serve from this client's
  shapes. A plug/behaviour helper for hosts is a later ask.
  """

  alias Exosphere.ATProto.HTTP
  alias Exosphere.ATProto.OAuth.Request

  @type policy :: :public | :member_list | {:managing_app, String.t()}
  @type app_access :: :open | {:allow_list, [String.t()]}

  @type auth ::
          [headers: [{String.t(), String.t()}]]
          | [credential: String.t(), dpop_key: map()]

  @nsid "com.atproto.simplespace"

  @doc """
  Create a space (`com.atproto.simplespace.createSpace`). The space anchors
  on the authenticated user's DID, who becomes its owner.

  Options: `:skey` (auto-generated TID when omitted), `:policy`
  (default `:member_list`), `:app_access` (default `:open`).
  """
  @spec create_space(String.t(), String.t(), auth(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def create_space(pds, type, auth, opts \\ []) do
    body =
      %{"type" => type}
      |> maybe_put("skey", Keyword.get(opts, :skey))
      |> Map.put("policy", policy(Keyword.get(opts, :policy, :member_list)))
      |> Map.put("appAccess", app_access(Keyword.get(opts, :app_access, :open)))

    procedure(pds, "createSpace", body, auth, opts)
  end

  @doc """
  Update a space (`com.atproto.simplespace.updateSpace`) — its policy and
  app-access configuration. `manage=update` in the session's scope.
  """
  @spec update_space(String.t(), String.t(), auth(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def update_space(pds, space_ref, auth, opts \\ []) do
    body = %{"space" => space_ref}

    body =
      case Keyword.get(opts, :policy) do
        nil -> body
        p -> Map.put(body, "policy", policy(p))
      end

    body =
      case Keyword.get(opts, :app_access) do
        nil -> body
        a -> Map.put(body, "appAccess", app_access(a))
      end

    procedure(pds, "updateSpace", body, auth, opts)
  end

  @doc """
  Delete a space (`com.atproto.simplespace.deleteSpace`). The authority's own
  repo in the space is deleted with it; other members' repos are flagged as
  belonging to a deleted space rather than erased. `manage=delete`.
  """
  @spec delete_space(String.t(), String.t(), auth(), keyword()) ::
          :ok | {:error, term()}
  def delete_space(pds, space_ref, auth, opts \\ []) do
    with {:ok, _body} <- procedure(pds, "deleteSpace", %{"space" => space_ref}, auth, opts) do
      :ok
    end
  end

  @doc """
  Fetch a space's details (`com.atproto.simplespace.getSpace`). Takes the
  owner's `read_self` OAuth grant or a space credential.
  """
  @spec get_space(String.t(), String.t(), auth(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def get_space(pds, space_ref, auth, opts \\ []) do
    query(pds, "getSpace", %{space: space_ref}, auth, opts)
  end

  @doc """
  Add a member (`com.atproto.simplespace.addMember`). `manage=update`.
  """
  @spec add_member(String.t(), String.t(), String.t(), auth(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def add_member(pds, space_ref, did, auth, opts \\ []) do
    procedure(pds, "addMember", %{"space" => space_ref, "did" => did}, auth, opts)
  end

  @doc """
  Remove a member (`com.atproto.simplespace.removeMember`). `manage=update`.
  """
  @spec remove_member(String.t(), String.t(), String.t(), auth(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def remove_member(pds, space_ref, did, auth, opts \\ []) do
    procedure(pds, "removeMember", %{"space" => space_ref, "did" => did}, auth, opts)
  end

  @doc """
  List a space's members (`com.atproto.simplespace.listMembers`), paged.
  """
  @spec list_members(String.t(), String.t(), auth(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def list_members(pds, space_ref, auth, opts \\ []) do
    params =
      %{space: space_ref}
      |> maybe_put("cursor", Keyword.get(opts, :cursor))
      |> maybe_put("limit", Keyword.get(opts, :limit))

    query(pds, "listMembers", params, auth, opts)
  end

  @doc """
  The managing-app side of the `managing_app` policy
  (`com.atproto.simplespace.checkUserAccess`): given a user and space, the
  verdict the authority asked for. Served by the managing app — this is the
  caller side exosphere consumers need to implement one.
  """
  @spec check_user_access(String.t(), String.t(), String.t(), auth(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def check_user_access(endpoint, space_ref, did, auth, opts \\ []) do
    query(endpoint, "checkUserAccess", %{space: space_ref, did: did}, auth, opts)
  end

  # -- wire shapes ---------------------------------------------------------------

  defp policy(:public), do: %{"$type" => "#{@nsid}.defs#publicPolicy"}
  defp policy(:member_list), do: %{"$type" => "#{@nsid}.defs#memberListPolicy"}

  defp policy({:managing_app, app}),
    do: %{"$type" => "#{@nsid}.defs#managingAppPolicy", "managingApp" => app}

  defp app_access(:open), do: %{"$type" => "#{@nsid}.defs#open"}

  defp app_access({:allow_list, allowed}),
    do: %{"$type" => "#{@nsid}.defs#allowList", "allowed" => allowed}

  # -- transport -------------------------------------------------------------------

  defp query(host, method, params, auth, opts) do
    http = Keyword.get(opts, :http, HTTP)
    qs = URI.encode_query(params)
    url = "#{String.trim_trailing(host, "/")}/xrpc/#{@nsid}.#{method}?#{qs}"

    case request(http, :get, url, [], auth) do
      {:ok, %{status: 200, body: body}} when is_map(body) ->
        {:ok, body}

      {:ok, %{status: status, body: body}} when is_map(body) ->
        {:error, {:http_error, status, body["error"]}}

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, _} = error ->
        error
    end
  end

  defp procedure(host, method, body, auth, opts) do
    http = Keyword.get(opts, :http, HTTP)
    url = "#{String.trim_trailing(host, "/")}/xrpc/#{@nsid}.#{method}"

    case request(http, :post, url, [json: body], auth) do
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

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  # OAuth sessions pass plain headers; credentials go DPoP-bound per request.
  defp request(http, method, url, opts, auth) when is_list(auth) do
    cond do
      headers = auth[:headers] ->
        http.request(method, url, Keyword.put(opts, :headers, headers))

      cred = auth[:credential] ->
        Request.authorized(http, method, url, opts, auth[:dpop_key], cred)

      true ->
        {:error, :invalid_auth}
    end
  end
end
