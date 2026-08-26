defmodule Exosphere.ATProto.Spaces.SimpleSpaceTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Spaces.SimpleSpace

  @pds "https://pds.example.com"
  @space "at://did:plc:owner/space/com.example.group/default"
  @headers [headers: [{"authorization", "Bearer tok"}]]

  defmodule SpaceHTTP do
    @behaviour Exosphere.ATProto.HTTP.Behaviour

    @impl true
    def get(url, opts \\ []) do
      Process.put({:get, self()}, {url, opts})
      stage(:get_response)
    end

    @impl true
    def post(url, opts \\ []) do
      Process.put({:post, self()}, {url, opts})
      stage(:post_response)
    end

    @impl true
    def request(method, url, opts \\ []),
      do: (method == :get && get(url, opts)) || post(url, opts)

    defp staged(key, default \\ {:ok, %{status: 404, headers: [], body: %{}}}) do
      Process.get(key) || default
    end

    defp stage(key), do: staged(key)
  end

  test "create_space sends typed policy and appAccess unions" do
    Process.put(:post_response, {:ok, %{status: 200, headers: [], body: %{"uri" => @space}}})

    assert {:ok, %{"uri" => _}} =
             SimpleSpace.create_space(@pds, "com.example.group", @headers,
               http: SpaceHTTP,
               skey: "default",
               policy: {:managing_app, "did:web:app.example.com#forum"},
               app_access: {:allow_list, ["https://app.example.com/client-metadata.json"]}
             )

    {url, opts} = Process.get({:post, self()})
    assert url == @pds <> "/xrpc/com.atproto.simplespace.createSpace"

    assert opts[:json] == %{
             "type" => "com.example.group",
             "skey" => "default",
             "policy" => %{
               "$type" => "com.atproto.simplespace.defs#managingAppPolicy",
               "managingApp" => "did:web:app.example.com#forum"
             },
             "appAccess" => %{
               "$type" => "com.atproto.simplespace.defs#allowList",
               "allowed" => ["https://app.example.com/client-metadata.json"]
             }
           }

    assert {"authorization", "Bearer tok"} in (opts[:headers] || [])
  end

  test "create_space defaults: member-list policy, open app access" do
    Process.put(:post_response, {:ok, %{status: 200, headers: [], body: %{}}})

    assert {:ok, _} =
             SimpleSpace.create_space(@pds, "com.example.group", @headers, http: SpaceHTTP)

    {_url, opts} = Process.get({:post, self()})

    assert opts[:json]["policy"] == %{"$type" => "com.atproto.simplespace.defs#memberListPolicy"}
    assert opts[:json]["appAccess"] == %{"$type" => "com.atproto.simplespace.defs#open"}
    refute Map.has_key?(opts[:json], "skey")
  end

  test "update_space sends only the configured axes" do
    Process.put(:post_response, {:ok, %{status: 200, headers: [], body: %{}}})

    assert {:ok, _} =
             SimpleSpace.update_space(@pds, @space, @headers,
               http: SpaceHTTP,
               policy: :public
             )

    {_url, opts} = Process.get({:post, self()})

    assert opts[:json] == %{
             "space" => @space,
             "policy" => %{"$type" => "com.atproto.simplespace.defs#publicPolicy"}
           }
  end

  test "delete_space returns :ok" do
    Process.put(:post_response, {:ok, %{status: 200, headers: [], body: %{}}})
    assert :ok = SimpleSpace.delete_space(@pds, @space, @headers, http: SpaceHTTP)
    {_url, opts} = Process.get({:post, self()})
    assert opts[:json] == %{"space" => @space}
  end

  test "get_space and list_members query with paging" do
    Process.put(:get_response, {:ok, %{status: 200, headers: [], body: %{"members" => []}}})

    assert {:ok, _} = SimpleSpace.get_space(@pds, @space, @headers, http: SpaceHTTP)
    {url, _} = Process.get({:get, self()})
    assert url =~ "com.atproto.simplespace.getSpace?"

    assert {:ok, _} =
             SimpleSpace.list_members(@pds, @space, @headers,
               http: SpaceHTTP,
               cursor: "c",
               limit: 50
             )

    {url, _} = Process.get({:get, self()})
    assert url =~ "com.atproto.simplespace.listMembers?"
    assert url =~ "cursor=c"
    assert url =~ "limit=50"
  end

  test "add and remove members" do
    Process.put(:post_response, {:ok, %{status: 200, headers: [], body: %{}}})

    assert {:ok, _} =
             SimpleSpace.add_member(@pds, @space, "did:plc:friend", @headers, http: SpaceHTTP)

    {_url, opts} = Process.get({:post, self()})
    assert opts[:json] == %{"space" => @space, "did" => "did:plc:friend"}

    assert {:ok, _} =
             SimpleSpace.remove_member(@pds, @space, "did:plc:friend", @headers, http: SpaceHTTP)
  end

  test "refusals surface the host's error code" do
    Process.put(
      :post_response,
      {:ok, %{status: 403, headers: [], body: %{"error" => "NotSpaceOwner"}}}
    )

    assert {:error, {:http_error, 403, "NotSpaceOwner"}} =
             SimpleSpace.delete_space(@pds, @space, @headers, http: SpaceHTTP)
  end

  test "check_user_access is the managing-app call" do
    Process.put(:get_response, {:ok, %{status: 200, headers: [], body: %{"access" => "Allow"}}})

    assert {:ok, _} =
             SimpleSpace.check_user_access(
               "https://app.example.com",
               @space,
               "did:plc:user",
               @headers, http: SpaceHTTP)

    {url, _} = Process.get({:get, self()})
    assert url =~ "com.atproto.simplespace.checkUserAccess?"
    assert url =~ "did=did%3Aplc%3Auser"
  end
end
