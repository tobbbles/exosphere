defmodule Exosphere.ATProto.Spaces.SpaceAdminTest do
  @moduledoc false
  # Spaces.Space / Spaces.Memberspace / Spaces.Managedspace / Spaces.Policy —
  # the policy-union administration surface that replaced simplespace
  # (atproto 7992095).
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.OAuth.{DPoP, Session}
  alias Exosphere.ATProto.Spaces.{Managedspace, Memberspace, Policy, Space}

  @pds "https://pds.example.com"
  @space "at://did:plc:owner/space/com.example.group/default"
  @headers [headers: [{"authorization", "Bearer tok"}]]
  @client_id "https://app.example.com/client-metadata.json"

  defmodule SpaceHTTP do
    @behaviour Exosphere.ATProto.HTTP.Behaviour

    @impl true
    def get(url, opts \\ []) do
      Process.put({:get, self()}, {url, opts})
      Process.get(:get_response) || {:ok, %{status: 404, headers: [], body: %{}}}
    end

    @impl true
    def post(url, opts \\ []) do
      Process.put({:post, self()}, {url, opts})
      Process.get(:post_response) || {:ok, %{status: 404, headers: [], body: %{}}}
    end

    @impl true
    def request(method, url, opts \\ []),
      do: (method == :get && get(url, opts)) || post(url, opts)
  end

  defp ok(body), do: {:ok, %{status: 200, headers: [], body: body}}

  describe "Policy" do
    test "builds the three baseline policy objects, omitting unset fields" do
      assert Policy.personal() == %{"$type" => "com.atproto.personalspace.policy"}
      assert Policy.member() == %{"$type" => "com.atproto.memberspace.policy"}

      assert Policy.member(
               public_read: true,
               public_write: false,
               allowed_apps: [@client_id],
               publish_policy: true,
               publish_members: true
             ) == %{
               "$type" => "com.atproto.memberspace.policy",
               "publicRead" => true,
               "publicWrite" => false,
               "allowedApps" => [@client_id],
               "publishPolicy" => true,
               "publishMembers" => true
             }

      assert Policy.managed("did:web:app.example.com#forum", publish_policy: true) == %{
               "$type" => "com.atproto.managedspace.policy",
               "managingApp" => "did:web:app.example.com#forum",
               "publishPolicy" => true
             }
    end

    test "decodes with the lexicon defaults, and keeps unknown policies" do
      assert {:ok, {:personal, %{}}} = Policy.decode(Policy.personal())

      assert {:ok,
              {:member,
               %{
                 public_read: true,
                 public_write: false,
                 allowed_apps: nil,
                 publish_policy: false,
                 publish_members: false
               }}} = Policy.decode(Policy.member(public_read: true))

      assert {:ok, {:managed, %{managing_app: "did:web:x", publish_policy: false}}} =
               Policy.decode(Policy.managed("did:web:x"))

      custom = %{"$type" => "com.example.gatedspace.policy", "tier" => "gold"}
      assert {:ok, {:unknown, ^custom}} = Policy.decode(custom)

      assert {:error, :invalid_policy} =
               Policy.decode(%{"$type" => "com.atproto.managedspace.policy"})

      assert {:error, :invalid_policy} = Policy.decode("nope")
    end
  end

  describe "Space" do
    test "create_space sends spaceType, skey and the policy union" do
      Process.put(:post_response, ok(%{"uri" => @space}))

      assert {:ok, %{"uri" => @space}} =
               Space.create_space(
                 @pds,
                 "com.example.group",
                 Policy.member(allowed_apps: [@client_id]),
                 @headers,
                 http: SpaceHTTP,
                 skey: "default"
               )

      {url, opts} = Process.get({:post, self()})
      assert url == @pds <> "/xrpc/com.atproto.space.createSpace"

      assert opts[:json] == %{
               "spaceType" => "com.example.group",
               "skey" => "default",
               "policy" => %{
                 "$type" => "com.atproto.memberspace.policy",
                 "allowedApps" => [@client_id]
               }
             }

      assert {"authorization", "Bearer tok"} in opts[:headers]
    end

    test "create_space omits an unset skey" do
      Process.put(:post_response, ok(%{"uri" => @space}))

      assert {:ok, _} =
               Space.create_space(@pds, "com.example.group", Policy.personal(), @headers,
                 http: SpaceHTTP
               )

      {_url, opts} = Process.get({:post, self()})
      refute Map.has_key?(opts[:json], "skey")
    end

    test "update_space replaces the policy wholesale" do
      Process.put(:post_response, ok(%{}))

      assert :ok =
               Space.update_space(@pds, @space, Policy.managed("did:web:app#forum"), @headers,
                 http: SpaceHTTP
               )

      {url, opts} = Process.get({:post, self()})
      assert url == @pds <> "/xrpc/com.atproto.space.updateSpace"

      assert opts[:json] == %{
               "space" => @space,
               "policy" => %{
                 "$type" => "com.atproto.managedspace.policy",
                 "managingApp" => "did:web:app#forum"
               }
             }
    end

    test "get_space, delete_space and list_spaces hit the space namespace" do
      Process.put(:get_response, ok(%{"uri" => @space, "policy" => Policy.personal()}))

      assert {:ok, %{"policy" => policy}} =
               Space.get_space(@pds, @space, @headers, http: SpaceHTTP)

      assert {:ok, {:personal, _}} = Policy.decode(policy)
      {url, _} = Process.get({:get, self()})
      assert url =~ "/xrpc/com.atproto.space.getSpace?space="

      Process.put(:post_response, ok(%{}))
      assert :ok = Space.delete_space(@pds, @space, @headers, http: SpaceHTTP)
      {url, opts} = Process.get({:post, self()})
      assert url == @pds <> "/xrpc/com.atproto.space.deleteSpace"
      assert opts[:json] == %{"space" => @space}

      Process.put(:get_response, ok(%{"spaces" => [%{"uri" => @space}]}))

      assert {:ok, %{"spaces" => [_]}} =
               Space.list_spaces(@pds, @headers,
                 http: SpaceHTTP,
                 space_type: "com.example.group",
                 limit: 10
               )

      {url, _} = Process.get({:get, self()})
      assert url =~ "/xrpc/com.atproto.space.listSpaces?"
      assert url =~ "spaceType=com.example.group"
      assert url =~ "limit=10"
      refute url =~ "cursor="
    end

    test "refusals surface the host's error code; transport errors pass through" do
      Process.put(
        :post_response,
        {:ok, %{status: 400, headers: [], body: %{"error" => "UnsupportedPolicy"}}}
      )

      assert {:error, {:http_error, 400, "UnsupportedPolicy"}} =
               Space.create_space(@pds, "com.example.group", Policy.personal(), @headers,
                 http: SpaceHTTP
               )

      Process.put(:get_response, {:error, :econnrefused})
      assert {:error, :econnrefused} = Space.get_space(@pds, @space, @headers, http: SpaceHTTP)
    end

    test "request options reach the transport" do
      Process.put(:get_response, ok(%{"uri" => @space, "policy" => Policy.personal()}))

      assert {:ok, _} = Space.get_space(@pds, @space, @headers, http: SpaceHTTP, timeout: 1_500)

      {_url, opts} = Process.get({:get, self()})
      assert opts[:timeout] == 1_500
    end

    test "a session: authorizes with DPoP through the shared executor" do
      {:ok, dpop_key} = DPoP.generate_key()

      session = %Session{
        access_token: "at",
        dpop_key: dpop_key,
        sub: "did:plc:owner",
        pds: @pds
      }

      Process.put(:post_response, ok(%{}))
      assert :ok = Space.delete_space(@pds, @space, [session: session], http: SpaceHTTP)

      {_url, opts} = Process.get({:post, self()})
      assert {"authorization", "DPoP at"} in opts[:headers]
      assert List.keymember?(opts[:headers], "dpop", 0)
    end

    test "no usable auth is an error, not an unauthenticated request" do
      assert {:error, :invalid_auth} = Space.get_space(@pds, @space, [], http: SpaceHTTP)
    end
  end

  describe "Memberspace" do
    test "put_member sends read/write (default true) to memberspace.putMember" do
      Process.put(:post_response, ok(%{}))

      assert :ok =
               Memberspace.put_member(@pds, @space, "did:plc:friend", @headers, http: SpaceHTTP)

      {url, opts} = Process.get({:post, self()})
      assert url == @pds <> "/xrpc/com.atproto.memberspace.putMember"

      assert opts[:json] == %{
               "space" => @space,
               "did" => "did:plc:friend",
               "read" => true,
               "write" => true
             }

      assert :ok =
               Memberspace.put_member(@pds, @space, "did:plc:friend", @headers,
                 http: SpaceHTTP,
                 write: false
               )

      {_url, opts} = Process.get({:post, self()})
      assert opts[:json]["write"] == false
    end

    test "remove_member and list_members" do
      Process.put(:post_response, ok(%{}))

      assert :ok =
               Memberspace.remove_member(@pds, @space, "did:plc:friend", @headers,
                 http: SpaceHTTP
               )

      {url, opts} = Process.get({:post, self()})
      assert url == @pds <> "/xrpc/com.atproto.memberspace.removeMember"
      assert opts[:json] == %{"space" => @space, "did" => "did:plc:friend"}

      Process.put(
        :get_response,
        ok(%{"members" => [%{"did" => "did:plc:friend", "read" => true, "write" => false}]})
      )

      assert {:ok, %{"members" => [_]}} =
               Memberspace.list_members(@pds, @space, @headers, http: SpaceHTTP, cursor: "c")

      {url, _} = Process.get({:get, self()})
      assert url =~ "/xrpc/com.atproto.memberspace.listMembers?"
      assert url =~ "cursor=c"
    end

    test "a space under another policy is a PolicyMismatch" do
      Process.put(
        :post_response,
        {:ok, %{status: 400, headers: [], body: %{"error" => "PolicyMismatch"}}}
      )

      assert {:error, {:http_error, 400, "PolicyMismatch"}} =
               Memberspace.put_member(@pds, @space, "did:plc:friend", @headers, http: SpaceHTTP)
    end
  end

  describe "Managedspace" do
    test "check_user_access sends user and access, returns the verdict" do
      Process.put(:get_response, ok(%{"authorized" => true}))

      assert {:ok, true} =
               Managedspace.check_user_access(
                 "https://app.example.com",
                 @space,
                 "did:plc:user",
                 :read,
                 @headers,
                 http: SpaceHTTP,
                 client_id: @client_id
               )

      {url, _} = Process.get({:get, self()})
      assert url =~ "/xrpc/com.atproto.managedspace.checkUserAccess?"
      assert url =~ "user=did%3Aplc%3Auser"
      assert url =~ "access=read"
      assert url =~ "clientId=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json"
    end

    test "write checks carry no client" do
      Process.put(:get_response, ok(%{"authorized" => false}))

      assert {:ok, false} =
               Managedspace.check_user_access(
                 "https://app.example.com",
                 @space,
                 "did:plc:user",
                 :write,
                 @headers, http: SpaceHTTP)

      {url, _} = Process.get({:get, self()})
      assert url =~ "access=write"
      refute url =~ "clientId"

      assert {:error, :client_id_on_write} =
               Managedspace.check_user_access(
                 "https://app.example.com",
                 @space,
                 "did:plc:user",
                 :write,
                 @headers,
                 http: SpaceHTTP,
                 client_id: @client_id
               )
    end

    test "a response without a boolean verdict is invalid" do
      Process.put(:get_response, ok(%{"authorized" => "yes"}))

      assert {:error, :invalid_response} =
               Managedspace.check_user_access(
                 "https://app.example.com",
                 @space,
                 "did:plc:user",
                 :read,
                 @headers, http: SpaceHTTP)
    end
  end
end
