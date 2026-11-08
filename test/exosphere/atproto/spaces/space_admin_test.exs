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
      Process.put(:post_response, ok(%{"space" => @space}))

      assert {:ok, %{"space" => @space}} =
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
      Process.put(:post_response, ok(%{"space" => @space}))

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
      Process.put(:get_response, ok(%{"space" => @space, "policy" => Policy.personal()}))

      assert {:ok, %{"space" => @space, "policy" => policy}} =
               Space.get_space(@pds, @space, @headers, http: SpaceHTTP)

      assert {:ok, {:personal, _}} = Policy.decode(policy)
      {url, _} = Process.get({:get, self()})
      assert url =~ "/xrpc/com.atproto.space.getSpace?space="

      Process.put(:post_response, ok(%{}))
      assert :ok = Space.delete_space(@pds, @space, @headers, http: SpaceHTTP)
      {url, opts} = Process.get({:post, self()})
      assert url == @pds <> "/xrpc/com.atproto.space.deleteSpace"
      assert opts[:json] == %{"space" => @space}

      view = %{
        "space" => @space,
        "repoRev" => "3kbcq3p7ad2c2",
        "spaceRev" => "3kbcq3p7ad3a2",
        "data" => %{"$bytes" => Base.encode64(<<0::256>>)}
      }

      Process.put(:get_response, ok(%{"spaces" => [view]}))

      assert {:ok, %{"spaces" => [^view]}} =
               Space.list_spaces(@pds, @headers,
                 http: SpaceHTTP,
                 space_type: "com.example.group",
                 space_did: "did:plc:owner",
                 limit: 10
               )

      {url, _} = Process.get({:get, self()})
      assert url =~ "/xrpc/com.atproto.space.listSpaces?"
      assert url =~ "spaceType=com.example.group"
      # The authority filter is `spaceDid` since atproto 4037310 (was `did`).
      assert url =~ "spaceDid=did%3Aplc%3Aowner"
      refute url =~ "&did="
      assert url =~ "limit=10"
      refute url =~ "cursor="
    end

    test "the 4037310 error names are typed" do
      for {code, expected} <- [
            {"NotAuthorized", :not_authorized},
            {"InvalidCursor", :invalid_cursor}
          ] do
        Process.put(:get_response, {:ok, %{status: 400, headers: [], body: %{"error" => code}}})
        assert {:error, ^expected} = Space.list_spaces(@pds, @headers, http: SpaceHTTP)
      end

      Process.put(
        :post_response,
        {:ok, %{status: 400, headers: [], body: %{"error" => "NotAuthorized"}}}
      )

      assert {:error, :not_authorized} =
               Space.delete_space(@pds, @space, @headers, http: SpaceHTTP)

      # The pre-rename name is just another error code now.
      Process.put(
        :post_response,
        {:ok, %{status: 400, headers: [], body: %{"error" => "NotSpaceOwner"}}}
      )

      assert {:error, {:http_error, 400, "NotSpaceOwner"}} =
               Space.delete_space(@pds, @space, @headers, http: SpaceHTTP)

      for {code, expected} <- [
            {"InvalidSpaceMeta", :invalid_space_meta},
            {"InvalidRepoFile", :invalid_repo_file},
            {"RepoMismatch", :repo_mismatch}
          ] do
        Process.put(:post_response, {:ok, %{status: 400, headers: [], body: %{"error" => code}}})

        assert {:error, ^expected} =
                 Space.import_space_meta(@pds, "star", @headers, http: SpaceHTTP)
      end
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
      Process.put(:get_response, ok(%{"space" => @space, "policy" => Policy.personal()}))

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

  describe "writer set, migration and discovery" do
    test "remove_writer posts the repo DID to space.removeWriter" do
      Process.put(:post_response, ok(%{}))
      assert :ok = Space.remove_writer(@pds, @space, "did:plc:spammer", @headers, http: SpaceHTTP)
      {url, opts} = Process.get({:post, self()})
      assert url == @pds <> "/xrpc/com.atproto.space.removeWriter"
      # `repo`, not `did`, since atproto-spaces-lexicon-review.
      assert opts[:json] == %{"space" => @space, "repo" => "did:plc:spammer"}
    end

    test "export_space_meta returns the archive bytes; import_space_meta uploads them" do
      star = <<0x2A, 0x6C, 0x01, 0x00, 9>>
      Process.put(:get_response, {:ok, %{status: 200, headers: [], body: star}})
      assert {:ok, ^star} = Space.export_space_meta(@pds, @space, @headers, http: SpaceHTTP)
      {url, _} = Process.get({:get, self()})
      assert url =~ "/xrpc/com.atproto.space.exportSpaceMeta?space="

      Process.put(:post_response, ok(%{}))
      assert :ok = Space.import_space_meta(@pds, star, @headers, http: SpaceHTTP)
      {url, opts} = Process.get({:post, self()})
      assert url == @pds <> "/xrpc/com.atproto.space.importSpaceMeta"
      assert opts[:body] == star
      assert opts[:content_type] == "application/vnd.dasl.star"

      Process.put(
        :post_response,
        {:ok, %{status: 400, headers: [], body: %{"error" => "UnsupportedPolicy"}}}
      )

      assert {:error, {:http_error, 400, "UnsupportedPolicy"}} =
               Space.import_space_meta(@pds, star, @headers, http: SpaceHTTP)
    end

    test "spaces_alpha?/2 reads describeServer's flag" do
      Process.put(:get_response, ok(%{"did" => "did:web:pds", "spacesAlpha" => true}))
      assert {:ok, true} = Space.spaces_alpha?(@pds, http: SpaceHTTP)
      {url, _} = Process.get({:get, self()})
      assert url == @pds <> "/xrpc/com.atproto.server.describeServer"

      Process.put(:get_response, ok(%{"did" => "did:web:pds"}))
      assert {:ok, false} = Space.spaces_alpha?(@pds, http: SpaceHTTP)
    end

    test "the published policy and member records" do
      assert Policy.record(Policy.personal()) == %{
               "$type" => "com.atproto.space.policy",
               "policy" => %{"$type" => "com.atproto.personalspace.policy"}
             }

      assert Policy.record_key() == "self"

      assert Memberspace.member_record(true, false) == %{
               "$type" => "com.atproto.memberspace.member",
               "read" => true,
               "write" => false
             }
    end
  end

  describe "Memberspace" do
    test "put_members sends a batch of defs#member entries (read/write default true)" do
      Process.put(:post_response, ok(%{}))

      assert :ok =
               Memberspace.put_members(
                 @pds,
                 @space,
                 ["did:plc:friend", %{did: "did:plc:reader", write: false}],
                 @headers,
                 http: SpaceHTTP
               )

      {url, opts} = Process.get({:post, self()})
      assert url == @pds <> "/xrpc/com.atproto.memberspace.putMembers"

      assert opts[:json] == %{
               "space" => @space,
               "members" => [
                 %{"did" => "did:plc:friend", "read" => true, "write" => true},
                 %{"did" => "did:plc:reader", "read" => true, "write" => false}
               ]
             }
    end

    test "put_members and remove_members refuse empty, oversized or malformed batches" do
      dids = for i <- 1..101, do: "did:plc:m#{i}"

      for bad <- [[], dids, ["not-a-did"], [%{did: "did:plc:x", read: "yes"}], "did:plc:x"] do
        assert {:error, :invalid_members} =
                 Memberspace.put_members(@pds, @space, bad, @headers, http: SpaceHTTP)
      end

      for bad <- [[], dids, ["not-a-did"]] do
        assert {:error, :invalid_members} =
                 Memberspace.remove_members(@pds, @space, bad, @headers, http: SpaceHTTP)
      end

      refute Process.get({:post, self()})

      # 100 is the most a batch may hold.
      Process.put(:post_response, ok(%{}))

      assert :ok =
               Memberspace.put_members(@pds, @space, Enum.take(dids, 100), @headers,
                 http: SpaceHTTP
               )
    end

    test "remove_members and list_members" do
      Process.put(:post_response, ok(%{}))

      assert :ok =
               Memberspace.remove_members(
                 @pds,
                 @space,
                 ["did:plc:friend", "did:plc:other"],
                 @headers,
                 http: SpaceHTTP
               )

      {url, opts} = Process.get({:post, self()})
      assert url == @pds <> "/xrpc/com.atproto.memberspace.removeMembers"
      assert opts[:json] == %{"space" => @space, "dids" => ["did:plc:friend", "did:plc:other"]}

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
               Memberspace.put_members(@pds, @space, ["did:plc:friend"], @headers,
                 http: SpaceHTTP
               )
    end
  end

  describe "Managedspace" do
    test "check_access sends repo and client, returns read and write" do
      Process.put(:get_response, ok(%{"read" => true, "write" => false}))

      assert {:ok, %{read: true, write: false}} =
               Managedspace.check_access("https://app.example.com", @space, @headers,
                 http: SpaceHTTP,
                 repo: "did:plc:user",
                 client_id: @client_id
               )

      {url, _} = Process.get({:get, self()})
      assert url =~ "/xrpc/com.atproto.managedspace.checkAccess?"
      assert url =~ "repo=did%3Aplc%3Auser"
      assert url =~ "clientId=https%3A%2F%2Fapp.example.com%2Fclient-metadata.json"
      refute url =~ "user="
      refute url =~ "access="
    end

    test "an anonymous read check omits the repo" do
      Process.put(:get_response, ok(%{"read" => true, "write" => false}))

      assert {:ok, %{read: true}} =
               Managedspace.check_access("https://app.example.com", @space, @headers,
                 http: SpaceHTTP
               )

      {url, _} = Process.get({:get, self()})
      refute url =~ "repo="
      refute url =~ "clientId"
    end

    test "the authority's service auth can be minted per request" do
      {:ok, key} = Exosphere.ATProto.OAuth.JWK.generate(:secp256k1)
      Process.put(:get_response, ok(%{"read" => false, "write" => false}))

      auth = [
        service_auth: [iss: "did:plc:owner", aud: "did:web:app.example.com#forum", key: key]
      ]

      assert {:ok, %{read: false, write: false}} =
               Managedspace.check_access("https://app.example.com", @space, auth,
                 http: SpaceHTTP,
                 repo: "did:plc:user"
               )

      {_url, opts} = Process.get({:get, self()})
      {_, "Bearer " <> jwt} = List.keyfind(opts[:headers], "authorization", 0)
      {:ok, _header, payload} = Exosphere.ATProto.OAuth.JWS.decode(jwt)
      assert payload["lxm"] == "com.atproto.managedspace.checkAccess"
      assert payload["aud"] == "did:web:app.example.com#forum"
      assert payload["iss"] == "did:plc:owner"
    end

    test "a response without both booleans is invalid" do
      for body <- [
            %{"authorized" => true},
            %{"read" => true},
            %{"read" => "yes", "write" => false}
          ] do
        Process.put(:get_response, ok(body))

        assert {:error, :invalid_response} =
                 Managedspace.check_access("https://app.example.com", @space, @headers,
                   http: SpaceHTTP
                 )
      end
    end
  end
end
