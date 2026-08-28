defmodule Exosphere.ATProto.Spaces.WritesTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.OAuth.{DPoP, Session}
  alias Exosphere.ATProto.Spaces.Writes

  @pds "https://pds.example.com"
  @space "at://did:plc:owner/space/com.example.group/default"
  @repo "did:plc:member"

  defmodule WritesHTTP do
    @behaviour Exosphere.ATProto.HTTP.Behaviour

    @impl true
    def get(url, opts \\ []), do: record(:get, url, opts)

    @impl true
    def post(url, opts \\ []), do: record(:post, url, opts)

    @impl true
    def request(method, url, opts \\ []),
      do: (method == :get && get(url, opts)) || post(url, opts)

    defp record(key, url, opts) do
      Process.put({:last, key}, {url, opts})
      Process.get({:response, key}) || {:ok, %{status: 200, headers: [], body: %{}}}
    end
  end

  test "create_record posts the space-targeted write" do
    assert {:ok, _} =
             Writes.create_record(
               @pds,
               @space,
               @repo,
               "com.example.groupPost",
               %{"text" => "hi"},
               [headers: [{"authorization", "Bearer tok"}]],
               http: WritesHTTP
             )

    {url, opts} = Process.get({:last, :post})
    assert url == @pds <> "/xrpc/com.atproto.space.createRecord"

    assert opts[:json] == %{
             "space" => @space,
             "repo" => @repo,
             "collection" => "com.example.groupPost",
             "record" => %{"text" => "hi"}
           }
  end

  test "put_record and delete_record address the record" do
    assert {:ok, _} =
             Writes.put_record(
               @pds,
               @space,
               @repo,
               "com.example.groupPost",
               "3jz1",
               %{"text" => "hi"},
               [headers: []],
               http: WritesHTTP
             )

    {_url, opts} = Process.get({:last, :post})
    assert opts[:json]["rkey"] == "3jz1"

    assert {:ok, _} =
             Writes.delete_record(
               @pds,
               @space,
               @repo,
               "com.example.groupPost",
               "3jz1",
               [headers: []],
               http: WritesHTTP
             )

    {_url, opts} = Process.get({:last, :post})

    assert opts[:json] == %{
             "space" => @space,
             "repo" => @repo,
             "collection" => "com.example.groupPost",
             "rkey" => "3jz1"
           }
  end

  test "apply_writes batches $type-discriminated ops atomically" do
    ops = [
      Writes.create_op("com.example.groupPost", %{"text" => "hi"}),
      Writes.create_op("com.example.groupPost", %{"text" => "pinned"}, "pinned"),
      Writes.update_op("com.example.groupPost", "3jz1", %{"text" => "edited"}),
      Writes.delete_op("com.example.groupPost", "3jz2")
    ]

    assert {:ok, _} =
             Writes.apply_writes(@pds, @space, @repo, ops, [headers: []],
               http: WritesHTTP,
               validate: true
             )

    {_url, opts} = Process.get({:last, :post})

    assert Enum.map(opts[:json]["writes"], & &1["$type"]) == [
             "com.atproto.space.applyWrites#create",
             "com.atproto.space.applyWrites#create",
             "com.atproto.space.applyWrites#update",
             "com.atproto.space.applyWrites#delete"
           ]

    assert Enum.at(opts[:json]["writes"], 1)["rkey"] == "pinned"
    assert opts[:json]["validate"] == true
  end

  test "transport errors pass through instead of crashing" do
    Process.put({:response, :post}, {:error, :nxdomain})

    assert {:error, :nxdomain} =
             Writes.create_record(
               @pds,
               @space,
               @repo,
               "com.example.groupPost",
               %{},
               [headers: []],
               http: WritesHTTP
             )
  end

  test "create/put accept rkey and validate options" do
    assert {:ok, _} =
             Writes.create_record(
               @pds,
               @space,
               @repo,
               "com.example.groupPost",
               %{"text" => "hi"},
               [headers: []],
               http: WritesHTTP,
               rkey: "pinned",
               validate: false
             )

    {_url, opts} = Process.get({:last, :post})
    assert opts[:json]["rkey"] == "pinned"
    assert opts[:json]["validate"] == false
  end

  test "a DPoP-bound session drives both headers per request" do
    {:ok, dpop_key} = DPoP.generate_key()

    session = %Session{
      sub: @repo,
      access_token: "access-jwt",
      scope: ["space:com.example.group"],
      pds: @pds,
      dpop_key: dpop_key
    }

    assert {:ok, _} =
             Writes.create_record(
               @pds,
               @space,
               @repo,
               "com.example.groupPost",
               %{},
               [session: session],
               http: WritesHTTP
             )

    {_url, opts} = Process.get({:last, :post})
    headers = opts[:headers] || []
    assert {"authorization", "DPoP access-jwt"} in headers

    {"dpop", proof} = List.keyfind(headers, "dpop", 0)

    assert {:ok, _} =
             DPoP.verify_proof(proof, "POST", @pds <> "/xrpc/com.atproto.space.createRecord",
               credential: "access-jwt"
             )
  end
end
