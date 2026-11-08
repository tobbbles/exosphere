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

  # A resource server that challenges the first request for a DPoP nonce
  # (401 + DPoP-Nonce, as a PDS does) and serves the staged response after.
  defmodule NonceHTTP do
    @behaviour Exosphere.ATProto.HTTP.Behaviour

    @impl true
    def get(url, opts \\ []), do: request(:get, url, opts)

    @impl true
    def post(url, opts \\ []), do: request(:post, url, opts)

    @impl true
    def request(method, url, opts \\ []) do
      seen = Process.get(:nonce_requests, [])
      Process.put(:nonce_requests, seen ++ [{method, url, opts}])

      if seen == [] do
        {:ok,
         %{
           status: 401,
           headers: [
             {"www-authenticate", ~s(DPoP error="use_dpop_nonce")},
             {"dpop-nonce", "nonce-1"}
           ],
           body: %{"error" => "use_dpop_nonce"}
         }}
      else
        Process.get(:nonce_response) || {:ok, %{status: 200, headers: [], body: %{}}}
      end
    end
  end

  defp proof_claims(headers) do
    {"dpop", proof} = List.keyfind(headers, "dpop", 0)
    [_header, payload, _sig] = String.split(proof, ".")
    payload |> Base.url_decode64!(padding: false) |> Jason.decode!()
  end

  # NonceStore is global and keyed by origin; a unique host keeps async tests
  # from seeing each other's nonces.
  defp unique_pds, do: "https://pds-#{System.unique_integer([:positive])}.example.com"

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

  test "a DPoP-bound session uses the PDS nonce and retries its challenge once" do
    {:ok, dpop_key} = DPoP.generate_key()
    pds = unique_pds()

    session = %Session{
      sub: @repo,
      access_token: "access-jwt",
      scope: ["space:com.example.group"],
      pds: pds,
      dpop_key: dpop_key
    }

    Process.put(:nonce_response, {:ok, %{status: 200, headers: [], body: %{"uri" => "at://x"}}})

    assert {:ok, %{"uri" => "at://x"}} =
             Writes.create_record(
               pds,
               @space,
               @repo,
               "com.example.groupPost",
               %{},
               [session: session],
               http: NonceHTTP
             )

    assert [{:post, url, first}, {:post, url, retry}] = Process.get(:nonce_requests)
    assert url == pds <> "/xrpc/com.atproto.space.createRecord"

    refute Map.has_key?(proof_claims(first[:headers]), "nonce")
    assert proof_claims(retry[:headers])["nonce"] == "nonce-1"
    assert {"authorization", "DPoP access-jwt"} in retry[:headers]
    assert retry[:json]["collection"] == "com.example.groupPost"
  end

  test "clear_records clears the caller's repo in the space" do
    assert :ok =
             Writes.clear_records(@pds, @space, @repo, [headers: [{"authorization", "x"}]],
               http: WritesHTTP
             )

    {url, opts} = Process.get({:last, :post})
    assert url == @pds <> "/xrpc/com.atproto.space.clearRecords"
    assert opts[:json] == %{"space" => @space, "repo" => @repo}
  end

  test "import_repo uploads a STAR archive as octet-stream" do
    star = <<0x2A, 0x6C, 0x01, 0x00, 1, 2, 3>>

    assert :ok =
             Writes.import_repo(@pds, star, [headers: [{"authorization", "x"}]], http: WritesHTTP)

    {url, opts} = Process.get({:last, :post})
    assert url == @pds <> "/xrpc/com.atproto.space.importRepo"
    assert opts[:body] == star
    assert opts[:content_type] == "application/octet-stream"
    refute Keyword.has_key?(opts, :json)
  end
end
