defmodule Exosphere.ATProto.XRPC.ClientTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.OAuth.DPoP
  alias Exosphere.ATProto.XRPC.{Client, Error}

  defmodule FakeHTTP do
    @behaviour Exosphere.ATProto.HTTP.Behaviour

    @impl true
    def get(url, opts \\ []) do
      send(self(), {:http, :get, url, opts})
      {:ok, %{status: 200, headers: [], body: %{"ok" => true}}}
    end

    @impl true
    def post(url, opts \\ []) do
      send(self(), {:http, :post, url, opts})
      {:ok, %{status: 200, headers: [], body: %{"ok" => true}}}
    end

    @impl true
    def request(method, url, opts \\ []) do
      send(self(), {:http, method, url, opts})
      {:ok, %{status: 200, headers: [], body: %{"ok" => true}}}
    end
  end

  defmodule FakeHTTPError do
    @behaviour Exosphere.ATProto.HTTP.Behaviour

    @impl true
    def get(url, opts \\ []) do
      send(self(), {:http, :get, url, opts})
      {:ok, %{status: 400, headers: [], body: %{"error" => "BadRequest", "message" => "nope"}}}
    end

    @impl true
    def post(url, opts \\ []) do
      send(self(), {:http, :post, url, opts})
      {:ok, %{status: 400, headers: [], body: %{"error" => "BadRequest", "message" => "nope"}}}
    end

    @impl true
    def request(method, url, opts \\ []) do
      send(self(), {:http, method, url, opts})
      {:ok, %{status: 400, headers: [], body: %{"error" => "BadRequest", "message" => "nope"}}}
    end
  end

  # Answers the first request with a 401 DPoP nonce challenge and every later
  # one with 200. The count lives in the calling (test) process, which is
  # where the DPoP executor runs.
  defmodule FakeHTTPNonce do
    @behaviour Exosphere.ATProto.HTTP.Behaviour

    @impl true
    def get(url, opts \\ []), do: request(:get, url, opts)

    @impl true
    def post(url, opts \\ []), do: request(:post, url, opts)

    @impl true
    def request(method, url, opts \\ []) do
      send(self(), {:http, method, url, opts})
      attempt = Process.get(__MODULE__, 0)
      Process.put(__MODULE__, attempt + 1)

      if attempt == 0 do
        {:ok,
         %{
           status: 401,
           headers: [
             {"dpop-nonce", "n-fresh"},
             {"www-authenticate", ~s(DPoP error="use_dpop_nonce")}
           ],
           body: %{"error" => "use_dpop_nonce"}
         }}
      else
        {:ok, %{status: 200, headers: [], body: %{"ok" => true}}}
      end
    end
  end

  test "new/2 trims trailing slash and stores injected http module" do
    client = Client.new("https://example.com/", http: FakeHTTP)
    assert client.base_url == "https://example.com"
    assert client.http == FakeHTTP
  end

  test "query/3 builds /xrpc/:nsid URL with query params and passes auth header" do
    client =
      Client.new("https://example.com", access_token: "t0k", http: FakeHTTP, timeout: 123)

    assert {:ok, %{"ok" => true}} =
             Client.query(client, "com.atproto.identity.resolveHandle", handle: "atproto.com")

    assert_received {:http, :get, url, opts}
    assert url == "https://example.com/xrpc/com.atproto.identity.resolveHandle?handle=atproto.com"

    assert Keyword.get(opts, :timeout) == 123
    assert Keyword.get(opts, :headers) == [{"authorization", "Bearer t0k"}]
  end

  test "query/3 URI-encodes query params" do
    client = Client.new("https://example.com", http: FakeHTTP)
    {:ok, _} = Client.query(client, "x.test", q: "a b", plus: "a+b")

    assert_received {:http, :get, url, _opts}
    assert url == "https://example.com/xrpc/x.test?q=a+b&plus=a%2Bb"
  end

  test "procedure/3 converts keyword body to map and uses POST" do
    client = Client.new("https://example.com", http: FakeHTTP)

    assert {:ok, %{"ok" => true}} =
             Client.procedure(client, "com.atproto.repo.createRecord", repo: "did:plc:123")

    assert_received {:http, :post, url, opts}
    assert url == "https://example.com/xrpc/com.atproto.repo.createRecord"
    assert Keyword.get(opts, :json) == %{repo: "did:plc:123"}
  end

  describe "procedure/4 body" do
    test "defaults to an empty JSON object" do
      client = Client.new("https://example.com", http: FakeHTTP)

      assert {:ok, _} = Client.procedure(client, "com.atproto.server.activateAccount")

      assert_received {:http, :post, _url, opts}
      assert Keyword.fetch!(opts, :json) == %{}
    end

    test "an empty keyword list or map is still sent as an empty JSON object" do
      client = Client.new("https://example.com", http: FakeHTTP)

      assert {:ok, _} = Client.procedure(client, "x.test", [])
      assert_received {:http, :post, _url, opts}
      assert Keyword.fetch!(opts, :json) == %{}

      assert {:ok, _} = Client.procedure(client, "x.test", %{})
      assert_received {:http, :post, _url, opts}
      assert Keyword.fetch!(opts, :json) == %{}
    end

    test "nil sends no body options at all" do
      client = Client.new("https://example.com", access_token: "t0k", http: FakeHTTP)

      assert {:ok, %{"ok" => true}} =
               Client.procedure(client, "com.atproto.identity.requestPlcOperationSignature", nil)

      assert_received {:http, :post, url, opts}
      assert url == "https://example.com/xrpc/com.atproto.identity.requestPlcOperationSignature"

      refute Keyword.has_key?(opts, :json)
      refute Keyword.has_key?(opts, :body)
      refute Keyword.has_key?(opts, :content_type)
      assert Keyword.get(opts, :headers) == [{"authorization", "Bearer t0k"}]
    end

    test "nil keeps query params" do
      client = Client.new("https://example.com", http: FakeHTTP)

      assert {:ok, _} = Client.procedure(client, "x.test", nil, a: "b")

      assert_received {:http, :post, "https://example.com/xrpc/x.test?a=b", opts}
      refute Keyword.has_key?(opts, :json)
    end
  end

  describe "procedure/4 with no body on the wire" do
    # The real HTTP adapter against a socket that answers like the reference
    # PDS does for a procedure with no `input`: any request body (an empty
    # `{}` included) is a 400 InvalidRequest.
    test "nil sends neither a body nor a content-type, and the PDS accepts it" do
      {port, server} = start_no_input_pds()
      client = Client.new("http://127.0.0.1:#{port}", access_token: "t0k", timeout: 5_000)

      assert {:ok, response} =
               Client.procedure(client, "com.atproto.identity.requestPlcOperationSignature", nil)

      assert response == %{}

      {head, body} = captured_request(server)
      assert head =~ ~r{^POST /xrpc/com\.atproto\.identity\.requestPlcOperationSignature }
      assert body == ""
      refute head =~ ~r/^content-type:/im
      assert head =~ ~r/^authorization: Bearer t0k\r?$/im
    end

    test "the default empty object is what the PDS rejects" do
      {port, server} = start_no_input_pds()
      client = Client.new("http://127.0.0.1:#{port}", timeout: 5_000)

      assert {:error,
              %Error{
                status: 400,
                error: "InvalidRequest",
                message: "A request body was provided when none was expected"
              }} = Client.procedure(client, "com.atproto.identity.requestPlcOperationSignature")

      assert {head, "{}"} = captured_request(server)
      assert head =~ ~r{^content-type: application/json\r?$}im
    end
  end

  describe "procedure/4 with a DPoP-bound client" do
    setup do
      {:ok, key} = DPoP.generate_key()
      # A host of its own, so the nonce store is not shared with other tests
      base = "https://pds-#{System.unique_integer([:positive])}.example"
      %{key: key, base: base}
    end

    test "nil sends no body, with DPoP auth and proof headers", %{key: key, base: base} do
      client = Client.new(base, access_token: "at-1", dpop: key, http: FakeHTTP)

      assert {:ok, %{"ok" => true}} =
               Client.procedure(client, "com.atproto.server.requestEmailConfirmation", nil)

      assert_received {:http, :post, url, opts}
      assert url == base <> "/xrpc/com.atproto.server.requestEmailConfirmation"

      refute Keyword.has_key?(opts, :json)
      refute Keyword.has_key?(opts, :body)
      refute Keyword.has_key?(opts, :content_type)

      headers = Keyword.fetch!(opts, :headers)
      assert {"authorization", "DPoP at-1"} in headers
      assert List.keymember?(headers, "dpop", 0)
    end

    test "nil survives the nonce-challenge retry", %{key: key, base: base} do
      client = Client.new(base, access_token: "at-1", dpop: key, http: FakeHTTPNonce)

      assert {:ok, %{"ok" => true}} =
               Client.procedure(client, "com.atproto.server.requestEmailConfirmation", nil)

      # The challenged first attempt and the retry both went out bodiless,
      # and the retry carried a fresh proof
      assert_received {:http, :post, _url, first}
      assert_received {:http, :post, _url, retry}

      for opts <- [first, retry] do
        refute Keyword.has_key?(opts, :json)
        refute Keyword.has_key?(opts, :body)
        refute Keyword.has_key?(opts, :content_type)
      end

      refute List.keyfind(first[:headers], "dpop", 0) == List.keyfind(retry[:headers], "dpop", 0)
    end
  end

  test "refresh_session/1 errors when refresh token is missing" do
    client = Client.new("https://example.com", http: FakeHTTP)
    assert {:error, :no_refresh_token} = Client.refresh_session(client)
  end

  test "non-200 responses are converted to XRPC.Error" do
    client = Client.new("https://example.com", http: FakeHTTPError)

    assert {:error, %Error{} = err} = Client.query(client, "x.test", [])
    assert err.status == 400
    assert err.error == "BadRequest"
    assert err.message == "nope"
  end

  # One-shot server: reads a single request, reports it to the test as
  # `{:wire, head, body}`, and answers 400 InvalidRequest if it carried a
  # body or a content-type, 200 `{}` otherwise. The captured request is
  # fetched with `captured_request/1` once the call has returned: the HTTP
  # adapter drains the caller's mailbox while it waits for the response, so a
  # message pushed at the test mid-request would be swallowed.
  defp start_no_input_pds do
    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(listen)

    {:ok, server} =
      Task.start_link(fn ->
        {:ok, sock} = :gen_tcp.accept(listen, 5_000)
        {head, body} = read_request(sock, "")

        {status, json} =
          if body == "" and not (head =~ ~r/^content-type:/im) do
            {"200 OK", %{}}
          else
            {"400 Bad Request",
             %{
               "error" => "InvalidRequest",
               "message" => "A request body was provided when none was expected"
             }}
          end

        payload = Jason.encode!(json)

        :ok =
          :gen_tcp.send(sock, [
            "HTTP/1.1 #{status}\r\n",
            "content-type: application/json\r\n",
            "content-length: #{byte_size(payload)}\r\n",
            "connection: close\r\n\r\n",
            payload
          ])

        :gen_tcp.close(sock)
        :gen_tcp.close(listen)

        receive do
          {:captured, from} -> send(from, {:captured, head, body})
        end
      end)

    {port, server}
  end

  defp captured_request(server) do
    send(server, {:captured, self()})
    assert_receive {:captured, head, body}, 2_000
    {head, body}
  end

  defp read_request(sock, buffer) do
    case :binary.split(buffer, "\r\n\r\n") do
      [head, rest] ->
        {head, read_body(sock, rest, content_length(head))}

      [_incomplete] ->
        {:ok, data} = :gen_tcp.recv(sock, 0, 2_000)
        read_request(sock, buffer <> data)
    end
  end

  defp read_body(_sock, body, length) when byte_size(body) >= length, do: body

  defp read_body(sock, body, length) do
    {:ok, data} = :gen_tcp.recv(sock, 0, 2_000)
    read_body(sock, body <> data, length)
  end

  defp content_length(head) do
    case Regex.run(~r/^content-length:\s*(\d+)/im, head) do
      [_, n] -> String.to_integer(n)
      nil -> 0
    end
  end
end
