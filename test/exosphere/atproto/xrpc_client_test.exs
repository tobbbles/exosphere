defmodule Exosphere.ATProto.XRPC.ClientTest do
  use ExUnit.Case, async: true

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

  test "procedure/2 sends no body for a procedure without input" do
    # A conforming XRPC server rejects any body (even `{}`) on a procedure
    # whose lexicon declares no input.
    client = Client.new("https://example.com", access_token: "t0k", http: FakeHTTP)

    assert {:ok, _} = Client.procedure(client, "com.atproto.server.deleteSession")
    assert_received {:http, :post, _url, opts}
    refute Keyword.has_key?(opts, :json)
    refute Keyword.has_key?(opts, :body)

    assert {:ok, _} = Client.procedure(client, "x.test", nil, since: "3l")
    assert_received {:http, :post, "https://example.com/xrpc/x.test?since=3l", opts}
    refute Keyword.has_key?(opts, :json)
  end

  test "procedure/3 still sends an explicit empty map as {}" do
    client = Client.new("https://example.com", http: FakeHTTP)

    assert {:ok, _} = Client.procedure(client, "x.test", %{})
    assert_received {:http, :post, _url, opts}
    assert Keyword.fetch(opts, :json) == {:ok, %{}}
  end

  test "procedure/2 on a DPoP session sends no body either" do
    {:ok, key} = Exosphere.ATProto.OAuth.DPoP.generate_key()

    client =
      Client.new("https://example.com", access_token: "t0k", dpop: key, http: FakeHTTP)

    assert {:ok, _} = Client.procedure(client, "com.atproto.server.activateAccount")
    assert_received {:http, :post, _url, opts}
    refute Keyword.has_key?(opts, :json)
    refute Keyword.has_key?(opts, :body)
    assert {"authorization", "DPoP t0k"} in Keyword.get(opts, :headers)
  end

  test "the public wrapper defaults to no body too" do
    client = Exosphere.XRPC.Client.new("https://example.com", http: FakeHTTP)

    assert {:ok, _} = Exosphere.XRPC.Client.procedure(client, "com.atproto.server.deleteSession")
    assert_received {:http, :post, _url, opts}
    refute Keyword.has_key?(opts, :json)
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
end
