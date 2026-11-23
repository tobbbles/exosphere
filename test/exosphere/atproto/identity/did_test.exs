defmodule Exosphere.ATProto.Identity.DIDTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Identity.DID
  alias Exosphere.ATProto.Identity.DID.{PLC, Web}
  alias Exosphere.ATProto.Identity.Document

  # Answers every GET with the response stashed in the calling process and
  # reports the URL it was asked for.
  defmodule StubHTTP do
    def get(url, _opts) do
      send(self(), {:http_get, url})
      Process.get(:stub_response, {:ok, %{status: 500, body: ""}})
    end
  end

  @plc "did:plc:z72i7hdynmk6r22z27h6tvur"
  @other_plc "did:plc:ewvi7nxzyoun6zhxrhs64oiz"

  defp respond(response), do: Process.put(:stub_response, response)
  defp doc(id), do: %{"id" => id, "alsoKnownAs" => ["at://alice.example.com"]}

  test "valid?/1 validates basic DID syntax" do
    assert DID.valid?("did:plc:z72i7hdynmk6r22z27h6tvur")
    assert DID.valid?("did:web:example.com")

    refute DID.valid?("not-a-did")
    refute DID.valid?("did::missing-method")
  end

  test "method/1 extracts DID method" do
    assert {:ok, :plc} = DID.method("did:plc:abc123")
    assert {:ok, :web} = DID.method("did:web:example.com")
    assert {:ok, :unknown} = DID.method("did:foo:bar")
    assert {:error, :invalid_did} = DID.method("nope")
  end

  describe "atproto_valid?/1" do
    test "did:plc is exactly 24 lowercase base32 characters" do
      assert DID.atproto_valid?(@plc)
      assert DID.atproto_valid?("did:plc:ewvi7nxzyoun6zhxrhs64oiz")

      refute DID.atproto_valid?("did:plc:abc")
      refute DID.atproto_valid?("did:plc:Z72I7HDYNMK6R22Z27H6TVUR")
      refute DID.atproto_valid?("did:plc:z72i7hdynmk6r22z27h6tvu1")
      refute DID.atproto_valid?("did:plc:z72i7hdynmk6r22z27h6tvurx")
      refute DID.atproto_valid?("did:plc:z72i7hdynmk6r22z27h6tvu")
      refute DID.atproto_valid?("did:plc:z72i7hdynmk6r22z27h6tvur\n")
      refute DID.atproto_valid?("DID:plc:z72i7hdynmk6r22z27h6tvur")
    end

    test "did:web is a lowercase hostname with no path and no port off localhost" do
      assert DID.atproto_valid?("did:web:example.com")
      assert DID.atproto_valid?("did:web:pds.sub.example-host.com")
      assert DID.atproto_valid?("did:web:localhost")
      assert DID.atproto_valid?("did:web:localhost%3A4000")

      refute DID.atproto_valid?("did:web:Example.com")
      refute DID.atproto_valid?("did:web:example.com%3A8443")
      refute DID.atproto_valid?("did:web:example.com:user")
      refute DID.atproto_valid?("did:web:example.com:user:alice")
      refute DID.atproto_valid?("did:web:example.com%2Fpath")
      refute DID.atproto_valid?("did:web:localhost%3Aabc")
      refute DID.atproto_valid?("did:web:-bad.example.com")
      refute DID.atproto_valid?("did:web:nodot")
      refute DID.atproto_valid?("did:web:")
    end

    test "other methods and non-strings are not atproto DIDs" do
      refute DID.atproto_valid?("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme")
      refute DID.atproto_valid?("did:example:123")
      refute DID.atproto_valid?(nil)
      refute DID.atproto_valid?(123)
    end
  end

  describe "resolve/2 refuses non-atproto DIDs before fetching" do
    test "malformed did:plc and did:web" do
      assert {:error, :invalid_did_format} = DID.resolve("did:plc:abc", http_client: StubHTTP)

      assert {:error, :invalid_did_format} =
               DID.resolve("did:web:Example.com", http_client: StubHTTP)

      assert {:error, :invalid_did_format} =
               DID.resolve("did:web:example.com:user", http_client: StubHTTP)

      assert {:error, :invalid_did_format} =
               DID.resolve("did:web:example.com%3A8443", http_client: StubHTTP)

      refute_received {:http_get, _}
    end

    test "a did:web path is refused as such" do
      assert {:error, :path_not_allowed} =
               Web.resolve("did:web:example.com%2Fuser", http_client: StubHTTP)

      refute_received {:http_get, _}
    end
  end

  describe "resolve/2 checks the document id" do
    test "did:plc: a document for another DID is :did_mismatch" do
      respond({:ok, %{status: 200, body: doc(@other_plc)}})
      assert {:error, :did_mismatch} = DID.resolve(@plc, http_client: StubHTTP)

      respond({:ok, %{status: 200, body: Jason.encode!(doc(@other_plc))}})
      assert {:error, :did_mismatch} = PLC.resolve(@plc, http_client: StubHTTP)
    end

    test "did:plc: the right document resolves" do
      respond({:ok, %{status: 200, body: doc(@plc)}})
      assert {:ok, %Document{id: @plc}} = DID.resolve(@plc, http_client: StubHTTP)
      assert_received {:http_get, "https://plc.directory/did:plc:z72i7hdynmk6r22z27h6tvur"}
    end

    test "the comparison is exact (DIDs are case-sensitive)" do
      respond({:ok, %{status: 200, body: doc(String.upcase(@plc))}})
      assert {:error, :did_mismatch} = DID.resolve(@plc, http_client: StubHTTP)
    end

    test "did:web: a document for another DID is :did_mismatch" do
      respond({:ok, %{status: 200, body: doc("did:web:evil.example.com")}})

      assert {:error, :did_mismatch} =
               DID.resolve("did:web:alice.example.com", http_client: StubHTTP)

      respond({:ok, %{status: 200, body: doc("did:web:alice.example.com")}})

      assert {:ok, %Document{id: "did:web:alice.example.com"}} =
               DID.resolve("did:web:alice.example.com", http_client: StubHTTP)
    end
  end

  describe "did:web URL building" do
    setup do
      respond({:ok, %{status: 404, body: ""}})
      :ok
    end

    test "a plain host is fetched over https with no port" do
      Web.resolve("did:web:example.com", http_client: StubHTTP)
      assert_received {:http_get, "https://example.com/.well-known/did.json"}
    end

    test "localhost may carry a port and is fetched over http" do
      Web.resolve("did:web:localhost%3A4000", http_client: StubHTTP)
      assert_received {:http_get, "http://localhost:4000/.well-known/did.json"}
    end
  end

  describe "did:plc tombstones" do
    test "410 Gone is :tombstoned, distinct from any other HTTP error" do
      respond({:ok, %{status: 410, body: %{"message" => "DID not available: " <> @plc}}})
      assert {:error, :tombstoned} = DID.resolve(@plc, http_client: StubHTTP)
      assert {:error, :tombstoned} = PLC.get_data(@plc, http_client: StubHTTP)

      respond({:ok, %{status: 404, body: ""}})
      assert {:error, :not_found} = DID.resolve(@plc, http_client: StubHTTP)

      respond({:ok, %{status: 503, body: ""}})
      assert {:error, {:http_error, 503}} = DID.resolve(@plc, http_client: StubHTTP)
    end
  end
end
