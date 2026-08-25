defmodule Exosphere.ATProto.OAuth.DiscoveryTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.OAuth.{Discovery, ServerMetadata}

  # All Discovery calls run synchronously in the test process, so a canned
  # fake keyed on full URL keeps per-test isolation simple.
  defmodule CannedHTTP do
    def get(url, _opts) do
      Map.fetch!(Process.get(:canned), url)
    end
  end

  @pds "https://pds.example.com"
  @as "https://as.example.com"

  defp canned(map) do
    Process.put(:canned, map)
    CannedHTTP
  end

  defp did_document(pds \\ @pds) do
    %{
      "id" => "did:web:alice.example.com",
      "alsoKnownAs" => ["at://alice.example.com"],
      "service" => [
        %{
          "id" => "did:web:alice.example.com#atproto_pds",
          "type" => "AtprotoPersonalDataServer",
          "serviceEndpoint" => pds
        }
      ]
    }
  end

  defp as_document do
    %{
      "issuer" => @as,
      "authorization_endpoint" => @as <> "/authorize",
      "token_endpoint" => @as <> "/token",
      "pushed_authorization_request_endpoint" => @as <> "/par",
      "response_types_supported" => ["code"],
      "grant_types_supported" => ["authorization_code", "refresh_token"],
      "scopes_supported" => ["atproto"],
      "token_endpoint_auth_methods_supported" => ["none", "private_key_jwt"],
      "token_endpoint_auth_signing_alg_values_supported" => ["ES256"],
      "dpop_signing_alg_values_supported" => ["ES256"],
      "require_pushed_authorization_requests" => true,
      "client_id_metadata_document_supported" => true,
      "authorization_response_iss_parameter_supported" => true
    }
  end

  defp identity_canned(did_doc \\ did_document()) do
    %{
      "https://alice.example.com/.well-known/atproto-did" =>
        {:ok, %{status: 200, headers: [], body: "did:web:alice.example.com"}},
      "https://alice.example.com/.well-known/did.json" =>
        {:ok, %{status: 200, headers: [], body: did_doc}},
      (@pds <> "/.well-known/oauth-protected-resource") =>
        {:ok, %{status: 200, headers: [], body: %{"authorization_servers" => [@as]}}},
      (@as <> "/.well-known/oauth-authorization-server") =>
        {:ok, %{status: 200, headers: [], body: as_document()}}
    }
  end

  test "resolve/2 walks handle -> DID -> PDS -> AS and verifies the handle bidirectionally" do
    http = canned(identity_canned())

    assert {:ok, resolved} = Discovery.resolve("alice.example.com", http: http)
    assert resolved.did == "did:web:alice.example.com"
    assert resolved.handle == "alice.example.com"
    assert resolved.pds == @pds
    assert resolved.auth_server.issuer == @as
  end

  test "resolve/2 accepts a DID directly" do
    canned = Map.delete(identity_canned(), "https://alice.example.com/.well-known/atproto-did")
    http = canned(canned)

    assert {:ok, resolved} = Discovery.resolve("did:web:alice.example.com", http: http)
    assert resolved.did == "did:web:alice.example.com"
    assert is_nil(resolved.handle)
  end

  test "resolve/2 rejects a handle the DID document does not claim back" do
    stranger_did = %{did_document() | "alsoKnownAs" => ["at://mallory.example.net"]}

    assert {:error, :handle_mismatch} =
             Discovery.resolve("alice.example.com", http: canned(identity_canned(stranger_did)))
  end

  test "resolve/2 fails when the PDS hosts no PDS service" do
    no_pds = %{"id" => "did:web:alice.example.com"}

    assert {:error, :pds_not_found} =
             Discovery.resolve("did:web:alice.example.com", http: canned(identity_canned(no_pds)))
  end

  test "resolve/2 with a server URL follows the resource-server document" do
    http =
      canned(%{
        (@pds <> "/.well-known/oauth-protected-resource") =>
          {:ok, %{status: 200, headers: [], body: %{"authorization_servers" => [@as]}}},
        (@as <> "/.well-known/oauth-authorization-server") =>
          {:ok, %{status: 200, headers: [], body: as_document()}}
      })

    assert {:ok, resolved} = Discovery.resolve(@pds, http: http)
    assert is_nil(resolved.did)
    assert resolved.auth_server.issuer == @as
  end

  test "resolve/2 with a server URL falls back to the server as its own AS" do
    self_hosted =
      as_document()
      |> Map.put("issuer", @pds)
      |> Map.put("authorization_endpoint", @pds <> "/authorize")
      |> Map.put("token_endpoint", @pds <> "/token")
      |> Map.put("pushed_authorization_request_endpoint", @pds <> "/par")

    http =
      canned(%{
        (@pds <> "/.well-known/oauth-protected-resource") =>
          {:ok, %{status: 404, headers: [], body: %{}}},
        (@pds <> "/.well-known/oauth-authorization-server") =>
          {:ok, %{status: 200, headers: [], body: self_hosted}}
      })

    assert {:ok, resolved} = Discovery.resolve(@pds, http: http)
    assert resolved.auth_server.issuer == @pds
  end

  test "verify_subject/3 checks the subject's PDS declares the expected issuer" do
    http = canned(identity_canned())

    assert {:ok, %{pds: @pds}} =
             Discovery.verify_subject("did:web:alice.example.com", @as, http: http)

    assert {:error, :subject_pds_authorization_server_mismatch} =
             Discovery.verify_subject("did:web:alice.example.com", "https://other.example.com",
               http: http
             )
  end

  test "ServerMetadata.to_map/from_map round-trips" do
    {:ok, metadata} = ServerMetadata.validate(as_document(), @as)
    {:ok, json} = metadata |> ServerMetadata.to_map() |> Jason.encode!() |> Jason.decode()
    {:ok, decoded} = ServerMetadata.from_map(json)

    assert decoded.issuer == metadata.issuer
    assert decoded.token_endpoint == metadata.token_endpoint
    assert decoded.raw == %{}
  end
end
