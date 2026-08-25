defmodule Exosphere.ATProto.OAuth.ServerMetadataTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.OAuth.ServerMetadata

  @origin "https://as.example.com"

  defp valid_metadata(overrides \\ %{}) do
    Map.merge(
      %{
        "issuer" => @origin,
        "authorization_endpoint" => @origin <> "/authorize",
        "token_endpoint" => @origin <> "/token",
        "pushed_authorization_request_endpoint" => @origin <> "/par",
        "response_types_supported" => ["code"],
        "grant_types_supported" => ["authorization_code", "refresh_token"],
        "scopes_supported" => ["atproto", "transition:generic"],
        "token_endpoint_auth_methods_supported" => ["none", "private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported" => ["ES256"],
        "dpop_signing_alg_values_supported" => ["ES256"],
        "require_pushed_authorization_requests" => true,
        "client_id_metadata_document_supported" => true,
        "authorization_response_iss_parameter_supported" => true
      },
      overrides
    )
  end

  # ServerMetadata calls the http module synchronously from the test
  # process, so a canned fake reading this process's dictionary is enough.
  defmodule CannedHTTP do
    def get(url, _opts) do
      Map.fetch!(Process.get(:canned), URI.parse(url).path)
    end
  end

  defp canned(map) do
    Process.put(:canned, map)
    CannedHTTP
  end

  test "validate/2 accepts spec-conformant metadata and exposes the endpoints" do
    assert {:ok, metadata} = ServerMetadata.validate(valid_metadata(), @origin)
    assert metadata.issuer == @origin
    assert metadata.token_endpoint == @origin <> "/token"
    assert metadata.pushed_authorization_request_endpoint == @origin <> "/par"
  end

  test "validate/2 rejects an issuer that does not match the fetch origin" do
    assert {:error, :issuer_mismatch} =
             ServerMetadata.validate(
               valid_metadata(%{"issuer" => "https://evil.example.com"}),
               @origin
             )
  end

  test "validate/2 enforces every profile requirement" do
    for field <- [
          "authorization_endpoint",
          "token_endpoint",
          "pushed_authorization_request_endpoint",
          "response_types_supported",
          "grant_types_supported",
          "scopes_supported",
          "token_endpoint_auth_methods_supported",
          "token_endpoint_auth_signing_alg_values_supported",
          "dpop_signing_alg_values_supported"
        ] do
      broken = valid_metadata() |> Map.delete(field)

      assert {:error, {:invalid_server_metadata, {:missing, ^field}}} =
               ServerMetadata.validate(broken, @origin)
    end

    for {field, required} <- [
          {"response_types_supported", ["code"]},
          {"grant_types_supported", ["refresh_token"]},
          {"scopes_supported", ["atproto"]},
          {"token_endpoint_auth_methods_supported", ["private_key_jwt"]},
          {"token_endpoint_auth_signing_alg_values_supported", ["ES256"]},
          {"dpop_signing_alg_values_supported", ["ES256"]}
        ] do
      broken = valid_metadata(%{field => List.delete(valid_metadata()[field], hd(required))})

      assert {:error, {:invalid_server_metadata, {:missing_supported, ^field}}} =
               ServerMetadata.validate(broken, @origin)
    end

    for field <- [
          "require_pushed_authorization_requests",
          "client_id_metadata_document_supported",
          "authorization_response_iss_parameter_supported"
        ] do
      broken = valid_metadata(%{field => false})

      assert {:error, {:invalid_server_metadata, {:flag_not_set, ^field}}} =
               ServerMetadata.validate(broken, @origin)
    end
  end

  test "validate/2 keeps endpoints inside the issuer origin" do
    assert {:error, {:invalid_server_metadata, {:not_issuer_origin, "token_endpoint"}}} =
             ServerMetadata.validate(
               valid_metadata(%{"token_endpoint" => "https://evil.example.com/token"}),
               @origin
             )
  end

  test "fetch_authorization_server/2 reads the protected-resource document" do
    http =
      canned(%{
        "/.well-known/oauth-protected-resource" =>
          {:ok,
           %{
             status: 200,
             headers: [],
             body: %{"authorization_servers" => ["https://entryway.example.com"]}
           }}
      })

    assert {:ok, "https://entryway.example.com"} =
             ServerMetadata.fetch_authorization_server(@origin, http: http)
  end

  test "fetch_authorization_server/2 detects self-hosted AS (404) and rejects ambiguity" do
    http =
      canned(%{
        "/.well-known/oauth-protected-resource" => {:ok, %{status: 404, headers: [], body: %{}}}
      })

    assert {:error, :protected_resource_metadata_not_found} =
             ServerMetadata.fetch_authorization_server(@origin, http: http)

    two =
      canned(%{
        "/.well-known/oauth-protected-resource" =>
          {:ok,
           %{
             status: 200,
             headers: [],
             body: %{
               "authorization_servers" => ["https://a.example.com", "https://b.example.com"]
             }
           }}
      })

    assert {:error, :multiple_authorization_servers} =
             ServerMetadata.fetch_authorization_server(@origin, http: two)
  end

  test "supported_scopes/2 intersects with server support" do
    {:ok, metadata} = ServerMetadata.validate(valid_metadata(), @origin)

    assert ServerMetadata.supported_scopes(metadata, [
             "atproto",
             "transition:chat.bsky",
             "made.up"
           ]) ==
             ["atproto"]
  end
end
