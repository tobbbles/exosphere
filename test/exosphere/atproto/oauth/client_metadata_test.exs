defmodule Exosphere.ATProto.OAuth.ClientMetadataTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.OAuth.{ClientMetadata, JWK}

  @valid_opts [
    client_id: "https://app.example.com/oauth-client-metadata.json",
    client_name: "My App",
    redirect_uris: ["https://app.example.com/oauth/callback"],
    scope: ["atproto", "transition:generic"]
  ]

  test "new/1 with a client key infers a confidential client" do
    {:ok, jwk} = JWK.generate(:p256)
    assert {:ok, metadata} = ClientMetadata.new(@valid_opts ++ [jwk: JWK.to_public(jwk)])
    assert ClientMetadata.confidential?(metadata)
    assert metadata.token_endpoint_auth_method == :private_key_jwt
  end

  test "new/1 without a key infers a public client" do
    assert {:ok, metadata} = ClientMetadata.new(@valid_opts)
    refute ClientMetadata.confidential?(metadata)
    assert metadata.token_endpoint_auth_method == :none
  end

  test "new/1 requires the atproto scope and at least one redirect URI" do
    assert {:error, :atproto_scope_required} =
             ClientMetadata.new(Keyword.put(@valid_opts, :scope, ["transition:generic"]))

    assert {:error, :redirect_uris_required} =
             ClientMetadata.new(Keyword.put(@valid_opts, :redirect_uris, []))
  end

  test "new/1 rejects http client ids and redirect URIs outside localhost" do
    assert {:error, {:not_https, :client_id}} =
             ClientMetadata.new(
               Keyword.put(@valid_opts, :client_id, "http://app.example.com/m.json")
             )

    assert {:error, :invalid_redirect_uri} =
             ClientMetadata.new(
               Keyword.put(@valid_opts, :redirect_uris, ["http://app.example.com/cb"])
             )

    assert {:ok, _} =
             ClientMetadata.new(
               Keyword.put(@valid_opts, :redirect_uris, ["http://localhost:7777/cb"])
             )
  end

  test "new/1 rejects private_key_jwt without a hosted key, and keys on public clients" do
    assert {:error, :jwk_required_for_confidential_client} =
             ClientMetadata.new(
               Keyword.put(@valid_opts, :token_endpoint_auth_method, :private_key_jwt)
             )

    {:ok, jwk} = JWK.generate(:p256)

    assert {:error, :key_forbidden_for_public_client} =
             ClientMetadata.new(
               @valid_opts ++ [jwk: JWK.to_public(jwk), token_endpoint_auth_method: :none]
             )
  end

  test "to_document/1 renders the confidential client metadata document" do
    {:ok, jwk} = JWK.generate(:p256)
    {:ok, metadata} = ClientMetadata.new(@valid_opts ++ [jwk: JWK.to_public(jwk)])
    doc = ClientMetadata.to_document(metadata)

    assert doc["client_id"] == metadata.client_id
    assert doc["application_type"] == "web"
    assert doc["grant_types"] == ["authorization_code", "refresh_token"]
    assert doc["response_types"] == ["code"]
    assert doc["scope"] == "atproto transition:generic"
    assert doc["token_endpoint_auth_method"] == "private_key_jwt"
    assert doc["token_endpoint_auth_signing_alg"] == "ES256"
    assert doc["dpop_bound_access_tokens"] == true
    assert [%{"kty" => "EC", "kid" => kid}] = doc["jwks"]["keys"]
    assert byte_size(kid) > 0
  end

  test "localhost_client_id/2 builds the special loopback client id" do
    assert {:ok, client_id} = ClientMetadata.localhost_client_id(["http://localhost:9/cb"])

    assert client_id ==
             "http://localhost?redirect_uri=http%3A%2F%2Flocalhost%3A9%2Fcb&scope=atproto+transition%3Ageneric"

    assert {:error, :redirect_uri_not_loopback} =
             ClientMetadata.localhost_client_id(["https://app.example.com/cb"])

    assert {:error, :atproto_scope_required} =
             ClientMetadata.localhost_client_id(["http://localhost:9/cb"], ["transition:generic"])
  end
end
