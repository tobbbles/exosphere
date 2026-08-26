defmodule Exosphere.ATProto.OAuth.ClientTest do
  @moduledoc """
  The client-authentication half: the assertion is what an authorization
  server checks us by, so its shape is pinned here.
  """
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.OAuth.{Client, ClientMetadata, JWK, JWS}

  setup do
    {:ok, jwk} = JWK.generate(:p256)

    {:ok, metadata} =
      ClientMetadata.new(
        client_id: "https://app.example/oauth/client-metadata.json",
        redirect_uris: ["https://app.example/callback"],
        jwk: JWK.to_public(jwk)
      )

    {:ok, client} =
      Client.new(metadata: metadata, key: jwk, redirect_uri: "https://app.example/callback")

    %{client: client, jwk: jwk, metadata: metadata}
  end

  describe "assertion/3" do
    test "carries the kid the metadata published, so the AS can pick the key", %{
      client: client,
      jwk: jwk
    } do
      assert {:ok, assertion} = Client.assertion(client, "https://as.example")
      assert {:ok, header, _claims} = JWS.decode(assertion)
      assert header["kid"]
      assert {:ok, thumbprint} = JWK.thumbprint(jwk)
      assert header["kid"] == thumbprint
    end

    test "keeps the private_key_jwt claims shape", %{client: client, metadata: metadata} do
      assert {:ok, assertion} = Client.assertion(client, "https://as.example", iat: 1_000)

      assert {:ok, claims} = JWS.verify(metadata.jwk, assertion, ["ES256"])

      assert claims["iss"] == Client.client_id(client)
      assert claims["sub"] == Client.client_id(client)
      assert claims["aud"] == "https://as.example"
      assert claims["iat"] == 1_000
      assert claims["exp"] == 1_000 + 300
    end

    test "a public client has no assertion to make" do
      {:ok, public} =
        ClientMetadata.new(
          client_id: "http://localhost",
          redirect_uris: ["http://127.0.0.1:1/callback"]
        )

      {:ok, client} = Client.new(metadata: public, redirect_uri: "http://127.0.0.1:1/callback")

      assert {:error, :public_client} = Client.assertion(client, "https://as.example")
      refute Client.confidential?(client)
    end
  end
end
