defmodule Exosphere.ATProto.Spaces.TokenTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.OAuth.{JWK, JWS}
  alias Exosphere.ATProto.Spaces.Token

  @space "at://did:example:space/space/app.bsky.group/test"
  @user "did:example:alice"
  @authority "did:example:space"
  @space_host Token.space_host_aud(@authority)
  @dpop_jkt "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
  @client_id "https://app.example.com/client-metadata.json"
  @now 1_800_000_000

  setup do
    {:ok, user} = JWK.generate(:secp256k1)
    {:ok, authority} = JWK.generate(:secp256k1)
    {:ok, client} = JWK.generate(:p256)
    {:ok, other} = JWK.generate(:secp256k1)
    %{user: user, authority: authority, client: client, other: other}
  end

  defp key_fn(jwk) do
    fn _iss, _kid, _refresh -> {:ok, JWK.to_public(jwk)} end
  end

  defp delegation(jwk, opts \\ []) do
    {:ok, jwt} =
      Token.sign(
        :delegation,
        [iss: @user, sub: @space, aud: @space_host, iat: @now] ++ opts,
        jwk
      )

    jwt
  end

  test "space_host_aud/1 addresses the authority's space host" do
    assert Token.space_host_aud("did:plc:abc") == "did:plc:abc#atproto_space_host"
  end

  describe "delegation token" do
    test "round-trips", %{user: user} do
      {:ok, %{header: header, payload: payload}} =
        Token.verify(:delegation, delegation(user),
          get_signing_key: key_fn(user),
          aud: @space_host,
          sub: @space,
          now: @now
        )

      assert header["typ"] == "atproto-space-delegation+jwt"
      assert header["kid"] == "#atproto"
      assert header["alg"] == "ES256K"
      assert payload["iss"] == @user
      assert payload["sub"] == @space
      assert payload["aud"] == @space_host
      assert payload["exp"] - payload["iat"] == 60
      assert Regex.match?(~r/^[0-9a-f]{32}$/, payload["jti"])
    end

    test "requires an aud at mint time", %{user: user} do
      assert {:error, :missing_aud} =
               Token.sign(:delegation, [iss: @user, sub: @space], user)
    end

    test "is rejected by an authority it was not addressed to", %{user: user} do
      assert {:error, :bad_audience} =
               Token.verify(:delegation, delegation(user),
                 get_signing_key: key_fn(user),
                 aud: "did:example:other#atproto_space_host",
                 now: @now
               )
    end

    test "is rejected for a space other than its subject", %{user: user} do
      assert {:error, :bad_subject} =
               Token.verify(:delegation, delegation(user),
                 get_signing_key: key_fn(user),
                 aud: @space_host,
                 sub: "at://did:example:space/space/app.bsky.group/other",
                 now: @now
               )
    end

    test "is rejected when signed by the wrong key", %{user: user, other: other} do
      assert {:error, :invalid_signature} =
               Token.verify(:delegation, delegation(user),
                 get_signing_key: key_fn(other),
                 now: @now
               )
    end

    test "recovers when the cached key was stale (rotation retry)", %{user: user, other: other} do
      fetch = fn _iss, _kid, force_refresh ->
        if force_refresh, do: {:ok, JWK.to_public(user)}, else: {:ok, JWK.to_public(other)}
      end

      assert {:ok, _} =
               Token.verify(:delegation, delegation(user), get_signing_key: fetch, now: @now)
    end

    test "is rejected when its type is wrong", %{user: user} do
      assert {:error, :wrong_token_type} =
               Token.verify(:credential, delegation(user),
                 get_signing_key: key_fn(user),
                 now: @now
               )
    end

    test "expiry allows clock skew but not much", %{user: user} do
      assert {:ok, _} =
               Token.verify(:delegation, delegation(user),
                 get_signing_key: key_fn(user),
                 now: @now + 64
               )

      assert {:error, :token_expired} =
               Token.verify(:delegation, delegation(user),
                 get_signing_key: key_fn(user),
                 now: @now + 65
               )
    end

    test "structural failures surface their reason", %{user: user} do
      assert {:error, :invalid_token} = Token.parse(:delegation, "not-a-jwt")

      # Swap the typ header, leaving payload and signature alone.
      [header, payload, sig] = String.split(delegation(user), ".")

      evil_header =
        header
        |> Base.url_decode64!(padding: false)
        |> Jason.decode!()
        |> Map.put("typ", "atproto-space-credential+jwt")
        |> Jason.encode!()
        |> Base.url_encode64(padding: false)

      assert {:error, :wrong_token_type} =
               Token.parse(:delegation, Enum.join([evil_header, payload, sig], "."))
    end
  end

  describe "space credential" do
    test "round-trips without an aud, bound to its DPoP key", %{authority: authority} do
      {:ok, jwt} =
        Token.sign(
          :credential,
          [iss: @authority, sub: @space, dpop_jkt: @dpop_jkt, iat: @now, kid: "#atproto_space"],
          authority
        )

      assert {:ok, %{header: header, payload: payload}} =
               Token.verify(:credential, jwt, get_signing_key: key_fn(authority), now: @now)

      assert header["typ"] == "atproto-space-credential+jwt"
      assert header["kid"] == "#atproto_space"
      assert header["alg"] == "ES256K"
      assert payload["cnf"] == %{"jkt" => @dpop_jkt}
      assert payload["exp"] - payload["iat"] == 7200
      refute Map.has_key?(payload, "aud")
    end

    test "requires the DPoP binding at mint time", %{authority: authority} do
      assert {:error, :missing_cnf} =
               Token.sign(:credential, [iss: @authority, sub: @space], authority)
    end

    test "a credential without cnf.jkt fails structurally", %{authority: authority} do
      header = %{
        "alg" => "ES256K",
        "typ" => "atproto-space-credential+jwt",
        "kid" => "#atproto"
      }

      payload = %{
        "iss" => @authority,
        "sub" => @space,
        "iat" => @now,
        "exp" => @now + 7200,
        "jti" => "j"
      }

      assert {:ok, jwt} = JWS.sign(authority, header, payload)
      assert {:error, :missing_cnf} = Token.parse(:credential, jwt)
    end
  end

  describe "client attestation" do
    test "round-trips with iss == sub == client_id", %{client: client} do
      {:ok, jwt} =
        Token.sign(
          :client_attestation,
          [iss: @client_id, sub: @client_id, aud: @space_host, iat: @now],
          client
        )

      assert {:ok, %{header: header, payload: payload}} =
               Token.verify(:client_attestation, jwt,
                 get_signing_key: key_fn(client),
                 aud: @space_host,
                 now: @now
               )

      assert header["typ"] == "atproto-client-attestation+jwt"
      assert header["alg"] == "ES256"
      refute Map.has_key?(header, "kid")
      assert payload["iss"] == @client_id
      assert payload["sub"] == @client_id
      assert payload["aud"] == @space_host
      assert payload["exp"] - payload["iat"] == 60
    end

    test "rejects an attestation whose iss is not its sub", %{client: client} do
      {:ok, jwt} =
        Token.sign(
          :client_attestation,
          [iss: @client_id, sub: "did:example:other", aud: @space_host, iat: @now, jti: "x"],
          client
        )

      assert {:error, :attestation_subject} = Token.parse(:client_attestation, jwt)
    end
  end
end
