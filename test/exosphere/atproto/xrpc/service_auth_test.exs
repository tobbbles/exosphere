defmodule Exosphere.ATProto.XRPC.ServiceAuthTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.OAuth.{JWK, JWS}
  alias Exosphere.ATProto.XRPC.ServiceAuth

  @iss "did:web:syncer.example.com"
  @aud "did:plc:spaceauthority#atproto_pds"
  @lxm "com.atproto.space.unregisterNotify"
  @now 1_800_000_000

  setup do
    {:ok, k256} = JWK.generate(:secp256k1)
    {:ok, p256} = JWK.generate(:p256)
    %{k256: k256, p256: p256}
  end

  defp opts(extra \\ []), do: [iss: @iss, aud: @aud, lxm: @lxm, iat: @now] ++ extra

  defp key_for(jwk), do: fn _iss, _kid, _refresh -> {:ok, JWK.to_public(jwk)} end

  test "mints the token shape the XRPC spec describes", ctx do
    for {key, alg} <- [{ctx.k256, "ES256K"}, {ctx.p256, "ES256"}] do
      assert {:ok, jwt} = ServiceAuth.sign(opts(), key)
      assert {:ok, header, payload} = JWS.decode(jwt)

      assert header == %{"typ" => "JWT", "alg" => alg, "kid" => "#atproto"}

      assert %{
               "iss" => @iss,
               "aud" => @aud,
               "lxm" => @lxm,
               "iat" => @now,
               "exp" => exp,
               "jti" => jti
             } = payload

      assert exp == @now + 60
      assert jti =~ ~r/^[0-9a-f]{32}$/
      assert {:ok, ^payload} = JWS.verify(JWK.to_public(key), jwt, [alg])
    end
  end

  test "each token gets a fresh jti", ctx do
    {:ok, a} = ServiceAuth.sign(opts(), ctx.k256)
    {:ok, b} = ServiceAuth.sign(opts(), ctx.k256)
    {:ok, _, %{"jti" => ja}} = JWS.decode(a)
    {:ok, _, %{"jti" => jb}} = JWS.decode(b)
    refute ja == jb
  end

  test "kid, lifetime and jti can be set", ctx do
    {:ok, jwt} = ServiceAuth.sign(opts(kid: "#atproto_label", expires_in: 30, jti: "n"), ctx.k256)
    {:ok, header, payload} = JWS.decode(jwt)
    assert header["kid"] == "#atproto_label"
    assert payload["exp"] - payload["iat"] == 30
    assert payload["jti"] == "n"
  end

  test "refuses an iss with a fragment, a malformed aud, or a missing lxm", ctx do
    assert {:error, :invalid_iss} =
             ServiceAuth.sign(opts() |> Keyword.put(:iss, @iss <> "#svc"), ctx.k256)

    assert {:error, :invalid_iss} = ServiceAuth.sign(Keyword.delete(opts(), :iss), ctx.k256)

    assert {:error, :invalid_aud} =
             ServiceAuth.sign(Keyword.put(opts(), :aud, "not-a-did"), ctx.k256)

    assert {:error, :invalid_aud} =
             ServiceAuth.sign(Keyword.put(opts(), :aud, "did:plc:x#"), ctx.k256)

    assert {:error, :invalid_lxm} = ServiceAuth.sign(Keyword.delete(opts(), :lxm), ctx.k256)
    assert {:error, :unsupported_key} = ServiceAuth.sign(opts(), %{"crv" => "Ed25519"})
  end

  test "headers/2 wraps the token as Bearer", ctx do
    assert {:ok, [{"authorization", "Bearer " <> jwt}]} = ServiceAuth.headers(opts(), ctx.k256)
    assert {:ok, _, %{"lxm" => @lxm}} = JWS.decode(jwt)
  end

  describe "verify/3" do
    test "accepts a token for this audience and method", ctx do
      {:ok, jwt} = ServiceAuth.sign(opts(), ctx.k256)

      assert {:ok, %{"iss" => @iss}} =
               ServiceAuth.verify(jwt, key_for(ctx.k256), aud: @aud, lxm: @lxm, now: @now)

      # Any of several acceptable audiences.
      assert {:ok, _} =
               ServiceAuth.verify(jwt, key_for(ctx.k256),
                 aud: ["did:plc:spaceauthority", @aud],
                 lxm: @lxm,
                 now: @now
               )
    end

    test "refuses the wrong audience, method, an expired token, or a bad signature", ctx do
      {:ok, jwt} = ServiceAuth.sign(opts(), ctx.k256)

      verify =
        &ServiceAuth.verify(
          jwt,
          key_for(ctx.k256),
          Keyword.merge([aud: @aud, lxm: @lxm, now: @now], &1)
        )

      assert {:error, :bad_audience} = verify.(aud: "did:plc:spaceauthority")
      assert {:error, :bad_lxm} = verify.(lxm: "com.atproto.space.registerNotify")
      assert {:error, :token_expired} = verify.(now: @now + 3600)

      assert {:error, :invalid_signature} =
               ServiceAuth.verify(jwt, key_for(ctx.p256), aud: @aud, lxm: @lxm, now: @now)

      assert {:error, :signing_key_unavailable} =
               ServiceAuth.verify(jwt, fn _, _, _ -> {:error, :nope} end,
                 aud: @aud,
                 lxm: @lxm,
                 now: @now
               )
    end

    test "retries the key once with a forced refresh, for a rotated key", ctx do
      {:ok, jwt} = ServiceAuth.sign(opts(), ctx.k256)
      stale = JWK.to_public(ctx.p256)
      fresh = JWK.to_public(ctx.k256)

      get_key = fn _iss, "#atproto", refresh -> {:ok, if(refresh, do: fresh, else: stale)} end

      assert {:ok, _} = ServiceAuth.verify(jwt, get_key, aud: @aud, lxm: @lxm, now: @now)
    end

    test "refuses token types that are not service auth", ctx do
      {:ok, jwt} =
        JWS.sign(ctx.k256, %{"alg" => "ES256K", "typ" => "at+jwt"}, %{
          "iss" => @iss,
          "aud" => @aud,
          "lxm" => @lxm,
          "exp" => @now + 60
        })

      assert {:error, :invalid_token} =
               ServiceAuth.verify(jwt, key_for(ctx.k256), aud: @aud, lxm: @lxm, now: @now)
    end
  end
end
