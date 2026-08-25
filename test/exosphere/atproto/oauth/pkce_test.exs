defmodule Exosphere.ATProto.OAuth.PKCETest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.OAuth.PKCE

  test "challenge/1 matches the RFC 7636 appendix B vector" do
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert PKCE.challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
  end

  test "generate_verifier/0 returns a valid verifier" do
    verifier = PKCE.generate_verifier()
    assert byte_size(verifier) == 43
    assert PKCE.valid_verifier?(verifier)
  end

  test "valid_verifier?/1 rejects short, long, and illegal characters" do
    refute PKCE.valid_verifier?("too-short")
    refute PKCE.valid_verifier?(String.duplicate("a", 129))
    refute PKCE.valid_verifier?("has space in it which is not unreserved ok?")
    refute PKCE.valid_verifier?(42)
    assert PKCE.valid_verifier?(String.duplicate("a", 43))
  end
end

defmodule Exosphere.ATProto.OAuth.JWKTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Crypto
  alias Exosphere.ATProto.OAuth.JWK

  test "keypair round-trips through a JWK for both curves" do
    for curve <- [:p256, :secp256k1] do
      {:ok, keypair} = Crypto.generate_keypair(curve)
      {:ok, jwk} = JWK.from_keypair(keypair, curve)

      assert %{"kty" => "EC", "d" => _} = jwk
      refute Map.has_key?(JWK.to_public(jwk), "d")

      assert {:ok, public, ^curve} = JWK.to_public_key(JWK.to_public(jwk))
      assert byte_size(public) == 33

      assert public in [
               keypair.public_key,
               elem(Crypto.compress_public_key(keypair.public_key, curve), 1)
             ]
    end
  end

  test "from_keypair/2 rejects garbage public keys" do
    assert {:error, :invalid_public_key} =
             JWK.from_keypair(%{public_key: "junk", private_key: <<1::256>>}, :p256)
  end

  test "thumbprint/1 is deterministic and sha-256 based" do
    {:ok, jwk} = JWK.generate(:p256)
    assert {:ok, t1} = JWK.thumbprint(JWK.to_public(jwk))
    assert {:ok, t2} = JWK.thumbprint(JWK.to_public(jwk))
    assert t1 == t2
    assert byte_size(Base.url_decode64!(t1, padding: false)) == 32
    assert {:error, :invalid_jwk} = JWK.thumbprint(%{"kty" => "oct"})
  end
end

defmodule Exosphere.ATProto.OAuth.JWSTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.OAuth.{JWK, JWS}

  test "sign/3 and verify/3 round-trip with ES256" do
    {:ok, jwk} = JWK.generate(:p256)
    {:ok, jwt} = JWS.sign(jwk, %{"alg" => "ES256"}, %{"sub" => "did:plc:abc"})

    assert {:ok, %{"sub" => "did:plc:abc"}} =
             JWS.verify(JWK.to_public(jwk), jwt, ["ES256"])
  end

  test "sign/3 and verify/3 round-trip with ES256K" do
    {:ok, jwk} = JWK.generate(:secp256k1)
    {:ok, jwt} = JWS.sign(jwk, %{"alg" => "ES256K"}, %{"sub" => "did:plc:abc"})

    assert {:ok, %{"sub" => "did:plc:abc"}} =
             JWS.verify(JWK.to_public(jwk), jwt, ["ES256K"])
  end

  test "verify/3 rejects tampered payloads and disallowed algorithms" do
    {:ok, jwk} = JWK.generate(:p256)
    {:ok, jwt} = JWS.sign(jwk, %{"alg" => "ES256"}, %{"sub" => "did:plc:abc"})
    [h, _p, s] = String.split(jwt, ".")
    tampered = [h, Base.url_encode64("tampered", padding: false), s] |> Enum.join(".")

    assert {:error, tamper_error} = JWS.verify(JWK.to_public(jwk), tampered, ["ES256"])
    assert tamper_error in [:invalid_signature, :invalid_token]
    # strict algorithm list rejects the token signed with ES256
    assert {:error, _} = JWS.verify(JWK.to_public(jwk), jwt, ["RS256"])
  end

  test "sign/3 requires a private key and a supported algorithm" do
    {:ok, jwk} = JWK.generate(:p256)
    assert {:error, :not_a_private_key} = JWS.sign(JWK.to_public(jwk), %{"alg" => "ES256"}, %{})
    assert {:error, :unsupported_alg} = JWS.sign(jwk, %{"alg" => "HS256"}, %{})
    assert {:error, :unsupported_alg} = JWS.sign(jwk, %{}, %{})
  end

  test "decode/2 splits header and payload without verifying" do
    {:ok, jwk} = JWK.generate(:p256)
    {:ok, jwt} = JWS.sign(jwk, %{"alg" => "ES256", "typ" => "dpop+jwt"}, %{"jti" => "x"})

    assert {:ok, %{"typ" => "dpop+jwt"}, %{"jti" => "x"}} = JWS.decode(jwt)
    assert {:error, :invalid_token} = JWS.decode("not.a.jwt.with.valid.base64url!!!")
    assert {:error, :invalid_token} = JWS.decode("")
  end
end
