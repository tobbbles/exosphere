defmodule Exosphere.ATProto.OAuth.JWSLowSTest do
  @moduledoc """
  Every JWT exosphere signs is low-S (the atproto cryptography spec), on
  both curves and through every minting API that sits on `JWS.sign/3`.
  """
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Crypto
  alias Exosphere.ATProto.OAuth.{JWK, JWS}
  alias Exosphere.ATProto.Spaces.Token
  alias Exosphere.ATProto.XRPC.ServiceAuth

  # Group orders / 2: a low-S signature has S at most this.
  @half_order %{
    secp256k1: 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
    p256: 0x7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8
  }

  @algs %{secp256k1: "ES256K", p256: "ES256"}

  # JOSE's signer lands high-S about half the time, so 64 signatures per
  # curve miss a regression with probability 2^-64.
  @samples 64

  defp signature(jwt) do
    [header, payload, sig] = String.split(jwt, ".")
    {:ok, <<_::binary-64>> = raw} = Base.url_decode64(sig, padding: false)
    {header <> "." <> payload, raw}
  end

  defp s_of(<<_r::binary-32, s::binary-32>>), do: :binary.decode_unsigned(s)

  # The strict atproto check: the raw `r || s` verifies under Crypto.verify/4,
  # which refuses high-S, as `@atproto/crypto` does by default.
  defp assert_strictly_valid(jwt, jwk, curve) do
    {input, raw} = signature(jwt)
    assert s_of(raw) <= @half_order[curve], "high-S signature: #{jwt}"
    assert {:ok, public, ^curve} = JWK.to_public_key(JWK.to_public(jwk))
    assert :ok = Crypto.verify(input, raw, public, curve)
  end

  for curve <- [:secp256k1, :p256] do
    describe "sign/3 on #{curve}" do
      setup do
        {:ok, jwk} = JWK.generate(unquote(curve))
        %{jwk: jwk}
      end

      test "always emits low-S signatures that verify strictly and with JOSE", %{jwk: jwk} do
        curve = unquote(curve)
        alg = @algs[curve]

        for i <- 1..@samples do
          claims = %{"sub" => "did:plc:abc", "n" => i}
          assert {:ok, jwt} = JWS.sign(jwk, %{"alg" => alg}, claims)
          assert_strictly_valid(jwt, jwk, curve)
          assert {:ok, ^claims} = JWS.verify(JWK.to_public(jwk), jwt, [alg])
        end
      end

      test "service auth tokens are low-S", %{jwk: jwk} do
        for i <- 1..@samples do
          {:ok, jwt} =
            ServiceAuth.sign(
              [
                iss: "did:plc:issuer",
                aud: "did:plc:audience#atproto_pds",
                lxm: "com.atproto.space.notifyRepoUpdate",
                jti: "jti-#{i}"
              ],
              jwk
            )

          assert_strictly_valid(jwt, jwk, unquote(curve))
        end
      end
    end
  end

  test "space delegation tokens are low-S" do
    {:ok, jwk} = JWK.generate(:secp256k1)

    for i <- 1..@samples do
      {:ok, jwt} =
        Token.sign(
          :delegation,
          [
            iss: "did:plc:alice",
            sub: "at://did:plc:space/space/app.bsky.group/test",
            aud: Token.space_host_aud("did:plc:space"),
            jti: "jti-#{i}"
          ],
          jwk
        )

      assert_strictly_valid(jwt, jwk, :secp256k1)
    end
  end

  test "verify/3 still accepts a high-S twin (JOSE does not check S)" do
    # Folding is a signing-side guarantee. This verifier serves the OAuth
    # profile (DPoP proofs, client assertions), where the reference verifier
    # (`jose`) accepts either half too; strictness lives in Crypto.verify/4.
    {:ok, jwk} = JWK.generate(:p256)
    {:ok, jwt} = JWS.sign(jwk, %{"alg" => "ES256"}, %{"sub" => "x"})
    [header, payload, _] = String.split(jwt, ".")
    {_input, <<r::binary-32, s::binary-32>>} = signature(jwt)

    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    high = <<r::binary, n - :binary.decode_unsigned(s)::unsigned-big-integer-size(256)>>
    twin = header <> "." <> payload <> "." <> Base.url_encode64(high, padding: false)

    assert {:ok, %{"sub" => "x"}} = JWS.verify(JWK.to_public(jwk), twin, ["ES256"])
  end
end
