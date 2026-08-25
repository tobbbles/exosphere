defmodule Exosphere.Interop.CryptoTest do
  @moduledoc """
  Conformance against the atproto interop crypto signature fixtures. Each fixture
  carries a message, a public key (as did:key + multibase), and a signature that
  is either valid or invalid in atproto. Notably this exercises rejection of
  high-S (malleable) and DER-encoded signatures.
  """
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Crypto
  alias Exosphere.Test.Interop

  @fixtures Interop.json("crypto/signature-fixtures.json")

  defp curve_for("ES256"), do: :p256
  defp curve_for("ES256K"), do: :secp256k1

  defp b64(str), do: Base.decode64!(str, padding: false)

  test "did:key round-trips byte-for-byte against every fixture" do
    for f <- @fixtures do
      did = f["publicKeyDid"]

      assert {:ok, pub, curve} = Crypto.from_did_key(did),
             "could not parse did:key for: #{f["comment"]}"

      assert curve == curve_for(f["algorithm"]), "curve mismatch for: #{f["comment"]}"

      # Re-encoding the recovered key must reproduce the exact network did:key,
      # proving the multicodec prefixes (incl. secp256k1 varint 0xe7 0x01) match.
      assert {:ok, ^did} = Crypto.to_did_key(pub, curve), "did:key re-encode mismatch: #{did}"
    end
  end

  test "verify/4 agrees with every signature fixture (incl. high-S and DER rejection)" do
    results =
      for f <- @fixtures do
        {:ok, pub, curve} = Crypto.from_did_key(f["publicKeyDid"])
        message = b64(f["messageBase64"])
        signature = b64(f["signatureBase64"])

        actual = Crypto.verify(message, signature, pub, curve) == :ok
        expected = f["validSignature"]

        {f["comment"], expected, actual}
      end

    mismatches = Enum.filter(results, fn {_c, expected, actual} -> expected != actual end)

    assert mismatches == [],
           "signature verification disagreements:\n" <>
             Enum.map_join(mismatches, "\n", fn {c, e, a} ->
               "  - expected valid=#{e}, got valid=#{a}: #{c}"
             end)
  end
end
