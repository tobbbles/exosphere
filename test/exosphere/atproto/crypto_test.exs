defmodule Exosphere.ATProto.CryptoTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Base58
  alias Exosphere.ATProto.Crypto

  describe "generate_keypair/1" do
    test "secp256k1 produces a 32-byte private key and 33-byte compressed public key" do
      assert {:ok, %{private_key: priv, public_key: pub}} = Crypto.generate_keypair(:secp256k1)
      assert byte_size(priv) == 32
      assert byte_size(pub) == 33
      assert <<prefix, _::binary-32>> = pub
      assert prefix in [0x02, 0x03]
    end

    test "p256 produces a 33-byte compressed public key" do
      assert {:ok, %{private_key: priv, public_key: pub}} = Crypto.generate_keypair(:p256)
      # P-256 private keys are typically 32 bytes but Erlang may return shorter
      # representations on rare occasions; assert the shape we actually rely on.
      assert is_binary(priv)
      assert byte_size(pub) == 33
      assert <<prefix, _::binary-32>> = pub
      assert prefix in [0x02, 0x03]
    end
  end

  describe "sign/3 + verify/4 round-trip" do
    test "secp256k1 sign and verify succeed for the original message" do
      {:ok, %{private_key: priv, public_key: pub}} = Crypto.generate_keypair(:secp256k1)
      data = "hello, atproto"

      assert {:ok, sig} = Crypto.sign(data, priv, :secp256k1)
      assert byte_size(sig) == 64
      assert :ok = Crypto.verify(data, sig, pub, :secp256k1)
    end

    test "secp256k1 verify rejects a tampered message" do
      {:ok, %{private_key: priv, public_key: pub}} = Crypto.generate_keypair(:secp256k1)
      {:ok, sig} = Crypto.sign("original", priv, :secp256k1)

      assert {:error, :invalid_signature} = Crypto.verify("tampered", sig, pub, :secp256k1)
    end

    test "p256 sign and verify succeed for the original message" do
      {:ok, %{private_key: priv, public_key: pub}} = Crypto.generate_keypair(:p256)
      data = "hello, atproto"

      assert {:ok, sig} = Crypto.sign(data, priv, :p256)
      assert byte_size(sig) == 64
      assert :ok = Crypto.verify(data, sig, pub, :p256)
    end

    test "p256 verify rejects a tampered message" do
      {:ok, %{private_key: priv, public_key: pub}} = Crypto.generate_keypair(:p256)
      {:ok, sig} = Crypto.sign("original", priv, :p256)

      assert {:error, :invalid_signature} = Crypto.verify("tampered", sig, pub, :p256)
    end

    test "verify rejects signatures of the wrong length" do
      {:ok, %{public_key: pub}} = Crypto.generate_keypair(:secp256k1)
      assert {:error, :invalid_signature} = Crypto.verify("data", <<0::512>>, pub, :secp256k1)
      # too-short signature falls through to the catch-all clause
      assert {:error, :invalid_signature} = Crypto.verify("data", <<0::8>>, pub, :secp256k1)
    end
  end

  describe "low-S signature property" do
    # secp256k1 group order / 2
    @secp256k1_half_order 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    # P-256 group order / 2
    @p256_half_order 0x7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8

    test "secp256k1 signatures are always low-S across many random messages" do
      {:ok, %{private_key: priv}} = Crypto.generate_keypair(:secp256k1)

      Enum.each(1..20, fn i ->
        {:ok, <<_r::binary-32, s::binary-32>>} =
          Crypto.sign("msg-#{i}-#{:rand.uniform(1_000_000)}", priv, :secp256k1)

        assert :binary.decode_unsigned(s) <= @secp256k1_half_order
      end)
    end

    test "p256 signatures are always low-S across many random messages" do
      {:ok, %{private_key: priv}} = Crypto.generate_keypair(:p256)

      Enum.each(1..20, fn i ->
        {:ok, <<_r::binary-32, s::binary-32>>} =
          Crypto.sign("msg-#{i}-#{:rand.uniform(1_000_000)}", priv, :p256)

        assert :binary.decode_unsigned(s) <= @p256_half_order
      end)
    end
  end

  describe "to_did_key/2 + from_did_key/1 round-trip" do
    test "secp256k1 round-trip preserves the compressed public key" do
      {:ok, %{public_key: pub}} = Crypto.generate_keypair(:secp256k1)

      assert {:ok, did_key} = Crypto.to_did_key(pub, :secp256k1)
      assert String.starts_with?(did_key, "did:key:z")
      assert {:ok, ^pub, :secp256k1} = Crypto.from_did_key(did_key)
    end

    test "p256 round-trip preserves the compressed public key" do
      {:ok, %{public_key: pub}} = Crypto.generate_keypair(:p256)

      assert {:ok, did_key} = Crypto.to_did_key(pub, :p256)
      assert String.starts_with?(did_key, "did:key:z")
      assert {:ok, ^pub, :p256} = Crypto.from_did_key(did_key)
    end

    test "to_did_key/2 accepts an uncompressed key" do
      # Build an uncompressed key by decompressing one we generate.
      {:ok, %{public_key: <<_prefix, x::binary-32>> = compressed}} =
        Crypto.generate_keypair(:secp256k1)

      {:ok, uncompressed} = ExSecp256k1.public_key_decompress(compressed)
      assert <<0x04, ^x::binary, _y::binary-32>> = uncompressed

      assert {:ok, did_key} = Crypto.to_did_key(uncompressed, :secp256k1)
      assert {:ok, ^compressed, :secp256k1} = Crypto.from_did_key(did_key)
    end

    test "to_did_key/2 returns :invalid_public_key for malformed input" do
      assert {:error, :invalid_public_key} = Crypto.to_did_key(<<1, 2, 3>>, :secp256k1)
      assert {:error, :invalid_public_key} = Crypto.to_did_key(<<1, 2, 3>>, :p256)
      # 33 bytes but with an invalid prefix byte
      assert {:error, :invalid_public_key} =
               Crypto.to_did_key(<<0x09, 0::unsigned-integer-size(256)>>, :secp256k1)
    end

    test "from_did_key/1 distinguishes error reasons" do
      assert {:error, :invalid_did_key_format} = Crypto.from_did_key("not-a-did")
      assert {:error, :invalid_did_key_format} = Crypto.from_did_key("did:plc:abc")

      # did:key: but unsupported multibase prefix (uppercase Z is not base58btc)
      assert {:error, :unsupported_multibase} = Crypto.from_did_key("did:key:Zabc")

      # did:key:z + garbage that base58-decodes but isn't a known multicodec
      # 0x99 isn't a multicodec we recognise
      bytes = <<0x99, 0::unsigned-integer-size(264)>>
      did = "did:key:z" <> Base58.encode(bytes)
      assert {:error, :unsupported_key_type} = Crypto.from_did_key(did)
    end
  end

  describe "to_multibase/2" do
    test "returns the multibase portion of did:key for both curves" do
      {:ok, %{public_key: secp_pub}} = Crypto.generate_keypair(:secp256k1)
      {:ok, %{public_key: p256_pub}} = Crypto.generate_keypair(:p256)

      assert {:ok, secp_mb} = Crypto.to_multibase(secp_pub, :secp256k1)
      assert {:ok, "did:key:" <> ^secp_mb} = Crypto.to_did_key(secp_pub, :secp256k1)

      assert {:ok, p256_mb} = Crypto.to_multibase(p256_pub, :p256)
      assert {:ok, "did:key:" <> ^p256_mb} = Crypto.to_did_key(p256_pub, :p256)
    end

    test "propagates :invalid_public_key for malformed input" do
      assert {:error, :invalid_public_key} = Crypto.to_multibase(<<1, 2, 3>>, :secp256k1)
    end
  end
end
