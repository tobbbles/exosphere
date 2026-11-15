defmodule Exosphere.ATProto.Crypto.HPKETest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Crypto
  alias Exosphere.ATProto.Crypto.HPKE

  defp unhex(hex), do: Base.decode16!(hex, case: :mixed)

  describe "HKDF-SHA256" do
    # RFC 5869 A.1 and A.3.
    test "extract and expand reproduce RFC 5869 test cases 1 and 3" do
      ikm = :binary.copy(<<0x0B>>, 22)

      prk = Crypto.hkdf_extract_sha256(unhex("000102030405060708090a0b0c"), ikm)
      assert prk == unhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")

      assert Crypto.hkdf_expand_sha256(prk, unhex("f0f1f2f3f4f5f6f7f8f9"), 42) ==
               unhex(
                 "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
               )

      prk = Crypto.hkdf_extract_sha256("", ikm)
      assert prk == unhex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
      # An empty salt is HashLen zero bytes.
      assert prk == Crypto.hkdf_extract_sha256(<<0::256>>, ikm)

      assert Crypto.hkdf_expand_sha256(prk, "", 42) ==
               unhex(
                 "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
               )
    end
  end

  # The CFRG HPKE test vector for exactly this suite: mode 0 (base),
  # kem_id 16 (DHKEM(P-256, HKDF-SHA256)), kdf_id 1 (HKDF-SHA256),
  # aead_id 65535 (Export-only), from test-vectors.json in
  # github.com/cfrg/draft-irtf-cfrg-hpke.
  @vector %{
    info: "4f6465206f6e2061204772656369616e2055726e",
    sk_em: "2f18b059576a0ec5a17121c0fe7ec8f00ea86f7b046fa3889ac8f21f89dbd484",
    pk_em:
      "04d804370b7e24b94749eb1dc8df6d4d4a5d75f9effad01739ebcad5c54a40d57aaa8b4190fc124dbde2e4f1e1d1b012a3bc4038157dc29b55533a932306d8d38d",
    sk_rm: "62c3868357a464f8461d03aa0182c7cebcde841036aea7230ddc7339f1088346",
    pk_rm:
      "046c6bb9e1976402c692fef72552f4aaeedd83a5e5079de3d7ae732da0f397b15921fb9c52c9866affc8e29c0271a35937023a9245982ec18bab1eb157cf16fc33",
    enc:
      "04d804370b7e24b94749eb1dc8df6d4d4a5d75f9effad01739ebcad5c54a40d57aaa8b4190fc124dbde2e4f1e1d1b012a3bc4038157dc29b55533a932306d8d38d",
    shared_secret: "7e5b6dd51bca56d4f30c95ff658af26c08eb0c073aa7180686cc4dbeabcb34f1",
    key_schedule_context:
      "00fbfdc9526168162fadfd17fe227356e9ffe3afbfc682ca8f7e2c2fa25fbc0879667157ef6a763236715d0cdfae0492d26fb4f02e2c8397d5fc765a529a167374",
    secret: "f0e51682347bc2d57dbc613ee6b2be6b0eeef155cb1d3e6ac09035981ac5d7ec",
    exporter_secret: "7c0347d69a219f33301056411e78672ae2d78698d10ee067f883ba266ef586a1",
    exports: [
      {"", 32, "8cf837d5bf1994f0fac3ee1faa671d07e9a38b7f6153bdbb8a66b90159ef7d13"},
      {"00", 32, "3c7708f8ae1f510f4439fa514deb1c7ece7a29085a2e8270a84b6ad6481cc0b4"},
      {"54657374436f6e74657874", 32,
       "f53fb127f67dabf35b14fae14b53e6ce5c49e572f95eb4ef7a3b3cb9cd85f12b"}
    ]
  }

  describe "the CFRG export-only DHKEM(P-256, HKDF-SHA256) vector" do
    test "Encap and Decap give the vector's enc and shared_secret" do
      v = @vector
      enc = unhex(v.enc)
      shared = unhex(v.shared_secret)

      assert {:ok, ^shared, ^enc} =
               HPKE.encap(unhex(v.pk_rm), ephemeral_private_key: unhex(v.sk_em))

      assert unhex(v.pk_em) == enc
      assert {:ok, ^shared} = HPKE.decap(enc, unhex(v.sk_rm))
    end

    test "the key schedule gives the vector's context, secret and exporter_secret" do
      v = @vector

      assert HPKE.key_schedule_base(unhex(v.shared_secret), unhex(v.info)) == %{
               key_schedule_context: unhex(v.key_schedule_context),
               secret: unhex(v.secret),
               exporter_secret: unhex(v.exporter_secret)
             }
    end

    test "every export matches, from both the sender and the receiver" do
      v = @vector

      for {context, length, expected} <- v.exports do
        context = unhex(context)
        expected = unhex(expected)
        enc = unhex(v.enc)

        assert HPKE.export(unhex(v.exporter_secret), context, length) == expected

        assert {:ok, {^enc, ^expected}} =
                 HPKE.send_export_base(unhex(v.pk_rm), unhex(v.info), context, length,
                   ephemeral_private_key: unhex(v.sk_em)
                 )

        assert {:ok, ^expected} =
                 HPKE.receive_export_base(enc, unhex(v.sk_rm), unhex(v.info), context, length)
      end
    end

    test "a compressed recipient key or enc gives the same result" do
      v = @vector
      {:ok, pk_rm} = Crypto.compress_public_key(unhex(v.pk_rm), :p256)
      {:ok, enc_c} = Crypto.compress_public_key(unhex(v.enc), :p256)
      enc = unhex(v.enc)
      shared = unhex(v.shared_secret)

      assert {:ok, ^shared, ^enc} = HPKE.encap(pk_rm, ephemeral_private_key: unhex(v.sk_em))
      assert {:ok, ^shared} = HPKE.decap(enc_c, unhex(v.sk_rm))
    end
  end

  # atproto's vector (packages/space/tests/kem.test.ts @ d4def6e): the CFRG
  # keys above with the atproto info, computed with Go's crypto/hpke.
  test "atproto's info=\"atproto-mac\" vector, computed with Go's crypto/hpke" do
    expected = unhex("2060e0558d1b34c10086bc137f849bb79ba59fcdc30544418e35c9cd301f0d0d")

    assert {:ok, ^expected} =
             HPKE.receive_export_base(
               unhex(@vector.enc),
               unhex(@vector.sk_rm),
               "atproto-mac",
               "",
               32
             )
  end

  test "a random sender and receiver agree, with a fresh enc each time" do
    {:ok, recipient} = Crypto.generate_keypair(:p256)

    assert {:ok, {enc, secret}} = HPKE.send_export_base(recipient.public_key, "i", "c", 32)
    assert byte_size(enc) == 65
    assert {:ok, ^secret} = HPKE.receive_export_base(enc, recipient.private_key, "i", "c", 32)

    assert {:ok, {other_enc, other}} = HPKE.send_export_base(recipient.public_key, "i", "c", 32)
    refute other_enc == enc
    refute other == secret

    # Another info or exporter context exports another secret.
    refute {:ok, secret} == HPKE.receive_export_base(enc, recipient.private_key, "j", "c", 32)
    refute {:ok, secret} == HPKE.receive_export_base(enc, recipient.private_key, "i", "d", 32)
  end

  test "refuses keys that are not P-256 points or scalars, and bad lengths" do
    v = @vector
    <<0x04, x::binary-32, y::binary-32>> = unhex(v.pk_rm)
    off_curve = <<0x04, x::binary, :crypto.exor(y, <<1::256>>)::binary>>

    assert {:error, :invalid_public_key} = HPKE.encap(off_curve)
    assert {:error, :invalid_public_key} = HPKE.decap(off_curve, unhex(v.sk_rm))
    assert {:error, :invalid_public_key} = HPKE.encap(<<1, 2, 3>>)

    # A secp256k1 point is (overwhelmingly likely) not on P-256. Its compressed
    # form carries no curve, so only the full point can be told apart.
    {:ok, k1} = Crypto.generate_keypair(:secp256k1)
    {:ok, k1_point} = Crypto.decompress(k1.public_key, :secp256k1)
    assert {:error, :invalid_public_key} = HPKE.encap(k1_point)

    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    assert {:error, :invalid_private_key} = HPKE.decap(unhex(v.enc), <<0::256>>)
    assert {:error, :invalid_private_key} = HPKE.decap(unhex(v.enc), <<order::256>>)

    assert {:error, :invalid_private_key} =
             HPKE.encap(unhex(v.pk_rm), ephemeral_private_key: <<0::256>>)

    assert {:error, :invalid_length} = HPKE.send_export_base(unhex(v.pk_rm), "", "", 0)

    assert {:error, :invalid_length} =
             HPKE.receive_export_base(unhex(v.enc), unhex(v.sk_rm), "", "", 255 * 32 + 1)
  end
end
