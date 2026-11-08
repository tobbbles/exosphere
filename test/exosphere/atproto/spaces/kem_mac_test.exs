defmodule Exosphere.ATProto.Spaces.KemMacTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Crypto
  alias Exosphere.ATProto.Spaces.{Kem, Mac}

  defp unhex(hex), do: Base.decode16!(hex, case: :lower)

  describe "Kem" do
    test "HKDF-SHA256 matches RFC 5869 test cases 1 and 3" do
      assert Kem.hkdf_sha256(
               :binary.copy(<<0x0B>>, 22),
               unhex("000102030405060708090a0b0c"),
               unhex("f0f1f2f3f4f5f6f7f8f9"),
               42
             ) ==
               unhex(
                 "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
               )

      assert Kem.hkdf_sha256(:binary.copy(<<0x0B>>, 22), "", "", 42) ==
               unhex(
                 "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
               )
    end

    # RFC 9180 A.3.1: DHKEM(P-256, HKDF-SHA256) base mode. The syncer is the
    # encapsulating sender (ephemeral skEm), the author's KEM key the
    # recipient (pkRm) — the proposal's derivation is exactly Encap.
    test "the derivation reproduces the RFC 9180 DHKEM(P-256) test vector" do
      sk_em = unhex("4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb")
      sk_rm = unhex("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2")

      pk_rm =
        unhex(
          "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0"
        )

      expected = unhex("c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8")

      assert {:ok, %{key_share: key_share, shared_secret: ^expected}} =
               Kem.encapsulate(pk_rm, ephemeral_private_key: sk_em)

      assert {:ok, ^expected} = Kem.decapsulate(sk_rm, key_share)
    end

    test "both sides derive the same secret; every encapsulation is fresh" do
      {:ok, author} = Crypto.generate_keypair(:p256)
      {:ok, author_did} = Crypto.to_did_key(author.public_key, :p256)

      assert {:ok, %{key_share: share, shared_secret: secret}} = Kem.encapsulate(author_did)
      assert {:ok, ^secret} = Kem.decapsulate(author.private_key, share)

      assert {:ok, %{key_share: other_share, shared_secret: other}} =
               Kem.encapsulate(author.public_key)

      refute other_share == share
      refute other == secret
    end

    test "only P-256 keys qualify" do
      {:ok, k1} = Crypto.generate_keypair(:secp256k1)
      {:ok, k1_did} = Crypto.to_did_key(k1.public_key, :secp256k1)

      assert {:error, :invalid_kem_key} = Kem.encapsulate(k1_did)
      assert {:error, :invalid_kem_key} = Kem.encapsulate(<<1, 2, 3>>)

      {:ok, author} = Crypto.generate_keypair(:p256)
      assert {:error, :invalid_kem_key} = Kem.decapsulate(author.private_key, k1_did)
    end
  end

  describe "Mac" do
    @secret :binary.copy(<<7>>, 32)
    @space "at://did:plc:authority/space/com.example.group/default"

    test "the commit MAC covers the length-prefixed context and data" do
      commit = %{
        "ver" => 1,
        "space" => @space,
        "repo" => "did:plc:author",
        "rev" => "3kbcq3p7ad2c2",
        "data" => :crypto.hash(:sha256, "state")
      }

      context =
        "atproto-space-repo-v1" <>
          <<byte_size(@space)::16>> <>
          @space <> <<14::16>> <> "did:plc:author" <> <<13::16>> <> "3kbcq3p7ad2c2"

      assert Mac.commit_context(@space, "did:plc:author", "3kbcq3p7ad2c2") == context

      assert Mac.commit_mac(@secret, commit) ==
               :crypto.mac(:hmac, :sha256, @secret, context <> commit["data"])

      refute Mac.commit_mac(@secret, %{commit | "rev" => "3kbcq3p7ad2c3"}) ==
               Mac.commit_mac(@secret, commit)
    end

    test "the record MAC covers the URI and the binary CID" do
      uri = @space <> "/did:plc:author/com.example.post/3kbcq3p7ad2c2"
      cid = <<1, 0x71, 0x12, 0x20>> <> :crypto.hash(:sha256, "rec")
      context = "atproto-space-record-v1" <> <<byte_size(uri)::16>> <> uri

      assert Mac.record_mac(@secret, uri, cid) ==
               :crypto.mac(:hmac, :sha256, @secret, context <> cid)
    end

    test "headers round-trip, and the wrong type, version or shape is BadSpaceMac" do
      want = Mac.want_mac_header(:commit, "did:key:zDnaeX")
      assert want == ~s(type="atproto-space-repo", ver=1, key_share="did:key:zDnaeX")
      assert {:ok, "did:key:zDnaeX"} = Mac.parse_want_mac_header(want, :commit)

      mac = :binary.copy(<<0xAB>>, 32)
      header = Mac.mac_header(:record, mac)
      assert header =~ ~s(type="atproto-space-record", ver=1, mac=:)
      assert {:ok, ^mac} = Mac.parse_mac_header(header, :record)

      assert {:error, {:bad_space_mac, :unsupported_type}} = Mac.parse_mac_header(header, :commit)

      assert {:error, {:bad_space_mac, :unsupported_version}} =
               Mac.parse_mac_header(~s(type="atproto-space-record", ver=2, mac=:AA==:), :record)

      # A Token is not a String: an unquoted type does not match.
      assert {:error, {:bad_space_mac, :unsupported_type}} =
               Mac.parse_mac_header("type=atproto-space-repo, ver=1, mac=:AA==:", :commit)

      assert {:error, {:bad_space_mac, :missing_mac}} =
               Mac.parse_mac_header(~s(type="atproto-space-repo", ver=1), :commit)

      assert {:error, {:bad_space_mac, :missing_header}} = Mac.parse_mac_header(nil, :commit)

      assert {:error, {:bad_space_mac, :malformed_header}} =
               Mac.parse_want_mac_header("type=(", :commit)
    end
  end
end
