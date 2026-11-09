defmodule Exosphere.ATProto.Spaces.HttpSignatureTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Crypto
  alias Exosphere.ATProto.Spaces.HttpSignature
  alias Exosphere.ATProto.Spaces.StructuredFields, as: SF

  @cred "eyJhbGciOiJFUzI1NksifQ.e30.c2ln"
  @audience "did:plc:repoowner"

  describe "StructuredFields" do
    test "parses the space headers' dictionaries, keeping item types apart" do
      assert {:ok, dict} =
               SF.parse_dictionary(
                 ~s(type="atproto-space-repo", ver=1, key_share="did:key:zDnae")
               )

      assert SF.get_bare(dict, "type") == "atproto-space-repo"
      assert SF.get_bare(dict, "ver") == 1
      assert SF.get_bare(dict, "key_share") == "did:key:zDnae"

      # An unquoted value is a Token, not a String.
      assert {:ok, dict} = SF.parse_dictionary("type=atproto-space-repo")
      assert SF.get_bare(dict, "type") == {:token, "atproto-space-repo"}

      assert {:ok, dict} = SF.parse_dictionary("mac=:AAECAw==:, flag, n=-1.5")
      assert SF.get_bare(dict, "mac") == {:bytes, <<0, 1, 2, 3>>}
      assert SF.get_bare(dict, "flag") == true
      assert SF.get_bare(dict, "n") == -1.5
    end

    test "parses inner lists with parameters and re-serializes them canonically" do
      input =
        ~s|sig1=("authorization"  "atproto-space-audience");tag="atproto-space-credential";created=1|

      assert {:ok, [{"sig1", {:inner_list, items, params} = member}]} =
               SF.parse_dictionary(input)

      assert items == [{"authorization", []}, {"atproto-space-audience", []}]
      assert params == [{"tag", "atproto-space-credential"}, {"created", 1}]

      assert SF.serialize_member(member) ==
               ~s|("authorization" "atproto-space-audience");tag="atproto-space-credential";created=1|
    end

    test "round-trips a dictionary" do
      dict = [
        {"type", {"atproto-space-repo", []}},
        {"ver", {1, []}},
        {"mac", {{:bytes, :crypto.strong_rand_bytes(32)}, []}}
      ]

      assert {:ok, ^dict} = SF.parse_dictionary(SF.serialize_dictionary(dict))
    end

    test "fails the whole field on malformed input" do
      for bad <- [
            "a=1,",
            "A=1",
            "a=\"unterminated",
            "a=(1 2",
            "a=:not base64!:",
            "a=1 b=2",
            "a=?2",
            "a=1234567890123456"
          ] do
        assert {:error, :invalid_structured_field} = SF.parse_dictionary(bad), bad
      end
    end

    test "string escapes" do
      assert {:ok, [{"a", {~s(say "hi" \\ bye), []}}]} =
               SF.parse_dictionary(~s(a="say \\"hi\\" \\\\ bye"))

      assert SF.serialize_dictionary([{"a", {~s(q"b\\), []}}]) == ~s(a="q\\"b\\\\")
    end
  end

  describe "HttpSignature" do
    setup do
      {:ok, key} = HttpSignature.generate_key()
      %{key: key}
    end

    test "headers/3 produces exactly the proposal's presentation", %{key: key} do
      assert {:ok, headers} = HttpSignature.headers(key, @cred, @audience)

      assert Enum.map(headers, &elem(&1, 0)) ==
               ["authorization", "atproto-space-audience", "signature-input", "signature"]

      assert {"authorization", "Atproto-Space-Credential " <> @cred} = hd(headers)

      assert {"signature-input",
              ~s|atproto-space-credential=("authorization" "atproto-space-audience");tag="atproto-space-credential"|} =
               List.keyfind(headers, "signature-input", 0)

      {"signature", sig_header} = List.keyfind(headers, "signature", 0)

      assert {:ok, [{"atproto-space-credential", {{:bytes, sig}, []}}]} =
               SF.parse_dictionary(sig_header)

      assert byte_size(sig) == 64

      assert :ok = HttpSignature.verify(headers, key.did_key)
    end

    test "the signature base is the RFC 9421 lines over the two fields" do
      assert HttpSignature.signature_base(
               ["Atproto-Space-Credential x ", " did:plc:a"],
               "(params)"
             ) ==
               ~s|"authorization": Atproto-Space-Credential x\n"atproto-space-audience": did:plc:a\n"@signature-params": (params)|
    end

    test "verify accepts a high-S signature, as the proposal requires", %{key: key} do
      {:ok, headers} = HttpSignature.headers(key, @cred, @audience)
      {"signature", sig_header} = List.keyfind(headers, "signature", 0)

      {:ok, [{_, {{:bytes, <<r::binary-32, s::binary-32>>}, []}}]} =
        SF.parse_dictionary(sig_header)

      n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
      high_s = <<n - :binary.decode_unsigned(s)::unsigned-big-256>>
      high = SF.serialize_dictionary([{"atproto-space-credential", {{:bytes, r <> high_s}, []}}])
      headers = List.keystore(headers, "signature", 0, {"signature", high})

      assert :ok = HttpSignature.verify(headers, key.did_key)
    end

    test "verify enforces the covered components, tag, alg and keyid", %{key: key} do
      {:ok, headers} = HttpSignature.headers(key, @cred, @audience)

      swap = fn input ->
        List.keystore(headers, "signature-input", 0, {"signature-input", input})
      end

      assert {:error, :wrong_covered_components} =
               HttpSignature.verify(
                 swap.(
                   ~s|atproto-space-credential=("atproto-space-audience" "authorization");tag="atproto-space-credential"|
                 ),
                 key.did_key
               )

      assert {:error, :wrong_covered_components} =
               HttpSignature.verify(
                 swap.(
                   ~s|atproto-space-credential=("authorization" "atproto-space-audience" "@method");tag="atproto-space-credential"|
                 ),
                 key.did_key
               )

      assert {:error, :wrong_signature_tag} =
               HttpSignature.verify(
                 swap.(
                   ~s|atproto-space-credential=("authorization" "atproto-space-audience");tag="other"|
                 ),
                 key.did_key
               )

      assert {:error, :wrong_signature_alg} =
               HttpSignature.verify(
                 swap.(
                   ~s|atproto-space-credential=("authorization" "atproto-space-audience");tag="atproto-space-credential";alg="ed25519"|
                 ),
                 key.did_key
               )

      assert {:error, :signature_keyid_mismatch} =
               HttpSignature.verify(
                 swap.(
                   ~s|atproto-space-credential=("authorization" "atproto-space-audience");tag="atproto-space-credential";keyid="did:key:zOther"|
                 ),
                 key.did_key
               )
    end

    test "a keyid naming the bound key is allowed, and is covered by the signature", %{key: key} do
      authorization = "Atproto-Space-Credential " <> @cred

      input =
        {:inner_list, [{"authorization", []}, {"atproto-space-audience", []}],
         [
           {"tag", "atproto-space-credential"},
           {"keyid", key.did_key},
           {"alg", "ecdsa-p256-sha256"}
         ]}

      base = HttpSignature.signature_base([authorization, @audience], SF.serialize_member(input))
      {:ok, sig} = Crypto.sign(base, key.private_key, :p256)

      headers = [
        {"Authorization", authorization},
        {"Atproto-Space-Audience", @audience},
        {"Signature-Input", SF.serialize_dictionary([{"atproto-space-credential", input}])},
        {"Signature",
         SF.serialize_dictionary([{"atproto-space-credential", {{:bytes, sig}, []}}])}
      ]

      assert :ok = HttpSignature.verify(headers, key.did_key)
    end

    test "verify refuses tampered fields, other keys, and non-P-256 key ids", %{key: key} do
      {:ok, headers} = HttpSignature.headers(key, @cred, @audience)

      tampered =
        List.keystore(
          headers,
          "atproto-space-audience",
          0,
          {"atproto-space-audience", "did:plc:x"}
        )

      assert {:error, :invalid_http_signature} = HttpSignature.verify(tampered, key.did_key)

      {:ok, other} = HttpSignature.generate_key()
      assert {:error, :invalid_http_signature} = HttpSignature.verify(headers, other.did_key)

      {:ok, %{public_key: k1}} = Crypto.generate_keypair(:secp256k1)
      {:ok, k1_did} = Crypto.to_did_key(k1, :secp256k1)
      assert {:error, :invalid_signature_key} = HttpSignature.verify(headers, k1_did)

      assert {:error, {:missing_header, "atproto-space-audience"}} =
               HttpSignature.verify(
                 List.keydelete(headers, "atproto-space-audience", 0),
                 key.did_key
               )

      assert {:error, :malformed_http_signature} =
               HttpSignature.verify(
                 List.keystore(
                   headers,
                   "signature",
                   0,
                   {"signature", "atproto-space-credential=:AAAA:"}
                 ),
                 key.did_key
               )
    end

    test "key_from_private/1 rebuilds the same did:key", %{key: key} do
      assert {:ok, ^key} = HttpSignature.key_from_private(key.private_key)
      assert {:error, :invalid_private_key} = HttpSignature.key_from_private(<<1, 2>>)
    end
  end
end
