defmodule Exosphere.ATProto.Spaces.HttpSignatureTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Crypto
  alias Exosphere.ATProto.Spaces.HttpSignature
  alias Exosphere.ATProto.Spaces.StructuredFields, as: SF

  @cred "eyJhbGciOiJFUzI1NksifQ.e30.c2ln"
  @authorization "Atproto-Space-Credential " <> @cred
  @audience "did:plc:repoowner"
  @components [{"authorization", []}, {"atproto-space-audience", []}]
  @input ~s|("authorization" "atproto-space-audience");tag="atproto-space-credential"|

  setup do
    {:ok, key} = HttpSignature.generate_key()
    {:ok, headers} = HttpSignature.headers(key, @cred, @audience)
    %{key: key, headers: headers}
  end

  defp put(headers, name, value), do: List.keystore(headers, name, 0, {name, value})
  defp get(headers, name), do: headers |> List.keyfind(name, 0) |> elem(1)

  # Headers carrying a signature made over `input` (the serialized signature
  # parameters), under `label`, standing in for another signer.
  defp signed(key, input, label \\ "sig") do
    base =
      ~s|"authorization": #{@authorization}\n"atproto-space-audience": #{@audience}\n"@signature-params": #{input}|

    {:ok, sig} = Crypto.sign(base, key.private_key, :p256)

    [
      {"authorization", @authorization},
      {"atproto-space-audience", @audience},
      {"signature-input", label <> "=" <> input},
      {"signature", label <> "=:" <> Base.encode64(sig) <> ":"}
    ]
  end

  describe "signing" do
    test "headers/3 presents the credential under the sig label", %{key: key, headers: headers} do
      assert Enum.map(headers, &elem(&1, 0)) ==
               ["authorization", "atproto-space-audience", "signature-input", "signature"]

      assert get(headers, "authorization") == @authorization
      assert get(headers, "atproto-space-audience") == @audience
      assert get(headers, "signature-input") == "sig=" <> @input

      assert {:ok, [{"sig", {{:bytes, sig}, []}}]} =
               SF.parse_dictionary(get(headers, "signature"))

      # A compact P-256 signature over the RFC 9421 signature base.
      assert byte_size(sig) == 64

      base =
        ~s|"authorization": #{@authorization}\n"atproto-space-audience": #{@audience}\n"@signature-params": #{@input}|

      {:ok, public} = Crypto.decompress(key.public_key, :p256)
      <<r::binary-32, s::binary-32>> = sig
      der = {:"ECDSA-Sig-Value", :binary.decode_unsigned(r), :binary.decode_unsigned(s)}

      assert :public_key.verify(base, :sha256, :public_key.der_encode(:"ECDSA-Sig-Value", der), {
               {:ECPoint, public},
               {:namedCurve, :secp256r1}
             })

      assert :ok = HttpSignature.verify(headers, key.did_key)
    end

    test "signature_base/3 is the RFC 9421 lines, values trimmed" do
      assert HttpSignature.signature_base(
               @components,
               ["Atproto-Space-Credential x ", " did:plc:a"],
               "(params)"
             ) ==
               ~s|"authorization": Atproto-Space-Credential x\n"atproto-space-audience": did:plc:a\n"@signature-params": (params)|

      assert HttpSignature.signature_base(
               [{"atproto-space-commit", [{"sf", true}]}],
               ["ver=1"],
               "(p)"
             ) == ~s|"atproto-space-commit";sf: ver=1\n"@signature-params": (p)|
    end

    test "format_components/1 includes component parameters" do
      assert HttpSignature.format_components(@components) ==
               ~s|("authorization" "atproto-space-audience")|

      assert HttpSignature.format_components([{"atproto-space-record", [{"sf", true}]}]) ==
               ~s|("atproto-space-record";sf)|
    end
  end

  describe "verify/2" do
    test "accepts a high-S signature, as the proposal requires", %{key: key, headers: headers} do
      {:ok, [{_, {{:bytes, <<r::binary-32, s::binary-32>>}, []}}]} =
        SF.parse_dictionary(get(headers, "signature"))

      n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
      high_s = <<n - :binary.decode_unsigned(s)::unsigned-big-256>>
      high = SF.serialize_dictionary([{"sig", {{:bytes, r <> high_s}, []}}])

      assert :ok = HttpSignature.verify(put(headers, "signature", high), key.did_key)
    end

    test "finds the signature by its tag, under any label, with optional parameters", %{
      key: key
    } do
      input =
        ~s|("authorization" "atproto-space-audience");alg="ecdsa-p256-sha256";created=1618884473;keyid="#{key.did_key}";tag="atproto-space-credential"|

      base =
        ~s|"authorization": #{@authorization}\n"atproto-space-audience": #{@audience}\n"@signature-params": #{input}|

      {:ok, sig} = Crypto.sign(base, key.private_key, :p256)

      headers = [
        {"Authorization", @authorization},
        {"Atproto-Space-Audience", @audience},
        {"Signature-Input", ~s|other=("authorization");keyid="other", custom=#{input}|},
        # Unpadded base64 parses too.
        {"Signature", "other=:YWJj:, custom=:" <> Base.encode64(sig, padding: false) <> ":"}
      ]

      assert :ok = HttpSignature.verify(headers, key.did_key)

      # The label the reference used before the November 12 alpha is just a label.
      assert :ok =
               HttpSignature.verify(signed(key, @input, "atproto-space-credential"), key.did_key)
    end

    test "combines repeated signature fields, as in a Req-style map", %{key: key} do
      other = signed(key, ~s|("authorization");tag="other"|, "other")
      mine = signed(key, @input)

      headers = %{
        "authorization" => [@authorization],
        "atproto-space-audience" => [@audience],
        "signature-input" => [get(other, "signature-input"), get(mine, "signature-input")],
        "signature" => [get(other, "signature"), get(mine, "signature")]
      }

      assert :ok = HttpSignature.verify(headers, key.did_key)
    end

    test "requires a signature with the credential tag", %{key: key, headers: headers} do
      for tag <- ["", ~s(;tag="other"), ";tag=atproto-space-credential"] do
        input =
          String.replace(
            get(headers, "signature-input"),
            ~s(;tag="atproto-space-credential"),
            tag
          )

        assert {:error, :missing_http_signature} =
                 HttpSignature.verify(put(headers, "signature-input", input), key.did_key),
               tag
      end

      assert {:error, :missing_http_signature} =
               HttpSignature.verify(List.keydelete(headers, "signature", 0), key.did_key)

      assert {:error, :missing_http_signature} =
               HttpSignature.verify(List.keydelete(headers, "signature-input", 0), key.did_key)

      # The signature must be under the tagged member's label.
      relabeled =
        put(headers, "signature", String.replace_prefix(get(headers, "signature"), "sig=", "x="))

      assert {:error, :missing_http_signature} = HttpSignature.verify(relabeled, key.did_key)
    end

    test "rejects more than one signature with the tag", %{key: key, headers: headers} do
      doubled =
        headers
        |> put("signature-input", get(headers, "signature-input") <> ", again=" <> @input)
        |> put(
          "signature",
          get(headers, "signature") <>
            ", again=" <> String.replace_prefix(get(headers, "signature"), "sig=", "")
        )

      assert {:error, :multiple_http_signatures} = HttpSignature.verify(doubled, key.did_key)
    end

    test "requires exactly the two components, in order", %{key: key} do
      for components <- [
            ~s|("atproto-space-audience" "authorization")|,
            ~s|("authorization")|,
            ~s|("authorization" "atproto-space-audience" "@method")|,
            ~s|("authorization";sf "atproto-space-audience")|
          ] do
        input = components <> ~s|;tag="atproto-space-credential"|

        assert {:error, :wrong_covered_components} =
                 HttpSignature.verify(signed(key, input), key.did_key),
               components
      end
    end

    test "checks an optional alg and keyid, and ignores other parameters", %{key: key} do
      assert {:error, :wrong_signature_alg} =
               HttpSignature.verify(
                 signed(key, @input <> ~s|;alg="ecdsa-p384-sha384"|),
                 key.did_key
               )

      assert {:error, :signature_keyid_mismatch} =
               HttpSignature.verify(
                 signed(key, @input <> ~s|;keyid="did:key:zOther"|),
                 key.did_key
               )

      assert :ok =
               HttpSignature.verify(
                 signed(
                   key,
                   @input <>
                     ~s|;keyid="#{key.did_key}";alg="ecdsa-p256-sha256";created=1;nonce="x"|
                 ),
                 key.did_key
               )
    end

    test "covers the parameters it carries", %{key: key, headers: headers} do
      changed =
        put(
          headers,
          "signature-input",
          get(headers, "signature-input") <> ~s|;alg="ecdsa-p256-sha256"|
        )

      assert {:error, :invalid_http_signature} = HttpSignature.verify(changed, key.did_key)
    end

    test "refuses tampered fields, other keys, and non-P-256 key ids", %{
      key: key,
      headers: headers
    } do
      for name <- ["authorization", "atproto-space-audience"] do
        tampered = put(headers, name, get(headers, name) <> "-changed")

        assert {:error, :invalid_http_signature} = HttpSignature.verify(tampered, key.did_key),
               name

        assert {:error, {:missing_header, ^name}} =
                 HttpSignature.verify(List.keydelete(headers, name, 0), key.did_key)

        assert {:error, {:missing_header, ^name}} =
                 HttpSignature.verify(put(headers, name, ""), key.did_key)
      end

      {:ok, other} = HttpSignature.generate_key()
      assert {:error, :invalid_http_signature} = HttpSignature.verify(headers, other.did_key)

      {:ok, %{public_key: k1}} = Crypto.generate_keypair(:secp256k1)
      {:ok, k1_did} = Crypto.to_did_key(k1, :secp256k1)
      assert {:error, :invalid_signature_key} = HttpSignature.verify(headers, k1_did)
    end

    test "refuses signatures that are not 64-byte Byte Sequences", %{key: key, headers: headers} do
      for {signature, reason} <- [
            {"not-a-byte-sequence", :missing_http_signature},
            {":YWJj:", :invalid_http_signature},
            {":!!!:", :malformed_http_signature},
            {"(:YWJj:)", :missing_http_signature}
          ] do
        assert {:error, ^reason} =
                 HttpSignature.verify(put(headers, "signature", "sig=" <> signature), key.did_key),
               signature
      end

      # A parameterized signature member is malformed.
      with_param = get(headers, "signature") <> ";x=1"

      assert {:error, :missing_http_signature} =
               HttpSignature.verify(put(headers, "signature", with_param), key.did_key)

      assert {:error, :malformed_http_signature} =
               HttpSignature.verify(put(headers, "signature-input", "sig=("), key.did_key)

      # A DER-encoded signature is not the compact encoding.
      {:ok, [{_, {{:bytes, <<r::binary-32, s::binary-32>>}, []}}]} =
        SF.parse_dictionary(get(headers, "signature"))

      der =
        :public_key.der_encode(
          :"ECDSA-Sig-Value",
          {:"ECDSA-Sig-Value", :binary.decode_unsigned(r), :binary.decode_unsigned(s)}
        )

      der_header = SF.serialize_dictionary([{"sig", {{:bytes, der}, []}}])

      assert {:error, :invalid_http_signature} =
               HttpSignature.verify(put(headers, "signature", der_header), key.did_key)
    end
  end

  describe "find_signature/3 and members_with_tag/2" do
    test "return the label, canonical parameters and bytes" do
      input = ~s|a=("x");tag="t";created=1,  b=("y");tag="u"|

      assert {:ok, %{label: "a", signature_params: ~s|("x");tag="t";created=1|, signature: "abc"}} =
               HttpSignature.find_signature(input, "a=:YWJj:", %{
                 tag: "t",
                 components: [{"x", []}],
                 alg: "a",
                 key_id: "k"
               })

      {:ok, dict} = SF.parse_dictionary(input)
      assert [{"b", {:inner_list, [{"y", []}], _}}] = HttpSignature.members_with_tag(dict, "u")
      assert [] = HttpSignature.members_with_tag(dict, "v")
    end
  end

  test "key_from_private/1 rebuilds the same did:key", %{key: key} do
    assert {:ok, ^key} = HttpSignature.key_from_private(key.private_key)
    assert {:error, :invalid_private_key} = HttpSignature.key_from_private(<<1, 2>>)
  end
end
