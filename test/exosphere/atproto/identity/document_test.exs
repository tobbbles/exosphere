defmodule Exosphere.ATProto.Identity.DocumentTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Identity.Document

  test "parse/1 builds a Document struct and exposes helpers" do
    # Build a valid Multikey secp256k1 compressed key:
    # multicodec prefix 0xE7 + 33-byte compressed public key
    compressed_pubkey = <<0x02, 0::unsigned-integer-size(256)>>
    multicodec = <<0xE7, compressed_pubkey::binary>>
    multibase = "z" <> Base58.encode(multicodec)

    raw = %{
      "id" => "did:plc:abc123",
      "alsoKnownAs" => ["at://alice.example.com"],
      "verificationMethod" => [
        %{
          "id" => "did:plc:abc123#atproto",
          "type" => "Multikey",
          "controller" => "did:plc:abc123",
          "publicKeyMultibase" => multibase
        }
      ],
      "service" => [
        %{
          "id" => "#atproto_pds",
          "type" => "AtprotoPersonalDataServer",
          "serviceEndpoint" => "https://pds.example.com"
        }
      ]
    }

    assert {:ok, %Document{} = doc} = Document.parse(raw)

    assert {:ok, "https://pds.example.com"} = Document.get_pds_endpoint(doc)
    assert {:ok, "alice.example.com"} = Document.get_handle(doc)

    assert {:ok, key, :secp256k1} = Document.get_signing_key(doc)
    assert key == compressed_pubkey
  end

  test "helpers return :not_found when required fields are missing" do
    doc = %Document{id: "did:plc:abc123", also_known_as: [], verification_method: [], service: []}

    assert {:error, :not_found} = Document.get_pds_endpoint(doc)
    assert {:error, :not_found} = Document.get_handle(doc)
    assert {:error, :not_found} = Document.get_signing_key(doc)
  end
end
