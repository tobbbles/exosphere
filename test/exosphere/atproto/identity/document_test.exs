defmodule Exosphere.ATProto.Identity.DocumentTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Base58
  alias Exosphere.ATProto.Identity.Document

  test "parse/1 builds a Document struct and exposes helpers" do
    # Build a valid Multikey secp256k1 compressed key:
    # multicodec varint 0xE7 0x01 + 33-byte compressed public key
    compressed_pubkey = <<0x02, 0::unsigned-integer-size(256)>>
    multicodec = <<0xE7, 0x01, compressed_pubkey::binary>>
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

  describe "space entries (proposal 0016)" do
    @account_key <<0x02, 0::unsigned-integer-size(256)>>
    @space_key <<0x03, 0::unsigned-integer-size(256)>>

    defp multibase(key) do
      "z" <> Base58.encode(<<0xE7, 0x01, key::binary>>)
    end

    defp document(methods, services) do
      {:ok, doc} =
        Document.parse(%{
          "id" => "did:plc:authority",
          "verificationMethod" => methods,
          "service" => services
        })

      doc
    end

    @kem_key <<0x02, 1::unsigned-integer-size(256)>>

    defp p256_multibase(key) do
      "z" <> Base58.encode(<<0x80, 0x24, key::binary>>)
    end

    defp method(fragment, multibase) do
      %{
        "id" => "did:plc:authority#" <> fragment,
        "type" => "Multikey",
        "controller" => "did:plc:authority",
        "publicKeyMultibase" => multibase
      }
    end

    defp pds_service do
      %{
        "id" => "did:plc:authority#atproto_pds",
        "type" => "AtprotoPersonalDataServer",
        "serviceEndpoint" => "https://pds.example.com"
      }
    end

    # atproto `432ef66` dropped the dedicated space entries: the space host is
    # the authority's PDS and credentials are signed by its `#atproto` key.
    test "dropped #atproto_space / #atproto_space_host entries are ignored" do
      doc =
        document(
          [
            method("atproto", multibase(@account_key)),
            method("atproto_space", multibase(@space_key))
          ],
          [
            pds_service(),
            %{
              "id" => "did:plc:authority#atproto_space_host",
              "type" => "AtprotoSpaceHost",
              "serviceEndpoint" => "https://space-host.example.com"
            }
          ]
        )

      assert {:ok, @account_key, :secp256k1} = Document.get_space_signing_key(doc)
      assert {:ok, "https://pds.example.com"} = Document.get_space_host_endpoint(doc)
    end

    test "the space entries are the #atproto key and the #atproto_pds endpoint" do
      doc = document([method("atproto", multibase(@account_key))], [pds_service()])

      assert {:ok, @account_key, :secp256k1} = Document.get_space_signing_key(doc)
      assert {:ok, "https://pds.example.com"} = Document.get_space_host_endpoint(doc)
    end

    test "missing both entries is :not_found" do
      doc = document([], [])

      assert {:error, :not_found} = Document.get_space_signing_key(doc)
      assert {:error, :not_found} = Document.get_space_host_endpoint(doc)
    end

    test "a token kid must be exactly #atproto" do
      doc =
        document(
          [
            method("atproto", multibase(@account_key)),
            method("atproto_space", multibase(@space_key))
          ],
          []
        )

      assert {:ok, @account_key, :secp256k1} = Document.get_space_signing_key(doc, "#atproto")

      assert {:error, :unsupported_space_kid} =
               Document.get_space_signing_key(doc, "#atproto_space")

      assert {:error, :unsupported_space_kid} =
               Document.get_space_signing_key(doc, "did:plc:authority#atproto")

      assert {:error, :missing_kid} = Document.get_space_signing_key(doc, nil)
    end

    test "get_kem_key/1 reads the P-256 #atproto_kem method" do
      doc =
        document(
          [
            method("atproto", multibase(@account_key)),
            method("atproto_kem", p256_multibase(@kem_key))
          ],
          []
        )

      assert {:ok, @kem_key} = Document.get_kem_key(doc)
    end

    test "get_kem_key/1 refuses a non-P-256 key and reports an absent one" do
      wrong_curve = document([method("atproto_kem", multibase(@kem_key))], [])
      assert {:error, :invalid_kem_key} = Document.get_kem_key(wrong_curve)

      assert {:error, :not_found} =
               Document.get_kem_key(document([method("atproto", multibase(@account_key))], []))
    end
  end
end
