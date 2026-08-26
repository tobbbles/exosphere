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

    test "dedicated #atproto_space entries win" do
      doc =
        document(
          [
            %{
              "id" => "did:plc:authority#atproto",
              "type" => "Multikey",
              "controller" => "did:plc:authority",
              "publicKeyMultibase" => multibase(@account_key)
            },
            %{
              "id" => "did:plc:authority#atproto_space",
              "type" => "Multikey",
              "controller" => "did:plc:authority",
              "publicKeyMultibase" => multibase(@space_key)
            }
          ],
          [
            %{
              "id" => "did:plc:authority#atproto_pds",
              "type" => "AtprotoPersonalDataServer",
              "serviceEndpoint" => "https://pds.example.com"
            },
            %{
              "id" => "did:plc:authority#atproto_space_host",
              "type" => "AtprotoSpaceHost",
              "serviceEndpoint" => "https://space-host.example.com"
            }
          ]
        )

      assert {:ok, @space_key, :secp256k1} = Document.get_space_signing_key(doc)
      assert {:ok, @account_key, :secp256k1} = Document.get_signing_key(doc)
      assert {:ok, "https://space-host.example.com"} = Document.get_space_host_endpoint(doc)
      assert {:ok, "https://pds.example.com"} = Document.get_pds_endpoint(doc)
    end

    test "space entries fall back to #atproto / #atproto_pds when absent" do
      doc =
        document(
          [
            %{
              "id" => "did:plc:authority#atproto",
              "type" => "Multikey",
              "controller" => "did:plc:authority",
              "publicKeyMultibase" => multibase(@account_key)
            }
          ],
          [
            %{
              "id" => "did:plc:authority#atproto_pds",
              "type" => "AtprotoPersonalDataServer",
              "serviceEndpoint" => "https://pds.example.com"
            }
          ]
        )

      assert {:ok, @account_key, :secp256k1} = Document.get_space_signing_key(doc)
      assert {:ok, "https://pds.example.com"} = Document.get_space_host_endpoint(doc)
    end

    test "missing both entries is :not_found" do
      doc = document([], [])

      assert {:error, :not_found} = Document.get_space_signing_key(doc)
      assert {:error, :not_found} = Document.get_space_host_endpoint(doc)
    end

    test "#atproto_space_host matches on id fragment, not type" do
      doc =
        document([], [
          %{
            "id" => "did:plc:authority#atproto_space_host",
            "type" => "UndocumentedServiceType",
            "serviceEndpoint" => "https://space-host.example.com"
          }
        ])

      assert {:ok, "https://space-host.example.com"} = Document.get_space_host_endpoint(doc)
    end
  end
end
