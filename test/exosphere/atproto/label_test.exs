defmodule Exosphere.ATProto.LabelTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.{Crypto, Label}
  alias Exosphere.ATProto.Identity.Document

  # Bluesky's moderation labeler, as plc.directory served it, and the first
  # label on its subscribeLabels stream (seq 1), exactly as it arrived. Signed
  # by Bluesky, so these tests check against a real labeler's signing rather
  # than only against our own round trip.
  @bsky_did "did:plc:ar7c4by46qjdydhdevvrndac"

  @bsky_doc %{
    "id" => @bsky_did,
    "alsoKnownAs" => ["at://moderation.bsky.app"],
    "verificationMethod" => [
      %{
        "id" => @bsky_did <> "#atproto",
        "type" => "Multikey",
        "controller" => @bsky_did,
        "publicKeyMultibase" => "zQ3shoG4QW9B3zvKSSiRwwc1De7MFQLNBT9A71gr12GKwMgHu"
      },
      %{
        "id" => @bsky_did <> "#atproto_label",
        "type" => "Multikey",
        "controller" => @bsky_did,
        "publicKeyMultibase" => "zQ3shmV1BNcX17coaDbfen6zArEad6SCLT3jVWCbC6Y9iinTa"
      }
    ],
    "service" => [
      %{
        "id" => "#atproto_pds",
        "type" => "AtprotoPersonalDataServer",
        "serviceEndpoint" => "https://inkcap.us-east.host.bsky.network"
      },
      %{
        "id" => "#atproto_labeler",
        "type" => "AtprotoLabeler",
        "serviceEndpoint" => "https://mod.bsky.app"
      }
    ]
  }

  @bsky_label %{
    "ver" => 1,
    "src" => @bsky_did,
    "uri" => "at://did:plc:t7bqlifbexxhsx7zcj5dablt/app.bsky.feed.post/3jta74y3luk2w",
    "cid" => "bafyreihu6jo2nciwlckipwfjebgcvqusfqwv6kljvjtvntd2g3gpkhap4q",
    "val" => "nudity",
    "cts" => "2023-04-13T05:48:27.340Z",
    "sig" => %{
      "$bytes" =>
        "HHIFvjJUDU85ouJFrA6pGffVQtjtZ6Bsvt9irH0Jh/tAf1Fa8Cmm3UiDouAi0SINUXJwDTVSMJjEp5IRqch/sw=="
    }
  }

  setup_all do
    {:ok, doc} = Document.parse(@bsky_doc)
    %{doc: doc}
  end

  describe "verify/2 against a real labeler" do
    test "accepts Bluesky's label with its JSON-form signature", %{doc: doc} do
      assert :ok = Label.verify(@bsky_label, doc)
    end

    test "accepts the same label with raw signature bytes, as CBOR delivers it", %{doc: doc} do
      raw = Map.update!(@bsky_label, "sig", &Base.decode64!(&1["$bytes"]))
      assert :ok = Label.verify(raw, doc)
    end

    test "rejects any change to a signed field", %{doc: doc} do
      for {field, value} <- [
            {"val", "porn"},
            {"uri", "at://did:plc:someoneelse/app.bsky.feed.post/3jta74y3luk2w"},
            {"cts", "2023-04-13T05:48:27.341Z"},
            {"neg", true},
            {"exp", "2030-01-01T00:00:00.000Z"}
          ] do
        assert {:error, :invalid_signature} =
                 Label.verify(Map.put(@bsky_label, field, value), doc),
               "a label with a changed #{field} still verified"
      end
    end

    test "ignores fields outside the label schema", %{doc: doc} do
      assert :ok =
               Label.verify(Map.put(@bsky_label, "$type", "com.atproto.label.defs#label"), doc)
    end

    test "refuses a document that is not the label's src", %{doc: doc} do
      other = %{doc | id: "did:plc:somebodyelse"}
      assert {:error, :wrong_document} = Label.verify(@bsky_label, other)
    end

    test "never falls back to the #atproto key", %{doc: doc} do
      # Remove #atproto_label. The spec: no other key may validate a label.
      without = %{
        doc
        | verification_method: Enum.reject(doc.verification_method, &(&1.id =~ "#atproto_label"))
      }

      assert {:error, :no_label_key} = Label.verify(@bsky_label, without)
    end

    test "an unsigned label is not valid", %{doc: doc} do
      assert {:error, :unsigned} = Label.verify(Map.delete(@bsky_label, "sig"), doc)
    end
  end

  describe "sign/3 round trip" do
    for curve <- [:secp256k1, :p256] do
      test "a label signed with a #{curve} key verifies with the public half" do
        {:ok, %{private_key: priv, public_key: pub}} = Crypto.generate_keypair(unquote(curve))

        label = %{
          "ver" => 1,
          "src" => "did:plc:labeler",
          "uri" => "at://did:plc:author/pub.example.post/3lk2",
          "val" => "ai-text",
          "cts" => "2026-11-09T12:00:00.000Z"
        }

        assert {:ok, signed} = Label.sign(label, priv, unquote(curve))
        assert is_binary(signed["sig"]) and byte_size(signed["sig"]) == 64
        assert :ok = Label.verify_with_key(signed, pub, unquote(curve))

        assert {:error, :invalid_signature} =
                 Label.verify_with_key(%{signed | "val" => "spam"}, pub, unquote(curve))
      end
    end
  end

  describe "to_json/1" do
    doctest Label, only: [to_json: 1]

    test "Bluesky's label comes back with its signature, unpadded", %{doc: doc} do
      raw = Map.update!(@bsky_label, "sig", &Base.decode64!(&1["$bytes"]))

      assert {:ok, json} = Label.to_json(raw)
      assert %{"$bytes" => b64} = json["sig"]
      refute b64 =~ "="
      assert b64 == String.trim_trailing(@bsky_label["sig"]["$bytes"], "=")
      assert :ok = Label.verify(json, doc)
    end

    test "normalises a padded $bytes sig to the unpadded form" do
      assert {:ok, %{"sig" => %{"$bytes" => b64}}} = Label.to_json(@bsky_label)
      refute b64 =~ "="
    end

    test "uses the standard alphabet, not the URL-safe one" do
      assert {:ok, %{"sig" => %{"$bytes" => "+/8"}}} = Label.to_json(%{"sig" => <<251, 255>>})
    end

    test "leaves an unsigned label unsigned" do
      label = Map.delete(@bsky_label, "sig")
      assert {:ok, ^label} = Label.to_json(label)
    end

    test "rejects a sig that is neither bytes nor base64" do
      assert {:error, :invalid_sig} = Label.to_json(%{"sig" => %{"$bytes" => "%%%"}})
      assert {:error, :invalid_sig} = Label.to_json(%{"sig" => 1})
    end
  end

  describe "sig_bytes/1" do
    test "reads raw bytes and both $bytes forms" do
      sig = Base.decode64!(@bsky_label["sig"]["$bytes"])

      assert {:ok, ^sig} = Label.sig_bytes(sig)
      assert {:ok, ^sig} = Label.sig_bytes(@bsky_label["sig"])
      assert {:ok, ^sig} = Label.sig_bytes(%{"$bytes" => Base.encode64(sig, padding: false)})
    end

    test "an empty signature is not a signature" do
      assert {:error, :invalid_sig} = Label.sig_bytes("")
      assert {:error, :invalid_sig} = Label.sig_bytes(%{"$bytes" => ""})
    end
  end

  describe "active?/2" do
    @now ~U[2026-11-09 12:00:00Z]

    test "an ordinary label is in force" do
      assert Label.active?(%{"val" => "x"}, @now)
    end

    test "a negation is never in force" do
      refute Label.active?(%{"val" => "x", "neg" => true}, @now)
    end

    test "a label stops counting at its expiry" do
      assert Label.active?(%{"exp" => "2026-11-10T00:00:00.000Z"}, @now)
      refute Label.active?(%{"exp" => "2026-11-09T00:00:00.000Z"}, @now)
    end

    test "an unparseable expiry counts as expired" do
      refute Label.active?(%{"exp" => "next tuesday"}, @now)
    end
  end

  describe "Document helpers" do
    test "get_label_key/1 and get_signing_key/1 find different keys", %{doc: doc} do
      assert {:ok, label_key, :secp256k1} = Document.get_label_key(doc)
      assert {:ok, signing_key, :secp256k1} = Document.get_signing_key(doc)
      refute label_key == signing_key
    end

    test "get_labeler_endpoint/1", %{doc: doc} do
      assert {:ok, "https://mod.bsky.app"} = Document.get_labeler_endpoint(doc)
    end

    test "a document without a labeler service has no endpoint", %{doc: doc} do
      assert {:error, :not_found} =
               Document.get_labeler_endpoint(%{
                 doc
                 | service: Enum.reject(doc.service, &(&1.type == "AtprotoLabeler"))
               })
    end
  end
end
