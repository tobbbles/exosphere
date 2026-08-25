defmodule Exosphere.ATProtoTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto

  describe "validate/2" do
    test "composes every grammar validator with :ok on valid input" do
      assert :ok = ATProto.validate(:nsid, "app.bsky.feed.post")
      assert :ok = ATProto.validate(:rkey, "3jzfcijpj2z2a")
      assert :ok = ATProto.validate(:at_uri, "at://did:plc:abc/app.bsky.feed.post/3jzfcijpj2z2a")
      assert :ok = ATProto.validate(:tid, "3jzfcijpj2z2a")
      assert :ok = ATProto.validate(:did, "did:plc:44ybard66vv44zksje25o7dz")
      assert :ok = ATProto.validate(:handle, "example.com")

      assert :ok =
               ATProto.validate(
                 :cid,
                 "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"
               )

      assert :ok = ATProto.validate(:mst_key, "app.bsky.feed.post/3jzfcijpj2z2a")
      assert :ok = ATProto.validate(:record, %{"$type" => "com.example.post", "a" => 123})
    end

    test "returns {:error, reason} on invalid input" do
      assert {:error, :invalid_nsid} = ATProto.validate(:nsid, "Not A NSID")
      assert {:error, :invalid_rkey} = ATProto.validate(:rkey, "..")
      assert {:error, :invalid_scheme} = ATProto.validate(:at_uri, "https://example.com")
      assert {:error, :invalid_tid} = ATProto.validate(:tid, "short")
      assert {:error, :invalid_did} = ATProto.validate(:did, "did:web")
      assert {:error, :invalid_handle} = ATProto.validate(:handle, "-bad-")
      assert {:error, :invalid_mst_key} = ATProto.validate(:mst_key, "noslash")
      assert {:error, :unsupported_multibase} = ATProto.validate(:cid, "x123abc")
      assert {:error, {"a", :non_integral_float}} = ATProto.validate(:record, %{"a" => 1.5})
      assert {:error, {"", :top_level_not_object}} = ATProto.validate(:record, "blah")
    end

    test ":at_uri surfaces the specific parse reason" do
      assert {:error, :invalid_scheme} = ATProto.validate(:at_uri, "https://example.com")

      assert {:error, :invalid_authority} =
               ATProto.validate(:at_uri, "at://not a did/collection/rkey")

      assert {:error, :invalid_collection} =
               ATProto.validate(:at_uri, "at://did:plc:abc/Not A Collection")

      assert {:error, :invalid_rkey} =
               ATProto.validate(:at_uri, "at://did:plc:abc/app.bsky.feed.post/..")

      # More than three path segments has no single reason: the catch-all.
      assert {:error, :invalid_at_uri} =
               ATProto.validate(:at_uri, "at://did:plc:abc/app.bsky.feed.post/rkey/extra")

      # Non-string input falls through to AtUri.parse's catch-all reason.
      assert {:error, :invalid_at_uri} = ATProto.validate(:at_uri, :not_a_uri)
    end

    test "rejects unknown kinds" do
      assert {:error, {:unknown_validation_kind, :nope}} = ATProto.validate(:nope, "x")

      # Non-atom kinds get the same tagged shape.
      assert {:error, {:unknown_validation_kind, "nsid"}} = ATProto.validate("nsid", "x")
    end
  end
end
