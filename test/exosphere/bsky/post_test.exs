defmodule Exosphere.Bsky.PostTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.{CBOR, CID, MST, TID}
  alias Exosphere.Bsky.Embed.Images
  alias Exosphere.Bsky.Feed.Post
  alias Exosphere.Bsky.Richtext.Facet

  @created_at "2026-08-25T12:00:00.000Z"

  defp post_attrs do
    %{
      "text" => "Hello @alice.bsky.social from the exosphere!",
      "createdAt" => @created_at,
      "langs" => ["en"],
      "facets" => [
        %{
          "index" => %{"byteStart" => 6, "byteEnd" => 27},
          "features" => [
            %{
              "$type" => "app.bsky.richtext.facet#mention",
              "did" => "did:plc:abc123def456"
            }
          ]
        }
      ],
      "reply" => %{
        "root" => %{
          "$type" => "com.atproto.repo.strongRef",
          "uri" => "at://did:plc:root/app.bsky.feed.post/3jzfcijpj2z2a",
          "cid" => "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
        },
        "parent" => %{
          "$type" => "com.atproto.repo.strongRef",
          "uri" => "at://did:plc:parent/app.bsky.feed.post/3jzfcijpj2z2b",
          "cid" => "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
        }
      }
    }
  end

  describe "new/1" do
    test "builds a post from wire-format attrs" do
      assert {:ok, %Post{} = post} = Post.new(post_attrs())
      assert post.text == "Hello @alice.bsky.social from the exosphere!"
      assert post.created_at == @created_at
      assert post.langs == ["en"]
      assert [%Facet{} = facet] = post.facets
      assert facet.index.byte_start == 6
      assert [%Facet.Mention{did: "did:plc:abc123def456"}] = facet.features
    end

    test "accepts atom keys too" do
      assert {:ok, %Post{}} = Post.new(%{text: "hi", created_at: @created_at})
    end

    test "keeps unknown fields in extra" do
      attrs = Map.put(post_attrs(), "someFutureField", %{"a" => 1})

      assert {:ok, %Post{extra: %{"someFutureField" => %{"a" => 1}}}} = Post.new(attrs)
    end

    test "requires text and createdAt" do
      assert {:error, errors} = Post.new(%{"createdAt" => @created_at})
      assert {"text", "is required"} in errors

      assert {:error, errors} = Post.new(%{"text" => "hi"})
      assert {"createdAt", "is required"} in errors
    end

    test "validates constraints" do
      assert {:error, [{"text", "must be at most 300 graphemes"}]} =
               Post.new(%{"text" => String.duplicate("🦋", 301), "createdAt" => @created_at})

      assert {:error, [{"createdAt", "is not a valid datetime"}]} =
               Post.new(%{"text" => "hi", "createdAt" => "not-a-date"})

      assert {:error, [{"langs[1]", "is not a valid language"}]} =
               Post.new(%{"text" => "hi", "createdAt" => @created_at, "langs" => ["en", "not a language!"]})
    end

    test "validates nested facets" do
      attrs =
        post_attrs()
        |> Map.put("facets", [
          %{"index" => %{"byteStart" => 0, "byteEnd" => 3}, "features" => []},
          %{"index" => %{"byteStart" => 0, "byteEnd" => 3}, "features" => nil}
        ])

      assert {:error, errors} = Post.new(attrs)
      assert {"facets[1].features", "is required"} in errors
    end

    test "decodes embed unions on $type" do
      attrs =
        Map.put(post_attrs(), "embed", %{
          "$type" => "app.bsky.embed.images",
          "images" => [%{"image" => %{"$type" => "blob"}, "alt" => "a photo"}]
        })

      assert {:ok, %Post{embed: %Images{} = embed} = post} = Post.new(attrs)
      assert [%Images.Image{alt: "a photo"}] = embed.images

      # Unknown embed variants pass through as maps (open-world)
      attrs = Map.put(post_attrs(), "embed", %{"$type" => "app.bsky.embed.video", "video" => %{}})
      assert {:ok, %Post{embed: %{"$type" => "app.bsky.embed.video"}}} = Post.new(attrs)
    end
  end

  describe "to_map/1" do
    test "encodes to the wire format with $type" do
      {:ok, post} = Post.new(post_attrs())
      map = Post.to_map(post)

      assert map["$type"] == "app.bsky.feed.post"
      assert map["text"] == post.text
      assert map["createdAt"] == @created_at

      [facet_map] = map["facets"]
      assert facet_map["index"]["byteStart"] == 6
      assert facet_map["features"] == [
               %{"$type" => "app.bsky.richtext.facet#mention", "did" => "did:plc:abc123def456"}
             ]

      # Unresolved refs (strongRef) pass through untouched
      assert map["reply"]["root"]["$type"] == "com.atproto.repo.strongRef"
    end

    test "re-emits unknown fields" do
      {:ok, post} = Post.new(Map.put(post_attrs(), "someFutureField", 42))
      assert Post.to_map(post)["someFutureField"] == 42
    end

    test "embed unions carry their $type" do
      {:ok, embed} =
        Images.new(%{"images" => [%{"image" => %{"$type" => "blob", "ref" => "bafy..."}, "alt" => "cat"}]})

      {:ok, post} = Post.new(%{text: "cat pic", created_at: @created_at, embed: embed})
      map = Post.to_map(post)

      assert map["embed"]["$type"] == "app.bsky.embed.images"
      assert map["embed"]["images"] == [%{"image" => %{"$type" => "blob", "ref" => "bafy..."}, "alt" => "cat"}]
    end
  end

  describe "round-trip" do
    test "to_map |> from_map is the identity" do
      attrs = post_attrs()
      {:ok, post} = Post.new(attrs)
      {:ok, decoded} = post |> Post.to_map() |> Post.from_map()

      assert decoded == post
    end

    test "survives CBOR encoding and an MST commit" do
      {:ok, post} = Post.new(post_attrs())
      map = Post.to_map(post)

      # The record as it would be stored in a repo block
      assert {:ok, cbor} = CBOR.encode(map)
      assert {:ok, decoded_map} = CBOR.decode(cbor)
      assert decoded_map == map

      # Commit it under a TID record key in an MST
      rkey = TID.generate()
      {:ok, %CID{} = record_cid} = CID.create(map)

      assert {:ok, root, mst_blocks} = MST.build(%{"app.bsky.feed.post/#{rkey}" => record_cid})

      # Read the tree back and recover the record from the block store
      blocks = Map.put(mst_blocks, record_cid, cbor)
      assert {:ok, entries} = MST.read(root, blocks)
      assert entries["app.bsky.feed.post/#{rkey}"] == record_cid

      stored = blocks[record_cid]
      assert stored == cbor

      assert {:ok, %Post{} = restored} = stored |> CBOR.decode!() |> Post.from_map()
      assert restored == post
    end
  end
end
