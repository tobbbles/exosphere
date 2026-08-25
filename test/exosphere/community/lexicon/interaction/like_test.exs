defmodule Exosphere.Community.Lexicon.Interaction.LikeTest do
  @moduledoc """
  Validates generation of a community (non app.bsky) lexicon:
  community.lexicon.interaction.like from the lexicon-community repo
  hosted on Tangled.
  """

  use ExUnit.Case, async: true

  alias Exosphere.ATProto.{CBOR, CID, MST}
  alias Exosphere.Bsky.Feed.Post
  alias Exosphere.Community.Lexicon.Interaction.Like

  @created_at "2026-08-25T12:00:00.000Z"

  @subject %{
    "$type" => "com.atproto.repo.strongRef",
    "uri" => "at://did:plc:author/app.bsky.feed.post/3jzfcijpj2z2a",
    "cid" => "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
  }

  test "type_id/0 is the community NSID" do
    assert Like.type_id() == "community.lexicon.interaction.like"
  end

  test "builds from wire-format attrs" do
    assert {:ok, %Like{} = like} = Like.new(%{"subject" => @subject, "createdAt" => @created_at})
    assert like.subject == @subject
    assert like.created_at == @created_at
  end

  test "requires subject and createdAt, validates datetime" do
    assert {:error, errors} = Like.new(%{"createdAt" => @created_at})
    assert {"subject", "is required"} in errors

    assert {:error, [{"createdAt", "is not a valid datetime"}]} =
             Like.new(%{"subject" => @subject, "createdAt" => "yesterday"})
  end

  test "to_map/1 includes $type and passes strongRef through untouched" do
    {:ok, like} = Like.new(%{"subject" => @subject, "createdAt" => @created_at})

    assert Like.to_map(like) == %{
             "$type" => "community.lexicon.interaction.like",
             "subject" => @subject,
             "createdAt" => @created_at
           }
  end

  test "to_map |> from_map is the identity" do
    {:ok, like} = Like.new(%{"subject" => @subject, "createdAt" => @created_at})
    assert {:ok, ^like} = like |> Like.to_map() |> Like.from_map()
  end

  test "commits alongside a bsky post in one MST" do
    {:ok, post} = Post.new(%{"text" => "likable", "createdAt" => @created_at})
    {:ok, like} = Like.new(%{"subject" => @subject, "createdAt" => @created_at})

    post_map = Post.to_map(post)
    like_map = Like.to_map(like)
    {:ok, post_cid} = CID.create(post_map)
    {:ok, like_cid} = CID.create(like_map)
    {:ok, post_cbor} = CBOR.encode(post_map)
    {:ok, like_cbor} = CBOR.encode(like_map)

    entries = %{
      "app.bsky.feed.post/3jzlikepost000" => post_cid,
      "community.lexicon.interaction.like/3jzlikerec000" => like_cid
    }

    assert {:ok, root, mst_blocks} = MST.build(entries)

    blocks = Map.merge(mst_blocks, %{post_cid => post_cbor, like_cid => like_cbor})
    assert {:ok, read_back} = MST.read(root, blocks)
    assert read_back == entries

    # Both records decode back to their generated structs
    assert {:ok, %Post{} = restored_post} = post_cbor |> CBOR.decode!() |> Post.from_map()
    assert restored_post == post

    assert {:ok, %Like{} = restored_like} = like_cbor |> CBOR.decode!() |> Like.from_map()
    assert restored_like == like
  end
end
