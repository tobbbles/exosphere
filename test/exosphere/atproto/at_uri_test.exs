defmodule Exosphere.ATProto.AtUriTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.AtUri

  test "parses authority-only URIs (DID and handle)" do
    assert {:ok, %AtUri{authority: "did:plc:44ybard66vv44zksje25o7dz"} = uri} =
             AtUri.parse("at://did:plc:44ybard66vv44zksje25o7dz")

    assert uri.collection == nil
    assert uri.rkey == nil

    assert {:ok, %AtUri{authority: "alice.example.com"}} =
             AtUri.parse("at://alice.example.com")
  end

  test "parses full collection/rkey URIs" do
    assert {:ok, uri} =
             AtUri.parse("at://did:plc:44ybard66vv44zksje25o7dz/app.bsky.feed.post/3jwdwj2ctlk26")

    assert uri.authority == "did:plc:44ybard66vv44zksje25o7dz"
    assert uri.collection == "app.bsky.feed.post"
    assert uri.rkey == "3jwdwj2ctlk26"
  end

  test "parses an optional fragment" do
    assert {:ok, uri} =
             AtUri.parse("at://did:plc:abc123def456ghij/app.bsky.actor.profile/self#/foo")

    assert uri.fragment == "/foo"
  end

  test "rejects invalid URIs" do
    assert {:error, :invalid_scheme} = AtUri.parse("https://example.com")
    assert {:error, :invalid_scheme} = AtUri.parse("did:plc:abc")
    assert {:error, :invalid_authority} = AtUri.parse("at://not a handle")
    assert {:error, :invalid_collection} = AtUri.parse("at://alice.example.com/not-an-nsid")
    assert {:error, :invalid_rkey} = AtUri.parse("at://alice.example.com/app.bsky.feed.post/..")
    assert {:error, :invalid_at_uri} = AtUri.parse("at://a.com/c.d.e/rkey/extra")
    assert {:error, :too_long} = AtUri.parse("at://" <> String.duplicate("a", 9000))
  end

  test "to_string/1 round-trips" do
    str = "at://did:plc:44ybard66vv44zksje25o7dz/app.bsky.feed.post/3jwdwj2ctlk26"
    assert {:ok, uri} = AtUri.parse(str)
    assert AtUri.to_string(uri) == str
  end

  test "valid?/1 mirrors parse/1" do
    assert AtUri.valid?("at://alice.example.com/app.bsky.feed.post/3jwdwj2ctlk26")
    refute AtUri.valid?("at://alice.example.com/bad rkey collection")
  end
end
