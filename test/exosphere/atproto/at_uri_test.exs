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

  describe "space grammar" do
    @space_record_uri "at://did:plc:spaceauthority/space/com.example.group/default/did:plc:author/com.example.groupPost/3jwdwj2ctlk26"

    test "parses the space-reference form" do
      assert {:ok, uri} =
               AtUri.parse("at://did:plc:spaceauthority/space/com.example.group/default")

      assert uri.authority == "did:plc:spaceauthority"
      assert uri.space_type == "com.example.group"
      assert uri.skey == "default"
      assert uri.author == nil
      assert uri.collection == nil
      assert uri.rkey == nil
      assert AtUri.space?(uri)
    end

    test "parses the space-record form" do
      assert {:ok, uri} = AtUri.parse(@space_record_uri)

      assert uri.authority == "did:plc:spaceauthority"
      assert uri.space_type == "com.example.group"
      assert uri.skey == "default"
      assert uri.author == "did:plc:author"
      assert uri.collection == "com.example.groupPost"
      assert uri.rkey == "3jwdwj2ctlk26"
    end

    test "round-trips both space forms" do
      ref = "at://did:plc:spaceauthority/space/com.example.group/default"
      assert {:ok, uri} = AtUri.parse(ref)
      assert AtUri.to_string(uri) == ref

      assert {:ok, record} = AtUri.parse(@space_record_uri)
      assert AtUri.to_string(record) == @space_record_uri
    end

    test "parses a fragment on a space URI" do
      assert {:ok, uri} = AtUri.parse(ref() <> "#/foo")
      assert uri.fragment == "/foo"
    end

    test "rejects non-DID space authority" do
      assert {:error, :invalid_authority} =
               AtUri.parse("at://alice.example.com/space/com.example.group/default")
    end

    test "rejects invalid space types and skeys" do
      assert {:error, :invalid_space_type} =
               AtUri.parse("at://did:plc:x/space/not-an-nsid/default")

      assert {:error, :invalid_skey} = AtUri.parse("at://did:plc:x/space/com.example.group/..")
    end

    test "rejects partial and over-long record segments" do
      # The record segments (author/collection/rkey) are all-or-none.
      assert {:error, :invalid_at_uri} =
               AtUri.parse("at://did:plc:x/space/com.example.group/default/did:plc:author")

      assert {:error, :invalid_at_uri} =
               AtUri.parse(
                 "at://did:plc:x/space/com.example.group/default/did:plc:author/com.example.groupPost"
               )

      assert {:error, :invalid_at_uri} =
               AtUri.parse(
                 "at://did:plc:x/space/com.example.group/default/did:plc:author/coll/rkey/extra"
               )
    end

    test "rejects a bare marker and invalid record segments" do
      assert {:error, :invalid_at_uri} = AtUri.parse("at://did:plc:x/space")

      assert {:error, :invalid_author} =
               AtUri.parse("at://did:plc:x/space/com.example.group/default/not-a-did/coll/rkey")

      assert {:error, :invalid_collection} =
               AtUri.parse(
                 "at://did:plc:x/space/com.example.group/default/did:plc:author/not-an-nsid/rkey"
               )

      assert {:error, :invalid_rkey} =
               AtUri.parse(
                 "at://did:plc:x/space/com.example.group/default/did:plc:author/com.example.groupPost/.."
               )
    end

    test "make_space/3 and make_space/6 build and round-trip" do
      assert {:ok, ref} = AtUri.make_space("did:plc:x", "com.example.group", "default")
      assert AtUri.to_string(ref) == "at://did:plc:x/space/com.example.group/default"

      assert {:ok, record} =
               AtUri.make_space(
                 "did:plc:spaceauthority",
                 "com.example.group",
                 "default",
                 "did:plc:author",
                 "com.example.groupPost",
                 "3jwdwj2ctlk26"
               )

      assert AtUri.to_string(record) == @space_record_uri
    end

    test "make_space validates its parts" do
      assert {:error, :invalid_authority} =
               AtUri.make_space("alice.example.com", "com.example.group", "k")

      assert {:error, :invalid_space_type} = AtUri.make_space("did:plc:x", "not-an-nsid", "k")
      assert {:error, :invalid_skey} = AtUri.make_space("did:plc:x", "com.example.group", "..")

      assert {:error, :invalid_author} =
               AtUri.make_space("did:plc:x", "com.example.group", "k", "not-a-did", "c", "r")

      assert {:error, :invalid_collection} =
               AtUri.make_space(
                 "did:plc:x",
                 "com.example.group",
                 "k",
                 "did:plc:a",
                 "not-an-nsid",
                 "r"
               )
    end

    test "space_ref/1 drops record segments; errors on public URIs" do
      assert {:ok, record} = AtUri.parse(@space_record_uri)
      assert {:ok, ref} = AtUri.space_ref(record)
      assert AtUri.to_string(ref) == "at://did:plc:spaceauthority/space/com.example.group/default"

      assert {:ok, same} = AtUri.parse("at://did:plc:s/space/com.example.group/k")
      assert {:ok, ^same} = AtUri.space_ref(same)

      assert {:error, :not_a_space_uri} = AtUri.space_ref(record_public())
    end

    test "the grammars are never confusable" do
      # A public URI never has space segments, and "space" can never be a
      # public collection (an NSID needs at least two dots).
      assert {:ok, public} = AtUri.parse("at://did:plc:x/app.bsky.feed.post/space")
      refute AtUri.space?(public)
      assert public.rkey == "space"

      # A bare marker is a malformed space URI, never a public collection URI.
      assert {:error, :invalid_at_uri} = AtUri.parse("at://did:plc:x/space")

      assert {:ok, space} = AtUri.parse("at://did:plc:x/space/com.example.group/self")
      assert AtUri.space?(space)
      assert space.collection == nil

      # A hand-built struct mixing the grammars refuses to render (via apply/3
      # so the compile-time type checker doesn't second-guess the raise).
      mixed = %AtUri{authority: "did:plc:x", collection: "app.bsky.feed.post", skey: "k"}
      assert_raise ArgumentError, fn -> apply(AtUri, :to_string, [mixed]) end

      partial = %AtUri{authority: "did:plc:x", space_type: "t", skey: "k", author: "did:plc:a"}
      assert_raise ArgumentError, fn -> apply(AtUri, :to_string, [partial]) end
    end

    test "validate/2 accepts space URIs" do
      assert :ok = Exosphere.ATProto.validate(:at_uri, @space_record_uri)

      assert {:error, :invalid_space_type} =
               Exosphere.ATProto.validate(:at_uri, "at://did:plc:x/space/nope/k")
    end

    defp ref do
      "at://did:plc:spaceauthority/space/com.example.group/default"
    end

    defp record_public do
      {:ok, uri} = AtUri.parse("at://did:plc:x/app.bsky.feed.post/rkey")
      uri
    end
  end
end
