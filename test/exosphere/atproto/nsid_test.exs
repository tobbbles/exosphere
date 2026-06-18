defmodule Exosphere.ATProto.NSIDTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.NSID

  test "valid?/1 accepts well-formed NSIDs" do
    assert NSID.valid?("app.bsky.feed.post")
    assert NSID.valid?("com.atproto.repo.getRecord")
    assert NSID.valid?("com.example.foo")
    assert NSID.valid?("com.example.fooBarBaz")
    # hyphens allowed in authority segments
    assert NSID.valid?("com.long-domain.name")
  end

  test "valid?/1 rejects malformed NSIDs" do
    # fewer than 3 segments
    refute NSID.valid?("com.example")
    refute NSID.valid?("foo")
    # TLD (first segment) starting with a digit
    refute NSID.valid?("0com.example.foo")
    # name (last segment) starting with a digit
    refute NSID.valid?("com.example.3foo")
    # name segment may not contain a hyphen
    refute NSID.valid?("com.example.foo-bar")
    # empty segment
    refute NSID.valid?("com..foo")
    refute NSID.valid?("")
    refute NSID.valid?(nil)
  end

  test "valid?/1 enforces length limits" do
    long_name = String.duplicate("a", 64)
    refute NSID.valid?("com.example." <> long_name)
  end

  test "parse/1 splits authority and name" do
    assert {:ok, parsed} = NSID.parse("app.bsky.feed.post")
    assert parsed.authority == "app.bsky.feed"
    assert parsed.name == "post"
    assert parsed.segments == ["app", "bsky", "feed", "post"]
  end

  test "parse/1 returns error for invalid input" do
    assert {:error, :invalid_nsid} = NSID.parse("com.example")
  end
end
