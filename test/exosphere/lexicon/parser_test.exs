defmodule Exosphere.Lexicon.ParserTest do
  use ExUnit.Case, async: true

  alias Exosphere.Lexicon.Parser

  @lexicon_dir "priv/lexicons"

  describe "parse_dir/1" do
    test "parses all vendored lexicons" do
      assert {:ok, lexicons} = Parser.parse_dir(@lexicon_dir)

      assert Map.keys(lexicons) == [
               "app.bsky.embed.external",
               "app.bsky.embed.images",
               "app.bsky.embed.record",
               "app.bsky.feed.post",
               "app.bsky.richtext.facet",
               "community.lexicon.interaction.like"
             ]
    end

    test "parses record schema with nested defs" do
      {:ok, lexicons} = Parser.parse_dir(@lexicon_dir)
      post = lexicons["app.bsky.feed.post"]

      assert post.id == "app.bsky.feed.post"
      main = post.defs["main"]
      assert main.kind == :record
      assert main.key == "tid"

      props = main.record.properties
      assert props["text"].kind == :string
      assert props["text"].max_length == 3000
      assert props["text"].max_graphemes == 300
      assert props["createdAt"].format == "datetime"
      assert main.record.required == ["text", "createdAt"]

      assert post.defs["replyRef"].kind == :object
      assert post.defs["replyRef"].properties["root"].kind == :ref
      assert post.defs["replyRef"].properties["root"].ref == "com.atproto.repo.strongRef"
    end

    test "parses unions and arrays" do
      {:ok, lexicons} = Parser.parse_dir(@lexicon_dir)
      post = lexicons["app.bsky.feed.post"]
      embed = post.defs["main"].record.properties["embed"]

      assert embed.kind == :union
      assert "app.bsky.embed.images" in embed.refs
      assert "app.bsky.embed.video" in embed.refs

      langs = post.defs["main"].record.properties["langs"]
      assert langs.kind == :array
      assert langs.max_length == 3
      assert langs.items.format == "language"
    end

    test "parses internal refs in object defs" do
      {:ok, lexicons} = Parser.parse_dir(@lexicon_dir)
      facet = lexicons["app.bsky.richtext.facet"]

      assert facet.defs["main"].kind == :object
      assert facet.defs["main"].properties["index"].ref == "#byteSlice"

      features = facet.defs["main"].properties["features"]
      assert features.items.kind == :union
      assert features.items.refs == ["#mention", "#link", "#tag"]
    end
  end

  describe "parse/1 validation" do
    test "rejects unsupported lexicon version" do
      assert {:error, {:unsupported_lexicon_version, 2}} = Parser.parse(%{"lexicon" => 2})
    end

    test "rejects invalid nsid" do
      assert {:error, {:invalid_nsid, "not an nsid"}} =
               Parser.parse(%{"lexicon" => 1, "id" => "not an nsid", "defs" => %{}})
    end

    test "rejects missing main def" do
      assert {:error, :missing_main_def} =
               Parser.parse(%{
                 "lexicon" => 1,
                 "id" => "com.example.foo",
                 "defs" => %{"other" => %{"type" => "object"}}
               })
    end

    test "rejects unknown schema types" do
      assert {:error, {:unsupported_schema_type, "magic"}} =
               Parser.parse(%{
                 "lexicon" => 1,
                 "id" => "com.example.foo",
                 "defs" => %{"main" => %{"type" => "magic"}}
               })
    end

    test "record schema must wrap an object" do
      assert {:error, :invalid_record_schema} =
               Parser.parse(%{
                 "lexicon" => 1,
                 "id" => "com.example.foo",
                 "defs" => %{"main" => %{"type" => "record", "record" => %{"type" => "string"}}}
               })
    end
  end
end
