defmodule Exosphere.Lexicon.GeneratorTest do
  @moduledoc """
  Golden-file tests: regeneration must be deterministic and match the
  committed generated modules byte-for-byte. Run `mix exosphere.gen.bsky`
  and commit the result when the generator changes intentionally.
  """

  use ExUnit.Case, async: true

  alias Exosphere.Lexicon.{Generator, Parser}

  @output_dir "lib/exosphere/bsky"

  test "generated files on disk match regeneration (no drift)" do
    {:ok, lexicons} = Parser.parse_dir("priv/lexicons")

    for %{path: rel, code: code} <- Generator.generate(lexicons) do
      path = Path.join(@output_dir, rel)
      assert File.exists?(path), "missing generated file: #{path}"
      assert File.read!(path) == code, "drifted generated file: #{path}"
    end
  end

  test "generates the expected module set" do
    {:ok, lexicons} = Parser.parse_dir("priv/lexicons")

    modules =
      lexicons
      |> Generator.generate()
      |> Enum.map(& &1.module)
      |> MapSet.new()

    assert MapSet.subset?(
             MapSet.new([
               Exosphere.Bsky.Feed.Post,
               Exosphere.Bsky.Feed.Post.ReplyRef,
               Exosphere.Bsky.Feed.Post.Entity,
               Exosphere.Bsky.Feed.Post.TextSlice,
               Exosphere.Bsky.Richtext.Facet,
               Exosphere.Bsky.Richtext.Facet.ByteSlice,
               Exosphere.Bsky.Richtext.Facet.Mention,
               Exosphere.Bsky.Richtext.Facet.Link,
               Exosphere.Bsky.Richtext.Facet.Tag,
               Exosphere.Bsky.Embed.Images,
               Exosphere.Bsky.Embed.Images.Image,
               Exosphere.Bsky.Embed.External,
               Exosphere.Bsky.Embed.External.External,
               Exosphere.Bsky.Embed.Record
             ]),
             modules
           )
  end

  test "modules nest to mirror their NSID paths" do
    {:ok, lexicons} = Parser.parse_dir("priv/lexicons")
    paths = MapSet.new(Generator.generate(lexicons), & &1.path)

    assert "feed/post.ex" in paths
    assert "feed/post/reply_ref.ex" in paths
    assert "richtext/facet.ex" in paths
    assert "richtext/facet/byte_slice.ex" in paths
    assert "embed/images.ex" in paths
  end
end
