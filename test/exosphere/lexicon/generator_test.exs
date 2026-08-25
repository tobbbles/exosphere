defmodule Exosphere.Lexicon.GeneratorTest do
  @moduledoc """
  Golden-file tests: regeneration must be deterministic and match the
  committed generated modules byte-for-byte. Run `mix exosphere.gen.lexicons`
  and commit the result when the generator changes intentionally.
  """

  use ExUnit.Case, async: true

  alias Exosphere.Lexicon.{Generator, Parser}

  @output_dir "lib/exosphere"

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
               Exosphere.Bsky.Embed.Record,
               Exosphere.Bsky.Graph.Follow,
               Exosphere.ATProto.Repo.StrongRef,
               Exosphere.ATProto.Label.Defs.SelfLabels,
               Exosphere.Community.Interaction.Like
             ]),
             modules
           )
  end

  test "modules nest to mirror their NSID paths" do
    {:ok, lexicons} = Parser.parse_dir("priv/lexicons")
    paths = MapSet.new(Generator.generate(lexicons), & &1.path)

    assert "bsky/feed/post.ex" in paths
    assert "bsky/feed/post/reply_ref.ex" in paths
    assert "bsky/richtext/facet.ex" in paths
    assert "bsky/richtext/facet/byte_slice.ex" in paths
    assert "bsky/embed/images.ex" in paths
    assert "community/interaction/like.ex" in paths
    assert "atproto/repo/strong_ref.ex" in paths
    assert "atproto/label/defs/self_labels.ex" in paths
  end

  # Host-app generation: --dir seeds only the host lexicons, but refs
  # resolve against the corpus passed alongside, and modules land under
  # the host's namespace.
  @host_lexicon %{
    "lexicon" => 1,
    "id" => "pub.oysters.comment",
    "defs" => %{
      "main" => %{
        "type" => "record",
        "key" => "tid",
        "record" => %{
          "type" => "object",
          "required" => ["subject"],
          "properties" => %{
            "subject" => %{"type" => "ref", "ref" => "com.atproto.repo.strongRef"}
          }
        }
      }
    }
  }

  test "seeds + base generate host modules with corpus-resolved refs" do
    {:ok, corpus} = Parser.parse_dir("priv/lexicons")
    {:ok, ours} = Parser.parse(@host_lexicon)
    lexicons = Map.put(corpus, "pub.oysters.comment", ours)

    specs =
      Generator.generate(lexicons, base: Oysters, seeds: ["pub.oysters.comment"])

    modules = Enum.map(specs, & &1.module)

    # The host record generates under the host namespace, and the corpus
    # strongRef it references generates typed alongside instead of
    # degrading subject to term()
    assert Oysters.Pub.Oysters.Comment in modules
    assert Oysters.ATProto.Repo.StrongRef in modules
    refute Exosphere.Bsky.Feed.Post in modules

    comment = Enum.find(specs, &(&1.module == Oysters.Pub.Oysters.Comment))
    assert comment.path == "pub/oysters/comment.ex"
    assert comment.code =~ "subject: StrongRef.t()"
  end

  test "default base and seeds are unchanged (no opts)" do
    {:ok, lexicons} = Parser.parse_dir("priv/lexicons")

    assert Enum.any?(Generator.generate(lexicons), &(&1.module == Exosphere.Bsky.Feed.Post))
  end
end
