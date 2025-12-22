defmodule Mix.Tasks.Exosphere.Gen.LexiconTest do
  use ExUnit.Case, async: true

  alias Mix.Tasks.Exosphere.Gen.Lexicon
  alias Exosphere.Bsky.Lexicon.{Parser, Generator}

  @fixtures_path "test/fixtures/lexicons"

  describe "info/2" do
    test "returns task info with correct schema" do
      info = Lexicon.info([], nil)

      assert info.group == :exosphere
      assert :namespace in info.positional
      assert Keyword.has_key?(info.schema, :lexicon_dir)
      assert Keyword.has_key?(info.schema, :output)
      assert Keyword.has_key?(info.schema, :dry_run)
    end

    test "has correct defaults" do
      info = Lexicon.info([], nil)

      assert info.defaults[:lexicon_dir] == "priv/lexicons"
      assert info.defaults[:output] == "lib/exosphere/bsky"
      assert info.defaults[:dry_run] == false
    end
  end

  describe "end-to-end code generation" do
    test "generates valid module from query lexicons" do
      # Load lexicon fixtures
      profile_path = Path.join(@fixtures_path, "app/bsky/actor/getProfile.json")
      prefs_path = Path.join(@fixtures_path, "app/bsky/actor/getPreferences.json")

      {:ok, profile} = Parser.parse_file(profile_path)
      {:ok, prefs} = Parser.parse_file(prefs_path)

      # Generate module
      code = Generator.generate_module("app.bsky.actor", [profile, prefs])

      # Should be valid Elixir code
      assert {:ok, _} = Code.string_to_quoted(code)

      # Should contain expected content
      assert code =~ "defmodule Exosphere.Bsky.Actor do"
      assert code =~ "def get_profile(client, params \\\\ %{})"
      assert code =~ "def get_preferences(client, params \\\\ %{})"
      assert code =~ "Client.query(client, \"app.bsky.actor.getProfile\", params)"
    end

    test "generates valid module from procedure lexicons" do
      # Load lexicon fixture
      post_path = Path.join(@fixtures_path, "app/bsky/feed/post.json")
      {:ok, post} = Parser.parse_file(post_path)

      # Generate module
      code = Generator.generate_module("app.bsky.feed", [post])

      # Should be valid Elixir code
      assert {:ok, _} = Code.string_to_quoted(code)

      # Should contain expected content
      assert code =~ "defmodule Exosphere.Bsky.Feed do"
      assert code =~ "def create_post(client, params \\\\ %{})"
      assert code =~ "Client.procedure(client, \"app.bsky.feed.createPost\", params)"
    end
  end

  describe "namespace handling" do
    test "converts namespace to correct directory path" do
      # Test via the generator which uses namespace_to_module
      assert Generator.namespace_to_module("app.bsky.actor") == "Exosphere.Bsky.Actor"
      assert Generator.namespace_to_module("com.atproto.repo") == "Exosphere.Atproto.Repo"
    end
  end

  describe "file path generation" do
    test "generates correct function names from NSIDs" do
      assert Generator.function_name("app.bsky.actor.getProfile") == "get_profile"
      assert Generator.function_name("com.atproto.repo.createRecord") == "create_record"
      assert Generator.function_name("app.bsky.feed.getLikes") == "get_likes"
    end
  end

  describe "lexicon parsing integration" do
    test "parses all fixtures successfully" do
      fixtures = [
        "app/bsky/actor/getProfile.json",
        "app/bsky/actor/getPreferences.json",
        "app/bsky/feed/post.json"
      ]

      for fixture <- fixtures do
        path = Path.join(@fixtures_path, fixture)
        assert {:ok, _} = Parser.parse_file(path), "Failed to parse #{fixture}"
      end
    end

    test "fixture lexicons have correct types" do
      profile_path = Path.join(@fixtures_path, "app/bsky/actor/getProfile.json")
      post_path = Path.join(@fixtures_path, "app/bsky/feed/post.json")

      {:ok, profile} = Parser.parse_file(profile_path)
      {:ok, post} = Parser.parse_file(post_path)

      assert profile.type == :query
      assert post.type == :procedure
    end
  end

  describe "generated code structure" do
    test "includes proper module documentation" do
      profile_path = Path.join(@fixtures_path, "app/bsky/actor/getProfile.json")
      {:ok, profile} = Parser.parse_file(profile_path)

      code = Generator.generate_module("app.bsky.actor", [profile])

      assert code =~ "@moduledoc"
      assert code =~ "Generated module for app.bsky.actor lexicons"
      assert code =~ "## Methods"
    end

    test "includes function documentation" do
      profile_path = Path.join(@fixtures_path, "app/bsky/actor/getProfile.json")
      {:ok, profile} = Parser.parse_file(profile_path)

      code = Generator.generate_module("app.bsky.actor", [profile])

      assert code =~ "@doc"
      assert code =~ "## Parameters"
      assert code =~ "## Returns"
      assert code =~ "## Lexicon"
    end

    test "includes typespecs" do
      profile_path = Path.join(@fixtures_path, "app/bsky/actor/getProfile.json")
      {:ok, profile} = Parser.parse_file(profile_path)

      code = Generator.generate_module("app.bsky.actor", [profile])

      assert code =~ "@spec"
      assert code =~ "Client.t()"
    end
  end
end
