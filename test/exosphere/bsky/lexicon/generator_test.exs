defmodule Exosphere.Bsky.Lexicon.GeneratorTest do
  use ExUnit.Case, async: true

  alias Exosphere.Bsky.Lexicon.{Generator, Parser}

  @fixtures_path "test/fixtures/lexicons"

  describe "generate_module/2" do
    test "generates complete module from query lexicons" do
      path = Path.join(@fixtures_path, "app/bsky/actor/getProfile.json")
      {:ok, lexicon} = Parser.parse_file(path)

      code = Generator.generate_module("app.bsky.actor", [lexicon])

      assert code =~ "defmodule Exosphere.Bsky.Actor do"
      assert code =~ "@moduledoc"
      assert code =~ "Generated module for app.bsky.actor lexicons"
      assert code =~ "def get_profile(client, params \\\\ %{})"
      assert code =~ "Client.query(client, \"app.bsky.actor.getProfile\", params)"
    end

    test "generates complete module from procedure lexicons" do
      path = Path.join(@fixtures_path, "app/bsky/feed/post.json")
      {:ok, lexicon} = Parser.parse_file(path)

      code = Generator.generate_module("app.bsky.feed", [lexicon])

      assert code =~ "defmodule Exosphere.Bsky.Feed do"
      assert code =~ "def create_post(client, params \\\\ %{})"
      assert code =~ "Client.procedure(client, \"app.bsky.feed.createPost\", params)"
    end

    test "generates module with multiple lexicons" do
      profile_path = Path.join(@fixtures_path, "app/bsky/actor/getProfile.json")
      prefs_path = Path.join(@fixtures_path, "app/bsky/actor/getPreferences.json")

      {:ok, profile} = Parser.parse_file(profile_path)
      {:ok, prefs} = Parser.parse_file(prefs_path)

      code = Generator.generate_module("app.bsky.actor", [profile, prefs])

      assert code =~ "defmodule Exosphere.Bsky.Actor do"
      assert code =~ "def get_profile(client, params \\\\ %{})"
      assert code =~ "def get_preferences(client, params \\\\ %{})"
    end

    test "generates valid, compilable code" do
      path = Path.join(@fixtures_path, "app/bsky/actor/getProfile.json")
      {:ok, lexicon} = Parser.parse_file(path)

      code = Generator.generate_module("app.bsky.actor", [lexicon])

      # Should not raise
      assert {:ok, _} = Code.string_to_quoted(code)
    end
  end

  describe "namespace_to_module/1" do
    test "converts NSID namespace to module name" do
      assert Generator.namespace_to_module("app.bsky.actor") == "Exosphere.Bsky.Actor"
      assert Generator.namespace_to_module("com.atproto.repo") == "Exosphere.Atproto.Repo"
      assert Generator.namespace_to_module("app.bsky.feed") == "Exosphere.Bsky.Feed"
    end
  end

  describe "function_name/1" do
    test "extracts function name from NSID" do
      assert Generator.function_name("app.bsky.actor.getProfile") == "get_profile"
      assert Generator.function_name("com.atproto.repo.createRecord") == "create_record"
      assert Generator.function_name("app.bsky.feed.getLikes") == "get_likes"
    end
  end

  describe "generate_function_doc/1" do
    test "includes description" do
      lexicon = %{
        id: "app.bsky.test.method",
        type: :query,
        description: "Test method description",
        parameters: [],
        input: nil,
        output: nil,
        errors: []
      }

      doc = Generator.generate_function_doc(lexicon)

      assert doc =~ "Test method description"
    end

    test "includes parameter documentation" do
      lexicon = %{
        id: "app.bsky.test.method",
        type: :query,
        description: "Test method",
        parameters: [
          %{
            name: "actor",
            type: "string",
            format: "at-identifier",
            required: true,
            description: "The actor handle",
            minimum: nil,
            maximum: nil,
            min_length: nil,
            max_length: nil,
            max_graphemes: nil,
            enum: nil,
            default: nil
          }
        ],
        input: nil,
        output: nil,
        errors: []
      }

      doc = Generator.generate_function_doc(lexicon)

      assert doc =~ "## Parameters"
      assert doc =~ "`actor`"
      assert doc =~ "string"
      assert doc =~ "required"
      assert doc =~ "The actor handle"
      assert doc =~ "at-identifier"
    end

    test "includes constraint documentation" do
      lexicon = %{
        id: "app.bsky.test.method",
        type: :query,
        description: "Test method",
        parameters: [
          %{
            name: "limit",
            type: "integer",
            format: nil,
            required: false,
            description: "Max results",
            minimum: 1,
            maximum: 100,
            min_length: nil,
            max_length: nil,
            max_graphemes: nil,
            enum: nil,
            default: 50
          }
        ],
        input: nil,
        output: nil,
        errors: []
      }

      doc = Generator.generate_function_doc(lexicon)

      assert doc =~ "minimum: 1"
      assert doc =~ "maximum: 100"
      assert doc =~ "default: 50"
    end

    test "includes returns documentation" do
      lexicon = %{
        id: "app.bsky.test.method",
        type: :query,
        description: "Test",
        parameters: [],
        input: nil,
        output: nil,
        errors: []
      }

      doc = Generator.generate_function_doc(lexicon)

      assert doc =~ "## Returns"
      assert doc =~ "{:ok, result}"
      assert doc =~ "{:error, reason}"
    end

    test "includes lexicon info" do
      lexicon = %{
        id: "app.bsky.test.method",
        type: :query,
        description: "Test",
        parameters: [],
        input: nil,
        output: nil,
        errors: []
      }

      doc = Generator.generate_function_doc(lexicon)

      assert doc =~ "## Lexicon"
      assert doc =~ "NSID: `app.bsky.test.method`"
      assert doc =~ "Type: `query`"
    end
  end

  describe "generate_typespec/1" do
    test "generates proper typespec" do
      lexicon = %{
        id: "app.bsky.test.method",
        type: :query,
        description: "Test",
        parameters: [],
        input: nil,
        output: nil,
        errors: []
      }

      spec = Generator.generate_typespec(lexicon)

      assert spec =~ "@spec method"
      assert spec =~ "Client.t()"
      assert spec =~ "map()"
      assert spec =~ "{:ok, map()} | {:error, term()}"
    end
  end

  describe "generate_function_body/1" do
    test "generates query implementation for query type" do
      lexicon = %{
        id: "app.bsky.actor.getProfile",
        type: :query,
        description: "Test",
        parameters: [],
        input: nil,
        output: nil,
        errors: []
      }

      body = Generator.generate_function_body(lexicon)

      assert body =~ "Client.query(client, \"app.bsky.actor.getProfile\", params)"
    end

    test "generates procedure implementation for procedure type" do
      lexicon = %{
        id: "app.bsky.feed.createPost",
        type: :procedure,
        description: "Test",
        parameters: [],
        input: nil,
        output: nil,
        errors: []
      }

      body = Generator.generate_function_body(lexicon)

      assert body =~ "Client.procedure(client, \"app.bsky.feed.createPost\", params)"
    end
  end

  describe "generate_parameter_docs/1" do
    test "returns nil for empty parameters" do
      assert Generator.generate_parameter_docs([]) == nil
    end

    test "documents required and optional parameters" do
      params = [
        %{
          name: "required_param",
          type: "string",
          format: nil,
          required: true,
          description: "A required param",
          minimum: nil,
          maximum: nil,
          min_length: nil,
          max_length: nil,
          max_graphemes: nil,
          enum: nil,
          default: nil
        },
        %{
          name: "optional_param",
          type: "integer",
          format: nil,
          required: false,
          description: "An optional param",
          minimum: nil,
          maximum: nil,
          min_length: nil,
          max_length: nil,
          max_graphemes: nil,
          enum: nil,
          default: nil
        }
      ]

      doc = Generator.generate_parameter_docs(params)

      assert doc =~ "required_param"
      assert doc =~ "required"
      assert doc =~ "optional_param"
      assert doc =~ "optional"
    end

    test "documents enum constraints" do
      params = [
        %{
          name: "status",
          type: "string",
          format: nil,
          required: false,
          description: nil,
          minimum: nil,
          maximum: nil,
          min_length: nil,
          max_length: nil,
          max_graphemes: nil,
          enum: ["active", "inactive"],
          default: nil
        }
      ]

      doc = Generator.generate_parameter_docs(params)

      assert doc =~ ~s(enum: ["active", "inactive"])
    end
  end

  describe "generate_module_doc/2" do
    test "lists all methods" do
      lexicons = [
        %{id: "app.bsky.actor.getProfile", type: :query},
        %{id: "app.bsky.actor.getPreferences", type: :query}
      ]

      doc = Generator.generate_module_doc("app.bsky.actor", lexicons)

      assert doc =~ "## Methods"
      assert doc =~ "`get_profile/2`"
      assert doc =~ "`get_preferences/2`"
    end

    test "includes usage example" do
      lexicons = [
        %{id: "app.bsky.actor.getProfile", type: :query}
      ]

      doc = Generator.generate_module_doc("app.bsky.actor", lexicons)

      assert doc =~ "## Usage"
      assert doc =~ "Exosphere.XRPC.Client.new"
      assert doc =~ "Exosphere.Bsky.Actor.get_profile"
    end
  end
end
