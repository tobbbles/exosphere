defmodule Exosphere.Bsky.Lexicon.ParserTest do
  use ExUnit.Case, async: true

  alias Exosphere.Bsky.Lexicon.Parser

  @fixtures_path "test/fixtures/lexicons"

  describe "parse_file/1" do
    test "parses valid query lexicon" do
      path = Path.join(@fixtures_path, "app/bsky/actor/getProfile.json")
      assert {:ok, lexicon} = Parser.parse_file(path)

      assert lexicon.id == "app.bsky.actor.getProfile"
      assert lexicon.type == :query

      assert lexicon.description ==
               "Get detailed profile view of an actor. Does not require auth, but contains relevant metadata with auth."
    end

    test "parses valid procedure lexicon" do
      path = Path.join(@fixtures_path, "app/bsky/feed/post.json")
      assert {:ok, lexicon} = Parser.parse_file(path)

      assert lexicon.id == "app.bsky.feed.createPost"
      assert lexicon.type == :procedure
      assert lexicon.description == "Create a new post record. Requires authentication."
    end

    test "returns error for non-existent file" do
      assert {:error, :enoent} = Parser.parse_file("nonexistent.json")
    end
  end

  describe "parse/1" do
    test "parses valid query with parameters" do
      json = %{
        "lexicon" => 1,
        "id" => "app.bsky.actor.getProfile",
        "defs" => %{
          "main" => %{
            "type" => "query",
            "description" => "Get a profile",
            "parameters" => %{
              "type" => "params",
              "required" => ["actor"],
              "properties" => %{
                "actor" => %{
                  "type" => "string",
                  "format" => "at-identifier",
                  "description" => "Handle or DID"
                }
              }
            }
          }
        }
      }

      assert {:ok, lexicon} = Parser.parse(json)

      assert lexicon.id == "app.bsky.actor.getProfile"
      assert lexicon.type == :query
      assert length(lexicon.parameters) == 1

      [actor_param] = lexicon.parameters
      assert actor_param.name == "actor"
      assert actor_param.type == "string"
      assert actor_param.format == "at-identifier"
      assert actor_param.required == true
      assert actor_param.description == "Handle or DID"
    end

    test "parses valid procedure with input/output" do
      json = %{
        "lexicon" => 1,
        "id" => "app.bsky.feed.createPost",
        "defs" => %{
          "main" => %{
            "type" => "procedure",
            "description" => "Create a post",
            "input" => %{
              "encoding" => "application/json",
              "schema" => %{"type" => "object"}
            },
            "output" => %{
              "encoding" => "application/json",
              "schema" => %{"type" => "object"}
            }
          }
        }
      }

      assert {:ok, lexicon} = Parser.parse(json)

      assert lexicon.type == :procedure
      assert lexicon.input != nil
      assert lexicon.input.encoding == "application/json"
      assert lexicon.output != nil
      assert lexicon.output.encoding == "application/json"
    end

    test "parses errors definitions" do
      json = %{
        "lexicon" => 1,
        "id" => "app.bsky.test.method",
        "defs" => %{
          "main" => %{
            "type" => "procedure",
            "errors" => [
              %{"name" => "InvalidSwap", "description" => "Swap failed"},
              %{"name" => "RecordNotFound"}
            ]
          }
        }
      }

      assert {:ok, lexicon} = Parser.parse(json)

      assert length(lexicon.errors) == 2
      [error1, error2] = lexicon.errors
      assert error1.name == "InvalidSwap"
      assert error1.description == "Swap failed"
      assert error2.name == "RecordNotFound"
      assert error2.description == nil
    end

    test "parses parameter constraints" do
      json = %{
        "lexicon" => 1,
        "id" => "app.bsky.test.method",
        "defs" => %{
          "main" => %{
            "type" => "query",
            "parameters" => %{
              "properties" => %{
                "limit" => %{
                  "type" => "integer",
                  "minimum" => 1,
                  "maximum" => 100,
                  "default" => 50
                },
                "name" => %{
                  "type" => "string",
                  "minLength" => 1,
                  "maxLength" => 256,
                  "maxGraphemes" => 64
                },
                "status" => %{
                  "type" => "string",
                  "enum" => ["active", "inactive", "pending"]
                }
              }
            }
          }
        }
      }

      assert {:ok, lexicon} = Parser.parse(json)

      params = Map.new(lexicon.parameters, &{&1.name, &1})

      assert params["limit"].minimum == 1
      assert params["limit"].maximum == 100
      assert params["limit"].default == 50

      assert params["name"].min_length == 1
      assert params["name"].max_length == 256
      assert params["name"].max_graphemes == 64

      assert params["status"].enum == ["active", "inactive", "pending"]
    end

    test "rejects invalid lexicon version" do
      json = %{
        "lexicon" => 2,
        "id" => "app.bsky.test.method",
        "defs" => %{"main" => %{"type" => "query"}}
      }

      assert {:error, {:unsupported_lexicon_version, 2}} = Parser.parse(json)
    end

    test "rejects missing lexicon version" do
      json = %{
        "id" => "app.bsky.test.method",
        "defs" => %{"main" => %{"type" => "query"}}
      }

      assert {:error, :missing_lexicon_version} = Parser.parse(json)
    end

    test "rejects missing id" do
      json = %{
        "lexicon" => 1,
        "defs" => %{"main" => %{"type" => "query"}}
      }

      assert {:error, :missing_id} = Parser.parse(json)
    end

    test "rejects invalid NSID" do
      json = %{
        "lexicon" => 1,
        "id" => "invalid",
        "defs" => %{"main" => %{"type" => "query"}}
      }

      assert {:error, {:invalid_nsid, "invalid"}} = Parser.parse(json)
    end

    test "rejects missing defs" do
      json = %{
        "lexicon" => 1,
        "id" => "app.bsky.test.method"
      }

      assert {:error, :missing_defs} = Parser.parse(json)
    end

    test "rejects missing main def" do
      json = %{
        "lexicon" => 1,
        "id" => "app.bsky.test.method",
        "defs" => %{"other" => %{"type" => "query"}}
      }

      assert {:error, :missing_main_def} = Parser.parse(json)
    end

    test "rejects unsupported type" do
      json = %{
        "lexicon" => 1,
        "id" => "app.bsky.test.method",
        "defs" => %{"main" => %{"type" => "subscription"}}
      }

      assert {:error, {:unsupported_type, "subscription"}} = Parser.parse(json)
    end

    test "rejects invalid input format" do
      assert {:error, :invalid_lexicon_format} = Parser.parse("not a map")
      assert {:error, :invalid_lexicon_format} = Parser.parse(nil)
      assert {:error, :invalid_lexicon_format} = Parser.parse([])
    end
  end

  describe "namespace/1" do
    test "extracts namespace from NSID" do
      assert Parser.namespace("app.bsky.actor.getProfile") == "app.bsky.actor"
      assert Parser.namespace("com.atproto.repo.createRecord") == "com.atproto.repo"
    end
  end

  describe "method_name/1" do
    test "extracts method name from NSID" do
      assert Parser.method_name("app.bsky.actor.getProfile") == "getProfile"
      assert Parser.method_name("com.atproto.repo.createRecord") == "createRecord"
    end
  end

  describe "validate_param_type/1" do
    test "accepts valid types" do
      assert :ok = Parser.validate_param_type("string")
      assert :ok = Parser.validate_param_type("integer")
      assert :ok = Parser.validate_param_type("boolean")
      assert :ok = Parser.validate_param_type("array")
      assert :ok = Parser.validate_param_type("unknown")
    end

    test "rejects invalid types" do
      assert {:error, {:invalid_param_type, "invalid"}} = Parser.validate_param_type("invalid")
    end
  end

  describe "validate_format/1" do
    test "accepts valid formats" do
      assert :ok = Parser.validate_format("at-identifier")
      assert :ok = Parser.validate_format("did")
      assert :ok = Parser.validate_format("handle")
      assert :ok = Parser.validate_format("uri")
      assert :ok = Parser.validate_format("datetime")
      assert :ok = Parser.validate_format(nil)
    end

    test "rejects invalid formats" do
      assert {:error, {:invalid_format, "invalid"}} = Parser.validate_format("invalid")
    end
  end
end

