defmodule Exosphere.Lexicon.RegistryTest do
  use ExUnit.Case, async: false

  alias Exosphere.Lexicon.{Parser, Registry}

  @json %{
    "lexicon" => 1,
    "id" => "com.example.post",
    "defs" => %{
      "main" => %{
        "type" => "record",
        "key" => "tid",
        "record" => %{
          "type" => "object",
          "required" => ["text"],
          "properties" => %{"text" => %{"type" => "string"}}
        }
      }
    }
  }

  setup do
    Registry.reset()
    on_exit(&Registry.reset/0)
    :ok
  end

  test "register/1 accepts raw JSON documents and parsed lexicons" do
    assert :ok = Registry.register(@json)
    assert Registry.registered?("com.example.post")

    {:ok, parsed} = Parser.parse(@json)
    assert :ok = Registry.register(parsed)

    assert {:ok, ^parsed} = Registry.fetch("com.example.post")
  end

  test "register/1 rejects invalid documents" do
    assert {:error, _} = Registry.register(%{"id" => "com.example.post"})
    refute Registry.registered?("com.example.post")
  end

  # Feedback §1: a %Schema{} struct matches the parsed-lexicon map clause
  # and used to poison the registry — every later validation failed.
  test "register/1 unwraps %Schema{} structs" do
    assert {:ok, schema} = Exosphere.Lexicon.Schema.new(@json)
    assert :ok = Registry.register(schema)

    assert :ok =
             Registry.validate("com.example.post", %{
               "$type" => "com.example.post",
               "text" => "hi"
             })
  end

  # Feedback §3: parse_dir/1 returns %{nsid => lexicon}; register_all
  # used to raise FunctionClauseError on it.
  test "register_all/1 accepts a Parser.parse_dir/1 result map" do
    dir = Application.app_dir(:exosphere, "priv/lexicons/app/bsky/actor")
    {:ok, lexicons} = Parser.parse_dir(dir)
    assert :ok = Registry.register_all(lexicons)
    assert Registry.registered?("app.bsky.actor.profile")
  end

  test "load_dir/1 registers a directory of lexicon JSON" do
    assert {:ok, nsids} =
             Registry.load_dir(Application.app_dir(:exosphere, "priv/lexicons/community"))

    assert "community.lexicon.interaction.like" in nsids
    assert Registry.registered?("community.lexicon.interaction.like")
  end

  test "validate/3 type-checks against registered lexicons" do
    Registry.register(@json)

    assert :ok =
             Registry.validate("com.example.post", %{
               "$type" => "com.example.post",
               "text" => "hi"
             })

    assert {:error, [{"text", _}]} =
             Registry.validate("com.example.post", %{
               "$type" => "com.example.post",
               "text" => 123
             })

    # Fragment form addresses non-main defs
    assert {:error, [{"", "unknown definition com.example.post#other"}]} =
             Registry.validate("com.example.post#other", %{})
  end

  test "validate/3 with optimistic passes unregistered types" do
    assert {:error, _} = Registry.validate("com.unknown.thing", %{})
    assert :ok = Registry.validate("com.unknown.thing", %{}, optimistic: true)
  end

  test "validate/3 strict rejects unknown fields" do
    Registry.register(@json)

    value = %{"$type" => "com.example.post", "text" => "hi", "extra" => 1}
    assert :ok = Registry.validate("com.example.post", value)

    assert {:error, [{"extra", "unknown field"}]} =
             Registry.validate("com.example.post", value, strict: true)
  end

  test "load_vendored/0 registers the vendored corpus" do
    assert {:ok, nsids} = Registry.load_vendored()
    assert "app.bsky.feed.post" in nsids
    assert "com.atproto.lexicon.schema" in nsids
    assert Registry.registered?("community.lexicon.interaction.like")
  after
    Registry.reset()
  end
end
