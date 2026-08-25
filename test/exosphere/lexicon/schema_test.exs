defmodule Exosphere.Lexicon.SchemaTest do
  use ExUnit.Case, async: true

  alias Exosphere.Lexicon.Schema

  @valid %{
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

  test "new/1 builds a schema from a valid document" do
    assert {:ok, schema} = Schema.new(@valid)
    assert schema.id == "com.example.post"
    assert schema.lexicon == 1
    assert Schema.record_key(schema) == "com.example.post"
    assert schema.parsed.defs["main"].kind == :record
  end

  test "new/1 accepts atom keys" do
    assert {:ok, schema} =
             Schema.new(%{lexicon: 1, id: "com.example.post", defs: @valid["defs"]})

    assert schema.id == "com.example.post"
  end

  test "new/1 rejects unsupported lexicon versions" do
    assert {:error, [{"", msg} | _]} = Schema.new(Map.put(@valid, "lexicon", 2))
    assert msg =~ "unsupported_lexicon_version"
  end

  test "new/1 rejects an id that is not a simple NSID" do
    assert {:error, errors} = Schema.new(Map.put(@valid, "id", "com.example.post#main"))
    assert {"id", "must be a simple NSID without a fragment"} in errors
  end

  test "new/1 rejects record defs without a key" do
    broken =
      put_in(@valid, ["defs", "main"], %{
        "type" => "record",
        "record" => %{"type" => "object", "properties" => %{}}
      })

    assert {:error, errors} = Schema.new(broken)
    assert {"defs.main.key", "record definitions require a key"} in errors
  end

  test "new/1 rejects multiple primary defs" do
    broken = put_in(@valid, ["defs", "extra"], %{"type" => "query", "parameters" => %{}})

    assert {:error, errors} = Schema.new(broken)
    assert {"defs", "multiple primary definitions: extra, main"} in errors
  end

  test "new/1 rejects refs pointing at unions" do
    broken =
      put_in(@valid, ["defs", "main", "record", "properties"], %{
        "text" => %{"type" => "string"},
        "choice" => %{"type" => "ref", "ref" => "#choices"}
      })
      |> put_in(["defs", "choices"], %{"type" => "union", "refs" => ["#main"]})

    assert {:error, errors} = Schema.new(broken)
    assert Enum.any?(errors, fn {_path, msg} -> String.contains?(msg, "union") end)
  end

  test "new/1 rejects unresolvable local refs" do
    broken =
      put_in(@valid, ["defs", "main", "record", "properties"], %{
        "text" => %{"type" => "string"},
        "thing" => %{"type" => "ref", "ref" => "#nope"}
      })

    assert {:error, errors} = Schema.new(broken)
    assert Enum.any?(errors, fn {_path, msg} -> msg =~ "unresolvable ref" end)
  end

  test "to_record/1 round-trips through from_record/1" do
    {:ok, schema} = Schema.new(Map.put(@valid, "description", "example lexicon"))
    record = Schema.to_record(schema)

    assert record["$type"] == "com.atproto.lexicon.schema"
    assert record["id"] == "com.example.post"
    assert record["defs"] == @valid["defs"]
    assert record["description"] == "example lexicon"

    assert {:ok, ^schema} = Schema.from_record(record)
  end

  test "from_record/1 rejects other record types" do
    assert {:error, [{"$type", _}]} = Schema.from_record(%{"$type" => "app.bsky.feed.post"})
  end
end
