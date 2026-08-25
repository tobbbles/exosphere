defmodule Exosphere.Lexicon.ValidatorTest do
  use ExUnit.Case, async: true

  alias Exosphere.Lexicon.{Parser, Validator}

  defp lexicon!(json), do: Parser.parse(json) |> elem(1)

  @lexicon %{
    "lexicon" => 1,
    "id" => "com.example.post",
    "defs" => %{
      "main" => %{
        "type" => "record",
        "key" => "tid",
        "record" => %{
          "type" => "object",
          "required" => ["text", "createdAt"],
          "nullable" => ["subject"],
          "properties" => %{
            "text" => %{"type" => "string", "maxGraphemes" => 5, "maxLength" => 20},
            "createdAt" => %{"type" => "string", "format" => "datetime"},
            "subject" => %{"type" => "ref", "ref" => "#subjectRef"},
            "status" => %{"type" => "string", "enum" => ["ok", "no"]},
            "tags" => %{"type" => "array", "items" => %{"type" => "string"}, "maxLength" => 2},
            "choice" => %{"type" => "union", "refs" => ["#plain", "com.example.other#thing"]},
            "link" => %{"type" => "cid-link"},
            "count" => %{"type" => "integer", "minimum" => 1, "maximum" => 10}
          }
        }
      },
      "subjectRef" => %{
        "type" => "object",
        "required" => ["uri"],
        "properties" => %{"uri" => %{"type" => "string", "format" => "at-uri"}}
      },
      "plain" => %{"type" => "object", "properties" => %{"v" => %{"type" => "string"}}}
    }
  }

  setup do
    %{lexicon: lexicon!(@lexicon)}
  end

  test "validates a conforming record", %{lexicon: lexicon} do
    value = %{
      "$type" => "com.example.post",
      "text" => "hello",
      "createdAt" => "2026-08-25T12:00:00.000Z",
      "status" => "ok",
      "tags" => ["a", "b"],
      "subject" => nil,
      "count" => 5
    }

    assert :ok = Validator.validate(value, lexicon)
    assert :ok = Validator.validate_record(value, lexicon)
  end

  test "missing required fields error", %{lexicon: lexicon} do
    assert {:error, errors} = Validator.validate(%{"text" => "hi"}, lexicon)
    assert {"createdAt", "missing required field"} in errors
  end

  test "null is allowed only for nullable fields", %{lexicon: lexicon} do
    assert :ok =
             Validator.validate(
               %{"text" => "hi", "createdAt" => "2026-08-25T12:00:00.000Z", "subject" => nil},
               lexicon
             )

    assert {:error, errors} =
             Validator.validate(
               %{"text" => nil, "createdAt" => "2026-08-25T12:00:00.000Z"},
               lexicon
             )

    assert {"text", "null but not nullable"} in errors
  end

  test "unknown fields are ignored unless strict", %{lexicon: lexicon} do
    value = %{"text" => "hi", "createdAt" => "2026-08-25T12:00:00.000Z", "future" => true}
    assert :ok = Validator.validate(value, lexicon)

    assert {:error, errors} = Validator.validate(value, lexicon, "main", strict: true)
    assert {"future", "unknown field"} in errors
  end

  test "maxLength counts UTF-8 bytes while maxGraphemes counts graphemes", %{lexicon: lexicon} do
    # 5 flag graphemes, 40 bytes: within maxGraphemes 5, over maxLength 20
    value = %{"text" => "🇯🇵🇯🇵🇯🇵🇯🇵🇯🇵", "createdAt" => "2026-08-25T12:00:00.000Z"}
    assert {:error, [{"text", msg}]} = Validator.validate(value, lexicon)
    assert msg =~ "maxLength"

    # 6 single-byte graphemes: within maxLength 20, over maxGraphemes 5
    value = %{"text" => "abcdef", "createdAt" => "2026-08-25T12:00:00.000Z"}
    assert {:error, [{"text", msg}]} = Validator.validate(value, lexicon)
    assert msg =~ "maxGraphemes"
  end

  test "string format validation", %{lexicon: lexicon} do
    value = %{"text" => "hi", "createdAt" => "not-a-date"}
    assert {:error, [{"createdAt", msg}]} = Validator.validate(value, lexicon)
    assert msg =~ "datetime"
  end

  test "enum is closed", %{lexicon: lexicon} do
    value = %{"text" => "hi", "createdAt" => "2026-08-25T12:00:00.000Z", "status" => "maybe"}

    assert {:error, [{"status", _}]} = Validator.validate(value, lexicon)
  end

  test "array length and item validation", %{lexicon: lexicon} do
    value = %{"text" => "hi", "createdAt" => "2026-08-25T12:00:00.000Z", "tags" => [1, 2]}

    assert {:error, errors} = Validator.validate(value, lexicon)
    assert {"tags[0]", "expected a string"} in errors

    value = %{
      "text" => "hi",
      "createdAt" => "2026-08-25T12:00:00.000Z",
      "tags" => ["a", "b", "c"]
    }

    assert {:error, [{"tags", msg}]} = Validator.validate(value, lexicon)
    assert msg =~ "maxLength"
  end

  test "ref validation resolves local defs", %{lexicon: lexicon} do
    value = %{
      "text" => "hi",
      "createdAt" => "2026-08-25T12:00:00.000Z",
      "subject" => %{"uri" => "at://did:plc:abc/com.example.post/3j"}
    }

    assert :ok = Validator.validate(value, lexicon)

    value = %{
      "text" => "hi",
      "createdAt" => "2026-08-25T12:00:00.000Z",
      "subject" => %{"uri" => "nope"}
    }

    assert {:error, [{"subject.uri", msg}]} = Validator.validate(value, lexicon)
    assert msg =~ "at-uri"
  end

  test "unions are open: unknown $type passes, known variant validates", %{lexicon: lexicon} do
    value = %{
      "text" => "hi",
      "createdAt" => "2026-08-25T12:00:00.000Z",
      "choice" => %{"$type" => "com.example.post#plain", "v" => 123}
    }

    assert {:error, [{"choice.v", "expected a string"}]} = Validator.validate(value, lexicon)

    value = %{
      "text" => "hi",
      "createdAt" => "2026-08-25T12:00:00.000Z",
      "choice" => %{"$type" => "com.someone.else#thing", "anything" => true}
    }

    assert :ok = Validator.validate(value, lexicon)
    assert {:error, errors} = Validator.validate(value, lexicon, "main", strict: true)

    assert Enum.any?(errors, fn
             {"choice.$type", msg} -> msg =~ "unknown union variant"
             _ -> false
           end)
  end

  test "union values must be objects with $type", %{lexicon: lexicon} do
    value = %{"text" => "hi", "createdAt" => "2026-08-25T12:00:00.000Z", "choice" => "plain"}
    assert {:error, [{"choice", _}]} = Validator.validate(value, lexicon)
  end

  test "closed unions reject unknown variants" do
    lexicon =
      lexicon!(
        put_in(@lexicon, ["defs", "main", "record", "properties", "choice"], %{
          "type" => "union",
          "refs" => ["#plain"],
          "closed" => true
        })
      )

    value = %{
      "text" => "hi",
      "createdAt" => "2026-08-25T12:00:00.000Z",
      "choice" => %{"$type" => "com.example.post#plain"}
    }

    assert :ok = Validator.validate(value, lexicon)

    value = %{
      "text" => "hi",
      "createdAt" => "2026-08-25T12:00:00.000Z",
      "choice" => %{"$type" => "com.example.other#thing"}
    }

    assert {:error, [{"choice.$type", msg}]} = Validator.validate(value, lexicon)
    assert msg =~ "closed union"
  end

  test "integer bounds", %{lexicon: lexicon} do
    value = %{"text" => "hi", "createdAt" => "2026-08-25T12:00:00.000Z", "count" => 99}
    assert {:error, [{"count", msg}]} = Validator.validate(value, lexicon)
    assert msg =~ "maximum"
  end

  test "cid-link validation", %{lexicon: lexicon} do
    value = %{
      "text" => "hi",
      "createdAt" => "2026-08-25T12:00:00.000Z",
      "link" => %{"$link" => "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"}
    }

    assert :ok = Validator.validate(value, lexicon)

    value = %{
      "text" => "hi",
      "createdAt" => "2026-08-25T12:00:00.000Z",
      "link" => %{"$link" => "x"}
    }

    assert {:error, [{"link.$link", _} | _]} = Validator.validate(value, lexicon)
  end

  test "cross-lexicon refs resolve through the registry option", %{lexicon: lexicon} do
    other =
      lexicon!(%{
        "lexicon" => 1,
        "id" => "com.example.other",
        "defs" => %{
          "thing" => %{
            "type" => "object",
            "required" => ["n"],
            "properties" => %{"n" => %{"type" => "integer"}}
          }
        }
      })

    value = %{
      "text" => "hi",
      "createdAt" => "2026-08-25T12:00:00.000Z",
      "choice" => %{"$type" => "com.example.other#thing"}
    }

    # Without the target registered: unknown variant in an open union passes
    assert :ok = Validator.validate(value, lexicon)

    # With it registered: the variant's own required fields are checked
    assert {:error, [{"choice.n", "missing required field"}]} =
             Validator.validate(value, lexicon, "main", registry: %{"com.example.other" => other})
  end

  test "validate_record checks $type", %{lexicon: lexicon} do
    value = %{
      "$type" => "com.example.wrong",
      "text" => "hi",
      "createdAt" => "2026-08-25T12:00:00.000Z"
    }

    assert {:error, [{"$type", _}]} = Validator.validate_record(value, lexicon)
  end
end
