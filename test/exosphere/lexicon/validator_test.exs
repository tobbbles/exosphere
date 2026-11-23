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

  # Feedback §2: an unresolved cross-lexicon ref used to pass silently,
  # even with strict: true — the green light came from a check that
  # was not running.
  test "strict: true errors on unresolved refs", %{lexicon: lexicon} do
    # com.example.other is not registered anywhere in this test
    value = %{
      "text" => "hi",
      "createdAt" => "2026-08-25T12:00:00.000Z",
      "choice" => %{"$type" => "com.someone.else#thing"}
    }

    # Permissive: unresolved variant of an open union passes
    assert :ok = Validator.validate(value, lexicon)

    # A ref *field* with an unregistered target passes permissively...
    ref_field = %{
      "text" => "hi",
      "createdAt" => "2026-08-25T12:00:00.000Z",
      "subject" => %{"uri" => "at://did:plc:abc/app.bsky.feed.post/3j"}
    }

    registry_lexicon =
      lexicon!(
        put_in(@lexicon, ["defs", "subjectRef"], %{
          "type" => "ref",
          "ref" => "com.atproto.repo.strongRef"
        })
      )

    assert :ok = Validator.validate(ref_field, registry_lexicon)

    # ...but errors under strict
    assert {:error, errors} =
             Validator.validate(ref_field, registry_lexicon, "main", strict: true)

    assert Enum.any?(errors, fn {"subject", msg} ->
             msg =~ "unresolved ref com.atproto.repo.strongRef"
           end)

    # and resolves once the target is registered
    assert {:ok, strong_ref} =
             Parser.parse(%{
               "lexicon" => 1,
               "id" => "com.atproto.repo.strongRef",
               "defs" => %{
                 "main" => %{
                   "type" => "object",
                   "required" => ["cid"],
                   "properties" => %{"cid" => %{"type" => "string"}}
                 }
               }
             })

    assert {:error, errors} =
             Validator.validate(ref_field, registry_lexicon, "main",
               registry: %{"com.atproto.repo.strongRef" => strong_ref},
               strict: true
             )

    assert {"subject.cid", "missing required field"} in errors
  end

  test "spec string formats: language, tid, record-key, at-identifier" do
    lexicon =
      lexicon!(%{
        "lexicon" => 1,
        "id" => "com.example.formats",
        "defs" => %{
          "main" => %{
            "type" => "object",
            "properties" => %{
              "lang" => %{"type" => "string", "format" => "language"},
              "tid" => %{"type" => "string", "format" => "tid"},
              "rkey" => %{"type" => "string", "format" => "record-key"},
              "ident" => %{"type" => "string", "format" => "at-identifier"}
            }
          }
        }
      })

    good = %{
      "lang" => "pt-BR",
      "tid" => "3jzfcijpj2z2a",
      "rkey" => "3jzfcijpj2z2a",
      "ident" => "did:plc:abc123"
    }

    assert :ok = Validator.validate(good, lexicon)

    bad = %{good | "lang" => "not a language", "tid" => "!!"}
    assert {:error, errors} = Validator.validate(bad, lexicon)
    assert Enum.any?(errors, fn {_path, msg} -> msg =~ "invalid language" end)
    assert Enum.any?(errors, fn {_path, msg} -> msg =~ "invalid tid" end)
  end

  describe "an app.bsky.feed.post with an image embed (vendored lexicons)" do
    defp vendored(nsid) do
      path =
        Application.app_dir(
          :exosphere,
          Path.join(["priv", "lexicons" | String.split(nsid, ".")]) <> ".json"
        )

      path |> File.read!() |> Jason.decode!() |> lexicon!()
    end

    setup do
      ids = ~w(app.bsky.feed.post app.bsky.embed.images app.bsky.embed.defs)
      registry = Map.new(ids, &{&1, vendored(&1)})
      %{registry: registry, post: registry["app.bsky.feed.post"]}
    end

    defp blob(mime, size \\ 12_345) do
      %{
        "$type" => "blob",
        "ref" => %{"$link" => "bafkreiccldh766hwcnuxnf2wh6jgzepf2nlu2lvcllt63eww5p6chi4ity"},
        "mimeType" => mime,
        "size" => size
      }
    end

    defp image_post(image) do
      %{
        "$type" => "app.bsky.feed.post",
        "text" => "look",
        "createdAt" => "2026-11-23T12:00:00.000Z",
        "embed" => %{"$type" => "app.bsky.embed.images", "images" => [image]}
      }
    end

    test "a real image post validates (image/* accepts image/jpeg)", ctx do
      post = image_post(%{"image" => blob("image/jpeg"), "alt" => "a cat"})

      assert :ok = Validator.validate_record(post, ctx.post, registry: ctx.registry)
      assert :ok = Validator.validate_record(post, ctx.post, registry: ctx.registry, strict: true)
    end

    test "the variant's local #image ref is checked in its own lexicon", ctx do
      # `alt` is required by app.bsky.embed.images#image; before the variant
      # kept its lexicon context the `#image` ref resolved against
      # app.bsky.feed.post (which has no #image) and was skipped.
      post = image_post(%{"image" => blob("image/png")})

      assert {:error, errors} = Validator.validate_record(post, ctx.post, registry: ctx.registry)
      assert {"embed.images[0].alt", "missing required field"} in errors
    end

    test "the accept wildcard still rejects a non-image and maxSize applies", ctx do
      not_image = image_post(%{"image" => blob("video/mp4"), "alt" => ""})

      assert {:error, [{"embed.images[0].image", "mimeType not in accept list"}]} =
               Validator.validate_record(not_image, ctx.post, registry: ctx.registry)

      too_big = image_post(%{"image" => blob("image/png", 2_000_001), "alt" => ""})

      assert {:error, [{"embed.images[0].image", "larger than maxSize 2000000"}]} =
               Validator.validate_record(too_big, ctx.post, registry: ctx.registry)
    end
  end

  test "blob accept patterns: exact, type/*, */*, and no partial globs" do
    lexicon =
      lexicon!(%{
        "lexicon" => 1,
        "id" => "com.example.blobs",
        "defs" => %{
          "main" => %{
            "type" => "object",
            "properties" => %{
              "exact" => %{"type" => "blob", "accept" => ["image/png"]},
              "family" => %{"type" => "blob", "accept" => ["image/*", "text/plain"]},
              "any" => %{"type" => "blob", "accept" => ["*/*"]},
              "partial" => %{"type" => "blob", "accept" => ["text/ht*"]}
            }
          }
        }
      })

    blob = fn mime ->
      %{
        "$type" => "blob",
        "ref" => %{"$link" => "bafkreiccldh766hwcnuxnf2wh6jgzepf2nlu2lvcllt63eww5p6chi4ity"},
        "mimeType" => mime,
        "size" => 1
      }
    end

    ok = fn field, mime -> Validator.validate(%{field => blob.(mime)}, lexicon) == :ok end

    assert ok.("exact", "image/png")
    assert ok.("exact", "IMAGE/PNG")
    refute ok.("exact", "image/jpeg")

    assert ok.("family", "image/webp")
    assert ok.("family", "text/plain")
    refute ok.("family", "text/html")
    refute ok.("family", "imagex/png")
    refute ok.("family", "image")

    assert ok.("any", "application/octet-stream")

    refute ok.("partial", "text/html")
  end

  test "unknown string formats are not checked" do
    # The validator stays permissive on format names it does not know
    # (mix exosphere.lint.lexicons warns about them instead)
    lexicon =
      lexicon!(%{
        "lexicon" => 1,
        "id" => "com.example.formats",
        "defs" => %{
          "main" => %{
            "type" => "object",
            "properties" => %{"a" => %{"type" => "string", "format" => "datetim"}}
          }
        }
      })

    assert :ok = Validator.validate(%{"a" => "anything"}, lexicon)
  end
end
