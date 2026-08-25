defmodule Mix.Tasks.Exosphere.Lint.LexiconsTest do
  use ExUnit.Case, async: false

  @valid %{
    "lexicon" => 1,
    "id" => "com.example.post",
    "description" => "example",
    "defs" => %{
      "main" => %{
        "type" => "record",
        "description" => "a post",
        "key" => "tid",
        "record" => %{
          "type" => "object",
          "description" => "the post body",
          "required" => ["text"],
          "properties" => %{
            "text" => %{"type" => "string", "description" => "the text"}
          }
        }
      }
    }
  }

  setup do
    Mix.shell(Mix.Shell.Process)
    dir = Path.join(System.tmp_dir!(), "exosphere-lint-#{System.unique_integer()}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)
    {:ok, dir: dir}
  end

  test "a valid lexicon lints clean", %{dir: dir} do
    write!(dir, "good.json", @valid)

    Mix.Tasks.Exosphere.Lint.Lexicons.run([dir])
    assert_received {:mix_shell, :info, [summary]}
    assert summary =~ "0 error(s) 0 warning(s)"
    refute_received {:mix_shell, :error, _}
  end

  test "spec violations are errors and exit non-zero", %{dir: dir} do
    broken =
      @valid
      |> Map.delete("description")
      |> put_in(["defs", "main"], Map.delete(@valid["defs"]["main"], "key"))

    write!(dir, "broken.json", broken)

    assert catch_exit(Mix.Tasks.Exosphere.Lint.Lexicons.run([dir])) == {:shutdown, 1}
    assert_received {:mix_shell, :error, [message]}
    assert message =~ "record definitions require a key"
  end

  test "missing descriptions are warnings, not errors", %{dir: dir} do
    undescribed =
      put_in(@valid, ["defs", "main", "record", "properties", "text"], %{"type" => "string"})

    write!(dir, "no-desc.json", undescribed)

    Mix.Tasks.Exosphere.Lint.Lexicons.run([dir])
    assert_received {:mix_shell, :info, [summary]}
    assert summary =~ "0 error(s) 1 warning(s)"
    assert_received {:mix_shell, :error, [warning]}
    assert warning =~ "warning: property has no description"

    # --strict promotes warnings to failures
    assert catch_exit(Mix.Tasks.Exosphere.Lint.Lexicons.run(["--strict", dir])) == {:shutdown, 1}
  end

  test "invalid JSON is an error", %{dir: dir} do
    File.write!(Path.join(dir, "broken.json"), "{not json")

    assert catch_exit(Mix.Tasks.Exosphere.Lint.Lexicons.run([dir])) == {:shutdown, 1}
    assert_received {:mix_shell, :error, [message]}
    assert message =~ "invalid JSON"
  end

  test "unknown paths raise", %{dir: dir} do
    missing = Path.join(dir, "nope")

    assert_raise Mix.Error, ~r/no such file or directory/, fn ->
      Mix.Tasks.Exosphere.Lint.Lexicons.run([missing])
    end
  end

  defp write!(dir, name, json) do
    File.write!(Path.join(dir, name), Jason.encode!(json, pretty: true))
  end
end
