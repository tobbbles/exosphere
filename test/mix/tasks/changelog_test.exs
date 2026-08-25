defmodule Exosphere.ChangelogTest do
  use ExUnit.Case, async: true

  alias Exosphere.Changelog

  @fixture """
  # Changelog

  Intro.

  ## [Unreleased]

  Prose about the pending release.

  ### Fixed (breaking — output changes)

  - **Encoding.** Wrapped prose
    continues here.

  ### Added

  - Existing entry (#6)

  ### Internal

  - CI tweak (#7)

  ## [0.2.0] - 2026-04-28

  ### Added

  - Old entry (#3)
  """

  describe "classify/1" do
    test "maps conventional types to groups" do
      assert Changelog.classify("feat: add MST support") == {:ok, "Added", "add MST support"}

      assert Changelog.classify("fix(mst): crash on empty frame") ==
               {:ok, "Fixed", "crash on empty frame"}

      assert Changelog.classify("refactor: tidy CAR reader") ==
               {:ok, "Changed", "tidy CAR reader"}

      assert Changelog.classify("docs: document XRPC") == {:ok, "Docs", "document XRPC"}
      assert Changelog.classify("chore: bump deps") == {:ok, "Internal", "bump deps"}
    end

    test "bang titles file under Breaking" do
      assert Changelog.classify("feat!: replace encoder") == {:ok, "Breaking", "replace encoder"}

      assert Changelog.classify("fix(crypto)!: reject high-S") ==
               {:ok, "Breaking", "reject high-S"}
    end

    test "unrecognised titles are skipped" do
      assert Changelog.classify("Add stuff") == :skip
      assert Changelog.classify("unknown: stuff") == :skip
    end
  end

  describe "add_entry/3" do
    test "appends to an existing group after its last entry" do
      {:ok, out} = Changelog.add_entry(@fixture, "Added", "- New entry (#8)")

      assert out =~ ~r/- Existing entry \(#6\)\n- New entry \(#8\)/
    end

    test "creates a missing group without merging into a qualified one" do
      {:ok, out} = Changelog.add_entry(@fixture, "Fixed", "- Bug fix (#9)")

      # "Fixed" must not merge into "Fixed (breaking — …)" and slots in before Internal
      assert out =~ ~r/### Fixed\n- Bug fix \(#9\)\n\n### Internal/
      assert out =~ "### Fixed (breaking — output changes)\n"
    end

    test "creates a Breaking group ahead of the others" do
      {:ok, out} = Changelog.add_entry(@fixture, "Breaking", "- Removal (#10)")

      assert out =~ ~r/### Breaking\n- Removal \(#10\)\n\n### Added/
    end

    test "errors when there is no Unreleased section" do
      assert Changelog.add_entry("# Changelog\n", "Added", "- x (#1)") ==
               {:error, :no_unreleased}
    end
  end

  describe "unreleased_body/1 and detect_level/1" do
    test "returns the trimmed section text" do
      {:ok, body} = Changelog.unreleased_body(@fixture)

      assert body =~ "Prose about the pending release."
      assert body =~ "- **Encoding.** Wrapped prose"
      refute body =~ "Old entry"
    end

    test "derives the bump level from the groups" do
      assert Changelog.detect_level("### Fixed (breaking — output changes)\n- x") == :breaking
      assert Changelog.detect_level("### Added\n- x") == :feature
      assert Changelog.detect_level("### Fixed\n- x") == :fix
    end
  end

  describe "cut/3" do
    test "promotes Unreleased into a versioned section and returns the notes" do
      {:ok, out, notes} = Changelog.cut(@fixture, "0.3.0", "2026-08-25")

      assert out =~
               ~r/^## \[Unreleased\]\n\n## \[0\.3\.0\] - 2026-08-25\n\nProse about the pending release\./m

      assert out =~ ~r/^## \[0\.2\.0\] - 2026-04-28$/m
      assert notes =~ "Prose about the pending release."
      assert notes =~ "- **Encoding.** Wrapped prose"
      refute notes =~ "Old entry"
    end

    test "refuses to cut an empty Unreleased" do
      contents = "# Changelog\n\n## [Unreleased]\n\n## [0.2.0] - 2026-04-28\n"
      assert Changelog.cut(contents, "0.3.0", "2026-08-25") == {:error, :empty}
    end
  end

  describe "mix.exs version handling" do
    test "reads and bumps the first version field" do
      mixfile = ~s(      version: "0.2.0",)

      assert Changelog.mix_exs_version(mixfile) == {:ok, "0.2.0"}

      {:ok, out} = Changelog.set_mix_exs_version(mixfile, "0.3.0")
      assert out == ~s(      version: "0.3.0",)
    end

    test "errors when no version field is present" do
      assert Changelog.mix_exs_version("defmodule X do\nend") == :error
      assert Changelog.set_mix_exs_version("defmodule X do\nend", "1.0.0") == :error
    end
  end

  describe "next_version/2" do
    test "bases the bump on the highest of the given versions" do
      assert Changelog.next_version(["0.2.0", "0.3.0"], :fix) == {:ok, "0.3.1"}
      assert Changelog.next_version(["0.3.0", "0.2.0"], :feature) == {:ok, "0.4.0"}
    end

    test "breaking bumps minor while 0.x and major afterwards" do
      assert Changelog.next_version(["0.2.0"], :breaking) == {:ok, "0.3.0"}
      assert Changelog.next_version(["1.2.3"], :breaking) == {:ok, "2.0.0"}
    end

    test "literal bumps pass straight through" do
      assert Changelog.next_version(["0.2.9"], :major) == {:ok, "1.0.0"}
      assert Changelog.next_version(["0.2.9"], :minor) == {:ok, "0.3.0"}
      assert Changelog.next_version(["0.2.9"], :patch) == {:ok, "0.2.10"}
    end

    test "rejects invalid versions" do
      assert Changelog.next_version(["0.2.0", "nope"], :fix) ==
               {:error, {:invalid_version, "nope"}}
    end
  end
end

defmodule Mix.Tasks.ChangelogTest do
  use ExUnit.Case, async: false

  @moduletag :tmp_dir

  @fixture """
  # Changelog

  ## [Unreleased]

  ### Added

  - Existing entry (#6)

  ### Internal

  - CI tweak (#7)

  ## [0.2.0] - 2026-04-28

  ### Added

  - Old entry (#3)
  """

  setup do
    Mix.shell(Mix.Shell.Process)
    :ok
  end

  test "changelog.add writes an entry and is idempotent per PR", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "CHANGELOG.md")
    File.write!(path, @fixture)

    Mix.Tasks.Changelog.Add.run([
      "--title",
      "feat: add MST support",
      "--pr",
      "5",
      "--changelog",
      path
    ])

    assert File.read!(path) =~ "- add MST support (#5)"

    before_second_run = File.read!(path)

    Mix.Tasks.Changelog.Add.run([
      "--title",
      "feat: add MST again",
      "--pr",
      "5",
      "--changelog",
      path
    ])

    assert File.read!(path) == before_second_run

    # drain the first run's messages, then expect the idempotence notice
    receive do
      {:mix_shell, :info, _msg} -> :ok
    after
      0 -> :ok
    end

    assert_received {:mix_shell, :info, [msg]}
    assert msg =~ "already present"
  end

  test "changelog.add takes positional arguments and skips untyped titles", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "CHANGELOG.md")
    File.write!(path, @fixture)

    Mix.Tasks.Changelog.Add.run(["fix: crash", "12", "--changelog", path])
    assert File.read!(path) =~ "- crash (#12)"

    with_untyped = File.read!(path)

    Mix.Tasks.Changelog.Add.run(["Add stuff without a type", "13", "--changelog", path])
    assert File.read!(path) == with_untyped
  end

  test "changelog.cut promotes, bumps, and writes notes", %{tmp_dir: tmp_dir} do
    changelog_path = Path.join(tmp_dir, "CUT_CHANGELOG.md")
    mixfile_path = Path.join(tmp_dir, "mix.exs")
    notes_path = Path.join(tmp_dir, "release_notes.md")
    File.write!(changelog_path, @fixture)
    File.write!(mixfile_path, ~s(      version: "9.9.9",))

    Mix.Tasks.Changelog.Cut.run([
      "--changelog",
      changelog_path,
      "--mixfile",
      mixfile_path,
      "--notes-path",
      notes_path
    ])

    # Added entries derive a minor bump; 9.9.9 beats every real tag, keeping the test hermetic
    assert File.read!(mixfile_path) == ~s(      version: "9.10.0",)
    assert File.read!(changelog_path) =~ ~r/## \[9\.10\.0\] - \d{4}-\d{2}-\d{2}/
    assert File.read!(changelog_path) =~ "## [0.2.0] - 2026-04-28"
    assert File.read!(notes_path) =~ "- Existing entry (#6)"
  end

  test "changelog.cut --dry-run writes nothing", %{tmp_dir: tmp_dir} do
    changelog_path = Path.join(tmp_dir, "DRY_CHANGELOG.md")
    mixfile_path = Path.join(tmp_dir, "dry_mix.exs")
    notes_path = Path.join(tmp_dir, "dry_notes.md")
    File.write!(changelog_path, @fixture)
    File.write!(mixfile_path, ~s(      version: "9.9.9",))

    Mix.Tasks.Changelog.Cut.run([
      "--dry-run",
      "--changelog",
      changelog_path,
      "--mixfile",
      mixfile_path,
      "--notes-path",
      notes_path
    ])

    assert File.read!(changelog_path) == @fixture
    assert File.read!(mixfile_path) == ~s(      version: "9.9.9",)
    refute File.exists?(notes_path)
  end
end
