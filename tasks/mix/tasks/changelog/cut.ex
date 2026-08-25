defmodule Mix.Tasks.Changelog.Cut do
  @shortdoc "Promotes the changelog's [Unreleased] section into a release"

  @moduledoc """
  Cuts a release from the changelog queue: renames `## [Unreleased]` to a
  versioned heading, bumps `version:` in mix.exs, and writes the promoted
  section to a release-notes file.

      MIX_ENV=test mix changelog.cut --dry-run
      MIX_ENV=test mix changelog.cut --bump minor --notes-path release_notes.md

  The next version is `max(version in mix.exs, highest vX.Y.Z tag)` plus the
  bump, so it can never go backwards even if one of the two is stale. Without
  `--bump`, the level is derived from the Unreleased entries: a Breaking group
  → major (minor while 0.x), an Added group → minor, otherwise patch. The
  task refuses to run when the target tag already exists or there is nothing
  in [Unreleased].

  This task only edits files; the release workflow commits the result, pushes
  it to main, and creates the tag and GitHub Release from the pushed commit.

  ## Command line options

    * `--bump` - force `major`, `minor`, or `patch` (default: derive from entries)
    * `--changelog` - path to the changelog (default: `CHANGELOG.md`)
    * `--mixfile` - path to mix.exs (default: `mix.exs`)
    * `--notes-path` - write the promoted section here as release notes
    * `--dry-run` - print what would be cut without writing anything
  """

  use Mix.Task

  @switches [
    bump: :string,
    changelog: :string,
    mixfile: :string,
    notes_path: :string,
    dry_run: :boolean
  ]

  @impl Mix.Task
  def run(args) do
    {opts, _positional, invalid} = OptionParser.parse(args, strict: @switches)

    if invalid != [] do
      Mix.raise("invalid options: #{inspect(invalid)}")
    end

    changelog_path = Keyword.get(opts, :changelog, "CHANGELOG.md")
    mixfile_path = Keyword.get(opts, :mixfile, "mix.exs")
    changelog = File.read!(changelog_path)
    mixfile = File.read!(mixfile_path)

    current = mix_exs_version(mixfile, mixfile_path)

    body = unreleased_body(changelog, changelog_path)

    if String.trim(body) == "" do
      Mix.raise("#{changelog_path} has no [Unreleased] entries; nothing to release")
    end

    intent = intent(opts[:bump], body)

    versions = [current | versions_from_tags()]
    {:ok, next} = Exosphere.Changelog.next_version(versions, intent)

    if Exosphere.Changelog.tag_exists?("v#{next}") do
      Mix.raise("tag v#{next} already exists; refusing to cut")
    end

    {:ok, new_changelog, notes} =
      Exosphere.Changelog.cut(changelog, next, Date.to_iso8601(Date.utc_today()))

    {:ok, new_mixfile} = Exosphere.Changelog.set_mix_exs_version(mixfile, next)

    if opts[:dry_run] do
      Mix.shell().info("changelog: would cut v#{next} (base v#{current}) [dry run]")
      Mix.shell().info(notes)
    else
      File.write!(changelog_path, new_changelog)
      File.write!(mixfile_path, new_mixfile)
      write_notes(opts[:notes_path], notes)
      Mix.shell().info("changelog: cut v#{next} (base v#{current})")
    end
  end

  defp mix_exs_version(mixfile, path) do
    case Exosphere.Changelog.mix_exs_version(mixfile) do
      {:ok, version} -> version
      :error -> Mix.raise("could not read the version from #{path}")
    end
  end

  defp unreleased_body(changelog, path) do
    case Exosphere.Changelog.unreleased_body(changelog) do
      {:ok, body} -> body
      {:error, :no_unreleased} -> Mix.raise("#{path} has no ## [Unreleased] section")
    end
  end

  defp versions_from_tags do
    Exosphere.Changelog.tag_versions()
    |> Enum.map(&String.trim_leading(&1, "v"))
  end

  defp intent(nil, body), do: Exosphere.Changelog.detect_level(body)
  defp intent("major", _body), do: :major
  defp intent("minor", _body), do: :minor
  defp intent("patch", _body), do: :patch

  defp intent(other, _body),
    do: Mix.raise("invalid --bump #{inspect(other)} (expected major, minor, or patch)")

  defp write_notes(nil, _notes), do: :ok
  defp write_notes(path, notes), do: File.write!(path, notes)
end
