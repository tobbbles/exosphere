defmodule Mix.Tasks.Changelog.Add do
  @shortdoc "Adds a PR entry to the changelog's [Unreleased] section"

  @moduledoc """
  Appends a Conventional-Commit-titled PR to `## [Unreleased]` in CHANGELOG.md.

      MIX_ENV=test mix changelog.add --title "feat: add MST support" --pr 5
      MIX_ENV=test mix changelog.add "fix: firehose crash on empty frame" 12

  The title's type picks the group: `feat` → Added, `fix` → Fixed,
  `perf`/`refactor` → Changed, `docs` → Docs, maintenance types (`chore`,
  `ci`, `build`, `test`, `style`, `revert`) → Internal. A `!` (e.g. `feat!:`)
  files the entry under Breaking instead. Titles without a recognisable type
  are left out of the changelog.

  Running twice for the same PR number is a no-op.

  ## Command line options

    * `--title` - the PR title (or pass it as the first positional argument)
    * `--pr` - the PR number (or as the second positional argument)
    * `--changelog` - path to the changelog (default: `CHANGELOG.md`)
  """

  use Mix.Task

  @switches [title: :string, pr: :integer, changelog: :string]

  @impl Mix.Task
  def run(args) do
    {opts, positional, invalid} = OptionParser.parse(args, strict: @switches)

    if invalid != [] do
      Mix.raise("invalid options: #{inspect(invalid)}")
    end

    {title, pr} = parse_arguments(opts, positional)

    if !is_binary(title) or !is_integer(pr) do
      Mix.raise("both a title (--title) and a PR number (--pr) are required")
    end

    path = Keyword.get(opts, :changelog, "CHANGELOG.md")
    contents = File.read!(path)

    if String.contains?(contents, "(##{pr})") do
      Mix.shell().info("changelog: entry for ##{pr} already present; skipping")
    else
      add(contents, title, pr, path)
    end
  end

  defp parse_arguments(opts, [title, pr]) do
    {Keyword.get(opts, :title, title), Keyword.get(opts, :pr, parse_pr(pr))}
  end

  defp parse_arguments(opts, []) do
    {opts[:title], opts[:pr]}
  end

  defp parse_arguments(_opts, _other) do
    Mix.raise("expected a title and PR number, either as switches or as two positional arguments")
  end

  defp parse_pr(pr) do
    case Integer.parse(pr) do
      {number, ""} -> number
      _other -> Mix.raise("invalid PR number: #{inspect(pr)}")
    end
  end

  defp add(contents, title, pr, path) do
    case Exosphere.Changelog.classify(title) do
      :skip ->
        Mix.shell().info("changelog: no entry for ##{pr} (unrecognised title type)")

      {:ok, group, subject} ->
        case Exosphere.Changelog.add_entry(contents, group, "- #{subject} (##{pr})") do
          {:ok, new_contents} ->
            File.write!(path, new_contents)
            Mix.shell().info("changelog: added ##{pr} to #{group}")

          {:error, :no_unreleased} ->
            Mix.raise("#{path} has no ## [Unreleased] section")
        end
    end
  end
end
