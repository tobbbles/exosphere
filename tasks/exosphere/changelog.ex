defmodule Exosphere.Changelog do
  @moduledoc false

  # Maintenance helper for the changelog.* Mix tasks. Compiled only in :test
  # (see elixirc_paths/1 in mix.exs) so it stays out of the Hex package and
  # the published docs.

  @unreleased_heading "## [Unreleased]"
  @group_order ["Breaking", "Added", "Changed", "Fixed", "Docs", "Removed", "Internal"]
  @unknown_group_rank 99

  @type intent :: :breaking | :feature | :fix | :major | :minor | :patch

  @spec classify(String.t()) :: {:ok, group :: String.t(), subject :: String.t()} | :skip
  def classify(title) do
    case Regex.run(~r/^([a-z]+)(?:\([^)]*\))?(!)?:\s*(.+)$/, title) do
      [_, type, bang, subject] ->
        case group_for(type) do
          :skip -> :skip
          _group when bang == "!" -> {:ok, "Breaking", subject}
          group -> {:ok, group, subject}
        end

      nil ->
        :skip
    end
  end

  @spec add_entry(String.t(), String.t(), String.t()) ::
          {:ok, String.t()} | {:error, :no_unreleased}
  def add_entry(contents, group, entry) do
    lines = String.split(contents, "\n")

    with {:ok, start, stop} <- unreleased_range(lines) do
      headings = group_headings(lines, start, stop)

      new_lines =
        case List.keyfind(headings, group, 1) do
          {_index, _name} = existing ->
            insert_into_group(lines, existing, headings, stop, entry)

          nil ->
            insert_new_group(lines, start, stop, headings, group, entry)
        end

      {:ok, Enum.join(new_lines, "\n")}
    end
  end

  @spec unreleased_body(String.t()) :: {:ok, String.t()} | {:error, :no_unreleased}
  def unreleased_body(contents) do
    lines = String.split(contents, "\n")

    with {:ok, start, stop} <- unreleased_range(lines) do
      {:ok, lines |> Enum.slice((start + 1)..(stop - 1)//1) |> trim_blanks() |> Enum.join("\n")}
    end
  end

  @spec detect_level(String.t()) :: :breaking | :feature | :fix
  def detect_level(body) do
    cond do
      body =~ ~r/^###.*breaking/im -> :breaking
      body =~ ~r/^### Added/m -> :feature
      true -> :fix
    end
  end

  @spec cut(String.t(), String.t(), String.t()) ::
          {:ok, String.t(), String.t()} | {:error, :no_unreleased | :empty}
  def cut(contents, version, date) do
    lines = String.split(contents, "\n")

    with {:ok, start, stop} <- unreleased_range(lines) do
      body = lines |> Enum.slice((start + 1)..(stop - 1)//1) |> trim_blanks()

      if body == [] do
        {:error, :empty}
      else
        head = Enum.slice(lines, 0..start//1)
        rest = Enum.slice(lines, stop..-1//1)
        section = ["", "## [#{version}] - #{date}", ""] ++ body ++ [""]

        {:ok, Enum.join(head ++ section ++ rest, "\n"), Enum.join(body, "\n")}
      end
    end
  end

  @spec mix_exs_version(String.t()) :: {:ok, String.t()} | :error
  def mix_exs_version(contents) do
    case Regex.run(~r/version:\s*"(\d+\.\d+\.\d+)"/, contents) do
      [_, version] -> {:ok, version}
      nil -> :error
    end
  end

  @spec set_mix_exs_version(String.t(), String.t()) :: {:ok, String.t()} | :error
  def set_mix_exs_version(contents, version) do
    if Regex.match?(~r/version:\s*"\d+\.\d+\.\d+"/, contents) do
      {:ok,
       Regex.replace(~r/(version:\s*")\d+\.\d+\.\d+(")/, contents, "\\g{1}#{version}\\g{2}",
         global: false
       )}
    else
      :error
    end
  end

  @spec set_readme_dep(String.t(), String.t()) :: {:ok, String.t()} | :error
  def set_readme_dep(contents, version) do
    if Regex.match?(~r/\{:exosphere,\s*"~> [\d.]+"/, contents) do
      {:ok,
       Regex.replace(
         ~r/(\{:exosphere,\s*"~> )[\d.]+(")/,
         contents,
         "\\g{1}#{requirement(version)}\\g{2}"
       )}
    else
      :error
    end
  end

  defp requirement(version) do
    %{major: major, minor: minor} = Version.parse!(version)
    "#{major}.#{minor}"
  end

  @spec next_version([String.t()], intent()) ::
          {:ok, String.t()} | {:error, {:invalid_version, String.t()}}
  def next_version(versions, intent) do
    # Version.parse/1 returns plain :error on invalid input
    case Enum.find(versions, &(:error == Version.parse(&1))) do
      nil ->
        base =
          versions
          |> Enum.map(&Version.parse!/1)
          |> max_version()

        {:ok, base |> bump(map_intent(intent, base)) |> to_string()}

      invalid ->
        {:error, {:invalid_version, invalid}}
    end
  end

  @spec tag_versions() :: [String.t()]
  def tag_versions do
    case System.cmd("git", ["tag", "--list", "v[0-9]*"]) do
      {output, 0} ->
        output
        |> String.split("\n", trim: true)
        |> Enum.filter(&Regex.match?(~r/^v\d+\.\d+\.\d+$/, &1))

      _error ->
        []
    end
  end

  @spec tag_exists?(String.t()) :: boolean()
  def tag_exists?(tag) do
    tag in tag_versions()
  end

  ## Unreleased section

  defp unreleased_range(lines) do
    case Enum.find_index(lines, &(&1 == @unreleased_heading)) do
      nil ->
        {:error, :no_unreleased}

      start ->
        tail = Enum.drop(lines, start + 1)

        stop =
          case Enum.find_index(tail, &Regex.match?(~r/^## /, &1)) do
            nil -> length(lines)
            offset -> start + 1 + offset
          end

        {:ok, start, stop}
    end
  end

  defp group_headings(lines, start, stop) do
    lines
    |> Enum.slice((start + 1)..(stop - 1)//1)
    |> Enum.with_index()
    |> Enum.flat_map(fn {line, offset} ->
      case Regex.run(~r/^### (.+)$/, line) do
        [_, name] -> [{start + 1 + offset, name}]
        nil -> []
      end
    end)
  end

  defp insert_into_group(lines, {heading_index, _name}, headings, stop, entry) do
    # When the group is the last one in the section, its block ends at the
    # section boundary (the next `## ` heading), not at the end of the file.
    block_end =
      case Enum.find(headings, fn {index, _} -> index > heading_index end) do
        {next_index, _} -> next_index
        nil -> stop
      end

    trailing_blanks =
      lines
      |> Enum.slice((heading_index + 1)..(block_end - 1)//1)
      |> Enum.reverse()
      |> Enum.take_while(&(&1 == ""))
      |> length()

    content_length = block_end - heading_index - 1 - trailing_blanks
    List.insert_at(lines, heading_index + 1 + content_length, entry)
  end

  defp insert_new_group(lines, start, stop, headings, group, entry) do
    rank = group_rank(group)

    insert_at =
      case Enum.find(headings, fn {_index, name} -> group_rank(name) > rank end) do
        {index, _} -> index
        nil -> stop
      end

    prefix =
      if insert_at > start + 1 and Enum.at(lines, insert_at - 1) != "" do
        [""]
      else
        []
      end

    block = prefix ++ ["### " <> group, entry, ""]

    Enum.slice(lines, 0..(insert_at - 1)//1) ++ block ++ Enum.slice(lines, insert_at..-1//1)
  end

  defp trim_blanks(lines) do
    lines
    |> Enum.drop_while(&(String.trim(&1) == ""))
    |> Enum.reverse()
    |> Enum.drop_while(&(String.trim(&1) == ""))
    |> Enum.reverse()
  end

  ## Groups and versions

  defp group_for(type) do
    case type do
      "feat" -> "Added"
      "fix" -> "Fixed"
      "perf" -> "Changed"
      "refactor" -> "Changed"
      "docs" -> "Docs"
      "chore" -> "Internal"
      "ci" -> "Internal"
      "build" -> "Internal"
      "test" -> "Internal"
      "style" -> "Internal"
      "revert" -> "Internal"
      _other -> :skip
    end
  end

  defp group_rank(name) do
    if String.contains?(String.downcase(name), "breaking") do
      0
    else
      base = name |> String.split(" (") |> hd() |> String.downcase()

      case Enum.find_index(@group_order, &(String.downcase(&1) == base)) do
        nil -> @unknown_group_rank
        index -> index + 1
      end
    end
  end

  defp max_version(versions) do
    Enum.max(versions, fn a, b -> Version.compare(a, b) == :gt end)
  end

  defp map_intent(:breaking, base) do
    if base.major == 0, do: :minor, else: :major
  end

  defp map_intent(:feature, _base), do: :minor
  defp map_intent(:fix, _base), do: :patch
  defp map_intent(literal, _base) when literal in [:major, :minor, :patch], do: literal

  defp bump(base, :major), do: %{base | major: base.major + 1, minor: 0, patch: 0}
  defp bump(base, :minor), do: %{base | minor: base.minor + 1, patch: 0}
  defp bump(base, :patch), do: %{base | patch: base.patch + 1}
end
