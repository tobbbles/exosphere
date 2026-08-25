defmodule Mix.Tasks.Exosphere.Lint.Lexicons do
  @shortdoc "Lint lexicon JSON files against the lexicon spec"

  @moduledoc """
  Lints lexicon JSON documents against the lexicon schema rules.

  Errors come from the specification itself (`Exosphere.Lexicon.Parser`
  node checks plus `Exosphere.Lexicon.Schema.validate_document/1`:
  lexicon version, NSID `id`, non-empty `defs`, single primary
  definition, record defs with a `key`, and refs never targeting
  refs/unions/tokens or unresolvable local defs).

  Warnings are style-guide suggestions that do not block: definitions
  and record properties without descriptions.

      mix exosphere.lint.lexicons                     # priv/lexicons/**
      mix exosphere.lint.lexicons path/to/lexicon.json
      mix exosphere.lint.lexicons path/to/dir

  Exits non-zero when any file has errors. `--strict` also fails on
  warnings.
  """

  use Mix.Task

  alias Exosphere.Lexicon.{Parser, Schema}

  @lexicon_dir "priv/lexicons"

  @impl Mix.Task
  def run(args) do
    {opts, positional, invalid} = OptionParser.parse(args, strict: [strict: :boolean])

    unless invalid == [] do
      Mix.raise("invalid arguments: #{inspect(invalid)}")
    end

    targets = targets!(positional)
    strict = Keyword.get(opts, :strict, false)

    results =
      targets
      |> Task.async_stream(&lint_file/1, timeout: 30_000)
      |> Enum.map(fn {:ok, result} -> result end)

    error_count =
      results |> Enum.map(fn {_path, errors, _warnings} -> length(errors) end) |> Enum.sum()

    warning_count =
      results |> Enum.map(fn {_path, _errors, warnings} -> length(warnings) end) |> Enum.sum()

    Enum.each(results, &report/1)

    message = [
      "linted #{length(results)} lexicons, ",
      "#{error_count} error(s)",
      " #{warning_count} warning(s)"
    ]

    Mix.shell().info(Enum.join(message, ""))

    if error_count > 0 or (strict and warning_count > 0) do
      exit({:shutdown, 1})
    end
  end

  defp targets!([]), do: Path.wildcard(Path.join(@lexicon_dir, "**/*.json")) |> Enum.sort()

  defp targets!(positional) do
    Enum.flat_map(positional, fn target ->
      cond do
        String.ends_with?(target, ".json") -> [target]
        File.dir?(target) -> Path.wildcard(Path.join(target, "**/*.json")) |> Enum.sort()
        true -> Mix.raise("no such file or directory: #{target}")
      end
    end)
  end

  # SOURCES.md lives beside the lexicons; skip it rather than erroring
  defp lint_file(path) do
    case Path.basename(path) do
      "SOURCES.md" ->
        {path, [], []}

      _ ->
        with {:ok, content} <- File.read(path),
             {:ok, json} <- Jason.decode(content) do
          lint_document(path, json)
        else
          {:error, %Jason.DecodeError{} = reason} ->
            {path, [{"", "invalid JSON: #{Exception.message(reason)}"}], []}

          {:error, reason} ->
            {path, [{"", "unreadable: #{inspect(reason)}"}], []}
        end
    end
  end

  defp lint_document(path, json) do
    errors =
      case Parser.parse(json) do
        {:ok, _parsed} -> []
        {:error, reason} -> [{"", "invalid lexicon: #{inspect(reason)}"}]
      end

    errors = errors ++ Schema.validate_document(json)
    warnings = style_warnings(json)

    {path, errors, warnings}
  end

  # Lexicon style guide: descriptions should accompany every definition
  # and its properties, and string formats must be names the spec (and
  # this library) actually checks. Advisory only.
  defp style_warnings(%{"defs" => defs}) when is_map(defs) do
    Enum.flat_map(defs, fn {name, def} ->
      []
      |> warn_missing(description_of(def), "defs.#{name}", "definition has no description")
      |> Kernel.++(property_warnings(name, def))
      |> Kernel.++(format_warnings(name, def))
    end)
  end

  defp style_warnings(_), do: []

  # The string formats the lexicon spec defines — and Exosphere validates
  @spec_formats ~w(datetime uri at-uri nsid did cid handle language tid record-key at-identifier)

  # Walk a def's raw JSON for string nodes carrying a "format", warning
  # on names outside the spec set (typos included: a format the library
  # does not recognize is never checked).
  defp format_warnings(def_name, def), do: node_format_warnings(def, "defs.#{def_name}")

  defp node_format_warnings(%{"type" => "string", "format" => format}, path)
       when is_binary(format) do
    if format in @spec_formats,
      do: [],
      else: [{path, "unknown string format #{inspect(format)}; it will never be checked"}]
  end

  defp node_format_warnings(%{"type" => "object", "properties" => props}, path)
       when is_map(props) do
    Enum.flat_map(props, fn {name, prop} ->
      node_format_warnings(prop, "#{path}.#{name}")
    end)
  end

  defp node_format_warnings(%{"type" => "record", "record" => record}, path) when is_map(record),
    do: node_format_warnings(record, "#{path}.record")

  defp node_format_warnings(%{"type" => "array", "items" => items}, path) when is_map(items),
    do: node_format_warnings(items, "#{path}.items")

  defp node_format_warnings(_, _path), do: []

  defp property_warnings(def_name, %{"record" => %{"properties" => props}}) when is_map(props) do
    Enum.map(props, fn {prop, spec} ->
      if description_of(spec),
        do: nil,
        else: {"defs.#{def_name}.record.#{prop}", "property has no description"}
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp property_warnings(_def_name, _def), do: []

  defp description_of(%{"description" => desc}) when is_binary(desc), do: desc
  defp description_of(_), do: nil

  defp warn_missing(acc, nil, path, message), do: [{path, message} | acc]
  defp warn_missing(acc, _desc, _path, _message), do: acc

  defp report({_path, [], []}), do: :ok

  defp report({path, errors, warnings}) do
    Enum.each(errors, fn {location, message} ->
      Mix.shell().error("#{path}: #{location}: error: #{message}")
    end)

    Enum.each(warnings, fn {location, message} ->
      Mix.shell().error("#{path}: #{location}: warning: #{message}")
    end)
  end
end
