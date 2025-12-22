defmodule Mix.Tasks.Exosphere.Gen.Lexicon do
  @shortdoc "Generate Elixir modules from ATProto lexicon specifications"

  @moduledoc """
  Generates Elixir modules from ATProto lexicon JSON specifications.

  ## Usage

      mix exosphere.gen.lexicon NAMESPACE [OPTIONS]

  ## Arguments

  - `NAMESPACE` - The NSID namespace to generate (e.g., `app.bsky.actor`)

  ## Options

  - `--lexicon-dir` - Source directory for lexicon files (default: `priv/lexicons`)
  - `--output` - Output directory for generated files (default: `lib/exosphere/bsky`)
  - `--dry-run` - Preview changes without writing files

  ## Examples

      # Generate module for app.bsky.actor namespace
      mix exosphere.gen.lexicon app.bsky.actor

      # Preview generated code without writing
      mix exosphere.gen.lexicon app.bsky.actor --dry-run

      # Use custom directories
      mix exosphere.gen.lexicon app.bsky.actor --lexicon-dir my_lexicons --output lib/my_app
  """

  use Igniter.Mix.Task

  alias Exosphere.Bsky.Lexicon.{Parser, Generator}

  @impl Igniter.Mix.Task
  def info(_argv, _composing_task) do
    %Igniter.Mix.Task.Info{
      group: :exosphere,
      positional: [:namespace],
      schema: [
        lexicon_dir: :string,
        output: :string,
        dry_run: :boolean
      ],
      defaults: [
        lexicon_dir: "priv/lexicons",
        output: "lib/exosphere/bsky",
        dry_run: false
      ],
      aliases: [
        d: :dry_run
      ],
      example: """
      mix exosphere.gen.lexicon app.bsky.actor
      mix exosphere.gen.lexicon app.bsky.actor --dry-run
      """
    }
  end

  @impl Igniter.Mix.Task
  def igniter(igniter) do
    options = igniter.args.options
    positional = igniter.args.positional

    namespace = get_positional(positional, :namespace)
    lexicon_dir = get_option(options, :lexicon_dir, "priv/lexicons")
    output_dir = get_option(options, :output, "lib/exosphere/bsky")
    dry_run = get_option(options, :dry_run, false)

    # Convert namespace to directory path
    namespace_path = namespace_to_path(namespace)
    full_lexicon_dir = Path.join(lexicon_dir, namespace_path)

    # Find all lexicon files for this namespace
    case find_lexicon_files(full_lexicon_dir) do
      {:ok, files} when files != [] ->
        # Parse all lexicon files
        case parse_lexicons(files) do
          {:ok, lexicons} ->
            # Generate module code
            code = Generator.generate_module(namespace, lexicons)

            if dry_run do
              Igniter.add_notice(igniter, """
              [DRY RUN] Would generate module for #{namespace}

              Generated code:
              #{code}
              """)
            else
              # Determine output file path
              output_file = output_file_path(namespace, output_dir)

              # Use Igniter to create/update the file
              igniter
              |> Igniter.create_or_update_elixir_file(output_file, code, fn source ->
                # Replace existing content
                Sourceror.parse_string!(code)
                |> then(fn parsed -> {:ok, Rewrite.Source.update(source, :quoted, parsed)} end)
              end)
              |> Igniter.add_notice("Generated #{output_file} from #{length(lexicons)} lexicon(s)")
            end

          {:error, errors} ->
            Igniter.add_issue(igniter, """
            Failed to parse lexicon files:
            #{format_errors(errors)}
            """)
        end

      {:ok, []} ->
        Igniter.add_issue(igniter, """
        No lexicon files found in #{full_lexicon_dir}

        Make sure lexicon JSON files exist at:
          #{full_lexicon_dir}/*.json
        """)

      {:error, reason} ->
        Igniter.add_issue(igniter, """
        Failed to find lexicon files: #{inspect(reason)}

        Directory: #{full_lexicon_dir}
        """)
    end
  end

  # Convert namespace to directory path
  # e.g., "app.bsky.actor" -> "app/bsky/actor"
  defp namespace_to_path(namespace) do
    namespace
    |> String.split(".")
    |> Path.join()
  end

  # Find all .json files in a directory
  defp find_lexicon_files(dir) do
    if File.dir?(dir) do
      files =
        dir
        |> File.ls!()
        |> Enum.filter(&String.ends_with?(&1, ".json"))
        |> Enum.map(&Path.join(dir, &1))

      {:ok, files}
    else
      {:error, :directory_not_found}
    end
  end

  # Parse all lexicon files and collect results
  defp parse_lexicons(files) do
    results =
      Enum.map(files, fn file ->
        case Parser.parse_file(file) do
          {:ok, lexicon} -> {:ok, lexicon}
          {:error, reason} -> {:error, {file, reason}}
        end
      end)

    errors = for {:error, err} <- results, do: err
    lexicons = for {:ok, lex} <- results, do: lex

    if Enum.empty?(errors) do
      {:ok, lexicons}
    else
      {:error, errors}
    end
  end

  # Generate output file path from namespace
  defp output_file_path(namespace, output_dir) do
    parts =
      namespace
      |> String.split(".")
      |> Enum.drop(1)

    filename = "#{Enum.join(parts, "_")}.ex"

    Path.join(output_dir, filename)
  end

  # Format errors for display
  defp format_errors(errors) do
    errors
    |> Enum.map(fn {file, reason} -> "  - #{file}: #{inspect(reason)}" end)
    |> Enum.join("\n")
  end

  # Helper to get positional args (handles both map and keyword list)
  defp get_positional(positional, key) when is_map(positional) do
    Map.fetch!(positional, key)
  end

  defp get_positional(positional, key) when is_list(positional) do
    Keyword.fetch!(positional, key)
  end

  # Helper to get options (handles both map and keyword list)
  defp get_option(options, key, default) when is_map(options) do
    Map.get(options, key, default)
  end

  defp get_option(options, key, default) when is_list(options) do
    Keyword.get(options, key, default)
  end
end

