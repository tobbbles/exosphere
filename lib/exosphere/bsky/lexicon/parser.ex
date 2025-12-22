defmodule Exosphere.Bsky.Lexicon.Parser do
  @moduledoc """
  Parser for ATProto Lexicon JSON specifications.

  This module parses lexicon JSON files according to the
  [ATProto Lexicon spec](https://atproto.com/specs/lexicon) and extracts
  structured data for code generation.

  ## Supported Types

  Currently supports:
  - `query` - XRPC queries (HTTP GET)
  - `procedure` - XRPC procedures (HTTP POST)

  ## Examples

      {:ok, lexicon} = Parser.parse_file("path/to/lexicon.json")
      {:ok, lexicon} = Parser.parse_json(json_string)
      {:ok, lexicon} = Parser.parse(decoded_map)
  """

  @type parameter :: %{
          name: String.t(),
          type: String.t(),
          format: String.t() | nil,
          required: boolean(),
          description: String.t() | nil,
          minimum: integer() | nil,
          maximum: integer() | nil,
          min_length: integer() | nil,
          max_length: integer() | nil,
          max_graphemes: integer() | nil,
          enum: [term()] | nil,
          default: term() | nil
        }

  @type schema :: %{
          encoding: String.t(),
          schema: map() | nil,
          description: String.t() | nil
        }

  @type error_def :: %{
          name: String.t(),
          description: String.t() | nil
        }

  @type lexicon :: %{
          id: String.t(),
          type: :query | :procedure,
          description: String.t() | nil,
          parameters: [parameter()],
          input: schema() | nil,
          output: schema() | nil,
          errors: [error_def()]
        }

  @valid_types ~w(query procedure)
  @valid_param_types ~w(string integer boolean array unknown)
  @valid_formats ~w(at-identifier at-uri cid datetime did handle nsid tid uri language)

  @doc """
  Parse a lexicon from a JSON file.

  ## Examples

      {:ok, lexicon} = Parser.parse_file("priv/lexicons/app/bsky/actor/getProfile.json")
  """
  @spec parse_file(String.t()) :: {:ok, lexicon()} | {:error, term()}
  def parse_file(path) do
    with {:ok, content} <- File.read(path),
         {:ok, json} <- Jason.decode(content) do
      parse(json)
    end
  end

  @doc """
  Parse a lexicon from a JSON string.

  ## Examples

      {:ok, lexicon} = Parser.parse_json(~s({"lexicon": 1, "id": "app.bsky.actor.getProfile", ...}))
  """
  @spec parse_json(String.t()) :: {:ok, lexicon()} | {:error, term()}
  def parse_json(json_string) do
    with {:ok, json} <- Jason.decode(json_string) do
      parse(json)
    end
  end

  @doc """
  Parse a lexicon from a decoded JSON map.

  ## Examples

      {:ok, lexicon} = Parser.parse(%{"lexicon" => 1, "id" => "app.bsky.actor.getProfile", ...})
  """
  @spec parse(map()) :: {:ok, lexicon()} | {:error, term()}
  def parse(json) when is_map(json) do
    with :ok <- validate_version(json),
         {:ok, id} <- validate_id(json),
         {:ok, defs} <- validate_defs(json),
         {:ok, main_def} <- extract_main_def(defs),
         {:ok, type} <- validate_type(main_def) do
      build_lexicon(id, type, main_def, json)
    end
  end

  def parse(_), do: {:error, :invalid_lexicon_format}

  # Validate lexicon version is 1
  defp validate_version(%{"lexicon" => 1}), do: :ok
  defp validate_version(%{"lexicon" => v}), do: {:error, {:unsupported_lexicon_version, v}}
  defp validate_version(_), do: {:error, :missing_lexicon_version}

  # Validate and extract id
  defp validate_id(%{"id" => id}) when is_binary(id) do
    if valid_nsid?(id) do
      {:ok, id}
    else
      {:error, {:invalid_nsid, id}}
    end
  end

  defp validate_id(_), do: {:error, :missing_id}

  # Validate NSID format
  defp valid_nsid?(nsid) do
    # NSIDs are dot-separated segments, each segment is alphanumeric
    # Pattern: authority.name (e.g., app.bsky.actor.getProfile)
    parts = String.split(nsid, ".")
    length(parts) >= 3 and Enum.all?(parts, &valid_nsid_segment?/1)
  end

  defp valid_nsid_segment?(segment) do
    segment != "" and String.match?(segment, ~r/^[a-zA-Z][a-zA-Z0-9]*$/)
  end

  # Validate and extract defs
  defp validate_defs(%{"defs" => defs}) when is_map(defs), do: {:ok, defs}
  defp validate_defs(_), do: {:error, :missing_defs}

  # Extract the main definition (the "main" key in defs)
  defp extract_main_def(%{"main" => main}) when is_map(main), do: {:ok, main}
  defp extract_main_def(_), do: {:error, :missing_main_def}

  # Validate the type is supported
  defp validate_type(%{"type" => type}) when type in @valid_types do
    {:ok, String.to_atom(type)}
  end

  defp validate_type(%{"type" => type}), do: {:error, {:unsupported_type, type}}
  defp validate_type(_), do: {:error, :missing_type}

  # Build the lexicon struct from validated data
  defp build_lexicon(id, type, main_def, json) do
    lexicon = %{
      id: id,
      type: type,
      description: Map.get(main_def, "description") || Map.get(json, "description"),
      parameters: parse_parameters(main_def),
      input: parse_input(main_def),
      output: parse_output(main_def),
      errors: parse_errors(main_def)
    }

    {:ok, lexicon}
  end

  # Parse parameters from the main definition
  defp parse_parameters(%{"parameters" => params}) when is_map(params) do
    required = Map.get(params, "required", [])
    properties = Map.get(params, "properties", %{})

    properties
    |> Enum.map(fn {name, prop} ->
      parse_parameter(name, prop, name in required)
    end)
    |> Enum.sort_by(fn p -> {!p.required, p.name} end)
  end

  defp parse_parameters(_), do: []

  # Parse a single parameter
  defp parse_parameter(name, prop, required) do
    %{
      name: name,
      type: Map.get(prop, "type", "unknown"),
      format: Map.get(prop, "format"),
      required: required,
      description: Map.get(prop, "description"),
      minimum: Map.get(prop, "minimum"),
      maximum: Map.get(prop, "maximum"),
      min_length: Map.get(prop, "minLength"),
      max_length: Map.get(prop, "maxLength"),
      max_graphemes: Map.get(prop, "maxGraphemes"),
      enum: Map.get(prop, "enum"),
      default: Map.get(prop, "default")
    }
  end

  # Parse input schema (for procedures)
  defp parse_input(%{"input" => input}) when is_map(input) do
    %{
      encoding: Map.get(input, "encoding", "application/json"),
      schema: Map.get(input, "schema"),
      description: Map.get(input, "description")
    }
  end

  defp parse_input(_), do: nil

  # Parse output schema
  defp parse_output(%{"output" => output}) when is_map(output) do
    %{
      encoding: Map.get(output, "encoding", "application/json"),
      schema: Map.get(output, "schema"),
      description: Map.get(output, "description")
    }
  end

  defp parse_output(_), do: nil

  # Parse error definitions
  defp parse_errors(%{"errors" => errors}) when is_list(errors) do
    Enum.map(errors, fn error ->
      %{
        name: Map.get(error, "name", "UnknownError"),
        description: Map.get(error, "description")
      }
    end)
  end

  defp parse_errors(_), do: []

  @doc """
  Validate a parameter type against the spec.

  ## Examples

      :ok = Parser.validate_param_type("string")
      {:error, {:invalid_param_type, "foo"}} = Parser.validate_param_type("foo")
  """
  @spec validate_param_type(String.t()) :: :ok | {:error, term()}
  def validate_param_type(type) when type in @valid_param_types, do: :ok
  def validate_param_type(type), do: {:error, {:invalid_param_type, type}}

  @doc """
  Validate a string format against the spec.

  ## Examples

      :ok = Parser.validate_format("at-identifier")
      {:error, {:invalid_format, "foo"}} = Parser.validate_format("foo")
  """
  @spec validate_format(String.t() | nil) :: :ok | {:error, term()}
  def validate_format(nil), do: :ok
  def validate_format(format) when format in @valid_formats, do: :ok
  def validate_format(format), do: {:error, {:invalid_format, format}}

  @doc """
  Extract the namespace from an NSID.

  The namespace is everything except the last segment.

  ## Examples

      "app.bsky.actor" = Parser.namespace("app.bsky.actor.getProfile")
  """
  @spec namespace(String.t()) :: String.t()
  def namespace(nsid) do
    nsid
    |> String.split(".")
    |> Enum.drop(-1)
    |> Enum.join(".")
  end

  @doc """
  Extract the method name from an NSID.

  The method name is the last segment.

  ## Examples

      "getProfile" = Parser.method_name("app.bsky.actor.getProfile")
  """
  @spec method_name(String.t()) :: String.t()
  def method_name(nsid) do
    nsid
    |> String.split(".")
    |> List.last()
  end
end

