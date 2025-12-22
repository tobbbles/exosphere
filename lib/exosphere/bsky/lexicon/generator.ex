defmodule Exosphere.Bsky.Lexicon.Generator do
  @moduledoc """
  Code generator for ATProto Lexicon specifications.

  This module generates well-documented Elixir modules from parsed lexicon
  data. Generated code uses the existing `Exosphere.ATProto.XRPC.Client`
  for HTTP operations.

  ## Examples

      lexicons = [Parser.parse_file!("getProfile.json"), Parser.parse_file!("getPreferences.json")]
      code = Generator.generate_module("app.bsky.actor", lexicons)
  """

  alias Exosphere.Bsky.Lexicon.Parser

  @doc """
  Generate a complete Elixir module from lexicons.

  ## Parameters

  - `namespace` - The NSID namespace (e.g., "app.bsky.actor")
  - `lexicons` - List of parsed lexicon maps

  ## Returns

  A formatted Elixir code string ready to be written to a file.

  ## Examples

      code = Generator.generate_module("app.bsky.actor", [lexicon1, lexicon2])
  """
  @spec generate_module(String.t(), [Parser.lexicon()]) :: String.t()
  def generate_module(namespace, lexicons) do
    module_name = namespace_to_module(namespace)

    functions =
      lexicons
      |> Enum.map(&generate_function/1)
      |> Enum.join("\n\n")

    module_doc = generate_module_doc(namespace, lexicons)

    code = """
    defmodule #{module_name} do
      @moduledoc \"\"\"
    #{indent(module_doc, 2)}
      \"\"\"

      alias Exosphere.ATProto.XRPC.Client

    #{functions}
    end
    """

    format_code(code)
  end

  @doc """
  Generate module documentation from lexicons.

  ## Examples

      doc = Generator.generate_module_doc("app.bsky.actor", lexicons)
  """
  @spec generate_module_doc(String.t(), [Parser.lexicon()]) :: String.t()
  def generate_module_doc(namespace, lexicons) do
    method_list =
      lexicons
      |> Enum.map(fn lex ->
        func_name = function_name(lex.id)
        type_badge = if lex.type == :query, do: "query", else: "procedure"
        "- `#{func_name}/2` - #{type_badge}"
      end)
      |> Enum.join("\n")

    """
    Generated module for #{namespace} lexicons.

    This module was auto-generated from ATProto lexicon specifications.
    Do not edit manually.

    ## Methods

    #{method_list}

    ## Usage

        client = Exosphere.XRPC.Client.new("https://bsky.social")
        {:ok, result} = #{namespace_to_module(namespace)}.#{function_name(hd(lexicons).id)}(client, %{})
    """
  end

  @doc """
  Generate a single function from a lexicon.

  ## Examples

      func = Generator.generate_function(lexicon)
  """
  @spec generate_function(Parser.lexicon()) :: String.t()
  def generate_function(lexicon) do
    func_name = function_name(lexicon.id)
    func_doc = generate_function_doc(lexicon)
    func_spec = generate_typespec(lexicon)
    func_body = generate_function_body(lexicon)

    """
      @doc \"\"\"
    #{indent(func_doc, 2)}
      \"\"\"
      #{func_spec}
      def #{func_name}(client, params \\\\ %{}) do
    #{indent(func_body, 4)}
      end
    """
  end

  @doc """
  Generate function documentation.

  ## Examples

      doc = Generator.generate_function_doc(lexicon)
  """
  @spec generate_function_doc(Parser.lexicon()) :: String.t()
  def generate_function_doc(lexicon) do
    parts = [
      lexicon.description || "No description available.",
      "",
      generate_parameter_docs(lexicon.parameters),
      generate_returns_doc(lexicon),
      generate_examples_doc(lexicon),
      generate_lexicon_info(lexicon)
    ]

    parts
    |> Enum.reject(&is_nil/1)
    |> Enum.join("\n\n")
  end

  @doc """
  Generate parameter documentation.

  ## Examples

      doc = Generator.generate_parameter_docs(parameters)
  """
  @spec generate_parameter_docs([Parser.parameter()]) :: String.t() | nil
  def generate_parameter_docs([]), do: nil

  def generate_parameter_docs(parameters) do
    param_docs =
      parameters
      |> Enum.map(&format_parameter_doc/1)
      |> Enum.join("\n")

    """
    ## Parameters

    #{param_docs}
    """
  end

  defp format_parameter_doc(param) do
    req = if param.required, do: "required", else: "optional"
    type = param.type

    base = "- `#{param.name}` (#{type}, #{req})"

    desc =
      if param.description do
        " - #{param.description}"
      else
        ""
      end

    constraints = format_constraints(param)

    format_line =
      if param.format do
        "\n  Format: `#{param.format}`"
      else
        ""
      end

    "#{base}#{desc}#{format_line}#{constraints}"
  end

  defp format_constraints(param) do
    constraints =
      []
      |> maybe_add_constraint(param.minimum, "minimum: #{param.minimum}")
      |> maybe_add_constraint(param.maximum, "maximum: #{param.maximum}")
      |> maybe_add_constraint(param.min_length, "minLength: #{param.min_length}")
      |> maybe_add_constraint(param.max_length, "maxLength: #{param.max_length}")
      |> maybe_add_constraint(param.max_graphemes, "maxGraphemes: #{param.max_graphemes}")
      |> maybe_add_constraint(param.enum, "enum: #{inspect(param.enum)}")
      |> maybe_add_constraint(param.default, "default: #{inspect(param.default)}")

    if Enum.empty?(constraints) do
      ""
    else
      "\n  Constraints: #{Enum.join(constraints, ", ")}"
    end
  end

  defp maybe_add_constraint(acc, nil, _), do: acc
  defp maybe_add_constraint(acc, _, text), do: acc ++ [text]

  defp generate_returns_doc(_lexicon) do
    """
    ## Returns

    - `{:ok, result}` - Success with response body
    - `{:error, reason}` - Request failed
    """
  end

  defp generate_examples_doc(lexicon) do
    func_name = function_name(lexicon.id)
    module_name = namespace_to_module(Parser.namespace(lexicon.id))

    """
    ## Examples

        client = Exosphere.XRPC.Client.new("https://bsky.social")
        {:ok, result} = #{module_name}.#{func_name}(client, %{})
    """
  end

  defp generate_lexicon_info(lexicon) do
    """
    ## Lexicon

    NSID: `#{lexicon.id}`
    Type: `#{lexicon.type}`
    """
  end

  @doc """
  Generate typespec for a function.

  ## Examples

      spec = Generator.generate_typespec(lexicon)
  """
  @spec generate_typespec(Parser.lexicon()) :: String.t()
  def generate_typespec(lexicon) do
    func_name = function_name(lexicon.id)
    "@spec #{func_name}(Client.t(), map()) :: {:ok, map()} | {:error, term()}"
  end

  @doc """
  Generate function body based on lexicon type.

  ## Examples

      body = Generator.generate_function_body(lexicon)
  """
  @spec generate_function_body(Parser.lexicon()) :: String.t()
  def generate_function_body(%{type: :query, id: nsid}) do
    """
    Client.query(client, "#{nsid}", params)
    """
  end

  def generate_function_body(%{type: :procedure, id: nsid}) do
    """
    Client.procedure(client, "#{nsid}", params)
    """
  end

  @doc """
  Convert an NSID namespace to an Elixir module name.

  ## Examples

      "Exosphere.Bsky.Actor" = Generator.namespace_to_module("app.bsky.actor")
  """
  @spec namespace_to_module(String.t()) :: String.t()
  def namespace_to_module(namespace) do
    namespace
    |> String.split(".")
    |> Enum.drop(1)
    |> Enum.map(&Macro.camelize/1)
    |> then(fn parts -> ["Exosphere" | parts] end)
    |> Enum.join(".")
  end

  @doc """
  Extract function name from an NSID.

  ## Examples

      "get_profile" = Generator.function_name("app.bsky.actor.getProfile")
  """
  @spec function_name(String.t()) :: String.t()
  def function_name(nsid) do
    nsid
    |> Parser.method_name()
    |> Macro.underscore()
  end

  # Indent a block of text by n spaces
  defp indent(text, spaces) do
    prefix = String.duplicate(" ", spaces)

    text
    |> String.split("\n")
    |> Enum.map(fn line ->
      if String.trim(line) == "" do
        ""
      else
        "#{prefix}#{line}"
      end
    end)
    |> Enum.join("\n")
  end

  # Format Elixir code
  defp format_code(code) do
    try do
      Code.format_string!(code)
      |> IO.iodata_to_binary()
    rescue
      _ -> code
    end
  end
end

