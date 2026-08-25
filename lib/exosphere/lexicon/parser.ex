defmodule Exosphere.Lexicon.Parser do
  @moduledoc """
  Parses ATProto lexicon JSON files into a normalized schema IR.

  Unlike a flat extractor, this walks schema nodes recursively, preserving
  every node type the lexicon spec defines:

  - Primitives: `string` (with `format`/`maxLength`/`maxGraphemes`/`enum`),
    `integer` (`minimum`/`maximum`), `boolean`, `bytes`, `unknown`
  - Containers: `object` (`properties`/`required`), `array` (`items`)
  - Links: `ref` (`#def`, `nsid`, `nsid#def`), `union` (`refs`), `cid-link`, `blob`
  - Records: `record` (`key` + embedded object)

  Nodes are plain maps tagged with `:kind`. Refs are kept symbolic; the
  generator resolves them against the full set of parsed lexicons.

  ## Examples

      {:ok, lexicons} = Parser.parse_dir("priv/lexicons")
      %{id: "app.bsky.feed.post", defs: %{"main" => %{kind: :record, ...}}} =
        lexicons["app.bsky.feed.post"]
  """

  alias Exosphere.ATProto.NSID

  @type schema_node ::
          %{
            kind: node_kind()
          }
          | %{optional(atom()) => term()}

  @type node_kind ::
          :string
          | :token
          | :integer
          | :boolean
          | :bytes
          | :unknown
          | :cid_link
          | :blob
          | :array
          | :object
          | :record
          | :ref
          | :union
          # XRPC and permission-set defs parse but are not yet generated
          | :params
          | :query
          | :procedure
          | :permission_set
          | :subscription

  @type lexicon :: %{
          id: String.t(),
          description: String.t() | nil,
          defs: %{String.t() => schema_node()}
        }

  @primitive_types ~w(string integer boolean bytes unknown cid-link blob)
  @container_types ~w(array object record ref union)
  @known_types @primitive_types ++ @container_types

  @doc """
  Parse every lexicon JSON file under `dir` (recursively).

  Returns `{:ok, %{nsid => lexicon}}` or `{:error, {path, reason}}` for the
  first file that fails.
  """
  @spec parse_dir(Path.t()) :: {:ok, %{String.t() => lexicon()}} | {:error, term()}
  def parse_dir(dir) do
    dir
    |> Path.join("**/*.json")
    |> Path.wildcard()
    |> Enum.sort()
    |> Enum.reduce_while({:ok, %{}}, fn path, {:ok, acc} ->
      case parse_file(path) do
        {:ok, lexicon} -> {:cont, {:ok, Map.put(acc, lexicon.id, lexicon)}}
        {:error, reason} -> {:halt, {:error, {path, reason}}}
      end
    end)
  end

  @doc "Parse a single lexicon JSON file."
  @spec parse_file(Path.t()) :: {:ok, lexicon()} | {:error, term()}
  def parse_file(path) do
    with {:ok, content} <- File.read(path),
         {:ok, json} <- Jason.decode(content) do
      parse(json)
    end
  end

  @doc "Parse a decoded lexicon JSON map."
  @spec parse(map()) :: {:ok, lexicon()} | {:error, term()}
  def parse(json) when is_map(json) do
    with :ok <- check_version(json),
         {:ok, id} <- check_id(json),
         {:ok, defs} <- parse_defs(json) do
      {:ok, %{id: id, description: json["description"], defs: defs}}
    end
  end

  def parse(_), do: {:error, :not_a_map}

  defp check_version(%{"lexicon" => 1}), do: :ok
  defp check_version(%{"lexicon" => v}), do: {:error, {:unsupported_lexicon_version, v}}
  defp check_version(_), do: {:error, :missing_lexicon_version}

  defp check_id(%{"id" => id}) when is_binary(id) do
    if NSID.valid?(id), do: {:ok, id}, else: {:error, {:invalid_nsid, id}}
  end

  defp check_id(_), do: {:error, :missing_id}

  # Lexicons without a "main" def (e.g. app.bsky.actor.defs) are pure ref
  # targets; they parse fine and the generator skips them.
  defp parse_defs(%{"defs" => defs}) when is_map(defs) and defs != %{} do
    defs
    |> Enum.sort()
    |> Enum.reduce_while({:ok, %{}}, fn {name, def}, {:ok, acc} ->
      case parse_node(def) do
        {:ok, node} -> {:cont, {:ok, Map.put(acc, name, node)}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp parse_defs(%{"defs" => _}), do: {:error, :empty_defs}
  defp parse_defs(_), do: {:error, :missing_defs}

  # --- Node parsing -------------------------------------------------------------

  defp parse_node(%{"type" => "record"} = node) do
    with {:ok, record} <- parse_node(node["record"]),
         :ok <- check_record_object(record) do
      {:ok, %{kind: :record, key: node["key"], record: record, description: node["description"]}}
    end
  end

  defp parse_node(%{"type" => "object"} = node) do
    with {:ok, properties} <- parse_properties(Map.get(node, "properties", %{})) do
      {:ok,
       %{
         kind: :object,
         properties: properties,
         required: Map.get(node, "required", []),
         nullable: Map.get(node, "nullable", []),
         description: node["description"]
       }}
    end
  end

  defp parse_node(%{"type" => "array"} = node) do
    with {:ok, items} <-
           if(node["items"], do: parse_node(node["items"]), else: {:ok, %{kind: :unknown}}) do
      {:ok,
       %{
         kind: :array,
         items: items,
         min_length: node["minLength"],
         max_length: node["maxLength"],
         description: node["description"]
       }}
    end
  end

  defp parse_node(%{"type" => "ref", "ref" => ref}) when is_binary(ref),
    do: {:ok, %{kind: :ref, ref: ref}}

  defp parse_node(%{"type" => "union"} = node) do
    refs = Map.get(node, "refs", [])

    if Enum.all?(refs, &is_binary/1) do
      {:ok,
       %{
         kind: :union,
         refs: refs,
         closed: Map.get(node, "closed", false),
         description: node["description"]
       }}
    else
      {:error, {:invalid_union_refs, refs}}
    end
  end

  defp parse_node(%{"type" => "token"} = node) do
    {:ok,
     %{
       kind: :token,
       min_length: node["minLength"],
       max_length: node["maxLength"],
       max_graphemes: node["maxGraphemes"],
       description: node["description"]
     }}
  end

  defp parse_node(%{"type" => "string"} = node) do
    {:ok,
     %{
       kind: :string,
       format: node["format"],
       min_length: node["minLength"],
       max_length: node["maxLength"],
       max_graphemes: node["maxGraphemes"],
       enum: node["enum"],
       const: node["const"],
       known_values: node["knownValues"],
       default: node["default"],
       description: node["description"]
     }}
  end

  defp parse_node(%{"type" => "integer"} = node) do
    {:ok,
     %{
       kind: :integer,
       minimum: node["minimum"],
       maximum: node["maximum"],
       const: node["const"],
       default: node["default"],
       description: node["description"]
     }}
  end

  defp parse_node(%{"type" => "boolean"} = node),
    do:
      {:ok,
       %{
         kind: :boolean,
         const: node["const"],
         default: node["default"],
         description: node["description"]
       }}

  defp parse_node(%{"type" => "bytes"} = node),
    do:
      {:ok,
       %{
         kind: :bytes,
         max_length: node["maxLength"],
         min_length: node["minLength"],
         description: node["description"]
       }}

  defp parse_node(%{"type" => "blob"} = node),
    do:
      {:ok,
       %{
         kind: :blob,
         accept: node["accept"],
         max_size: node["maxSize"],
         description: node["description"]
       }}

  defp parse_node(%{"type" => "cid-link"} = node),
    do: {:ok, %{kind: :cid_link, description: node["description"]}}

  defp parse_node(%{"type" => "unknown"} = node),
    do: {:ok, %{kind: :unknown, description: node["description"]}}

  defp parse_node(%{"type" => "params"} = node) do
    with {:ok, properties} <- parse_properties(Map.get(node, "properties", %{})) do
      {:ok, %{kind: :params, properties: properties, required: Map.get(node, "required", [])}}
    end
  end

  # XRPC defs parse into a light IR (kept for future endpoint generation);
  # the generator currently skips lexicons whose main def is one of these.
  defp parse_node(%{"type" => "query"} = node),
    do: {:ok, xrpc_node(:query, node)}

  defp parse_node(%{"type" => "procedure"} = node),
    do: {:ok, xrpc_node(:procedure, node)}

  defp parse_node(%{"type" => "subscription"} = node),
    do: {:ok, xrpc_node(:subscription, node)}

  defp parse_node(%{"type" => "permission-set"} = node),
    do: {:ok, %{kind: :permission_set, description: node["description"], raw: node}}

  defp parse_node(%{"type" => type}), do: {:error, {:unsupported_schema_type, type}}
  defp parse_node(_), do: {:error, :missing_schema_type}

  defp xrpc_node(kind, node) do
    %{
      kind: kind,
      description: node["description"],
      parameters: node["parameters"],
      input: node["input"],
      output: node["output"],
      errors: node["errors"]
    }
  end

  @doc """
  Parse a single schema node (e.g. an XRPC `parameters` block or a
  property) into the IR. Public for the endpoint generator.
  """
  @spec parse_schema_node(map()) :: {:ok, schema_node()} | {:error, term()}
  def parse_schema_node(node), do: parse_node(node)

  @doc false
  defp check_record_object(%{kind: :object}), do: :ok
  defp check_record_object(_), do: {:error, :invalid_record_schema}

  defp parse_properties(properties) do
    Enum.reduce_while(Enum.sort(properties), {:ok, %{}}, fn {name, prop}, {:ok, acc} ->
      case parse_node(prop) do
        {:ok, parsed} -> {:cont, {:ok, Map.put(acc, name, parsed)}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  def known_types, do: @known_types
end
