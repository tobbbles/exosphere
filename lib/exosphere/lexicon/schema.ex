defmodule Exosphere.Lexicon.Schema do
  @moduledoc """
  The `com.atproto.lexicon.schema` record type: publishing lexicons as
  atproto records.

  A lexicon document is stored in the `com.atproto.lexicon.schema`
  collection with the lexicon's NSID as the record key, giving it the
  AT-URI `at://<did>/com.atproto.lexicon.schema/<nsid>`.

  This module wraps the document in a struct and validates it against the
  meta-rules lexicons must follow (beyond the per-node checks
  `Lexicon.Parser` already performs): `lexicon` version 1, an NSID `id`
  with no fragment, at most one primary definition per file, record defs
  carrying a `key`, and refs not pointing at refs/unions/tokens.

  ## Examples

      {:ok, schema} = Exosphere.Lexicon.Schema.new(%{
        "lexicon" => 1,
        "id" => "com.example.post",
        "defs" => %{
          "main" => %{
            "type" => "record",
            "key" => "tid",
            "record" => %{
              "type" => "object",
              "properties" => %{"text" => %{"type" => "string"}}
            }
          }
        }
      })

      schema.record_key
      #=> "com.example.post"

      Exosphere.Lexicon.publish(session, pds_url, did, schema)
  """

  alias Exosphere.ATProto.NSID
  alias Exosphere.Lexicon.Parser

  @collection "com.atproto.lexicon.schema"

  @primary_kinds ~w(query procedure subscription record permission-set)

  @enforce_keys [:id, :defs]
  defstruct [:id, :description, lexicon: 1, defs: %{}, parsed: nil]

  @type t :: %__MODULE__{
          lexicon: 1,
          id: String.t(),
          description: String.t() | nil,
          # Raw JSON defs map, kept for lossless round-tripping on publish
          defs: %{optional(String.t()) => map()},
          parsed: Parser.lexicon() | nil
        }

  @doc "The collection NSID lexicon records live in."
  @spec collection() :: String.t()
  def collection, do: @collection

  @doc """
  Build a `Lexicon.Schema` from a lexicon document map (string or atom
  keys), validating it against the lexicon meta-rules.

  Returns `{:ok, schema}` or `{:error, [{path, message}]}`.
  """

  def new(attrs) when is_map(attrs) do
    doc = atomize_top(attrs)

    case {Parser.parse(doc), validate_document(doc)} do
      {{:ok, parsed}, []} ->
        {:ok,
         %__MODULE__{
           lexicon: parsed_lexicon_version(doc),
           id: parsed.id,
           description: parsed.description,
           defs: doc["defs"],
           parsed: parsed
         }}

      {{:ok, _parsed}, errors} ->
        {:error, errors}

      {{:error, reason}, errors} ->
        {:error, [{"", "invalid lexicon: #{inspect(reason)}"} | errors]}
    end
  end

  def new(_), do: {:error, [{"", "expected a map"}]}

  @doc """
  Decode a fetched `com.atproto.lexicon.schema` record value (the `"value"`
  of a `com.atproto.repo.getRecord` response).
  """
  @spec from_record(map()) :: {:ok, t()} | {:error, [{path :: String.t(), message :: String.t()}]}
  def from_record(%{"$type" => @collection} = record) do
    record
    |> Map.drop(["$type"])
    |> new()
  end

  def from_record(_), do: {:error, [{"$type", "not a #{@collection} record"}]}

  @doc "Encode to the wire record map, including `$type`."
  @spec to_record(t()) :: map()
  def to_record(%__MODULE__{} = schema) do
    %{"$type" => @collection}
    |> Map.put("lexicon", schema.lexicon)
    |> Map.put("id", schema.id)
    |> Map.put("defs", schema.defs)
    |> maybe_put("description", schema.description)
  end

  @doc """
  The record key for this schema: the lexicon NSID itself.
  """
  @spec record_key(t()) :: String.t()
  def record_key(%__MODULE__{id: id}), do: id

  @doc """
  Validate a raw lexicon document against the lexicon meta-rules.

  `Lexicon.Parser` checks the per-node structure (types, record shape,
  union refs); this adds the document-level rules: one primary def per
  lexicon, record defs require a `key`, refs never target refs/unions/
  tokens, and `id` must be a simple NSID. Returns a list of
  `{path, message}` errors (empty when valid).
  """
  @spec validate_document(map()) :: [{path :: String.t(), message :: String.t()}]
  def validate_document(%{"defs" => defs} = doc) when is_map(defs) do
    (Enum.flat_map(defs, fn {name, def} -> validate_def(name, def) end) ++
       validate_single_primary(defs) ++ validate_id(doc) ++ validate_ref_targets(defs, doc))
    |> Enum.uniq()
  end

  def validate_document(_), do: [{"defs", "expected a map of definitions"}]

  defp primary?(%{"type" => kind}), do: kind in @primary_kinds
  defp primary?(_), do: false

  defp validate_single_primary(defs) do
    primaries = for {name, def} <- defs, primary?(def), do: name

    case primaries do
      [] -> []
      [_] -> []
      many -> [{"defs", "multiple primary definitions: #{Enum.join(Enum.sort(many), ", ")}"}]
    end
  end

  defp validate_id(%{"id" => id}) do
    cond do
      not is_binary(id) -> [{"id", "expected a string"}]
      String.contains?(id, "#") -> [{"id", "must be a simple NSID without a fragment"}]
      not NSID.valid?(id) -> [{"id", "not a valid NSID"}]
      true -> []
    end
  end

  defp validate_id(_), do: [{"id", "missing"}]

  defp validate_def(name, def) do
    case def do
      %{"type" => "record"} ->
        key_errors =
          if valid_key?(def["key"]),
            do: [],
            else: [{"defs.#{name}.key", "record definitions require a key"}]

        record_errors =
          if is_map(def["record"]),
            do: [],
            else: [{"defs.#{name}.record", "record definitions require a record object"}]

        key_errors ++ record_errors

      _ ->
        []
    end
  end

  defp valid_key?(key), do: is_binary(key) and key != ""

  defp validate_ref_targets(defs, doc) do
    id = doc["id"]

    defs
    |> Enum.flat_map(fn {_name, def} ->
      def
      |> all_refs()
      |> Enum.map(fn {path, ref} -> {path, ref, resolve_local(ref, id, defs)} end)
    end)
    |> Enum.flat_map(fn {path, ref, target} ->
      case target do
        :remote ->
          []

        nil ->
          [{"#{path}", "unresolvable ref #{ref}"}]

        %{"type" => type} when type in ["ref", "union", "token"] ->
          [{"#{path}", "refs must not target #{type} defs"}]

        _ ->
          []
      end
    end)
  end

  # All refs in a def node, with dotted paths (objects, arrays, unions,
  # records included).
  defp all_refs(%{"type" => "ref", "ref" => ref}), do: [{"", ref}]

  defp all_refs(%{"type" => "union", "refs" => refs}),
    do: refs |> Enum.with_index() |> Enum.map(fn {r, i} -> {"refs[#{i}]", r} end)

  defp all_refs(%{"type" => "array", "items" => items}) when is_map(items),
    do: prepend_path(all_refs(items), "items")

  defp all_refs(%{"type" => "object", "properties" => props}) when is_map(props) do
    Enum.flat_map(props, fn {k, v} -> prepend_path(all_refs(v), k) end)
  end

  defp all_refs(%{"type" => "record", "record" => record}) when is_map(record),
    do: prepend_path(all_refs(record), "record")

  defp all_refs(_), do: []

  defp prepend_path(refs, prefix),
    do:
      Enum.map(refs, fn {path, ref} -> {"#{prefix}.#{path}" |> String.trim_trailing("."), ref} end)

  # Resolve "#def", bare nsid, and "nsid#def" refs against this document.
  defp resolve_local("#" <> def_name, _id, defs), do: defs[def_name]

  defp resolve_local(ref, id, defs) do
    case String.split(ref, "#", parts: 2) do
      [^id] -> defs["main"]
      [^id, def_name] -> defs[def_name]
      _ -> :remote
    end
  end

  defp parsed_lexicon_version(%{"lexicon" => v}) when is_integer(v), do: v
  defp parsed_lexicon_version(_), do: 1

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp atomize_top(attrs) do
    Map.new(attrs, fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), v}
      {k, v} when is_binary(k) -> {k, v}
    end)
  end
end
