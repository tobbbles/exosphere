defmodule Exosphere.Bsky.Runtime do
  @moduledoc """
  Shared runtime helpers used by the generated `Exosphere.Bsky.*` modules.

  This module is hand-written, not generated. It provides the coercion and
  validation primitives that generated record modules call with their
  lexicon-derived constraints, so the generated files stay lean.

  All validators return `{value, errors}` where errors is a list of
  `{field_path, message}` tuples. `nil` values for optional fields are
  skipped (or replaced by the lexicon default).
  """

  alias Exosphere.ATProto.{AtUri, CID, NSID, TID}
  alias Exosphere.ATProto.Identity.{DID, Handle}

  @type error :: {String.t(), String.t()}

  # --- Coercion ----------------------------------------------------------------

  @doc """
  Split a wire-format map into known atom-keyed attrs and unknown extras.

  Accepts atom or string keys. String keys are translated through `fields`
  (atom key => wire name); `"$type"` is dropped; unknown keys land in `extra`
  keyed by their original string name.
  """
  @spec atomize(map(), %{atom() => String.t()}) :: {map(), map()}
  def atomize(attrs, fields) when is_map(attrs) do
    inverse = Map.new(fields, fn {k, v} -> {v, k} end)

    Enum.reduce(attrs, {%{}, %{}}, fn
      {"$type", _}, acc -> acc
      {key, value}, {known, extra} ->
        atom = if is_atom(key), do: key, else: Map.get(inverse, key)

        if atom && Map.has_key?(fields, atom) do
          {Map.put(known, atom, value), extra}
        else
          {known, Map.put(extra, to_string(key), value)}
        end
    end)
  end

  # --- Field getters -----------------------------------------------------------

  @doc "Fetch and validate a string field."
  @spec get_string(map(), atom(), String.t(), keyword()) :: {term(), [error()]}
  def get_string(attrs, key, path, opts \\ []) do
    case fetch(attrs, key, path, opts) do
      {:ok, nil} -> if(opts[:required], do: {nil, [{path, "is required"}]}, else: {nil, []})
      {:ok, value} -> check_string(value, path, opts)
      {:error, error} -> {nil, [error]}
    end
  end

  @doc "Fetch and validate an integer field."
  @spec get_integer(map(), atom(), String.t(), keyword()) :: {term(), [error()]}
  def get_integer(attrs, key, path, opts \\ []) do
    case fetch(attrs, key, path, opts) do
      {:ok, nil} -> if(opts[:required], do: {nil, [{path, "is required"}]}, else: {nil, []})
      {:ok, value} when is_integer(value) -> check_integer(value, path, opts)
      {:ok, value} -> {nil, [{path, "expected integer, got #{type_name(value)}"}]}
      {:error, error} -> {nil, [error]}
    end
  end

  @doc "Fetch and validate a boolean field."
  @spec get_boolean(map(), atom(), String.t(), keyword()) :: {term(), [error()]}
  def get_boolean(attrs, key, path, opts \\ []) do
    case fetch(attrs, key, path, opts) do
      {:ok, nil} -> if(opts[:required], do: {nil, [{path, "is required"}]}, else: {nil, []})
      {:ok, value} when is_boolean(value) ->
        case Keyword.get(opts, :const) do
          nil -> {value, []}
          expected when expected == value -> {value, []}
          expected -> {nil, [{path, "must be #{inspect(expected)}"}]}
        end

      {:ok, value} ->
        {nil, [{path, "expected boolean, got #{type_name(value)}"}]}

      {:error, error} ->
        {nil, [error]}
    end
  end

  @doc """
  Fetch and validate an array field, checking each item with `item_fn`.

  `item_fn` receives `(value, path)` and returns `{:ok, value}` or
  `{:error, message}`.
  """
  @spec get_array(map(), atom(), String.t(), keyword(), (term(), String.t() -> {:ok, term()} | {:error, String.t()})) ::
          {term(), [error()]}
  def get_array(attrs, key, path, opts, item_fn) do
    case fetch(attrs, key, path, opts) do
      {:ok, nil} ->
        if opts[:required], do: {nil, [{path, "is required"}]}, else: {nil, []}

      {:ok, value} when is_list(value) ->
        {values, errors} =
          Enum.with_index(value)
          |> Enum.reduce({[], []}, fn {item, i}, {values, errors} ->
            case item_fn.(item, "#{path}[#{i}]") do
              {:ok, coerced} -> {[coerced | values], errors}
              {:error, new_errors} -> {[item | values], Enum.reverse(new_errors) ++ errors}
            end
          end)

        values = Enum.reverse(values)
        errors = Enum.reverse(errors)

        length_errors =
          []
          |> maybe_error(opts[:min_length] && length(value) < opts[:min_length], path,
            "must have at least #{opts[:min_length]} items"
          )
          |> maybe_error(opts[:max_length] && length(value) > opts[:max_length], path,
            "must have at most #{opts[:max_length]} items"
          )

        {values, errors ++ length_errors}

      {:ok, value} ->
        {nil, [{path, "expected array, got #{type_name(value)}"}]}

      {:error, error} ->
        {nil, [error]}
    end
  end

  @doc """
  Fetch a field referencing another lexicon object.

  Accepts a struct built by `mod`/`new/1` directly, or a map which is
  coerced through `mod.new/1`.
  """
  @spec get_ref(map(), atom(), String.t(), keyword(), module()) :: {term(), [error()]}
  def get_ref(attrs, key, path, opts, mod) do
    case fetch(attrs, key, path, opts) do
      {:ok, nil} -> if(opts[:required], do: {nil, [{path, "is required"}]}, else: {nil, []})
      {:ok, %^mod{} = value} -> {value, []}
      {:ok, value} when is_map(value) -> coerce(mod, value, path)
      {:ok, value} -> {nil, [{path, "expected #{inspect(mod)} or map, got #{type_name(value)}"}]}
      {:error, error} -> {nil, [error]}
    end
  end

  @doc """
  Fetch a union field. `variants` is a list of `{nsid, module}` pairs.

  Discriminates on `$type` for maps; unknown `$type`s pass through as maps
  (unions are open-world). Structs of a known variant module pass as-is.
  """
  @spec get_union(map(), atom(), String.t(), keyword(), [{String.t(), module()}]) ::
          {term(), [error()]}
  def get_union(attrs, key, path, opts, variants) do
    case fetch(attrs, key, path, opts) do
      {:ok, nil} ->
        if opts[:required], do: {nil, [{path, "is required"}]}, else: {nil, []}

      {:ok, value} ->
        case union_item(value, path, variants) do
          {:ok, value} -> {value, []}
          {:error, {path, message}} -> {nil, [{path, message}]}
        end

      {:error, error} ->
        {nil, [error]}
    end
  end

  @doc "Validate a single union value against known variants."
  @spec union_item(term(), String.t(), [{String.t(), module()}]) ::
          {:ok, term()} | {:error, {String.t(), String.t()}}
  def union_item(%mod{} = value, path, variants) do
    if Enum.any?(variants, fn {_nsid, m} -> m == mod end),
      do: {:ok, value},
      else: {:error, {path, "unknown variant struct #{inspect(mod)}"}}
  end

  def union_item(%{"$type" => type} = value, path, variants) do
    case List.keyfind(variants, type, 0) do
      nil ->
        {:ok, value}

      {_type, mod} ->
        case coerce(mod, value, path) do
          {v, []} -> {:ok, v}
          {_v, errors} -> {:error, List.first(errors)}
        end
    end
  end

  def union_item(value, _path, _variants) when is_map(value), do: {:ok, value}
  def union_item(value, path, _variants), do: {:error, {path, "expected map, got #{type_name(value)}"}}

  @doc "Fetch a field of any shape (unknown, blob, cid-link, bytes, unresolved ref)."
  @spec get_any(map(), atom(), String.t(), keyword()) :: {term(), [error()]}
  def get_any(attrs, key, path, opts \\ []) do
    case fetch(attrs, key, path, opts) do
      {:ok, value} -> {value, []}
      {:error, error} -> {nil, [error]}
    end
  end

  # --- Item validators (for array elements) ------------------------------------

  @doc "Validate one string item; opts as for `get_string/4` constraints."
  @spec item_string(term(), String.t(), keyword()) :: {:ok, term()} | {:error, [{String.t(), String.t()}]}
  def item_string(value, path, opts) do
    case check_string(value, path, opts) do
      {_v, []} -> {:ok, value}
      {_v, [{^path, message} | _]} -> {:error, [{path, message}]}
    end
  end

  @doc "Validate one ref item: struct of `mod` or a map coerced through `mod.new/1`."
  @spec item_ref(term(), String.t(), module()) :: {:ok, term()} | {:error, [{String.t(), String.t()}]}
  def item_ref(%mod{} = value, _path, mod), do: {:ok, value}

  def item_ref(value, path, mod) when is_map(value) do
    case coerce(mod, value, path) do
      {v, []} -> {:ok, v}
      {_v, errors} -> {:error, errors}
    end
  end

  def item_ref(value, path, mod),
    do: {:error, [{path, "expected #{inspect(mod)} or map, got #{type_name(value)}"}]}

  @doc "Validate one union item against known variants."
  @spec item_union(term(), String.t(), [{String.t(), module()}]) ::
          {:ok, term()} | {:error, [{String.t(), String.t()}]}
  def item_union(value, path, variants) do
    case union_item(value, path, variants) do
      {:ok, value} -> {:ok, value}
      {:error, {path, message}} -> {:error, [{path, message}]}
    end
  end

  # --- Encoding (to_map) helpers -----------------------------------------------

  @doc "Put a field into the wire map, skipping `nil` values."
  @spec put_field(map(), String.t(), term()) :: map()
  def put_field(map, _name, nil), do: map
  def put_field(map, name, value), do: Map.put(map, name, value)

  @doc "Put an encoded field into the wire map, skipping `nil` values."
  @spec put_field(map(), String.t(), term(), (term() -> term())) :: map()
  def put_field(map, _name, nil, _encoder), do: map
  def put_field(map, name, value, encoder), do: Map.put(map, name, encoder.(value))

  # --- Internals -----------------------------------------------------------------

  defp fetch(attrs, key, path, opts) do
    case Map.fetch(attrs, key) do
      :error ->
        if opts[:required],
          do: {:error, {path, "is required"}},
          else: {:ok, Keyword.get(opts, :default)}

      {:ok, value} ->
        {:ok, value}
    end
  end

  defp coerce(mod, value, path) do
    case mod.new(value) do
      {:ok, coerced} -> {coerced, []}
      # Subfield errors keep their path relative to the parent field
      {:error, errors} -> {nil, Enum.map(errors, fn {sub, msg} -> {"#{path}.#{sub}", msg} end)}
    end
  end

  defp check_string(value, path, opts) when is_binary(value) do
    errors =
      []
      |> maybe_error(opts[:min_length] && String.length(value) < opts[:min_length], path,
        "must be at least #{opts[:min_length]} characters"
      )
      |> maybe_error(opts[:max_length] && utf16_length(value) > opts[:max_length], path,
        "must be at most #{opts[:max_length]} characters"
      )
      |> maybe_error(opts[:max_graphemes] && String.length(value) > opts[:max_graphemes], path,
        "must be at most #{opts[:max_graphemes]} graphemes"
      )
      |> maybe_error(opts[:enum] && value not in opts[:enum], path,
        "must be one of #{inspect(opts[:enum])}"
      )
      |> maybe_error(
        opts[:const] && value != opts[:const],
        path,
        "must be #{inspect(opts[:const])}"
      )
      |> maybe_error(
        opts[:format] && format(opts[:format], value) == false,
        path,
        "is not a valid #{opts[:format]}"
      )

    {value, errors}
  end

  defp check_string(value, path, _opts),
    do: {nil, [{path, "expected string, got #{type_name(value)}"}]}

  defp check_integer(value, path, opts) do
    errors =
      []
      |> maybe_error(opts[:minimum] && value < opts[:minimum], path,
        "must be >= #{opts[:minimum]}"
      )
      |> maybe_error(opts[:maximum] && value > opts[:maximum], path, "must be <= #{opts[:maximum]}")

    {value, errors}
  end

  defp maybe_error(errors, true, path, message), do: [{path, message} | errors]
  defp maybe_error(errors, _falsy, _path, _message), do: errors

  # Lexicon string maxLength is counted in UTF-16 code units.
  defp utf16_length(string) do
    string
    |> String.codepoints()
    |> Enum.map(&if byte_size(&1) == 4, do: 2, else: 1)
    |> Enum.sum()
  end

  defp type_name(value) do
    case value do
      v when is_binary(v) -> "string"
      v when is_integer(v) -> "integer"
      v when is_boolean(v) -> "boolean"
      v when is_list(v) -> "array"
      v when is_map(v) -> "map"
      v when is_nil(v) -> "nil"
      _ -> "unknown"
    end
  end

  # Lexicon string formats. Unknown formats are accepted (open-world).
  defp format("at-uri", v), do: AtUri.valid?(v)
  defp format("did", v), do: DID.valid?(v)
  defp format("handle", v), do: Handle.valid?(v)
  defp format("at-identifier", v), do: DID.valid?(v) or Handle.valid?(v)
  defp format("nsid", v), do: NSID.valid?(v)
  defp format("tid", v), do: TID.valid?(v)
  defp format("cid", v), do: match?({:ok, _}, CID.decode(v))
  defp format("datetime", v), do: match?({:ok, _, _}, DateTime.from_iso8601(v))
  defp format("uri", v), do: uri?(v)
  defp format("language", v), do: Regex.match?(~r/^[a-zA-Z]{2,3}(-[a-zA-Z0-9]{1,8})*$/, v)
  defp format(_unknown, _v), do: true

  defp uri?(v) do
    case URI.new(v) do
      {:ok, %URI{scheme: scheme}} when not is_nil(scheme) -> true
      _ -> false
    end
  end
end
