defmodule Exosphere.ATProto.DataModel do
  @moduledoc """
  Validation of values against the atproto data model.

  atproto records are restricted to a subset of DAG-CBOR: no non-integral
  floats, string map keys, and the special wrapper objects (`$link`, `$bytes`,
  blobs) must have exactly the right shape. This module checks those rules on
  the JSON representation used by XRPC and the interop fixtures — the form
  where wrappers are still plain maps (`%{"$link" => cid_string}`) — so a
  value can be validated before encoding or after decoding.

  ## Rules

  - Top level must be an object (map); map keys must be strings.
  - Allowed leaves: `nil`, booleans, integers, strings, and integer-valued
    floats (JSON has no integer/float distinction; `123.0` is fine, `123.456`
    is not representable in the data model).
  - `{"$link": cid}` — exactly one key; the value must be a string containing
    a valid CID.
  - `{"$bytes": b64}` — exactly one key; the value must be an unpadded
    base64 string (standard alphabet, no `=` padding), the form atproto
    specifies for byte strings.
  - A blob is `{"$type": "blob", "ref": {"$link": …}, "mimeType": string,
    "size": non-negative integer}` with exactly those keys.
  - `$type`, where present, must be a non-empty string (blobs require it).
  - Integers are signed 64-bit: outside `-2^63..2^63-1` is
    `:integer_out_of_range` (DAG-CBOR could carry them only as tag-2/3
    bignums, which the data model does not have).
  - Map keys must be non-empty strings (`:empty_map_key`).
  - Nesting (maps and lists, the top level counting as 1) is at most 32
    deep (`:max_depth_exceeded`), so a hostile record cannot push recursive
    consumers into unbounded recursion.
  - Lists and maps validate recursively.

  Unknown `$`-prefixed keys are *not* rejected: the spec reserves them for
  the protocol but says "implementations should ignore unknown `$` fields
  (to allow protocol evolution)". The three defined ones (`$type`, `$link`,
  `$bytes`) are checked as above.

  ## Examples

      iex> Exosphere.ATProto.DataModel.valid?(%{"a" => [1, 2, nil]})
      true

      iex> Exosphere.ATProto.DataModel.valid?(%{"a" => 123.456})
      false
  """

  alias Exosphere.ATProto.CID

  @max_depth 32
  @int_min -0x8000000000000000
  @int_max 0x7FFFFFFFFFFFFFFF

  @type value ::
          nil
          | boolean()
          | integer()
          | float()
          | String.t()
          | [value()]
          | %{optional(String.t()) => value()}

  @doc """
  Validate an atproto record: like `validate/1` but the top level must be an
  object.
  """
  @spec validate_record(term()) :: :ok | {:error, {path :: String.t(), reason :: atom()}}
  def validate_record(v) when is_map(v), do: validate(v, "", 0)
  def validate_record(_v), do: {:error, {"", :top_level_not_object}}

  @doc """
  Validate a value against the atproto data model.

  Returns `:ok` or `{:error, reason}` with a path-prefixed reason such as
  `{:error, {"rcrd.a", :non_integral_float}}`.
  """
  @spec validate(term()) :: :ok | {:error, {path :: String.t(), reason :: atom()}}
  def validate(value), do: validate(value, "", 0)

  @doc "The maximum container nesting depth `validate/1` accepts."
  @spec max_depth() :: pos_integer()
  def max_depth, do: @max_depth

  @doc "Whether `n` fits the data model's signed 64-bit integer range."
  @spec int64?(term()) :: boolean()
  def int64?(n), do: is_integer(n) and n >= @int_min and n <= @int_max

  defp validate(nil, _path, _depth), do: :ok
  defp validate(v, _path, _depth) when is_boolean(v), do: :ok

  defp validate(v, path, _depth) when is_integer(v) do
    if int64?(v), do: :ok, else: {:error, {path, :integer_out_of_range}}
  end

  defp validate(v, _path, _depth) when is_binary(v), do: :ok

  defp validate(%CBOR.Tag{tag: :bytes, value: bytes}, _path, _depth) when is_binary(bytes),
    do: :ok

  defp validate(%CID{} = _link, _path, _depth), do: :ok

  defp validate(v, path, _depth) when is_float(v) do
    if trunc(v) == v, do: :ok, else: {:error, {path, :non_integral_float}}
  end

  defp validate(v, path, depth) when (is_list(v) or is_map(v)) and depth >= @max_depth,
    do: {:error, {path, :max_depth_exceeded}}

  defp validate(v, path, depth) when is_list(v) do
    v
    |> Enum.with_index()
    |> Enum.find_value(fn {item, i} ->
      case validate(item, "#{path}[#{i}]", depth + 1) do
        :ok -> nil
        {:error, _} = error -> error
      end
    end)
    |> Kernel.||(:ok)
  end

  defp validate(v, path, depth) when is_map(v) do
    with :ok <- validate_keys(v, path) do
      validate_map(v, path, depth + 1)
    end
  end

  defp validate(_v, path, _depth), do: {:error, {path, :unsupported_type}}

  defp validate_keys(v, path) do
    keys = Map.keys(v)

    cond do
      not Enum.all?(keys, &is_binary/1) -> {:error, {path, :non_string_map_key}}
      "" in keys -> {:error, {path, :empty_map_key}}
      true -> :ok
    end
  end

  # The JSON-representation wrappers, checked before generic map recursion.
  defp validate_map(v, path, depth) do
    cond do
      Map.has_key?(v, "$link") -> validate_wrapper(v, "$link", path, &validate_link/2)
      Map.has_key?(v, "$bytes") -> validate_wrapper(v, "$bytes", path, &validate_bytes/2)
      true -> validate_object(v, path, depth)
    end
  end

  # Wrappers must be exactly one key of the right shape.
  defp validate_wrapper(v, key, path, validate_value) do
    if map_size(v) == 1 do
      validate_value.(Map.get(v, key), join(path, key))
    else
      {:error, {join(path, key), :wrapper_with_extra_fields}}
    end
  end

  defp validate_link(link, path) do
    cond do
      not is_binary(link) -> {:error, {path, :invalid_field_type}}
      match?({:ok, _}, CID.decode(link)) -> :ok
      true -> {:error, {path, :invalid_cid}}
    end
  end

  # atproto specifies byte strings as unpadded standard-alphabet base64
  # (Base.decode64/2 with padding: false tolerates padding, hence the
  # explicit "=" rejection).
  defp validate_bytes(bytes, path) do
    cond do
      not is_binary(bytes) ->
        {:error, {path, :invalid_field_type}}

      String.contains?(bytes, "=") ->
        {:error, {path, :invalid_base64}}

      match?({:ok, _}, Base.decode64(bytes, padding: false)) ->
        :ok

      true ->
        {:error, {path, :invalid_base64}}
    end
  end

  defp validate_object(v, path, depth) do
    with :ok <- validate_type_field(v, path),
         :ok <- maybe_validate_blob(v, path) do
      v
      |> Enum.find_value(fn {k, value} ->
        case validate(value, join(path, k), depth) do
          :ok -> nil
          {:error, _} = error -> error
        end
      end)
      |> Kernel.||(:ok)
    end
  end

  defp validate_type_field(v, path) do
    case Map.fetch(v, "$type") do
      :error ->
        :ok

      {:ok, t} when is_binary(t) ->
        if t != "", do: :ok, else: {:error, {join(path, "$type"), :empty_type}}

      {:ok, _} ->
        {:error, {join(path, "$type"), :invalid_field_type}}
    end
  end

  defp maybe_validate_blob(%{"$type" => "blob"} = blob, path), do: validate_blob(blob, path)
  defp maybe_validate_blob(_v, _path), do: :ok

  # A blob is exactly $type/ref/mimeType/size with the right field types.
  defp validate_blob(blob, path) do
    with :ok <- check_blob_fields(blob, path),
         :ok <- validate_link_wrapper(Map.get(blob, "ref"), join(path, "ref")),
         :ok <- check_binary(Map.get(blob, "mimeType"), join(path, "mimeType")) do
      check_size(Map.get(blob, "size"), join(path, "size"))
    end
  end

  defp check_blob_fields(blob, path) do
    case Map.keys(blob)
         |> MapSet.new()
         |> MapSet.difference(MapSet.new(["$type", "ref", "mimeType", "size"]))
         |> Enum.to_list() do
      [] -> :ok
      extra -> {:error, {join(path, hd(extra)), :blob_with_unexpected_fields}}
    end
  end

  defp validate_link_wrapper(%{"$link" => link} = ref, path) when map_size(ref) == 1,
    do: validate_link(link, path)

  defp validate_link_wrapper(_ref, path), do: {:error, {path, :invalid_field_type}}

  defp check_binary(v, _path) when is_binary(v), do: :ok
  defp check_binary(_v, path), do: {:error, {path, :invalid_field_type}}

  defp check_size(v, _path) when is_integer(v) and v >= 0, do: :ok
  defp check_size(_v, path), do: {:error, {path, :invalid_field_type}}

  defp join("", key), do: key
  defp join(path, key), do: path <> "." <> key

  @doc """
  Returns `true` when `value` conforms to the atproto data model.
  """
  @spec valid?(term()) :: boolean()
  def valid?(value), do: validate(value) == :ok
end
