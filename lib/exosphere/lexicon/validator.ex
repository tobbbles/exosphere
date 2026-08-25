defmodule Exosphere.Lexicon.Validator do
  @moduledoc """
  Runtime validation of values against parsed lexicon schemas.

  Where the generated modules validate at compile-time types (via
  `new/1`), this module validates plain maps at runtime against the
  `Lexicon.Parser` IR — for lexicons that were never code-generated, for
  records fetched off the wire, and for third-party types discovered at
  runtime via `Lexicon.Resolver`.

  Validation follows the [lexicon spec](https://atproto.com/specs/lexicon):

  - Unknown properties in objects are ignored, permissive for schema
    evolution (pass `strict: true` to reject them).
  - Unions are open: a `$type` outside the declared refs still passes as
    long as the value satisfies the data model (`strict: true` rejects).
  - `enum` is closed; `knownValues` is advisory and never fails.
  - `maxLength`/`minLength` count UTF-8 bytes; `maxGraphemes`/
    `minGraphemes` count grapheme clusters.
  - Required fields may hold `null` only when listed in `nullable`.

  Cross-lexicon refs (e.g. a `com.atproto.repo.strongRef` subject field)
  resolve through `Lexicon.Registry` (or the `:registry` opt). **A ref
  whose target lexicon is not registered is skipped silently in the
  permissive mode** — the field passes unchecked. Use `strict: true` to
  make unresolved refs an error, and load the referenced lexicons
  (`Registry.load_vendored/0` covers the vendored corpus) before
  validating anything that refs into it.

  Values are the JSON wire representation (CID links as
  `%{"$link" => cid}`, bytes as `%{"$bytes" => b64}`, blobs as
  `%{"$type" => "blob", ...}`) and are additionally checked against the
  atproto data model.

  ## Examples

      {:ok, lexicon} = Exosphere.Lexicon.Parser.parse(json)

      :ok = Exosphere.Lexicon.Validator.validate(%{"text" => "hi"}, lexicon)
      {:error, [{"text", _}]} =
        Exosphere.Lexicon.Validator.validate(%{"text" => 123}, lexicon)
  """

  alias Exosphere.ATProto.{AtUri, CID, DataModel, NSID, RecordKey, TID}
  alias Exosphere.Lexicon.{Parser, Registry}

  @type error :: {path :: String.t(), message :: String.t()}
  @type opt :: {:strict, boolean()} | {:registry, module() | map()}

  @string_formats ~w(datetime uri at-uri nsid did cid handle language tid record-key at-identifier)

  @doc """
  Validate `value` against a definition of a parsed lexicon.

  `def_name` defaults to `"main"`. Returns `:ok` or
  `{:error, [{path, message}]}`.
  """
  @spec validate(term(), Parser.lexicon(), String.t(), [opt()]) ::
          :ok | {:error, [error()]}
  def validate(value, %{} = lexicon, def_name \\ "main", opts \\ []) do
    ctx = %{
      lexicon: lexicon,
      strict: Keyword.get(opts, :strict, false),
      registry: Keyword.get(opts, :registry, Registry)
    }

    case DataModel.validate(value) do
      :ok ->
        case lexicon.defs[def_name] do
          nil ->
            {:error, [{"", "unknown definition #{lexicon.id}##{def_name}"}]}

          node ->
            case check(value, node, "", ctx) do
              [] -> :ok
              errors -> {:error, errors}
            end
        end

      {:error, {path, reason}} ->
        {:error, [{path, "violates the atproto data model: #{inspect(reason)}"}]}
    end
  end

  @doc "Validate a record map (with `$type`) against its lexicon."
  @spec validate_record(term(), Parser.lexicon(), [opt()]) :: :ok | {:error, [error()]}
  def validate_record(value, lexicon, opts \\ []) do
    case DataModel.validate_record(value) do
      :ok ->
        case value do
          %{"$type" => type} when type == lexicon.id ->
            validate(value, lexicon, "main", opts)

          %{"$type" => other} ->
            {:error, [{"$type", "expected #{lexicon.id}, got: #{other}"}]}

          _ ->
            {:error, [{"$type", "missing $type"}]}
        end

      {:error, {path, reason}} ->
        {:error, [{path, "violates the atproto data model: #{inspect(reason)}"}]}
    end
  end

  # --- Node checks ----------------------------------------------------------------

  defp check(value, %{kind: :object} = node, path, ctx) do
    if is_map(value) do
      %{properties: props, required: required, nullable: nullable} = node
      required = required || []
      nullable = nullable || []

      Enum.flat_map(required, fn name ->
        cond do
          not Map.has_key?(value, name) ->
            [err(path, name, "missing required field")]

          is_nil(value[name]) and name not in nullable ->
            [err(path, name, "null but not nullable")]

          true ->
            []
        end
      end) ++
        Enum.flat_map(props, fn {name, prop} ->
          child = join(path, name)

          cond do
            not Map.has_key?(value, name) ->
              []

            is_nil(value[name]) ->
              if name in nullable,
                do: [],
                else: [err(path, name, "null but not nullable")]

            true ->
              check(value[name], prop, child, ctx)
          end
        end) ++ unknown_fields(value, props, path, ctx)
    else
      [err(path, "", "expected an object")]
    end
  end

  defp check(value, %{kind: :record} = node, path, ctx),
    do: check(value, node.record, path, ctx)

  defp check(value, %{kind: :string} = node, path, _ctx) do
    if is_binary(value) do
      []
      |> check_byte_length(value, node, path)
      |> check_graphemes(value, node, path)
      |> check_enum(value, node, path)
      |> check_const(value, node, path)
      |> check_format(value, node, path)
    else
      [err(path, "", "expected a string")]
    end
  end

  # Tokens share string checks but never carry format/enum
  defp check(value, %{kind: :token} = node, path, _ctx) do
    if is_binary(value) do
      [] |> check_byte_length(value, node, path) |> check_graphemes(value, node, path)
    else
      [err(path, "", "expected a string")]
    end
  end

  defp check(value, %{kind: :integer} = node, path, _ctx) do
    if is_integer(value) do
      []
      |> check_min(value, node, path)
      |> check_max(value, node, path)
      |> check_const(value, node, path)
    else
      [err(path, "", "expected an integer")]
    end
  end

  defp check(value, %{kind: :boolean} = node, path, _ctx) do
    if is_boolean(value) do
      check_const([], value, node, path)
    else
      [err(path, "", "expected a boolean")]
    end
  end

  defp check(value, %{kind: :bytes} = node, path, _ctx) do
    case value do
      bin when is_binary(bin) ->
        check_byte_length([], bin, node, path)

      %{"$bytes" => b64} ->
        if match?({:ok, _}, Base.decode64(b64, padding: false)) and
             not String.contains?(b64, "="),
           do: check_byte_length([], b64, node, path),
           else: [err(path, "", "expected unpadded base64 bytes")]

      _ ->
        [err(path, "", "expected bytes")]
    end
  end

  defp check(value, %{kind: :cid_link}, path, _ctx) do
    case value do
      %{"$link" => link} when map_size(value) == 1 ->
        if match?({:ok, _}, CID.decode(link)), do: [], else: [err(path, "", "invalid CID")]

      %CID{} ->
        []

      _ ->
        [err(path, "", "expected a CID link")]
    end
  end

  defp check(value, %{kind: :blob} = node, path, _ctx) do
    case value do
      %{"$type" => "blob"} ->
        accept = node[:accept] || node.accept

        if is_list(accept) and accept != [] and value["mimeType"] not in accept,
          do: [err(path, "", "mimeType not in accept list")],
          else: []

      _ ->
        [err(path, "", "expected a blob")]
    end
  end

  defp check(value, %{kind: :array} = node, path, ctx) do
    if is_list(value) do
      length_errors =
        []
        |> check_min_length(value, node, path)
        |> check_max_length(value, node, path)

      item_errors =
        value
        |> Enum.with_index()
        |> Enum.flat_map(fn {item, i} ->
          check(item, node.items, "#{path}[#{i}]", ctx)
        end)

      length_errors ++ item_errors
    else
      [err(path, "", "expected an array")]
    end
  end

  defp check(value, %{kind: :ref} = node, path, ctx) do
    case resolve_ref(node.ref, ctx) do
      {:ok, target, ctx} ->
        check(value, target, path, ctx)

      :error ->
        # Without the target lexicon the field cannot be checked; only
        # strict mode surfaces the omission.
        if ctx.strict,
          do: [err(path, "", "unresolved ref #{node.ref} (lexicon not registered)")],
          else: []
    end
  end

  defp check(value, %{kind: :union} = node, path, ctx) do
    case value do
      %{"$type" => type} when is_binary(type) ->
        {variants, unresolved} =
          Enum.reduce(node.refs, {[], []}, fn ref, {ok, bad} ->
            case resolve_ref(ref, ctx) do
              {:ok, _, _} -> {[ref_type_id(ref, ctx.lexicon.id) | ok], bad}
              :error -> {ok, [ref | bad]}
            end
          end)

        variants = Enum.reverse(variants)

        cond do
          type in variants ->
            check(value, resolve_variant(type, node, ctx), path, ctx)

          node.closed ->
            [
              err(path, "$type", "closed union: unknown variant #{type}")
              | unresolved_error(unresolved, ctx)
            ]

          ctx.strict ->
            [
              err(path, "$type", "unknown union variant #{type}")
              | unresolved_error(unresolved, ctx)
            ]

          true ->
            []
        end

      _ ->
        [err(path, "", "union values must be objects with a $type")]
    end
  end

  defp check(_value, %{kind: :unknown}, _path, _ctx), do: []

  # XRPC def nodes (params/query/...) never validate record values
  defp check(_value, _node, path, _ctx), do: [err(path, "", "unsupported schema node")]

  defp unresolved_error(_unresolved, %{strict: false}), do: []

  defp unresolved_error([], %{strict: true}), do: []

  defp unresolved_error(unresolved, %{strict: true}),
    do: [
      err("", "$type", "unresolved union refs #{inspect(unresolved)} (lexicons not registered)")
    ]

  # --- Helpers ---------------------------------------------------------------------

  defp resolve_variant(type, node, ctx) do
    ref =
      Enum.find(node.refs, fn ref ->
        ref_type_id(ref, ctx.lexicon.id) == type
      end) || ""

    case resolve_ref(ref, ctx) do
      {:ok, target, _ctx} -> target
      :error -> %{kind: :unknown}
    end
  end

  # The $type a union variant ref corresponds to: "#def" → "nsid#def",
  # "nsid" → "nsid", "nsid#def" → itself.
  defp ref_type_id("#" <> def_name, owner_nsid), do: "#{owner_nsid}##{def_name}"
  defp ref_type_id(ref, _owner_nsid), do: ref

  # Resolve a ref string to its target node, locally first, then through
  # the registry for cross-lexicon refs.
  defp resolve_ref("#" <> def_name, ctx) do
    case ctx.lexicon.defs[def_name] do
      nil -> :error
      node -> {:ok, node, ctx}
    end
  end

  defp resolve_ref(ref, ctx) do
    case String.split(ref, "#", parts: 2) do
      [nsid] ->
        with {:ok, lexicon} <- lookup(nsid, ctx),
             %{} = node <- Map.get(lexicon.defs, "main", :missing) do
          {:ok, node, Map.put(ctx, :lexicon, lexicon)}
        else
          _ -> :error
        end

      [nsid, def_name] ->
        with {:ok, lexicon} <- lookup(nsid, ctx),
             %{} = node <- Map.get(lexicon.defs, def_name, :missing) do
          {:ok, node, Map.put(ctx, :lexicon, lexicon)}
        else
          _ -> :error
        end
    end
  end

  defp lookup(nsid, %{registry: registry}) when is_map(registry),
    do: Map.fetch(registry, nsid)

  defp lookup(nsid, %{registry: registry}) when is_atom(registry),
    do: registry.fetch(nsid)

  defp unknown_fields(value, props, path, ctx) do
    if ctx.strict do
      known = MapSet.new(Map.keys(props)) |> MapSet.put("$type")

      value
      |> Map.keys()
      |> Enum.reject(&MapSet.member?(known, &1))
      |> Enum.map(&err(path, &1, "unknown field"))
      |> Enum.sort()
    else
      []
    end
  end

  defp check_byte_length(errors, value, node, path) do
    size = byte_size(value)

    errors ++
      over(node, :max_length, size, path, "longer than maxLength") ++
      under(node, :min_length, size, path, "shorter than minLength")
  end

  defp check_graphemes(errors, value, node, path) do
    size = String.length(value)

    errors ++
      over(node, :max_graphemes, size, path, "longer than maxGraphemes") ++
      under(node, :min_graphemes, size, path, "shorter than minGraphemes")
  end

  defp over(node, key, size, path, message) do
    case opt(node, key) do
      bound when is_integer(bound) and size > bound -> [err(path, "", "#{message} #{bound}")]
      _ -> []
    end
  end

  defp under(node, key, size, path, message) do
    case opt(node, key) do
      bound when is_integer(bound) and size < bound -> [err(path, "", "#{message} #{bound}")]
      _ -> []
    end
  end

  defp check_enum(errors, value, node, path) do
    case opt(node, :enum) do
      nil ->
        errors

      enum ->
        if value in enum, do: errors, else: [err(path, "", "not one of enum #{inspect(enum)}")]
    end
  end

  defp check_const(errors, value, node, path) do
    case opt(node, :const) do
      nil ->
        errors

      const ->
        if value === const,
          do: errors,
          else: [err(path, "", "must equal const #{inspect(const)}")]
    end
  end

  defp check_format(errors, value, node, path) do
    case opt(node, :format) do
      format when format in @string_formats ->
        if format_valid?(format, value),
          do: errors,
          else: [err(path, "", "invalid #{format} format")]

      _ ->
        errors
    end
  end

  defp check_min(errors, value, node, path) do
    case opt(node, :minimum) do
      nil ->
        errors

      min ->
        if value >= min, do: errors, else: [err(path, "", "below minimum #{min}")]
    end
  end

  defp check_max(errors, value, node, path) do
    case opt(node, :maximum) do
      nil ->
        errors

      max ->
        if value <= max, do: errors, else: [err(path, "", "above maximum #{max}")]
    end
  end

  defp check_min_length(errors, value, node, path) do
    case opt(node, :min_length) do
      nil ->
        errors

      min ->
        if length(value) >= min,
          do: errors,
          else: [err(path, "", "shorter than minLength #{min}")]
    end
  end

  defp check_max_length(errors, value, node, path) do
    case opt(node, :max_length) do
      nil ->
        errors

      max ->
        if length(value) <= max, do: errors, else: [err(path, "", "longer than maxLength #{max}")]
    end
  end

  # Parser nodes use atom keys (max_length) while raw JSON uses camelCase
  # (maxLength); support both so callers can pass either form.
  defp opt(node, key) do
    camel = key |> Atom.to_string() |> Macro.camelize()

    case Map.get(node, key) || Map.get(node, camel) do
      nil -> nil
      value -> value
    end
  end

  defp format_valid?("datetime", v), do: match?({:ok, _, _}, DateTime.from_iso8601(v))
  defp format_valid?("uri", v), do: URI.parse(v).scheme != nil and String.contains?(v, ":")
  defp format_valid?("at-uri", v), do: AtUri.valid?(v)
  defp format_valid?("nsid", v), do: NSID.valid?(v)
  defp format_valid?("cid", v), do: match?({:ok, _}, CID.decode(v))
  defp format_valid?("did", v), do: Regex.match?(~r{^did:[a-z]+:[A-Za-z0-9._:%-]+$}, v)

  defp format_valid?("handle", v),
    do: Regex.match?(~r/^[a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})+$/, v)

  # BCP-47 language tag: e.g. "en", "pt-BR", "zh-Hant-TW" (the bsky
  # corpus uses well-formed tags; a light structural check suffices)
  defp format_valid?("language", v),
    do: Regex.match?(~r/^[a-zA-Z]{2,3}(-[a-zA-Z0-9]{1,8})*$/, v)

  defp format_valid?("tid", v), do: TID.valid?(v)
  defp format_valid?("record-key", v), do: RecordKey.valid?(v)

  # A DID or a handle
  defp format_valid?("at-identifier", v),
    do: format_valid?("did", v) or format_valid?("handle", v)

  defp err(path, key, message), do: {join(path, key), message}

  defp join("", key), do: to_string(key)
  defp join(path, ""), do: path
  defp join(path, key), do: "#{path}.#{key}"
end
