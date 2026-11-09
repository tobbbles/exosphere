defmodule Exosphere.ATProto.Spaces.StructuredFields do
  @moduledoc """
  The subset of RFC 9651 Structured Field Values that space requests use:
  Dictionaries (the `Signature-Input`/`Signature` headers of RFC 9421, and
  `Atproto-Space-Want-Mac`/`Atproto-Space-Mac`), Inner Lists, Parameters, and
  the bare item types Integer, Decimal, String, Token, Byte Sequence and
  Boolean.

  Values are tagged so the item *type* survives a round trip — a Token and a
  String with the same characters are different values, and the space
  headers care (`type="atproto-space-repo"` is a String; an unquoted
  `type=atproto-space-repo` is a Token and does not match):

  | RFC 9651 type | Elixir |
  |---|---|
  | Integer | `integer()` |
  | Decimal | `float()` |
  | String | `binary()` |
  | Token | `{:token, binary()}` |
  | Byte Sequence | `{:bytes, binary()}` |
  | Boolean | `true` / `false` |

  An Item is `{bare, params}`, an Inner List is `{:inner_list, [item], params}`,
  and Parameters are an ordered `[{key, bare}]`. A Dictionary parses to an
  ordered `[{key, member}]` (later duplicates replace earlier ones, per the
  RFC).

  Parsing follows the RFC's algorithms (§4.2) and fails the whole field on
  any error, as it requires. Dates and Display Strings are not supported and
  fail to parse.
  """

  @type bare ::
          integer() | float() | binary() | {:token, binary()} | {:bytes, binary()} | boolean()
  @type params :: [{String.t(), bare()}]
  @type item :: {bare(), params()}
  @type inner_list :: {:inner_list, [item()], params()}
  @type member :: item() | inner_list()
  @type dictionary :: [{String.t(), member()}]

  # -- parsing ---------------------------------------------------------------

  @doc "Parse a Dictionary field value."
  @spec parse_dictionary(String.t()) :: {:ok, dictionary()} | {:error, :invalid_structured_field}
  def parse_dictionary(input) when is_binary(input) do
    input |> skip_sp() |> dict_members([]) |> finish()
  catch
    :invalid -> {:error, :invalid_structured_field}
  end

  def parse_dictionary(_), do: {:error, :invalid_structured_field}

  @doc "Parse an Item field value."
  @spec parse_item(String.t()) :: {:ok, item()} | {:error, :invalid_structured_field}
  def parse_item(input) when is_binary(input) do
    input |> skip_sp() |> item() |> finish()
  catch
    :invalid -> {:error, :invalid_structured_field}
  end

  defp finish({value, rest}) do
    case skip_sp(rest) do
      "" -> {:ok, value}
      _ -> throw(:invalid)
    end
  end

  defp dict_members(input, acc) do
    {key, rest} = key(input)

    {member, rest} =
      case rest do
        "=" <> rest ->
          item_or_inner_list(rest)

        _ ->
          {params, rest} = params(rest)
          {{true, params}, rest}
      end

    acc = List.keystore(acc, key, 0, {key, member})
    rest = skip_ows(rest)

    case rest do
      "" ->
        {acc, ""}

      "," <> rest ->
        case skip_ows(rest) do
          "" -> throw(:invalid)
          rest -> dict_members(rest, acc)
        end

      _ ->
        throw(:invalid)
    end
  end

  defp item_or_inner_list("(" <> rest), do: inner_list(rest, [])
  defp item_or_inner_list(input), do: item(input)

  defp inner_list(input, acc) do
    case skip_sp(input) do
      ")" <> rest ->
        {params, rest} = params(rest)
        {{:inner_list, Enum.reverse(acc), params}, rest}

      rest ->
        {item, rest} = item(rest)

        case rest do
          <<c, _::binary>> when c in [?\s, ?)] -> inner_list(rest, [item | acc])
          _ -> throw(:invalid)
        end
    end
  end

  defp item(input) do
    {bare, rest} = bare_item(input)
    {params, rest} = params(rest)
    {{bare, params}, rest}
  end

  defp params(input, acc \\ [])

  defp params(";" <> rest, acc) do
    {key, rest} = rest |> skip_sp() |> key()

    {value, rest} =
      case rest do
        "=" <> rest -> bare_item(rest)
        _ -> {true, rest}
      end

    params(rest, List.keystore(acc, key, 0, {key, value}))
  end

  defp params(rest, acc), do: {acc, rest}

  defp key(<<c, _::binary>> = input) when c in ?a..?z or c == ?*, do: key_chars(input, "")
  defp key(_), do: throw(:invalid)

  defp key_chars(<<c, rest::binary>>, acc)
       when c in ?a..?z or c in ?0..?9 or c in [?_, ?-, ?., ?*],
       do: key_chars(rest, <<acc::binary, c>>)

  defp key_chars(rest, acc), do: {acc, rest}

  defp bare_item(<<c, _::binary>> = input) when c == ?- or c in ?0..?9, do: number(input)
  defp bare_item("\"" <> rest), do: string(rest, "")
  defp bare_item(":" <> rest), do: byte_sequence(rest)
  defp bare_item("?1" <> rest), do: {true, rest}
  defp bare_item("?0" <> rest), do: {false, rest}

  defp bare_item(<<c, _::binary>> = input) when c in ?a..?z or c in ?A..?Z or c == ?*,
    do: token(input, "")

  defp bare_item(_), do: throw(:invalid)

  defp number(input) do
    {sign, rest} =
      case input do
        "-" <> rest -> {-1, rest}
        rest -> {1, rest}
      end

    {int_digits, rest} = digits(rest, "")
    if int_digits == "", do: throw(:invalid)

    case rest do
      "." <> rest ->
        {frac, rest} = digits(rest, "")

        if byte_size(int_digits) > 12 or frac == "" or byte_size(frac) > 3,
          do: throw(:invalid)

        {sign * String.to_float(int_digits <> "." <> frac), rest}

      _ ->
        if byte_size(int_digits) > 15, do: throw(:invalid)
        {sign * String.to_integer(int_digits), rest}
    end
  end

  defp digits(<<c, rest::binary>>, acc) when c in ?0..?9, do: digits(rest, <<acc::binary, c>>)
  defp digits(rest, acc), do: {acc, rest}

  defp string("\\" <> <<c, rest::binary>>, acc) when c in [?", ?\\],
    do: string(rest, <<acc::binary, c>>)

  defp string("\"" <> rest, acc), do: {acc, rest}

  defp string(<<c, rest::binary>>, acc) when c in 0x20..0x7E and c != ?\\,
    do: string(rest, <<acc::binary, c>>)

  defp string(_, _), do: throw(:invalid)

  defp token(<<c, rest::binary>>, acc) when c in ?a..?z or c in ?A..?Z or c in ?0..?9,
    do: token(rest, <<acc::binary, c>>)

  defp token(<<c, rest::binary>>, acc)
       when c in [?!, ?#, ?$, ?%, ?&, ?', ?*, ?+, ?-, ?., ?^, ?_, ?`, ?|, ?~, ?:, ?/],
       do: token(rest, <<acc::binary, c>>)

  defp token(rest, acc), do: {{:token, acc}, rest}

  defp byte_sequence(input) do
    case :binary.split(input, ":") do
      [b64, rest] ->
        if b64 =~ ~r/\A[A-Za-z0-9+\/=]*\z/ do
          case Base.decode64(b64, padding: false) do
            {:ok, bytes} -> {{:bytes, bytes}, rest}
            :error -> throw(:invalid)
          end
        else
          throw(:invalid)
        end

      _ ->
        throw(:invalid)
    end
  end

  defp skip_sp(" " <> rest), do: skip_sp(rest)
  defp skip_sp(rest), do: rest

  defp skip_ows(<<c, rest::binary>>) when c in [?\s, ?\t], do: skip_ows(rest)
  defp skip_ows(rest), do: rest

  # -- serialization -------------------------------------------------------

  @doc "Serialize a Dictionary (`[{key, member}]`)."
  @spec serialize_dictionary(dictionary()) :: String.t()
  def serialize_dictionary(members) do
    Enum.map_join(members, ", ", fn
      {key, {true, params}} -> serialize_key(key) <> serialize_params(params)
      {key, member} -> serialize_key(key) <> "=" <> serialize_member(member)
    end)
  end

  @doc "Serialize an Item or Inner List."
  @spec serialize_member(member()) :: String.t()
  def serialize_member({:inner_list, items, params}) do
    "(" <> Enum.map_join(items, " ", &serialize_member/1) <> ")" <> serialize_params(params)
  end

  def serialize_member({bare, params}), do: serialize_bare(bare) <> serialize_params(params)

  defp serialize_params(params) do
    Enum.map_join(params, fn
      {key, true} -> ";" <> serialize_key(key)
      {key, value} -> ";" <> serialize_key(key) <> "=" <> serialize_bare(value)
    end)
  end

  defp serialize_key(key) do
    if key =~ ~r/\A[a-z*][a-z0-9_\-.*]*\z/, do: key, else: raise(ArgumentError, "invalid key")
  end

  defp serialize_bare(true), do: "?1"
  defp serialize_bare(false), do: "?0"
  defp serialize_bare(int) when is_integer(int), do: Integer.to_string(int)

  defp serialize_bare(float) when is_float(float),
    do: :erlang.float_to_binary(float, [:short]) |> trim_decimal()

  defp serialize_bare({:token, token}), do: token
  defp serialize_bare({:bytes, bytes}), do: ":" <> Base.encode64(bytes) <> ":"

  defp serialize_bare(string) when is_binary(string) do
    if String.printable?(string) and string =~ ~r/\A[\x20-\x7E]*\z/ do
      "\"" <> String.replace(string, ["\\", "\""], &("\\" <> &1)) <> "\""
    else
      raise ArgumentError, "structured field strings are printable ASCII"
    end
  end

  defp trim_decimal(str) do
    if String.contains?(str, "."), do: str, else: str <> ".0"
  end

  # -- lookups ----------------------------------------------------------------

  @doc "Fetch a member's bare value from a parsed Dictionary, ignoring parameters."
  @spec get_bare(dictionary(), String.t()) :: bare() | {:inner_list, [item()], params()} | nil
  def get_bare(dict, key) do
    case List.keyfind(dict, key, 0) do
      {^key, {:inner_list, _, _} = inner} -> inner
      {^key, {bare, _params}} -> bare
      nil -> nil
    end
  end
end
