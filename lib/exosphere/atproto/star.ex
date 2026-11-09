defmodule Exosphere.ATProto.Star do
  @moduledoc """
  STAR archives (<https://dasl.ing/star.html>): a DRISL metadata header,
  then key/value pairs, each preceded by a `0x01` control byte, then a `0x00`
  control byte to end the archive.

      [ magic | len | meta ] [ 1 | len | key | len | val ] ... [ 0 ]

  The magic is `2A 6C 01 00`; each `len` is an unsigned LEB128 varint in its
  shortest form. The metadata is a DRISL (canonical DAG-CBOR) map with a
  string `$type` naming the *profile*, which says what the keys and values
  mean. Proposal 0016 serializes space repos (`atproto-space-repo`, see
  `Exosphere.ATProto.Spaces.Repo`) and space meta archives
  (`atproto-space-meta`) as STAR; atproto `bf02818`/`13994f1`/`bd58bd8`.

  STAR itself sets no ordering or size rules: profiles do. `decode/2` takes
  the limits a profile imposes (`:max_meta_length`, `:max_key_length`,
  `:max_value_length`) and checks each length *before* reading the frame.

  Readers reject the whole archive on any error — bad magic, a
  non-canonical varint (a padding zero byte) or one longer than 9 bytes, a
  truncated frame, an unknown control byte, trailing bytes after the end
  byte, or metadata that is not a map with a string `$type` or does not
  re-encode to exactly its own bytes. This works on a binary already in
  memory; the archives in question are bounded by the profile limits.
  """

  alias Exosphere.ATProto.CBOR, as: DagCbor

  @magic <<0x2A, 0x6C, 0x01, 0x00>>
  @pair 0x01
  @end_byte 0x00
  @max_varint_bytes 9

  @type pair :: {key :: binary(), value :: binary()}
  @type limits :: [
          max_meta_length: non_neg_integer(),
          max_key_length: non_neg_integer(),
          max_value_length: non_neg_integer()
        ]

  @doc "The four magic bytes every STAR archive starts with."
  @spec magic() :: binary()
  def magic, do: @magic

  @doc """
  Encode an archive. `meta` must be a DAG-CBOR-encodable map carrying a
  string `"$type"` (wrap byte-string values in `%CBOR.Tag{tag: :bytes}` so
  they encode as bytes); `pairs` are written in the order given — ordering is
  the profile's concern.
  """
  @spec encode(map(), [pair()]) :: binary()
  def encode(%{"$type" => type} = meta, pairs) when is_binary(type) and is_list(pairs) do
    meta_bytes = DagCbor.encode!(meta)

    IO.iodata_to_binary([
      @magic,
      frame(meta_bytes),
      Enum.map(pairs, fn {key, value} when is_binary(key) and is_binary(value) ->
        [@pair, frame(key), frame(value)]
      end),
      @end_byte
    ])
  end

  @doc """
  Decode an archive into `%{meta: map, meta_bytes: binary, pairs: [pair]}`.

  `meta` has byte strings as plain binaries (as `Exosphere.ATProto.CBOR.decode/1`
  returns them); `meta_bytes` is the canonical encoding it was read from.
  """
  @spec decode(binary(), limits()) ::
          {:ok, %{meta: map(), meta_bytes: binary(), pairs: [pair()]}} | {:error, term()}
  def decode(archive, limits \\ [])

  def decode(<<@magic, rest::binary>>, limits) do
    with {:ok, meta_bytes, rest} <- read_frame(rest, limits[:max_meta_length], :meta),
         {:ok, meta} <- parse_meta(meta_bytes),
         {:ok, pairs} <- read_pairs(rest, limits, []) do
      {:ok, %{meta: meta, meta_bytes: meta_bytes, pairs: pairs}}
    end
  end

  def decode(archive, _limits) when is_binary(archive), do: {:error, :invalid_star_magic}
  def decode(_, _), do: {:error, :invalid_star}

  @doc "Encode an unsigned varint in its shortest form."
  @spec encode_varint(non_neg_integer()) :: binary()
  def encode_varint(value) when is_integer(value) and value >= 0 and value < 0x80, do: <<value>>

  def encode_varint(value) when is_integer(value) and value >= 0x80,
    do: <<1::1, rem(value, 0x80)::7, encode_varint(div(value, 0x80))::binary>>

  defp frame(bytes), do: [encode_varint(byte_size(bytes)), bytes]

  defp read_pairs(<<@end_byte>>, _limits, acc), do: {:ok, Enum.reverse(acc)}
  defp read_pairs(<<@end_byte, _::binary>>, _limits, _acc), do: {:error, :trailing_bytes}

  defp read_pairs(<<@pair, rest::binary>>, limits, acc) do
    with {:ok, key, rest} <- read_frame(rest, limits[:max_key_length], :key),
         {:ok, value, rest} <- read_frame(rest, limits[:max_value_length], :value) do
      read_pairs(rest, limits, [{key, value} | acc])
    end
  end

  defp read_pairs(<<>>, _limits, _acc), do: {:error, :unexpected_end}

  defp read_pairs(<<control, _::binary>>, _limits, _acc),
    do: {:error, {:invalid_control_byte, control}}

  defp read_frame(bytes, max, what) do
    with {:ok, length, rest} <- read_varint(bytes, 0, 0) do
      cond do
        is_integer(max) and length > max ->
          {:error, {:length_exceeds_limit, what}}

        byte_size(rest) < length ->
          {:error, :unexpected_end}

        true ->
          {:ok, binary_part(rest, 0, length), binary_part(rest, length, byte_size(rest) - length)}
      end
    end
  end

  defp read_varint(_bytes, _value, @max_varint_bytes), do: {:error, :varint_too_long}
  defp read_varint(<<>>, _value, _i), do: {:error, :unexpected_end}

  defp read_varint(<<byte, rest::binary>>, value, i) do
    value = value + Bitwise.band(byte, 0x7F) * Integer.pow(2, 7 * i)

    cond do
      byte >= 0x80 -> read_varint(rest, value, i + 1)
      # A final zero byte only pads the encoding, which STAR forbids.
      byte == 0 and i > 0 -> {:error, :non_canonical_varint}
      true -> {:ok, value, rest}
    end
  end

  # The metadata must be a map with a string $type, and canonical: it must
  # re-encode to exactly the bytes it was read from (the decoder alone would
  # accept unsorted keys, non-minimal integers and the like).
  defp parse_meta(bytes) do
    with {:ok, raw, ""} <- raw_decode(bytes),
         {:ok, ^bytes} <- DagCbor.encode(raw),
         meta = DagCbor.transform_links(raw),
         %{"$type" => type} when is_binary(type) <- meta do
      {:ok, meta}
    else
      {:ok, _raw, _trailing} -> {:error, :invalid_star_meta}
      {:ok, _other_bytes} -> {:error, :non_canonical_star_meta}
      %{} -> {:error, :invalid_star_meta}
      _ -> {:error, :invalid_star_meta}
    end
  end

  defp raw_decode(bytes) do
    CBOR.decode(bytes)
  rescue
    _ -> {:error, :invalid_cbor}
  end
end
