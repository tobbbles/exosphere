defmodule Exosphere.ATProto.CBOR do
  @moduledoc """
  DAG-CBOR encoding and decoding with Exosphere.ATProto normalization.

  DAG-CBOR is a restricted subset of CBOR used for content-addressed data.
  This module wraps the `:cbor` library with Exosphere.ATProto-specific handling for:

  - CID links (CBOR tag 42, encoded as byte strings)
  - Canonical map key ordering (RFC 8949 length-first: shorter keys first,
    ties broken bytewise)
  - No floating point numbers (Exosphere.ATProto disallows floats)
  - Bytes and link representation

  ## Examples

      iex> Exosphere.ATProto.CBOR.encode(%{"hello" => "world"})
      {:ok, <<...>>}

      iex> Exosphere.ATProto.CBOR.decode(cbor_bytes)
      {:ok, %{"hello" => "world"}}

  ## CID Links

  CID links are encoded with CBOR tag 42 and decoded as `Exosphere.ATProto.CID` structs:

      iex> cid = Exosphere.ATProto.CID.decode!("bafyreidykglsfhoixmivffc5uwhcgshx4j465xwqntbmu43nb2dzqwfvae")
      iex> Exosphere.ATProto.CBOR.encode(%{"ref" => cid})
      {:ok, <<...>>}  # Contains tag 42 with CID bytes
  """

  alias Exosphere.ATProto.CID

  # CBOR tag for CID links per DAG-CBOR spec
  @cid_tag 42

  @type encode_error :: {:error, term()}
  @type decode_error :: {:error, :invalid_cbor | :unsupported_type | term()}

  @doc """
  Encode a term to DAG-CBOR binary format.

  Encoding is always canonical / deterministic: map keys are sorted using
  RFC 8949 length-first ordering (shorter keys first, ties broken bytewise)
  and CID structs are encoded as CBOR tag 42 wrapping a byte string.

  ## Examples

      iex> Exosphere.ATProto.CBOR.encode(%{"bb" => 1, "a" => 2})
      {:ok, binary}  # Keys sorted as "a" (len 1), then "bb" (len 2)

      iex> Exosphere.ATProto.CBOR.encode(3.14)
      {:error, :floats_not_allowed}
  """
  @spec encode(term()) :: {:ok, binary()} | encode_error()
  def encode(term) do
    {:ok, encode_value(term, <<>>)}
  rescue
    e -> {:error, e}
  catch
    {:error, _} = error -> error
  end

  @doc """
  Encode a term to DAG-CBOR, raising on error.
  """
  @spec encode!(term()) :: binary()
  def encode!(term) do
    case encode(term) do
      {:ok, binary} -> binary
      {:error, reason} -> raise ArgumentError, "CBOR encoding failed: #{inspect(reason)}"
    end
  end

  @doc """
  Decode DAG-CBOR binary to an Elixir term.

  CID links (tag 42) are decoded as `Exosphere.ATProto.CID` structs.

  ## Examples

      iex> Exosphere.ATProto.CBOR.decode(<<...>>)
      {:ok, %{"hello" => "world"}}

      iex> Exosphere.ATProto.CBOR.decode(<<0xFF>>)
      {:error, :invalid_cbor}
  """
  @spec decode(binary()) :: {:ok, term()} | decode_error()
  def decode(binary) when is_binary(binary) do
    case CBOR.decode(binary) do
      {:ok, term, _rest} ->
        {:ok, transform_links(term)}

      {:error, _} = error ->
        error
    end
  rescue
    _ -> {:error, :invalid_cbor}
  end

  def decode(_), do: {:error, :invalid_cbor}

  @doc """
  Decode DAG-CBOR binary, raising on error.
  """
  @spec decode!(binary()) :: term()
  def decode!(binary) do
    case decode(binary) do
      {:ok, term} -> term
      {:error, reason} -> raise ArgumentError, "CBOR decoding failed: #{inspect(reason)}"
    end
  end

  # Manually serialize a term to canonical DAG-CBOR.
  #
  # We do NOT delegate map/list/CID encoding to the `:cbor` library because:
  #
  #   * It does not sort map keys, and even if we pre-sort, Elixir maps are
  #     unordered so the order is lost. DAG-CBOR requires RFC 8949 *length-first*
  #     key ordering (shorter keys first, ties broken bytewise), which we apply
  #     here.
  #   * It encodes Elixir binaries as CBOR *text* strings. CID links must be
  #     encoded as CBOR *byte* strings (major type 2) inside tag 42, so we wrap
  #     the CID bytes in `%CBOR.Tag{tag: :bytes}`.
  #
  # Scalar leaves (integers, booleans, nil, strings, byte-string tags) are
  # delegated to the library's canonical (minimal-length) encoder. Floats are
  # rejected via a thrown error caught in `encode/1`.
  defp encode_value(term, _acc) when is_float(term) do
    throw({:error, :floats_not_allowed})
  end

  defp encode_value(%CID{} = cid, acc) do
    # CID links: CBOR tag 42 wrapping a byte string of 0x00 ++ binary CID.
    cid_bytes = <<0x00>> <> CID.to_bytes(cid)
    tag = %CBOR.Tag{tag: @cid_tag, value: %CBOR.Tag{tag: :bytes, value: cid_bytes}}
    CBOR.Encoder.encode_into(tag, acc)
  end

  defp encode_value(term, acc) when is_map(term) and not is_struct(term) do
    pairs =
      term
      |> Enum.map(fn {k, v} -> {to_string(k), v} end)
      |> Map.new()
      |> Enum.sort_by(fn {k, _v} -> {byte_size(k), k} end)

    acc = acc <> encode_head(5, length(pairs))
    Enum.reduce(pairs, acc, fn {k, v}, a -> encode_value(v, encode_value(k, a)) end)
  end

  defp encode_value(term, acc) when is_list(term) do
    acc = acc <> encode_head(4, length(term))
    Enum.reduce(term, acc, fn item, a -> encode_value(item, a) end)
  end

  defp encode_value(term, acc), do: CBOR.Encoder.encode_into(term, acc)

  # Encode a CBOR head byte(s): 3-bit major type + minimal-length argument.
  defp encode_head(major, n) when n < 0x18, do: <<major::size(3), n::size(5)>>
  defp encode_head(major, n) when n < 0x100, do: <<major::size(3), 24::size(5), n::size(8)>>
  defp encode_head(major, n) when n < 0x10000, do: <<major::size(3), 25::size(5), n::size(16)>>

  defp encode_head(major, n) when n < 0x100000000,
    do: <<major::size(3), 26::size(5), n::size(32)>>

  defp encode_head(major, n), do: <<major::size(3), 27::size(5), n::size(64)>>

  @doc """
  Transform a raw `:cbor`-decoded term into Exosphere structures.

  Converts CID links (tag 42) into `Exosphere.ATProto.CID` structs and unwraps
  CBOR byte strings (which the `:cbor` library decodes as
  `%CBOR.Tag{tag: :bytes}`) back into raw binaries.

  This is shared by `decode/1`, `Exosphere.ATProto.Firehose.Frame`, and
  `Exosphere.ATProto.CAR` so all three handle real (byte-string) CID links
  identically. A malformed CID link is converted to `nil` rather than raising.
  """
  @spec transform_links(term()) :: term()
  def transform_links(%CBOR.Tag{tag: @cid_tag, value: value}) do
    case link_bytes(value) do
      {:ok, <<0x00, cid_bytes::binary>>} -> cid_or_nil(cid_bytes)
      {:ok, cid_bytes} -> cid_or_nil(cid_bytes)
      :error -> nil
    end
  end

  def transform_links(%CBOR.Tag{tag: :bytes, value: bytes}) when is_binary(bytes), do: bytes

  def transform_links(term) when is_map(term) and not is_struct(term) do
    Map.new(term, fn {k, v} -> {k, transform_links(v)} end)
  end

  def transform_links(term) when is_list(term) do
    Enum.map(term, &transform_links/1)
  end

  def transform_links(%CBOR.Tag{value: value}), do: value
  def transform_links(term), do: term

  # Tag-42 values are byte strings, which the :cbor library decodes either as a
  # nested `%CBOR.Tag{tag: :bytes}` or (for our own legacy text-string output) a
  # raw binary. Accept both.
  defp link_bytes(%CBOR.Tag{tag: :bytes, value: bytes}) when is_binary(bytes), do: {:ok, bytes}
  defp link_bytes(bytes) when is_binary(bytes), do: {:ok, bytes}
  defp link_bytes(_), do: :error

  defp cid_or_nil(bytes) do
    case CID.from_bytes(bytes) do
      {:ok, cid} -> cid
      _ -> nil
    end
  end

  @doc """
  Hash the DAG-CBOR encoding of a term using SHA-256.

  This is used for generating CIDs of data objects.

  ## Examples

      iex> Exosphere.ATProto.CBOR.hash(%{"hello" => "world"})
      {:ok, <<sha256_bytes::binary-32>>}
  """
  @spec hash(term()) :: {:ok, binary()} | {:error, term()}
  def hash(term) do
    case encode(term) do
      {:ok, cbor} -> {:ok, :crypto.hash(:sha256, cbor)}
      error -> error
    end
  end
end
