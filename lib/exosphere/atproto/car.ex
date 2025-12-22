defmodule Exosphere.ATProto.CAR do
  @moduledoc """
  CAR (Content Addressable aRchive) file parser.

  CAR files are used in Exosphere.ATProto to bundle multiple CBOR blocks together,
  typically containing record data and MST (Merkle Search Tree) nodes.

  ## Format

  A CAR file consists of:
  1. Header: varint-length-prefixed CBOR with `{version, roots}`
  2. Blocks: repeated `<varint-length><CID><data>` entries

  ## Usage

      # Parse CAR blocks from firehose
      {:ok, blocks} = Exosphere.ATProto.CAR.decode(car_binary)

      # Get a specific record by CID
      record = Exosphere.ATProto.CAR.get_block(blocks, cid)
  """

  alias Exosphere.ATProto.CID

  require Logger

  @type block_map :: %{CID.t() => term()}

  @doc """
  Decode a CAR file into a map of CID → decoded data.

  Returns `{:ok, %{cid => data}}` on success.
  """
  @spec decode(binary()) :: {:ok, block_map()} | {:error, term()}
  def decode(<<>>) do
    {:ok, %{}}
  end

  def decode(data) when is_binary(data) do
    with {:ok, _header, rest} <- decode_header(data) do
      decode_blocks(rest)
    end
  rescue
    e ->
      Logger.debug("[CAR] Decode error: #{inspect(e)}")
      {:error, {:decode_failed, e}}
  end

  def decode(_), do: {:error, :invalid_input}

  @doc """
  Get a block by CID from the parsed blocks map.

  Returns the decoded CBOR data if found.
  """
  @spec get_block(block_map(), CID.t() | String.t()) :: term() | nil
  def get_block(blocks, %CID{} = cid) do
    Map.get(blocks, cid)
  end

  def get_block(blocks, cid_string) when is_binary(cid_string) do
    case CID.decode(cid_string) do
      {:ok, cid} -> get_block(blocks, cid)
      _ -> nil
    end
  end

  def get_block(_, _), do: nil

  # Decode CAR header
  defp decode_header(data) do
    case read_varint(data) do
      {:ok, header_len, rest} when header_len > 0 and byte_size(rest) >= header_len ->
        <<header_bytes::binary-size(header_len), remaining::binary>> = rest

        case CBOR.decode(header_bytes) do
          {:ok, header, _} ->
            version = header["version"] || header[:version] || 1

            if version == 1 do
              {:ok, header, remaining}
            else
              {:error, {:unsupported_car_version, version}}
            end

          {:error, reason} ->
            {:error, {:header_decode_failed, reason}}
        end

      {:ok, _, _} ->
        {:error, :header_too_short}

      {:error, reason} ->
        {:error, {:varint_error, reason}}
    end
  end

  # Decode all blocks
  defp decode_blocks(data) do
    decode_blocks(data, %{})
  end

  defp decode_blocks(<<>>, acc) do
    {:ok, acc}
  end

  defp decode_blocks(data, acc) do
    case decode_block(data) do
      {:ok, cid, block_data, rest} ->
        # Decode CBOR block data
        decoded =
          case CBOR.decode(block_data) do
            {:ok, value, _} -> transform_cbor(value)
            _ -> block_data
          end

        decode_blocks(rest, Map.put(acc, cid, decoded))

      {:error, :incomplete} ->
        # Reached end of complete blocks
        {:ok, acc}

      {:error, reason} ->
        Logger.debug(
          "[CAR] Block decode error: #{inspect(reason)}, accumulated #{map_size(acc)} blocks"
        )

        {:ok, acc}
    end
  end

  # Decode a single block: <varint-length><CID><data>
  defp decode_block(data) when byte_size(data) < 2 do
    {:error, :incomplete}
  end

  defp decode_block(data) do
    with {:ok, block_len, rest} <- read_varint(data),
         true <- byte_size(rest) >= block_len,
         <<block::binary-size(block_len), remaining::binary>> <- rest,
         {:ok, cid, block_data} <- split_cid_and_data(block) do
      {:ok, cid, block_data, remaining}
    else
      false -> {:error, :incomplete}
      {:error, reason} -> {:error, reason}
    end
  end

  # Split CID bytes from block data
  defp split_cid_and_data(block) do
    # CID v1 format: <multibase-prefix><version><codec><multihash>
    # In CAR files, CIDs are raw bytes (no multibase prefix)
    # Version 1 CIDs start with 0x01
    case block do
      <<0x01, codec, rest::binary>> ->
        # CIDv1: version(1) + codec(varint) + multihash
        with {:ok, _codec_value, after_codec} <- read_varint(<<codec, rest::binary>>),
             {:ok, _hash_fn, after_fn} <- read_varint(after_codec),
             {:ok, hash_len, after_len} <- read_varint(after_fn),
             true <- byte_size(after_len) >= hash_len do
          # Calculate CID length
          codec_varint_len = byte_size(<<codec, rest::binary>>) - byte_size(after_codec)
          fn_varint_len = byte_size(after_codec) - byte_size(after_fn)
          len_varint_len = byte_size(after_fn) - byte_size(after_len)
          cid_len = 1 + codec_varint_len + fn_varint_len + len_varint_len + hash_len

          <<cid_bytes::binary-size(cid_len), data::binary>> = block

          case CID.from_bytes(cid_bytes) do
            {:ok, cid} -> {:ok, cid, data}
            error -> error
          end
        else
          false -> {:error, :cid_hash_too_short}
          error -> error
        end

      <<0x12, 0x20, _hash::binary-size(32), data::binary>> ->
        # CIDv0 (legacy): sha2-256 multihash (0x12 = sha2-256, 0x20 = 32 bytes)
        <<cid_bytes::binary-size(34), _::binary>> = block

        case CID.from_bytes(cid_bytes) do
          {:ok, cid} -> {:ok, cid, data}
          _ -> {:error, :invalid_cidv0}
        end

      _ ->
        {:error, :unknown_cid_format}
    end
  end

  # Read a varint from binary
  defp read_varint(data) do
    {value, rest} = Varint.LEB128.decode(data)
    {:ok, value, rest}
  rescue
    _ -> {:error, :varint_decode_failed}
  end

  # Transform CBOR values (handle tags, etc.)
  defp transform_cbor(value) when is_map(value) and not is_struct(value) do
    Map.new(value, fn {k, v} -> {k, transform_cbor(v)} end)
  end

  defp transform_cbor(value) when is_list(value) do
    Enum.map(value, &transform_cbor/1)
  end

  defp transform_cbor(%CBOR.Tag{tag: :bytes, value: bytes}) when is_binary(bytes) do
    bytes
  end

  defp transform_cbor(%CBOR.Tag{tag: 42, value: <<0x00, cid_bytes::binary>>}) do
    case CID.from_bytes(cid_bytes) do
      {:ok, cid} -> cid
      _ -> nil
    end
  end

  defp transform_cbor(%CBOR.Tag{tag: 42, value: cid_bytes}) when is_binary(cid_bytes) do
    case CID.from_bytes(cid_bytes) do
      {:ok, cid} -> cid
      _ -> nil
    end
  end

  defp transform_cbor(%CBOR.Tag{value: value}), do: value

  defp transform_cbor(value), do: value
end
