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

      # Serve one: a repository export, or a firehose commit slice
      {:ok, car} = Exosphere.ATProto.CAR.encode(commit_cid, blocks)

  ## Serving

  `encode/3` builds a whole archive; `encode_iodata/3` returns iodata so a
  large export can go straight to a socket without first collapsing into one
  binary. Both take blocks as a list (order preserved — the spec prefers the
  commit first, then MST nodes in pre-order) or as a map (ordered
  deterministically by CID, so the same block set always serializes to the
  same bytes).
  """

  alias Exosphere.ATProto.CID

  # Aliased under a distinct name so the bare `CBOR` below still refers to the
  # `:cbor` library (whose decode/1 returns the trailing bytes we need).
  alias Exosphere.ATProto.CBOR, as: DagCBOR

  require Logger

  @type block_map :: %{CID.t() => term()}

  @typedoc """
  Blocks to serialize: CID-keyed. A binary value is written verbatim (already
  encoded DAG-CBOR, or a raw blob); any other term is DAG-CBOR encoded first.
  """
  @type block_input :: %{CID.t() => binary() | term()} | [{CID.t(), binary() | term()}]

  @doc """
  Decode a CAR file into a map of CID → decoded data.

  Returns `{:ok, %{cid => data}}` on success. The header's `roots` are
  discarded; use `decode_full/1` when you need them (e.g. to locate a
  repository's root commit for verification).
  """
  @spec decode(binary()) :: {:ok, block_map()} | {:error, term()}
  def decode(<<>>) do
    {:ok, %{}}
  end

  def decode(data) when is_binary(data) do
    with {:ok, %{blocks: blocks}} <- decode_full(data), do: {:ok, blocks}
  end

  def decode(_), do: {:error, :invalid_input}

  @doc """
  Decode a CAR file into its header roots and block map.

  Returns `{:ok, %{roots: [%CID{}, ...], blocks: %{cid => data}}}`. The roots
  come from the CAR header (CID links decoded via `Exosphere.ATProto.CBOR.transform_links/1`);
  for atproto repository archives the single root is the CID of the top commit
  block, which is itself present in `blocks`.
  """
  @spec decode_full(binary()) ::
          {:ok, %{roots: [CID.t()], blocks: block_map()}} | {:error, term()}
  def decode_full(<<>>), do: {:error, :empty_car}

  def decode_full(data) when is_binary(data) do
    with {:ok, header, rest} <- decode_header(data),
         {:ok, roots} <- extract_roots(header),
         {:ok, blocks} <- decode_blocks(rest) do
      {:ok, %{roots: roots, blocks: blocks}}
    end
  rescue
    e ->
      Logger.debug("[CAR] Decode error: #{inspect(e)}")
      {:error, {:decode_failed, e}}
  end

  def decode_full(_), do: {:error, :invalid_input}

  @doc """
  Decode a CAR into its roots and its blocks' **encoded bytes**, in stream order.

  `decode_full/1` decodes every block, which is what a consumer inspecting
  records wants. A server importing an archive wants the opposite: the bytes
  exactly as they arrived, so they can go into a block store and be served back
  out untouched.

  That distinction is load-bearing, not stylistic. Decoding is lossy in one
  direction — `Exosphere.ATProto.CBOR.transform_links/1` unwraps CBOR byte
  strings to plain binaries, which re-encode as *text* strings — so a commit
  block that is decoded and re-encoded gets a different CID and stops
  verifying. Keep bytes as bytes and the problem does not arise.

  Returns `{:ok, %{roots: [%CID{}], blocks: %{cid => bytes}, order: [cid]}}`.
  `order` preserves the archive's block order, which `decode_full/1`'s map
  cannot.

  ## Examples

      {:ok, %{roots: [commit], blocks: blocks}} = CAR.decode_raw(car)
      # `blocks` is a `%{CID => bytes}` map — persist it, or hand it straight to
      # `Exosphere.ATProto.MST` as a block source.
  """
  @spec decode_raw(binary()) ::
          {:ok, %{roots: [CID.t()], blocks: %{CID.t() => binary()}, order: [CID.t()]}}
          | {:error, term()}
  def decode_raw(<<>>), do: {:error, :empty_car}

  def decode_raw(data) when is_binary(data) do
    with {:ok, header, rest} <- decode_header(data),
         {:ok, roots} <- extract_roots(header),
         {:ok, entries} <- decode_raw_blocks(rest, []) do
      {:ok, %{roots: roots, blocks: Map.new(entries), order: Enum.map(entries, &elem(&1, 0))}}
    end
  rescue
    e ->
      Logger.debug("[CAR] Raw decode error: #{inspect(e)}")
      {:error, {:decode_failed, e}}
  end

  def decode_raw(_), do: {:error, :invalid_input}

  defp decode_raw_blocks(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_raw_blocks(data, acc) do
    case decode_block(data) do
      {:ok, cid, block_data, rest} ->
        decode_raw_blocks(rest, [{cid, block_data} | acc])

      # Unlike decode_full/1, a truncated or malformed tail is an error rather
      # than a short read: a server importing an archive must not silently
      # accept a partial one.
      {:error, reason} ->
        {:error, reason}
    end
  end

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

  @doc """
  Serialize `roots` and `blocks` into a CAR v1 archive.

  `roots` is a single CID or a list of them; for an atproto repository export
  the single root is the top commit's CID, and for a `#commit` firehose slice
  it is the CID of the commit that message carries.

  Blocks are written in the order given when `blocks` is a list. A map has no
  order, so its blocks are written sorted by CID bytes — deterministic, but
  not the pre-order the spec prefers for large exports; pass a list when
  ordering matters.

  ## Options

    * `:verify` - when `true`, check every block's bytes against the CID it is
      filed under and fail with `{:error, {:cid_mismatch, cid}}` on a
      disagreement. Off by default: on a serving path the caller has just
      computed those CIDs. Worth turning on in tests and in any path that
      accepts blocks from elsewhere.

  ## Examples

      iex> {:ok, cid} = Exosphere.ATProto.CID.create(%{"hello" => "world"})
      iex> {:ok, car} = Exosphere.ATProto.CAR.encode(cid, %{cid => %{"hello" => "world"}})
      iex> {:ok, %{roots: [^cid], blocks: blocks}} = Exosphere.ATProto.CAR.decode_full(car)
      iex> blocks[cid]
      %{"hello" => "world"}
  """
  @spec encode(CID.t() | [CID.t()], block_input(), keyword()) ::
          {:ok, binary()} | {:error, term()}
  def encode(roots, blocks, opts \\ []) do
    with {:ok, iodata} <- encode_iodata(roots, blocks, opts) do
      {:ok, IO.iodata_to_binary(iodata)}
    end
  end

  @doc """
  Serialize a CAR archive, raising on error.
  """
  @spec encode!(CID.t() | [CID.t()], block_input(), keyword()) :: binary()
  def encode!(roots, blocks, opts \\ []) do
    case encode(roots, blocks, opts) do
      {:ok, car} -> car
      {:error, reason} -> raise ArgumentError, "CAR encoding failed: #{inspect(reason)}"
    end
  end

  @doc """
  Serialize a CAR archive as iodata.

  Same as `encode/3` without the final `IO.iodata_to_binary/1`: a full
  repository export can be several hundred megabytes, and handing iodata
  straight to the socket avoids copying all of it into one binary first.
  """
  @spec encode_iodata(CID.t() | [CID.t()], block_input(), keyword()) ::
          {:ok, iodata()} | {:error, term()}
  def encode_iodata(roots, blocks, opts \\ []) do
    with {:ok, roots} <- normalize_roots(roots),
         {:ok, frames} <- block_frames(blocks, Keyword.get(opts, :verify, false)) do
      {:ok, [header_frame(roots) | frames]}
    end
  end

  @doc """
  The length-prefixed CAR v1 header frame for `roots`.

  Exposed for producers that stream blocks themselves and only need the
  header; pair it with `block_frame/2`.
  """
  @spec header_frame([CID.t()]) :: iodata()
  def header_frame(roots) when is_list(roots) do
    header = DagCBOR.encode!(%{"version" => 1, "roots" => roots})
    [Varint.LEB128.encode(byte_size(header)), header]
  end

  @doc """
  One length-prefixed `<varint><CID><data>` block frame.

  `data` must be the block's encoded bytes; the CID is written verbatim, so it
  is the caller's job for it to be the hash of those bytes (or to have used
  `encode/3` with `verify: true`).
  """
  @spec block_frame(CID.t(), binary()) :: iodata()
  def block_frame(%CID{} = cid, data) when is_binary(data) do
    cid_bytes = CID.to_bytes(cid)
    [Varint.LEB128.encode(byte_size(cid_bytes) + byte_size(data)), cid_bytes, data]
  end

  defp normalize_roots(%CID{} = cid), do: {:ok, [cid]}

  defp normalize_roots(roots) when is_list(roots) do
    if Enum.all?(roots, &is_struct(&1, CID)), do: {:ok, roots}, else: {:error, :invalid_roots}
  end

  defp normalize_roots(_), do: {:error, :invalid_roots}

  # A map's iteration order is an implementation detail, so sort it: the same
  # block set must always produce the same archive. A list is left alone —
  # that is how a caller expresses pre-order.
  defp block_frames(blocks, verify?) when is_map(blocks) and not is_struct(blocks) do
    blocks
    |> Enum.sort_by(fn {cid, _} -> CID.to_bytes(cid) end)
    |> block_frames(verify?)
  end

  defp block_frames(blocks, verify?) when is_list(blocks) do
    Enum.reduce_while(blocks, {:ok, []}, fn entry, {:ok, acc} ->
      case block_frame_for(entry, verify?) do
        {:ok, frame} -> {:cont, {:ok, [frame | acc]}}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, frames} -> {:ok, Enum.reverse(frames)}
      error -> error
    end
  end

  defp block_frames(_, _), do: {:error, :invalid_blocks}

  defp block_frame_for({%CID{} = cid, value}, verify?) do
    with {:ok, bytes} <- block_bytes(value),
         :ok <- verify_cid(cid, bytes, verify?) do
      {:ok, block_frame(cid, bytes)}
    end
  end

  defp block_frame_for(entry, _verify?), do: {:error, {:invalid_block, entry}}

  # A binary is already-encoded block data — DAG-CBOR bytes or a raw blob.
  # Anything else is a decoded value we encode on the way out.
  defp block_bytes(value) when is_binary(value), do: {:ok, value}
  defp block_bytes(value), do: DagCBOR.encode(value)

  defp verify_cid(_cid, _bytes, false), do: :ok

  defp verify_cid(%CID{hash: hash} = cid, bytes, true) do
    if :crypto.hash(:sha256, bytes) == hash, do: :ok, else: {:error, {:cid_mismatch, cid}}
  end

  # The header's `roots` are CID links; decode them to %CID{} structs and
  # reject anything malformed (a link that won't parse becomes nil).
  defp extract_roots(header) do
    case Map.get(header, "roots", []) do
      roots when is_list(roots) ->
        cids = Enum.map(roots, &DagCBOR.transform_links/1)

        if Enum.all?(cids, &is_struct(&1, CID)) do
          {:ok, cids}
        else
          {:error, :invalid_roots}
        end

      _ ->
        {:error, :invalid_roots}
    end
  end

  # Decode CAR header
  defp decode_header(data) do
    case read_varint(data) do
      {:ok, header_len, rest} when header_len > 0 and byte_size(rest) >= header_len ->
        <<header_bytes::binary-size(^header_len), remaining::binary>> = rest

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
            {:ok, value, _} -> DagCBOR.transform_links(value)
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
         <<block::binary-size(^block_len), remaining::binary>> <- rest,
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

          <<cid_bytes::binary-size(^cid_len), data::binary>> = block

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
end
