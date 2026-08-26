defmodule Exosphere.ATProto.Spaces.Repo do
  @moduledoc """
  Permissioned repo serialization and verification (atproto proposal 0016).

  A permissioned repo serializes as a two-root CAR: the signed commit block,
  then the index block — a DAG-CBOR map from `"{collection}/{rkey}"` to the
  record's CID, in canonical key order — followed by one record block per
  index entry, *in the index's order*. Blobs are excluded.

  `verify_car/5` runs the full pipeline the reference consumer runs, failing
  loudly at each stage: frame CIDs are hashed against their contents at decode
  time, the commit block must lead and the index follow, the commit's MAC and
  signature must verify, the index must be canonically encoded and fold (via
  LtHash) to the commit's hash, and every record block must appear in index
  order under its index CID. An index-only CAR (`exclude_values: true` at
  serialization, `expect_values: false` at verification) carries no record
  blocks; the index still authenticates against the commit.
  """

  alias Exosphere.ATProto.CBOR
  alias Exosphere.ATProto.CID
  alias Exosphere.ATProto.Spaces.Commit
  alias Exosphere.ATProto.Spaces.Lthash

  @car_version 1
  @sha256_code 0x12
  @sha256_digest_len 32

  @type decoded_car :: %{
          required(:roots) => [CID.t()],
          required(:blocks) => %{CID.t() => binary()},
          # The index order matters, which a map cannot carry.
          required(:order) => [CID.t()]
        }

  @type ctx_input :: %{required(:space) => String.t(), required(:author) => String.t()}

  @type verified_record :: %{
          required(:collection) => String.t(),
          required(:rkey) => String.t(),
          required(:cid) => CID.t(),
          required(:record) => map()
        }

  @type verified :: %{
          required(:commit) => Commit.t(),
          required(:index) => %{String.t() => CID.t()},
          required(:records) => [verified_record()],
          required(:lthash) => Lthash.t(),
          required(:rev) => String.t()
        }

  @doc """
  Decode a CAR into its header roots, raw block bytes, and stream order.

  Every frame's CID is checked against the sha256 of its contents, so a
  tampered block fails here, loudly.
  """
  @spec decode_car(binary()) :: {:ok, decoded_car()} | {:error, term()}
  def decode_car(data) when is_binary(data) do
    with {:ok, header, rest} <- decode_header(data),
         {:ok, roots} <- extract_roots(header),
         {:ok, entries} <- decode_blocks(rest, []) do
      blocks = Map.new(entries)
      order = Enum.map(entries, &elem(&1, 0))
      {:ok, %{roots: roots, blocks: blocks, order: order}}
    end
  end

  def decode_car(_), do: {:error, :invalid_car}

  @doc """
  Serialize a repo as a two-root CAR.

  `records` is a list of `{collection, rkey, record_map}` triples. The index
  is built over the canonically-sorted paths and record blocks follow in that
  order. With `exclude_values: true` only the two roots are written.
  """
  @spec serialize(Commit.t(), [{String.t(), String.t(), map()}], keyword()) :: binary()
  def serialize(commit, records, opts \\ []) when is_list(records) do
    sorted =
      records
      |> Map.new(fn {collection, rkey, record} -> {record_path(collection, rkey), record} end)
      |> Enum.sort_by(fn {path, _record} -> {byte_size(path), path} end)

    index = Map.new(sorted, fn {path, record} -> {path, CID.create!(record)} end)

    commit_bytes = CBOR.encode!(commit)
    index_bytes = CBOR.encode!(index)

    commit_cid = raw_cid(commit_bytes)
    index_cid = raw_cid(index_bytes)

    record_frames =
      if opts[:exclude_values] do
        []
      else
        for {_path, record} <- sorted do
          bytes = CBOR.encode!(record)
          block_frame(raw_cid(bytes), bytes)
        end
      end

    header_bytes = CBOR.encode!(%{"version" => @car_version, "roots" => [commit_cid, index_cid]})

    IO.iodata_to_binary([
      varint(byte_size(header_bytes)),
      header_bytes,
      block_frame(commit_cid, commit_bytes),
      block_frame(index_cid, index_bytes),
      record_frames
    ])
  end

  @doc """
  Verify a permissioned repo CAR end to end.

  `ctx` supplies the space URI and author DID from the surrounding request;
  the `rev` comes from the commit itself, per the reference consumer. The
  public key is the author's account signing key (`#atproto`).

  With `expect_values: false` the CAR must be index-only (no record blocks).
  """
  @spec verify_car(binary(), ctx_input(), binary(), atom(), keyword()) ::
          {:ok, verified()} | {:error, term()}
  def verify_car(car, ctx, public_key, curve, opts \\ [])

  def verify_car(car, %{space: space, author: author}, public_key, curve, opts)
      when is_binary(space) and is_binary(author) do
    with {:ok, decoded} <- decode_car(car),
         {:ok, commit_cid, index_cid} <- check_roots(decoded),
         {:ok, commit} <- commit_block(decoded, commit_cid),
         {:ok, index, index_bytes} <- index_block(decoded, index_cid),
         {:ok, rev} <- commit_rev(commit),
         commit_ctx = %{space: space, author: author, rev: rev},
         :ok <- Commit.verify(commit, commit_ctx, public_key, curve),
         :ok <- canonical_index?(index, index_bytes),
         {:ok, lthash} <- fold_index(index),
         :ok <- index_matches_commit(lthash, commit),
         {:ok, records} <-
           verify_records(decoded, index, Keyword.get(opts, :expect_values, true)) do
      {:ok, %{commit: commit, index: index, records: records, lthash: lthash, rev: rev}}
    end
  end

  def verify_car(_, _, _, _, _), do: {:error, :invalid_context}

  @doc """
  Fold an index (path → CID) into the set hash it commits to.
  """
  @spec fold_index(%{String.t() => CID.t()}) :: {:ok, Lthash.t()} | {:error, term()}
  def fold_index(index) when is_map(index) do
    index
    |> Enum.sort_by(fn {path, _cid} -> {byte_size(path), path} end)
    |> Enum.reduce_while({:ok, Lthash.new()}, fn {path, cid}, {:ok, hash} ->
      case {is_struct(cid, CID), split_record_path(path)} do
        {true, {:ok, collection, rkey}} ->
          {:cont, {:ok, Commit.add_record(hash, collection, rkey, CID.encode(cid))}}

        _ ->
          {:halt, {:error, :invalid_index}}
      end
    end)
  end

  def fold_index(_), do: {:error, :invalid_index}

  # -- verification stages ------------------------------------------------------

  defp check_roots(%{roots: [commit_cid, index_cid]}), do: {:ok, commit_cid, index_cid}
  defp check_roots(%{roots: roots}), do: {:error, {:expected_two_roots, length(roots)}}

  defp commit_block(%{order: [commit_cid | _], blocks: blocks}, commit_cid) do
    with {:ok, bytes} <- fetch_block(blocks, commit_cid) do
      decode_block(bytes)
    end
  end

  defp commit_block(_, _), do: {:error, :commit_block_must_lead}

  defp index_block(%{order: [_, index_cid | _], blocks: blocks}, index_cid) do
    with {:ok, bytes} <- fetch_block(blocks, index_cid),
         {:ok, index} <- decode_block(bytes),
         :ok <- index_shape(index) do
      {:ok, index, bytes}
    end
  end

  defp index_block(_, _), do: {:error, :index_block_must_follow}

  defp fetch_block(blocks, cid) do
    case Map.fetch(blocks, cid) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> {:error, :missing_block}
    end
  end

  defp index_shape(index) when is_map(index) do
    if Enum.all?(index, fn {k, v} -> is_binary(k) and is_struct(v, CID) end) do
      :ok
    else
      {:error, :invalid_index}
    end
  end

  defp index_shape(_), do: {:error, :invalid_index}

  defp commit_rev(%{"rev" => rev}) when is_binary(rev), do: {:ok, rev}
  defp commit_rev(_), do: {:error, :invalid_commit}

  defp canonical_index?(index, index_bytes) do
    case CBOR.encode(index) do
      {:ok, ^index_bytes} -> :ok
      _ -> {:error, :index_not_canonical}
    end
  end

  defp index_matches_commit(lthash, %{"hash" => hash}) do
    if Lthash.digest(lthash) == hash do
      :ok
    else
      {:error, :index_hash_mismatch}
    end
  end

  defp index_matches_commit(_, _), do: {:error, :invalid_commit}

  defp verify_records(
         %{order: [_commit_cid, _index_cid | record_cids], blocks: blocks},
         index,
         expect_values
       ) do
    if expect_values do
      if length(record_cids) != map_size(index) do
        {:error, :record_count_mismatch}
      else
        ordered_paths =
          index
          |> Enum.sort_by(fn {path, _cid} -> {byte_size(path), path} end)
          |> Enum.map(&elem(&1, 0))

        verify_ordered_records(record_cids, blocks, index, ordered_paths, [])
      end
    else
      if record_cids == [] do
        {:ok, []}
      else
        {:error, :unexpected_record_blocks}
      end
    end
  end

  defp verify_records(_, _, _), do: {:error, :invalid_car_order}

  defp verify_ordered_records([], _blocks, _index, [], acc), do: {:ok, Enum.reverse(acc)}

  defp verify_ordered_records([cid | cids], blocks, index, [path | paths], acc) do
    case Map.fetch(index, path) do
      {:ok, expected} when expected == cid ->
        with {:ok, bytes} <- fetch_block(blocks, cid),
             {:ok, record} <- decode_block(bytes),
             {:ok, collection, rkey} <- split_record_path(path) do
          verify_ordered_records(cids, blocks, index, paths, [
            %{collection: collection, rkey: rkey, cid: expected, record: record} | acc
          ])
        else
          {:error, reason} -> {:error, reason}
        end

      _ ->
        {:error, {:record_block_out_of_order, path}}
    end
  end

  # -- CAR framing ---------------------------------------------------------------

  defp decode_header(data) do
    with {:ok, header_len, rest} <- read_varint(data),
         true <- header_len > 0 and byte_size(rest) >= header_len,
         <<header_bytes::binary-size(^header_len), remaining::binary>> <- rest,
         {:ok, header} <- CBOR.decode(header_bytes),
         %{"version" => @car_version} <- header do
      {:ok, header, remaining}
    else
      _ -> {:error, :invalid_car_header}
    end
  end

  defp extract_roots(%{"roots" => roots}) when is_list(roots) do
    cids = Enum.map(roots, &CBOR.transform_links/1)

    if Enum.all?(cids, &is_struct(&1, CID)) do
      {:ok, cids}
    else
      {:error, :invalid_roots}
    end
  end

  defp extract_roots(_), do: {:error, :invalid_roots}

  defp decode_blocks(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_blocks(data, acc) do
    with {:ok, frame_len, rest} <- read_varint(data),
         true <- frame_len > 0 and byte_size(rest) >= frame_len,
         <<frame::binary-size(^frame_len), remaining::binary>> <- rest,
         {:ok, cid, bytes} <- split_frame(frame),
         :ok <- check_content_cid(cid, bytes) do
      decode_blocks(remaining, [{cid, bytes} | acc])
    else
      {:error, :content_hash_mismatch} = mismatch -> mismatch
      _ -> {:error, :invalid_block_frame}
    end
  end

  # A block frame is <CID bytes><block data>. The CID length is walked from
  # its varint structure (v1) or fixed at 34 bytes (v0 sha2-256).
  defp split_frame(<<0x01, rest0::binary>>) do
    with {:ok, _codec, after_codec} <- read_varint(rest0),
         {:ok, @sha256_code, after_fn} <- read_varint(after_codec),
         {:ok, @sha256_digest_len, after_len} <- read_varint(after_fn),
         <<digest::binary-size(@sha256_digest_len), bytes::binary>> <- after_len do
      varints = binary_part(rest0, 0, byte_size(rest0) - byte_size(after_len))

      case CID.from_bytes(<<0x01, varints::binary, digest::binary>>) do
        {:ok, cid} -> {:ok, cid, bytes}
        error -> error
      end
    else
      _ -> {:error, :unknown_cid_format}
    end
  end

  defp split_frame(<<0x12, 0x20, _::binary-size(32), bytes::binary>> = frame) do
    with {:ok, cid} <- CID.from_bytes(binary_part(frame, 0, 34)) do
      {:ok, cid, bytes}
    end
  end

  defp split_frame(_), do: {:error, :unknown_cid_format}

  defp check_content_cid(%CID{} = cid, bytes) do
    if :crypto.hash(:sha256, bytes) == cid.hash do
      :ok
    else
      {:error, :content_hash_mismatch}
    end
  end

  defp decode_block(bytes) when is_binary(bytes) do
    case CBOR.decode(bytes) do
      {:ok, value} -> {:ok, CBOR.transform_links(value)}
      _ -> {:error, :invalid_block}
    end
  end

  defp decode_block(_), do: {:error, :invalid_block}

  defp block_frame(%CID{} = cid, bytes) do
    cid_bytes = CID.to_bytes(cid)
    varint(byte_size(cid_bytes) + byte_size(bytes)) <> cid_bytes <> bytes
  end

  defp raw_cid(bytes), do: %CID{version: 1, codec: :dag_cbor, hash: :crypto.hash(:sha256, bytes)}

  defp record_path(collection, rkey), do: collection <> "/" <> rkey

  defp split_record_path(path) do
    case String.split(path, "/") do
      [collection, rkey] -> {:ok, collection, rkey}
      _ -> {:error, :invalid_record_path}
    end
  end

  defp varint(n) when n < 128, do: <<n>>
  defp varint(n), do: <<1::1, Integer.mod(n, 128)::7>> <> varint(div(n, 128))

  defp read_varint(data) do
    {value, rest} = Varint.LEB128.decode(data)
    {:ok, value, rest}
  rescue
    _ -> {:error, :varint_decode_failed}
  end
end
