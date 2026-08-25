defmodule Exosphere.ATProto.MST do
  @moduledoc """
  Merkle Search Tree (MST) for AT Protocol repositories.

  A repository's records are stored in an MST: a deterministic, content-addressed
  key/value map from record paths (`<collection>/<rkey>`) to record CIDs. The
  structure depends only on the current set of keys (not insertion order), so the
  root CID is a stable fingerprint of the repository contents and is what a
  commit's `data` field points at.

  This module can:

  - `build/1` an MST from a set of `path => CID` entries, returning the root CID
    and the encoded node blocks (so you can verify a commit's `data` root or
    construct a repository).
  - `read/2` an MST from a root CID and a block store back into a
    `path => CID` map (so you can verify and walk a repository checkout or the
    `blocks` of a firehose commit).
  - `depth/1` compute the layer of a key, and `valid_key?/1` validate a key.

  ## Node format

  Each node is DAG-CBOR with the shape:

      %{
        "l" => CID | nil,   # left subtree (keys sorting before all entries)
        "e" => [            # entries, sorted by key
          %{
            "p" => integer, # bytes shared with the previous entry's key
            "k" => bytes,   # key suffix after the shared prefix
            "v" => CID,     # value (record CID)
            "t" => CID | nil # right subtree (keys between this and the next entry)
          }
        ]
      }

  ## Examples

      iex> {:ok, root, _blocks} = Exosphere.ATProto.MST.build([])
      iex> to_string(root)
      "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"
  """

  alias Exosphere.ATProto.CBOR, as: DagCBOR
  alias Exosphere.ATProto.{CID, NSID, RecordKey}

  @max_key_length 1024

  @type key :: String.t()
  @type blocks :: %{CID.t() => binary()}

  @doc """
  Compute the MST layer (depth) of a key.

  The key is hashed with SHA-256 and the number of leading zero *bits* is
  counted in 2-bit chunks (fanout 4): every two leading zero bits increments the
  layer. Implemented to match the reference `leadingZerosOnHash`.

  ## Examples

      iex> Exosphere.ATProto.MST.depth("com.example.record/3jqfcqzm3fx2j")
      2
  """
  @spec depth(key()) :: non_neg_integer()
  def depth(key) when is_binary(key) do
    :sha256
    |> :crypto.hash(key)
    |> count_leading_zero_chunks(0)
  end

  defp count_leading_zero_chunks(<<0, rest::binary>>, acc),
    do: count_leading_zero_chunks(rest, acc + 4)

  defp count_leading_zero_chunks(<<byte, _rest::binary>>, acc) when byte < 4, do: acc + 3
  defp count_leading_zero_chunks(<<byte, _rest::binary>>, acc) when byte < 16, do: acc + 2
  defp count_leading_zero_chunks(<<byte, _rest::binary>>, acc) when byte < 64, do: acc + 1
  defp count_leading_zero_chunks(_, acc), do: acc

  @doc """
  Validate an MST key (a repository record path `<collection>/<rkey>`).

  The collection must be a valid NSID and the rkey a valid record key, so keys
  built here are accepted by reference implementations.
  """
  @spec valid_key?(term()) :: boolean()
  def valid_key?(key) when is_binary(key) do
    case String.split(key, "/") do
      [collection, rkey] ->
        byte_size(key) <= @max_key_length and
          NSID.valid?(collection) and RecordKey.valid?(rkey)

      _ ->
        false
    end
  end

  def valid_key?(_), do: false

  @doc """
  Build an MST from `path => CID` entries.

  Accepts a map or an enumerable of `{key, %CID{}}` pairs. Returns
  `{:ok, root_cid, blocks}` where `blocks` maps each node CID to its encoded
  DAG-CBOR bytes.

  Returns `{:error, {:invalid_key, key}}` or `{:error, {:invalid_value, key}}`
  for malformed input, `{:error, {:duplicate_key, key}}` if the same path appears
  with different CIDs, and `{:error, {:invalid_entry, term}}` for non-pair elements.
  """
  @spec build(Enumerable.t()) ::
          {:ok, CID.t(), blocks()} | {:error, term()}
  def build(entries) do
    with {:ok, triples} <- normalize(entries) do
      {root, blocks} =
        case triples do
          [] -> store(empty_node(), %{})
          _ -> build_layer(triples, top_layer(triples), %{})
        end

      {:ok, root, blocks}
    end
  end

  @doc """
  Build an MST and return only the root CID.
  """
  @spec root_cid(Enumerable.t()) :: {:ok, CID.t()} | {:error, term()}
  def root_cid(entries) do
    with {:ok, root, _blocks} <- build(entries), do: {:ok, root}
  end

  @doc """
  Read an MST into a `path => CID` map, walking from `root` through `blocks`.

  `blocks` may map CIDs to encoded DAG-CBOR bytes (e.g. a raw block store) or to
  already-decoded node maps (e.g. the output of `Exosphere.ATProto.CAR.decode/1`).

  This walks the tree but does not validate its structure (entry ordering or key
  layering): use `build/1` on the resulting entries and compare root CIDs (as
  `Exosphere.ATProto.Repo.Commit.verify_data/2` does) to fully authenticate a tree.

  Returns `{:error, {:missing_block, cid}}` if a referenced node is absent,
  `{:error, {:invalid_node, cid}}` if a node cannot be decoded, and
  `{:error, {:cycle, cid}}` if a node links to itself or an ancestor (possible
  with hostile block data).
  """
  @spec read(CID.t(), %{CID.t() => binary() | map()}) ::
          {:ok, %{key() => CID.t()}} | {:error, term()}
  def read(%CID{} = root, blocks) when is_map(blocks) do
    with {:ok, entries} <- collect(root, blocks, [], %{}) do
      {:ok, Map.new(entries)}
    end
  end

  # --- Build internals ---------------------------------------------------------

  defp top_layer(triples) do
    triples |> Enum.map(fn {_k, depth, _v} -> depth end) |> Enum.max()
  end

  # Build the node(s) covering `triples` ({key, depth, value}, sorted by key) at
  # `layer`. If no key sits exactly at this layer, descend (no empty intermediate
  # nodes are created). Depths are precomputed once by normalize/1.
  defp build_layer(triples, layer, blocks) do
    if Enum.any?(triples, fn {_k, depth, _v} -> depth == layer end) do
      {left, segments} = split_segments(triples, layer)
      {l_cid, blocks} = subtree(left, layer, blocks)

      {entries, blocks} =
        Enum.reduce(segments, {[], blocks}, fn {{key, _depth, value}, between}, {acc, blocks} ->
          {t_cid, blocks} = subtree(between, layer, blocks)
          {[%{key: key, value: value, tree: t_cid} | acc], blocks}
        end)

      store(node(l_cid, Enum.reverse(entries)), blocks)
    else
      build_layer(triples, layer - 1, blocks)
    end
  end

  defp subtree([], _layer, blocks), do: {nil, blocks}
  defp subtree(triples, layer, blocks), do: build_layer(triples, layer - 1, blocks)

  # Split sorted `triples` around the leaves whose depth == layer:
  # {triples_before_first_leaf, [{leaf, triples_between_it_and_next_leaf}, ...]}
  defp split_segments(triples, layer) do
    {left, rest} = Enum.split_while(triples, fn {_k, depth, _v} -> depth != layer end)
    [leaf | tail] = rest
    {left, segments(leaf, tail, layer, [])}
  end

  defp segments(leaf, rest, layer, acc) do
    {between, rest} = Enum.split_while(rest, fn {_k, depth, _v} -> depth != layer end)

    case rest do
      [] -> Enum.reverse([{leaf, between} | acc])
      [next | tail] -> segments(next, tail, layer, [{leaf, between} | acc])
    end
  end

  defp empty_node, do: %{"l" => nil, "e" => []}

  # Build a node map with prefix-compressed entries.
  defp node(l_cid, entries) do
    {e, _prev} =
      Enum.reduce(entries, {[], <<>>}, fn %{key: key, value: value, tree: tree}, {acc, prev} ->
        p = common_prefix_length(prev, key)
        suffix = binary_part(key, p, byte_size(key) - p)

        entry = %{
          "p" => p,
          "k" => %CBOR.Tag{tag: :bytes, value: suffix},
          "v" => value,
          "t" => tree
        }

        {[entry | acc], key}
      end)

    %{"l" => l_cid, "e" => Enum.reverse(e)}
  end

  defp common_prefix_length(a, b), do: common_prefix_length(a, b, 0)

  defp common_prefix_length(<<x, a::binary>>, <<x, b::binary>>, n),
    do: common_prefix_length(a, b, n + 1)

  defp common_prefix_length(_, _, n), do: n

  # Encode a node to DAG-CBOR, store it by CID, return {cid, blocks}.
  # The encoder is deterministic, so the stored bytes hash to `cid`.
  defp store(node, blocks) do
    bytes = DagCBOR.encode!(node)
    cid = CID.create!(node)
    {cid, Map.put(blocks, cid, bytes)}
  end

  # --- Read internals ----------------------------------------------------------

  # `visited` (a map of CIDs to `true`) guards against cycles in hostile block
  # data: a node linking to itself or an ancestor would otherwise recurse forever.
  defp collect(%CID{} = cid, blocks, acc, visited) do
    if Map.has_key?(visited, cid) do
      {:error, {:cycle, cid}}
    else
      visited = Map.put(visited, cid, true)

      with {:ok, node} <- fetch_node(cid, blocks) do
        left = node_link(node, "l")

        with {:ok, acc} <- collect_optional(left, blocks, acc, visited) do
          walk_entries(Map.get(node, "e", []), blocks, acc, visited, <<>>)
        end
      end
    end
  end

  defp collect_optional(nil, _blocks, acc, _visited), do: {:ok, acc}

  defp collect_optional(%CID{} = cid, blocks, acc, visited),
    do: collect(cid, blocks, acc, visited)

  defp walk_entries([], _blocks, acc, _visited, _prev), do: {:ok, acc}

  defp walk_entries([entry | rest], blocks, acc, visited, prev) do
    with {:ok, key} <- entry_key(entry, prev),
         %CID{} = value <- entry_value(entry),
         {:ok, acc} <-
           collect_optional(node_link(entry, "t"), blocks, [{key, value} | acc], visited) do
      walk_entries(rest, blocks, acc, visited, key)
    else
      nil -> {:error, :invalid_entry}
      {:error, _} = error -> error
    end
  end

  defp entry_key(entry, prev) do
    with p when is_integer(p) <- Map.get(entry, "p"),
         suffix when is_binary(suffix) <- entry_suffix(entry),
         true <- p <= byte_size(prev) do
      {:ok, binary_part(prev, 0, p) <> suffix}
    else
      _ -> {:error, :invalid_entry_key}
    end
  end

  defp entry_suffix(entry) do
    case Map.get(entry, "k") do
      bytes when is_binary(bytes) -> bytes
      %CBOR.Tag{tag: :bytes, value: bytes} when is_binary(bytes) -> bytes
      _ -> nil
    end
  end

  defp entry_value(entry) do
    case Map.get(entry, "v") do
      %CID{} = cid -> cid
      _ -> nil
    end
  end

  defp node_link(node, field) do
    case Map.get(node, field) do
      %CID{} = cid -> cid
      _ -> nil
    end
  end

  defp fetch_node(cid, blocks) do
    case Map.get(blocks, cid) do
      nil -> {:error, {:missing_block, cid}}
      node when is_map(node) -> {:ok, node}
      bytes when is_binary(bytes) -> decode_node(cid, bytes)
    end
  end

  defp decode_node(cid, bytes) do
    case DagCBOR.decode(bytes) do
      {:ok, node} when is_map(node) -> {:ok, node}
      _ -> {:error, {:invalid_node, cid}}
    end
  end

  # --- Input normalization -----------------------------------------------------

  # Validate, dedupe, and sort entries into `{key, depth, value}` triples with
  # each key's depth computed exactly once.
  defp normalize(entries) do
    entries
    |> Enum.reduce_while({:ok, %{}}, fn
      {key, %CID{} = value}, {:ok, acc} when is_binary(key) ->
        cond do
          not valid_key?(key) ->
            {:halt, {:error, {:invalid_key, key}}}

          Map.has_key?(acc, key) and Map.get(acc, key) != value ->
            {:halt, {:error, {:duplicate_key, key}}}

          true ->
            {:cont, {:ok, Map.put(acc, key, value)}}
        end

      {key, _value}, {:ok, _acc} ->
        {:halt, {:error, {:invalid_value, key}}}

      other, {:ok, _acc} ->
        {:halt, {:error, {:invalid_entry, other}}}
    end)
    |> case do
      {:ok, map} ->
        {:ok,
         map
         |> Enum.map(fn {key, value} -> {key, depth(key), value} end)
         |> Enum.sort_by(&elem(&1, 0))}

      error ->
        error
    end
  end
end
