defmodule Exosphere.ATProto.MST.Node do
  @moduledoc """
  The node algebra behind `Exosphere.ATProto.MST`'s incremental operations.

  `Exosphere.ATProto.MST.build/1` computes a whole tree from a key set, which
  is the right shape for verifying someone else's repository and the wrong one
  for serving writes: a PDS applying three record operations should touch the
  handful of nodes on those keys' paths, not rebuild a million-node tree. This
  module is the splice-level machinery that makes that possible — insertion,
  deletion, splitting and merging of subtrees — with the same output, node for
  node, as a rebuild.

  You are unlikely to call this directly; `Exosphere.ATProto.MST.apply_ops/3` and
  friends are the public surface. It is documented because the invariants
  matter to anyone changing it.

  ## In-memory shape

      %Node{
        layer: 2,                      # every entry's key hashes to this layer
        left: child,                   # keys sorting before all entries
        entries: [%{key: binary, value: %CID{}, tree: child}]
      }

  A `child` is `nil`, a `%CID{}` (still in the blocks, not yet loaded), or a
  loaded `%Node{}` (typically one this edit has dirtied). Lazy children are
  what keep an edit proportional to the path it touches: everything off the
  path stays a CID and is written back out unchanged.

  ## Invariants

  These hold for every tree `Exosphere.ATProto.MST.build/1` produces, and every
  operation here preserves them:

    * Entries are sorted by key, and every entry's key hashes to the node's
      layer (`Exosphere.ATProto.MST.depth/1`).
    * A subtree link descends *exactly* one layer. Where a layer has no keys of
      its own it is still represented, by an empty shell (`entries: []` with
      only a left link).
    * Empty nodes are pruned from the top and the bottom: the root is never a
      shell, and a shell never bottoms out in `nil`.

  The last two pull in opposite directions, and between them they are what
  makes the tree a pure function of its key set — the property the whole design
  rests on. Concretely: any sequence of operations reaching a given key set must
  produce the same root CID as `Exosphere.ATProto.MST.build/1` over that set,
  and the same CID the reference implementation would produce. If you change
  anything here, that equivalence is the thing to check.
  """

  alias Exosphere.ATProto.CBOR, as: DagCBOR
  alias Exosphere.ATProto.CID
  alias Exosphere.ATProto.MST.Blocks

  @enforce_keys [:layer, :left, :entries]
  defstruct [:layer, :left, :entries]

  @type entry :: %{key: binary(), value: CID.t(), tree: child()}
  @type child :: nil | CID.t() | t()
  @type t :: %__MODULE__{layer: integer(), left: child(), entries: [entry()]}

  @doc """
  An empty tree: one node with no entries and no subtrees.

  Its layer is `0` by convention — the tree has no keys, so no key implies a
  layer, and a rebuild of an empty entry set produces exactly this node.
  """
  @spec empty() :: t()
  def empty, do: %__MODULE__{layer: 0, left: nil, entries: []}

  @doc """
  Load the root node at `cid`, deriving its layer.

  A root with entries takes its layer from any entry's key. A shell root
  cannot happen in a well-formed tree, but a partial or hostile store can
  present one, so the layer is derived by descending until entries appear.
  """
  @spec load_root(CID.t(), Blocks.source()) :: {:ok, t()} | {:error, term()}
  def load_root(%CID{} = cid, blocks) do
    with {:ok, layer} <- derive_layer(cid, blocks, 0, %{}) do
      load(cid, layer, blocks)
    end
  end

  @doc """
  Load the node at `cid`, which sits at `layer`.
  """
  @spec load(CID.t(), integer(), Blocks.source()) :: {:ok, t()} | {:error, term()}
  def load(%CID{} = cid, layer, blocks) do
    with {:ok, block} <- Blocks.fetch(blocks, cid),
         {:ok, decoded} <- decode_block(cid, block) do
      decode_node(cid, decoded, layer)
    end
  end

  @doc """
  Resolve a child to a loaded node, or `nil`.
  """
  @spec resolve(child(), integer(), Blocks.source()) :: {:ok, t() | nil} | {:error, term()}
  def resolve(nil, _layer, _blocks), do: {:ok, nil}
  def resolve(%__MODULE__{} = node, _layer, _blocks), do: {:ok, node}
  def resolve(%CID{} = cid, layer, blocks), do: load(cid, layer, blocks)

  @doc """
  Insert or replace `key => value`, growing the root if the key belongs above it.

  Returns the new root. `key_layer` is `Exosphere.ATProto.MST.depth(key)`,
  passed in so a batch of operations hashes each key once.
  """
  @spec put(t(), binary(), CID.t(), integer(), Blocks.source()) :: {:ok, t()} | {:error, term()}
  def put(%__MODULE__{} = root, key, %CID{} = value, key_layer, blocks) do
    root
    |> grow_to(key_layer)
    |> insert(key, value, key_layer, blocks)
  end

  @doc """
  Remove `key`, pruning any empty shells left at the top.

  Returns `{:error, {:key_not_found, key}}` if the key is absent.
  """
  @spec delete(t(), binary(), integer(), Blocks.source()) :: {:ok, t()} | {:error, term()}
  def delete(%__MODULE__{} = root, key, key_layer, blocks) do
    with {:ok, root} <- remove(root, key, key_layer, blocks) do
      trim_top(root, blocks)
    end
  end

  @doc """
  Encode every dirty node, bottom-up, and return the root's CID with the blocks
  produced.

  Nothing is written anywhere: the new blocks come back as a map for the caller
  to persist, and they are exactly the set a `#commit` message must carry for
  the nodes it changed. Children still held as CIDs are untouched, so a flush
  costs only what the edit dirtied.
  """
  @spec flush(t()) :: {CID.t(), %{CID.t() => binary()}}
  def flush(%__MODULE__{} = node), do: do_flush(node, %{})

  @doc """
  The CIDs visited looking `key` up, root first.

  These are exactly the blocks a proof for `key` must carry, whether the key is
  present (an inclusion proof: the walk ends at the node holding it) or absent
  (an exclusion proof: the walk ends where it would have been). Loaded-but-not-
  yet-flushed nodes have no CID and are skipped, so call this against a
  flushed tree.
  """
  @spec path(CID.t(), binary(), Blocks.source()) :: {:ok, [CID.t()]} | {:error, term()}
  def path(%CID{} = root, key, blocks) do
    with {:ok, node} <- load_root(root, blocks) do
      walk_path(node, root, key, blocks, [])
    end
  end

  defp walk_path(%__MODULE__{layer: layer} = node, cid, key, blocks, acc) do
    acc = [cid | acc]
    index = insertion_index(node.entries, key)

    case Enum.at(node.entries, index) do
      %{key: ^key} ->
        {:ok, Enum.reverse(acc)}

      _ ->
        case span_child(node, index) do
          nil ->
            {:ok, Enum.reverse(acc)}

          %CID{} = child_cid ->
            with {:ok, child} <- load(child_cid, layer - 1, blocks) do
              walk_path(child, child_cid, key, blocks, acc)
            end

          %__MODULE__{} ->
            {:ok, Enum.reverse(acc)}
        end
    end
  end

  @doc """
  The value stored at `key`, or `nil` when the tree does not hold it.
  """
  @spec find(CID.t(), binary(), Blocks.source()) :: {:ok, CID.t() | nil} | {:error, term()}
  def find(%CID{} = root, key, blocks) do
    with {:ok, node} <- load_root(root, blocks) do
      walk_find(node, key, blocks)
    end
  end

  defp walk_find(%__MODULE__{layer: layer} = node, key, blocks) do
    index = insertion_index(node.entries, key)

    case Enum.at(node.entries, index) do
      %{key: ^key, value: value} ->
        {:ok, value}

      _ ->
        case span_child(node, index) do
          nil ->
            {:ok, nil}

          child ->
            with {:ok, resolved} <- resolve(child, layer - 1, blocks) do
              walk_find(resolved, key, blocks)
            end
        end
    end
  end

  @doc """
  The keys immediately either side of `key` in the tree.

  Returns `{:ok, {previous, next}}`, either of which is `nil` at the ends of
  the tree. A firehose commit's covering proof needs the neighbours' paths as
  well as the operated key's: a deletion merges the subtrees on both sides of
  the removed entry, and a consumer inverting that operation has to walk into
  them.
  """
  @spec neighbor_keys(CID.t(), binary(), Blocks.source()) ::
          {:ok, {binary() | nil, binary() | nil}} | {:error, term()}
  def neighbor_keys(%CID{} = root, key, blocks) do
    with {:ok, node} <- load_root(root, blocks) do
      walk_neighbors(node, key, blocks, {nil, nil})
    end
  end

  defp walk_neighbors(%__MODULE__{layer: layer} = node, key, blocks, {prev, next}) do
    index = insertion_index(node.entries, key)

    # Each node on the way down narrows the bracket: the entry before the gap
    # is the closest predecessor seen so far, the entry after it the closest
    # successor.
    prev = if index > 0, do: Enum.at(node.entries, index - 1).key, else: prev
    at = Enum.at(node.entries, index)
    next = if at && at.key != key, do: at.key, else: next

    case at do
      %{key: ^key} = entry ->
        # An exact hit: the true neighbours are the extremes of the subtrees
        # hanging either side of this entry, falling back to the bracket.
        with {:ok, deeper_prev} <- rightmost_key(span_child(node, index), layer - 1, blocks),
             {:ok, deeper_next} <- leftmost_key(entry.tree, layer - 1, blocks) do
          {:ok, {deeper_prev || prev, deeper_next || next}}
        end

      _ ->
        case span_child(node, index) do
          nil ->
            {:ok, {prev, next}}

          child ->
            with {:ok, resolved} <- resolve(child, layer - 1, blocks) do
              walk_neighbors(resolved, key, blocks, {prev, next})
            end
        end
    end
  end

  @doc """
  The smallest key in a subtree, or `nil` when it is empty.
  """
  @spec leftmost_key(child(), integer(), Blocks.source()) ::
          {:ok, binary() | nil} | {:error, term()}
  def leftmost_key(nil, _layer, _blocks), do: {:ok, nil}

  def leftmost_key(child, layer, blocks) do
    with {:ok, node} <- resolve(child, layer, blocks) do
      case {node.left, node.entries} do
        {nil, [first | _]} -> {:ok, first.key}
        {nil, []} -> {:ok, nil}
        {left, entries} -> descend_leftmost(left, entries, layer - 1, blocks)
      end
    end
  end

  defp descend_leftmost(left, entries, layer, blocks) do
    with {:ok, deeper} <- leftmost_key(left, layer, blocks) do
      case {deeper, entries} do
        {nil, [first | _]} -> {:ok, first.key}
        {nil, []} -> {:ok, nil}
        {key, _} -> {:ok, key}
      end
    end
  end

  @doc """
  The largest key in a subtree, or `nil` when it is empty.
  """
  @spec rightmost_key(child(), integer(), Blocks.source()) ::
          {:ok, binary() | nil} | {:error, term()}
  def rightmost_key(nil, _layer, _blocks), do: {:ok, nil}

  def rightmost_key(child, layer, blocks) do
    with {:ok, node} <- resolve(child, layer, blocks) do
      case List.last(node.entries) do
        nil ->
          rightmost_key(node.left, layer - 1, blocks)

        last ->
          with {:ok, deeper} <- rightmost_key(last.tree, layer - 1, blocks) do
            {:ok, deeper || last.key}
          end
      end
    end
  end

  # --- Insertion ---------------------------------------------------------------

  # A key whose layer sits above the root's needs the tree to grow: wrap the
  # current root in shells until the top is at the key's layer, so the insert
  # below can splice at `layer == node.layer`. The old root becomes the left
  # subtree and is then split around the key.
  defp grow_to(%__MODULE__{layer: layer} = node, target) when layer >= target, do: node

  defp grow_to(%__MODULE__{layer: layer} = node, target) do
    grow_to(%__MODULE__{layer: layer + 1, left: node, entries: []}, target)
  end

  defp insert(%__MODULE__{layer: layer} = node, key, value, key_layer, blocks)
       when key_layer == layer do
    index = insertion_index(node.entries, key)

    case Enum.at(node.entries, index) do
      %{key: ^key} = existing ->
        {:ok, %{node | entries: List.replace_at(node.entries, index, %{existing | value: value})}}

      _ ->
        splice(node, key, value, index, blocks)
    end
  end

  defp insert(%__MODULE__{layer: layer} = node, key, value, key_layer, blocks)
       when key_layer < layer do
    index = insertion_index(node.entries, key)
    child_layer = layer - 1

    with {:ok, child} <- resolve(span_child(node, index), child_layer, blocks),
         {:ok, updated} <- insert_into_child(child, key, value, key_layer, child_layer, blocks) do
      {:ok, put_span_child(node, index, updated)}
    end
  end

  defp insert(%__MODULE__{}, key, _value, _key_layer, _blocks),
    do: {:error, {:key_above_root, key}}

  # No subtree spans this key yet: build the chain of shells down to the key's
  # own layer and hang a single leaf off the bottom.
  defp insert_into_child(nil, key, value, key_layer, from_layer, _blocks),
    do: {:ok, chain(key, value, key_layer, from_layer)}

  defp insert_into_child(%__MODULE__{} = child, key, value, key_layer, _from, blocks),
    do: insert(child, key, value, key_layer, blocks)

  defp chain(key, value, key_layer, layer) when layer == key_layer do
    %__MODULE__{layer: layer, left: nil, entries: [%{key: key, value: value, tree: nil}]}
  end

  defp chain(key, value, key_layer, layer) do
    %__MODULE__{layer: layer, left: chain(key, value, key_layer, layer - 1), entries: []}
  end

  # Insert a leaf at `index`. The subtree that currently spans the key's
  # position straddles it, so it splits: its lower half stays with the entry
  # before, its upper half becomes the new entry's own subtree.
  defp splice(%__MODULE__{layer: layer} = node, key, value, index, blocks) do
    with {:ok, {left, right}} <- split(span_child(node, index), key, layer - 1, blocks) do
      entry = %{key: key, value: value, tree: right}

      entries =
        node.entries
        |> Enum.take(index)
        |> replace_last_tree(left)
        |> Kernel.++([entry | Enum.drop(node.entries, index)])

      left_link = if index == 0, do: left, else: node.left

      {:ok, %{node | left: left_link, entries: entries}}
    end
  end

  # --- Deletion ----------------------------------------------------------------

  defp remove(%__MODULE__{layer: layer} = node, key, key_layer, blocks)
       when key_layer == layer do
    case Enum.find_index(node.entries, &(&1.key == key)) do
      nil ->
        {:error, {:key_not_found, key}}

      index ->
        entry = Enum.at(node.entries, index)

        # The removed entry's subtree and the one before it become adjacent,
        # so they merge into a single subtree in its place.
        with {:ok, merged} <- merge(span_child(node, index), entry.tree, layer - 1, blocks) do
          entries =
            node.entries
            |> Enum.take(index)
            |> replace_last_tree(merged)
            |> Kernel.++(Enum.drop(node.entries, index + 1))

          left_link = if index == 0, do: merged, else: node.left

          {:ok, prune(%{node | left: left_link, entries: entries})}
        end
    end
  end

  defp remove(%__MODULE__{layer: layer} = node, key, key_layer, blocks)
       when key_layer < layer do
    index = insertion_index(node.entries, key)
    child_layer = layer - 1

    case resolve(span_child(node, index), child_layer, blocks) do
      {:ok, nil} ->
        {:error, {:key_not_found, key}}

      {:ok, child} ->
        with {:ok, updated} <- remove(child, key, key_layer, blocks) do
          {:ok, prune(put_span_child(node, index, updated))}
        end

      {:error, _} = error ->
        error
    end
  end

  defp remove(%__MODULE__{}, key, _key_layer, _blocks), do: {:error, {:key_not_found, key}}

  # The root may not be an empty shell, so collapse into the left subtree until
  # it has entries (or the tree is empty, which is the one node with neither).
  defp trim_top(nil, _blocks), do: {:ok, empty()}

  defp trim_top(%__MODULE__{entries: [_ | _]} = node, _blocks), do: {:ok, node}

  defp trim_top(%__MODULE__{entries: [], left: nil}, _blocks), do: {:ok, empty()}

  defp trim_top(%__MODULE__{entries: [], left: left, layer: layer}, blocks) do
    with {:ok, child} <- resolve(left, layer - 1, blocks) do
      trim_top(child, blocks)
    end
  end

  # A node with neither entries nor a left subtree holds nothing: it is the
  # bottom of the tree, and the link to it becomes nil.
  defp prune(%__MODULE__{entries: [], left: nil}), do: nil
  defp prune(%__MODULE__{} = node), do: node

  # --- Split and merge ---------------------------------------------------------

  # Split the subtree into the keys below `key` and the keys above it. `key`
  # itself is never present (callers split only where it is absent), so no
  # entry is dropped.
  defp split(nil, _key, _layer, _blocks), do: {:ok, {nil, nil}}

  defp split(child, key, layer, blocks) do
    with {:ok, node} <- resolve(child, layer, blocks) do
      split_node(node, key, layer, blocks)
    end
  end

  defp split_node(%__MODULE__{} = node, key, layer, blocks) do
    index = insertion_index(node.entries, key)

    # The subtree at the boundary straddles the key and splits in turn.
    with {:ok, {sub_left, sub_right}} <- split(span_child(node, index), key, layer - 1, blocks) do
      left_entries = node.entries |> Enum.take(index) |> replace_last_tree(sub_left)
      left_link = if index == 0, do: sub_left, else: node.left

      left = prune(%__MODULE__{layer: layer, left: left_link, entries: left_entries})

      right =
        prune(%__MODULE__{
          layer: layer,
          left: sub_right,
          entries: Enum.drop(node.entries, index)
        })

      {:ok, {left, right}}
    end
  end

  # Merge two adjacent subtrees at the same layer — every key on the left sorts
  # before every key on the right. Their facing edges (the left tree's last
  # subtree and the right tree's left subtree) are themselves adjacent, so they
  # merge one layer down.
  defp merge(nil, right, _layer, _blocks), do: {:ok, right}
  defp merge(left, nil, _layer, _blocks), do: {:ok, left}

  defp merge(left, right, layer, blocks) do
    with {:ok, l} <- resolve(left, layer, blocks),
         {:ok, r} <- resolve(right, layer, blocks) do
      merge_nodes(l, r, layer, blocks)
    end
  end

  defp merge_nodes(%__MODULE__{entries: []} = l, %__MODULE__{} = r, layer, blocks) do
    with {:ok, merged} <- merge(l.left, r.left, layer - 1, blocks) do
      {:ok, prune(%__MODULE__{layer: layer, left: merged, entries: r.entries})}
    end
  end

  defp merge_nodes(%__MODULE__{} = l, %__MODULE__{} = r, layer, blocks) do
    with {:ok, merged} <- merge(List.last(l.entries).tree, r.left, layer - 1, blocks) do
      entries = replace_last_tree(l.entries, merged) ++ r.entries
      {:ok, prune(%__MODULE__{layer: layer, left: l.left, entries: entries})}
    end
  end

  # --- Child access ------------------------------------------------------------

  # The subtree covering the gap before `entries[index]`: the node's left link
  # at the start, otherwise the previous entry's own subtree.
  defp span_child(%__MODULE__{left: left}, 0), do: left
  defp span_child(%__MODULE__{entries: entries}, index), do: Enum.at(entries, index - 1).tree

  defp put_span_child(%__MODULE__{} = node, 0, child), do: %{node | left: child}

  defp put_span_child(%__MODULE__{entries: entries} = node, index, child) do
    entry = Enum.at(entries, index - 1)
    %{node | entries: List.replace_at(entries, index - 1, %{entry | tree: child})}
  end

  defp replace_last_tree([], _child), do: []

  defp replace_last_tree(entries, child) do
    List.replace_at(entries, -1, %{List.last(entries) | tree: child})
  end

  # Index of the first entry whose key is >= `key` — where a leaf for `key`
  # would go, and the boundary the subtree before it spans.
  defp insertion_index(entries, key) do
    Enum.count(entries, &(&1.key < key))
  end

  # --- Encoding ----------------------------------------------------------------

  @doc """
  Encode a node to its canonical DAG-CBOR map.

  Entry keys are prefix-compressed against the previous entry, per the
  repository spec. Children must already be CIDs — `flush/2` writes
  bottom-up so they are.
  """
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{left: left, entries: entries}) do
    {encoded, _prev} =
      Enum.reduce(entries, {[], <<>>}, fn %{key: key, value: value, tree: tree}, {acc, prev} ->
        prefix = common_prefix_length(prev, key)
        suffix = binary_part(key, prefix, byte_size(key) - prefix)

        entry = %{
          "p" => prefix,
          "k" => %CBOR.Tag{tag: :bytes, value: suffix},
          "v" => value,
          "t" => tree
        }

        {[entry | acc], key}
      end)

    %{"l" => left, "e" => Enum.reverse(encoded)}
  end

  @doc """
  Length of the common byte prefix of two keys.
  """
  @spec common_prefix_length(binary(), binary()) :: non_neg_integer()
  def common_prefix_length(a, b), do: common_prefix_length(a, b, 0)

  defp common_prefix_length(<<x, a::binary>>, <<x, b::binary>>, n),
    do: common_prefix_length(a, b, n + 1)

  defp common_prefix_length(_, _, n), do: n

  # Depth-first, so every child is a CID by the time its parent is encoded.
  # Nothing here can fail: the tree is already in memory.
  defp do_flush(%__MODULE__{} = node, written) do
    {left, written} = flush_child(node.left, written)
    {entries, written} = flush_entries(node.entries, written, [])

    map = to_map(%{node | left: left, entries: entries})
    bytes = DagCBOR.encode!(map)
    cid = CID.create!(map)

    {cid, Map.put(written, cid, bytes)}
  end

  defp flush_child(nil, written), do: {nil, written}
  defp flush_child(%CID{} = cid, written), do: {cid, written}
  defp flush_child(%__MODULE__{} = node, written), do: do_flush(node, written)

  defp flush_entries([], written, acc), do: {Enum.reverse(acc), written}

  defp flush_entries([entry | rest], written, acc) do
    {tree, written} = flush_child(entry.tree, written)
    flush_entries(rest, written, [%{entry | tree: tree} | acc])
  end

  # --- Decoding ----------------------------------------------------------------

  # Bytes or an already-decoded node: the two shapes a store may hold. See the
  # note on `Exosphere.ATProto.MST`'s `block_bytes/1` for why there is no
  # catch-all.
  defp decode_block(_cid, block) when is_map(block), do: {:ok, block}

  defp decode_block(cid, bytes) when is_binary(bytes) do
    case DagCBOR.decode(bytes) do
      {:ok, node} when is_map(node) -> {:ok, node}
      _ -> {:error, {:invalid_node, cid}}
    end
  end

  defp decode_node(cid, map, layer) do
    case decode_entries(Map.get(map, "e", []), <<>>, []) do
      {:ok, entries} -> {:ok, %__MODULE__{layer: layer, left: link(map, "l"), entries: entries}}
      {:error, reason} -> {:error, {reason, cid}}
    end
  end

  defp decode_entries([], _prev, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_entries([entry | rest], prev, acc) when is_map(entry) do
    with prefix when is_integer(prefix) and prefix >= 0 <- Map.get(entry, "p"),
         suffix when is_binary(suffix) <- entry_suffix(entry),
         true <- prefix <= byte_size(prev),
         %CID{} = value <- Map.get(entry, "v") do
      key = binary_part(prev, 0, prefix) <> suffix
      decode_entries(rest, key, [%{key: key, value: value, tree: link(entry, "t")} | acc])
    else
      _ -> {:error, :invalid_entry}
    end
  end

  defp decode_entries(_, _prev, _acc), do: {:error, :invalid_entry}

  defp entry_suffix(entry) do
    case Map.get(entry, "k") do
      bytes when is_binary(bytes) -> bytes
      %CBOR.Tag{tag: :bytes, value: bytes} when is_binary(bytes) -> bytes
      _ -> nil
    end
  end

  defp link(map, field) do
    case Map.get(map, field) do
      %CID{} = cid -> cid
      _ -> nil
    end
  end

  # A well-formed root has entries, so its layer is any entry key's depth. A
  # shell root (only reachable from a partial or hostile blocks) means
  # descending, counting a layer per level; `seen` stops a self-referential
  # store from looping forever.
  defp derive_layer(%CID{} = cid, blocks, depth, seen) do
    if Map.has_key?(seen, cid) do
      {:error, {:cycle, cid}}
    else
      with {:ok, block} <- Blocks.fetch(blocks, cid),
           {:ok, map} <- decode_block(cid, block) do
        case Map.get(map, "e", []) do
          [entry | _] when is_map(entry) ->
            with {:ok, [%{key: key} | _]} <- decode_entries([entry], <<>>, []) do
              {:ok, Exosphere.ATProto.MST.depth(key) + depth}
            end

          _ ->
            case link(map, "l") do
              %CID{} = left -> derive_layer(left, blocks, depth + 1, Map.put(seen, cid, true))
              nil -> {:ok, depth}
            end
        end
      end
    end
  end
end
