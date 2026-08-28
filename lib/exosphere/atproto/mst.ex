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
  - `apply_ops/3` edit a tree, touching only the paths the operations reach,
    and return the new blocks (the serving path: a PDS applying a write should
    not rebuild the repository).
  - `proof/3` and `covering_proof/4` extract the blocks that prove what the
    tree says about a set of keys — an inclusion or exclusion proof for
    `getRecord`, and the covering proof a `#commit` firehose message must
    carry.
  - `invert/3` run a commit's operations backwards against those proof blocks
    to recover the previous root, the consumer half of the inductive firehose.
  - `diff/3` the blocks reachable from one root but not another.
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

  alias Exosphere.ATProto.CAR
  alias Exosphere.ATProto.CBOR, as: DagCBOR
  alias Exosphere.ATProto.MST.{Blocks, Node}
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

  @doc """
  Read the record set from a repository CAR archive.

  Accepts raw CAR bytes (e.g. the body of `com.atproto.sync.getRepo`) or the
  `%{roots: [...], blocks: ...}` map returned by `CAR.decode_full/1`. A
  repository CAR is rooted at its top commit block; the tree is read from the
  commit's `data` (MST root) link.

  The archive must contain every MST node reachable from that root —
  full-repo CARs do; incremental firehose commit CARs only carry new blocks
  and will report `{:error, {:missing_block, cid}}` for unchanged subtrees.
  """
  @spec from_repo_car(binary() | %{roots: [CID.t()], blocks: %{CID.t() => binary() | map()}}) ::
          {:ok, %{key() => CID.t()}} | {:error, term()}
  def from_repo_car(car) when is_binary(car) do
    with {:ok, %{roots: roots, blocks: blocks}} <- CAR.decode_full(car) do
      from_repo_car(%{roots: roots, blocks: blocks})
    end
  end

  def from_repo_car(%{roots: roots, blocks: blocks}) when is_map(blocks) do
    with [%CID{} = commit_cid] <- roots,
         commit when is_map(commit) <-
           Map.get(blocks, commit_cid) || {:error, {:missing_block, commit_cid}},
         %CID{} = data <- Map.get(commit, "data") || {:error, :missing_data} do
      read(data, blocks)
    else
      [] -> {:error, :no_root}
      [_ | _] -> {:error, :multiple_roots}
      {:error, _} = error -> error
      _ -> {:error, :invalid_commit}
    end
  end

  # --- Incremental operations --------------------------------------------------

  @doc """
  Apply record operations to a tree, touching only the paths they reach.

  `root` is the current MST root, or `nil` for a repository that has none yet.
  `source` supplies the existing blocks — see `t:Exosphere.ATProto.MST.Blocks.source/0`:
  a plain `%{CID.t() => bytes}` map, or a `fn cid -> {:ok, bytes} | :error end`
  for a repository too large to hold in one. Only the nodes on the operated
  paths are read.

  Operations are `{:put, path, %CID{}}` (create or overwrite) and
  `{:delete, path}`, applied in order.

  Returns `{:ok, root_cid, blocks}`, where `blocks` holds **only the nodes this
  call produced**. Nothing is written anywhere — persist them yourself, however
  your storage works. That set is what a `#commit` firehose message needs for
  its own changes; add `covering_proof/4` for the unchanged nodes a consumer
  needs to invert the operations, reading through `overlay/2` so the new nodes
  are visible.

  The result is identical, node for node, to `build/1` over the resulting key
  set — the tree is a function of its keys, so an edited tree and a rebuilt one
  cannot disagree. The difference is cost: this walks the operated paths, where
  `build/1` walks everything.

  ## Examples

      iex> {:ok, cid} = Exosphere.ATProto.CID.create(%{"text" => "hi"})
      iex> {:ok, root, blocks} =
      ...>   Exosphere.ATProto.MST.apply_ops(nil, %{}, [
      ...>     {:put, "app.bsky.feed.post/3jqfcqzm3fx2j", cid}
      ...>   ])
      iex> Exosphere.ATProto.MST.read(root, blocks)
      {:ok, %{"app.bsky.feed.post/3jqfcqzm3fx2j" => cid}}
  """
  @spec apply_ops(CID.t() | nil, Blocks.source(), [op()]) ::
          {:ok, CID.t(), blocks()} | {:error, term()}
  def apply_ops(root, source, ops) when is_list(ops) do
    with {:ok, node} <- root_node(root, source),
         {:ok, node} <- reduce_ops(node, ops, source) do
      {cid, written} = Node.flush(node)
      {:ok, cid, written}
    end
  end

  @typedoc """
  A tree edit: set a path to a record CID, or remove it.
  """
  @type op :: {:put, key(), CID.t()} | {:delete, key()}

  defp root_node(nil, _source), do: {:ok, Node.empty()}
  defp root_node(%CID{} = cid, source), do: Node.load_root(cid, source)
  defp root_node(_, _source), do: {:error, :invalid_root}

  defp reduce_ops(node, ops, source) do
    Enum.reduce_while(ops, {:ok, node}, fn op, {:ok, node} ->
      case apply_op(node, op, source) do
        {:ok, node} -> {:cont, {:ok, node}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp apply_op(node, {:put, key, %CID{} = value}, source) do
    if valid_key?(key) do
      Node.put(node, key, value, depth(key), source)
    else
      {:error, {:invalid_key, key}}
    end
  end

  defp apply_op(node, {:delete, key}, source) when is_binary(key) do
    Node.delete(node, key, depth(key), source)
  end

  defp apply_op(_node, op, _source), do: {:error, {:invalid_op, op}}

  @doc """
  The record CID stored at `key`, or `nil`.

  Walks only the key's path, so this is the read a PDS serves `getRecord`
  from — pair it with `proof/3` when the caller wants to check the answer
  against the signed root rather than trust it.
  """
  @spec fetch(CID.t(), Blocks.source(), key()) :: {:ok, CID.t() | nil} | {:error, term()}
  def fetch(%CID{} = root, source, key) when is_binary(key),
    do: Node.find(root, key, source)

  @doc """
  A block source that reads `new` first and falls back to `source`.

  `apply_ops/3` returns its new nodes rather than writing them, so a caller that
  wants to read the tree it just built — `covering_proof/4` does, since the new
  root's nodes are not in the original source — layers them on top:

      {:ok, root, written} = MST.apply_ops(previous, blocks, ops)
      {:ok, proof} = MST.covering_proof(previous, root, MST.overlay(blocks, written), paths)

  Works for both source shapes: a map is merged, a function is wrapped.
  """
  @spec overlay(Blocks.source(), blocks()) :: Blocks.source()
  def overlay(source, new) when is_map(source) and not is_struct(source) and is_map(new),
    do: Map.merge(source, new)

  def overlay(source, new) when is_function(source, 1) and is_map(new) do
    fn cid ->
      case Map.fetch(new, cid) do
        {:ok, block} -> {:ok, block}
        :error -> source.(cid)
      end
    end
  end

  # --- Proofs ------------------------------------------------------------------

  @doc """
  The blocks proving what the tree says about `keys`.

  For a key that is present this is an inclusion proof — the nodes from the
  root down to the one holding it, which is enough to recompute the root CID
  and see the key's value under it. For a key that is absent it is an exclusion
  proof: the same walk, ending where the key would have been, which shows the
  tree could not have contained it.

  This is what `com.atproto.sync.getRecord` returns alongside a record, and the
  raw material of `covering_proof/4`.

  Returns `{:ok, %{cid => bytes}}`, or `{:error, {:missing_block, cid}}` if the
  store cannot supply a node on the path.
  """
  @spec proof(CID.t(), Blocks.source(), key() | [key()]) :: {:ok, blocks()} | {:error, term()}
  def proof(%CID{} = root, source, key) when is_binary(key), do: proof(root, source, [key])

  def proof(%CID{} = root, source, keys) when is_list(keys) do
    Enum.reduce_while(keys, {:ok, %{}}, fn key, {:ok, acc} ->
      case Node.path(root, key, source) do
        {:ok, cids} ->
          case collect_blocks(cids, source, acc) do
            {:ok, acc} -> {:cont, {:ok, acc}}
            {:error, _} = error -> {:halt, error}
          end

        {:error, _} = error ->
          {:halt, error}
      end
    end)
  end

  @doc """
  The proof blocks a `#commit` firehose message must carry for `keys`.

  A consumer receiving a commit has to be able to run the operations backwards
  and land on the previous MST root (`prevData`) — the "inductive" half of the
  sync spec, which is what lets a commit be verified on its own without the
  consumer holding the repository. That needs more than the nodes the commit
  changed: it needs the unchanged nodes on the operated paths in *both* trees,
  and the paths to the keys immediately either side, because a deletion merges
  the subtrees that sat around the removed entry.

  `previous` may be `nil` for a repository's first commit. The result includes
  the blocks from `apply_ops/3`, so it is the complete `blocks` set for the
  message.

  Round-trip this with `invert/3`, which is the consumer side of the same
  contract.
  """
  @spec covering_proof(CID.t() | nil, CID.t(), Blocks.source(), [key()]) ::
          {:ok, blocks()} | {:error, term()}
  def covering_proof(previous, %CID{} = current, source, keys) when is_list(keys) do
    with {:ok, adjacent} <- adjacent_keys(previous, current, source, keys) do
      wanted = Enum.uniq(keys ++ adjacent)

      Enum.reduce_while([previous, current], {:ok, %{}}, fn
        nil, acc ->
          {:cont, acc}

        root, {:ok, acc} ->
          case proof(root, source, wanted) do
            {:ok, blocks} -> {:cont, {:ok, Map.merge(acc, blocks)}}
            {:error, _} = error -> {:halt, error}
          end
      end)
    end
  end

  # The neighbours of every operated key, in whichever trees exist. Gathered
  # from both roots because a key created in this commit has no neighbours in
  # the old tree, and one deleted has none in the new.
  defp adjacent_keys(previous, current, source, keys) do
    roots = Enum.reject([previous, current], &is_nil/1)

    Enum.reduce_while(roots, {:ok, []}, fn root, {:ok, acc} ->
      Enum.reduce_while(keys, {:ok, acc}, fn key, {:ok, acc} ->
        case Node.neighbor_keys(root, key, source) do
          {:ok, {prev, next}} -> {:cont, {:ok, Enum.reject([prev, next | acc], &is_nil/1)}}
          {:error, _} = error -> {:halt, error}
        end
      end)
      |> case do
        {:ok, acc} -> {:cont, {:ok, acc}}
        error -> {:halt, error}
      end
    end)
  end

  @doc """
  Run a commit's operations backwards to recover the previous MST root.

  This is the consumer half of the inductive firehose: given the commit's new
  root, the proof blocks it carried, and its `ops`, invert each one — a create
  becomes a delete, a delete restores the record it names in `prev`, an update
  goes back to its `prev` — and return the root that results. A consumer
  compares that to the commit's `prevData` (and to the root it last saw) to
  decide whether the message is consistent.

  `ops` are `Exosphere.ATProto.Firehose.Message` operations: maps with
  `:action`, `:path`, `:cid` and `:prev`.

  Returns `{:error, {:missing_block, cid}}` when the proof was not covering
  enough to invert — which is a defect in the *producer*, and worth reporting
  as one.
  """
  @spec invert(CID.t(), Blocks.source(), [map()]) :: {:ok, CID.t()} | {:error, term()}
  def invert(%CID{} = root, source, ops) when is_list(ops) do
    with {:ok, inverse} <- inverse_ops(ops),
         {:ok, previous, _written} <- apply_ops(root, source, inverse) do
      {:ok, previous}
    end
  end

  # Inverting runs the operations backwards, so the list reverses too: two
  # operations touching the same path must undo in the opposite order.
  defp inverse_ops(ops) do
    ops
    |> Enum.reverse()
    |> Enum.reduce_while({:ok, []}, fn op, {:ok, acc} ->
      case inverse_op(op) do
        {:ok, inverted} -> {:cont, {:ok, [inverted | acc]}}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, inverted} -> {:ok, Enum.reverse(inverted)}
      error -> error
    end
  end

  defp inverse_op(%{action: :create, path: path}) when is_binary(path),
    do: {:ok, {:delete, path}}

  defp inverse_op(%{action: action, path: path, prev: %CID{} = prev})
       when action in [:update, :delete] and is_binary(path),
       do: {:ok, {:put, path, prev}}

  defp inverse_op(%{action: action, path: path}) when action in [:update, :delete],
    do: {:error, {:missing_prev, path}}

  defp inverse_op(op), do: {:error, {:invalid_op, op}}

  @doc """
  The blocks reachable from `current` but not from `previous`.

  The nodes a commit actually changed, computed from two roots rather than
  from the edit that produced them — useful to check a producer's `blocks`
  against, or to re-derive a diff after the fact.
  """
  @spec diff(CID.t() | nil, CID.t(), Blocks.source()) :: {:ok, blocks()} | {:error, term()}
  def diff(previous, %CID{} = current, source) do
    with {:ok, old} <- reachable(previous, source),
         {:ok, new} <- reachable(current, source) do
      {:ok, Map.drop(new, Map.keys(old))}
    end
  end

  defp reachable(nil, _source), do: {:ok, %{}}

  defp reachable(%CID{} = root, source), do: reachable([root], source, %{})

  defp reachable([], _source, acc), do: {:ok, acc}

  defp reachable([cid | rest], source, acc) do
    if Map.has_key?(acc, cid) do
      reachable(rest, source, acc)
    else
      with {:ok, block} <- Blocks.fetch(source, cid),
           {:ok, bytes} <- block_bytes(block),
           {:ok, map} <- decode_node_map(cid, block) do
        reachable(node_links(map) ++ rest, source, Map.put(acc, cid, bytes))
      end
    end
  end

  # Subtree links only: an entry's "v" points at a record, which is not part of
  # the tree.
  defp node_links(map) do
    left =
      case Map.get(map, "l") do
        %CID{} = cid -> [cid]
        _ -> []
      end

    trees =
      map
      |> Map.get("e", [])
      |> Enum.flat_map(fn
        %{"t" => %CID{} = cid} -> [cid]
        _ -> []
      end)

    left ++ trees
  end

  defp collect_blocks([], _source, acc), do: {:ok, acc}

  defp collect_blocks([cid | rest], source, acc) do
    if Map.has_key?(acc, cid) do
      collect_blocks(rest, source, acc)
    else
      with {:ok, block} <- Blocks.fetch(source, cid),
           {:ok, bytes} <- block_bytes(block) do
        collect_blocks(rest, source, Map.put(acc, cid, bytes))
      end
    end
  end

  # A store may hold encoded bytes or decoded node maps; proofs are bytes.
  # `Exosphere.ATProto.MST.Blocks.fetch/2` promises one or the other, so there
  # is no third case to handle — a source returning anything else has broken
  # its own contract, and a FunctionClauseError names the culprit better than
  # an error tuple that surfaces three layers up.
  defp block_bytes(block) when is_binary(block), do: {:ok, block}
  defp block_bytes(block) when is_map(block), do: DagCBOR.encode(block)

  defp decode_node_map(_cid, block) when is_map(block), do: {:ok, block}

  defp decode_node_map(cid, bytes) when is_binary(bytes) do
    case DagCBOR.decode(bytes) do
      {:ok, map} when is_map(map) -> {:ok, map}
      _ -> {:error, {:invalid_node, cid}}
    end
  end

  # --- Build internals ---------------------------------------------------------

  defp top_layer(triples) do
    triples |> Enum.map(fn {_k, depth, _v} -> depth end) |> Enum.max()
  end

  # Build the node covering `triples` ({key, depth, value}, sorted by key) at
  # `layer`: its entries are the keys with depth == layer, with the gaps between
  # them (and before the first) as subtrees at `layer - 1`. When no key sits at
  # this layer the node is an *empty shell* (`e: []`, only a left link) — the
  # reference tree keeps these shells so that every subtree link descends
  # exactly one layer. Depths are precomputed once by normalize/1.
  defp build_layer(triples, layer, blocks) do
    {left, segments} = split_segments(triples, layer)
    {l_cid, blocks} = subtree(left, layer, blocks)

    {entries, blocks} =
      Enum.reduce(segments, {[], blocks}, fn {{key, _depth, value}, between}, {acc, blocks} ->
        {t_cid, blocks} = subtree(between, layer, blocks)
        {[%{key: key, value: value, tree: t_cid} | acc], blocks}
      end)

    store(node(l_cid, Enum.reverse(entries)), blocks)
  end

  defp subtree([], _layer, blocks), do: {nil, blocks}
  defp subtree(triples, layer, blocks), do: build_layer(triples, layer - 1, blocks)

  # Split sorted `triples` around the leaves whose depth == layer:
  # {triples_before_first_leaf, [{leaf, triples_between_it_and_next_leaf}, ...]}.
  # When no key sits at this layer, all triples land in `left` and the segments
  # list is empty (the node becomes a shell).
  defp split_segments(triples, layer) do
    {left, rest} = Enum.split_while(triples, fn {_k, depth, _v} -> depth != layer end)

    case rest do
      [] -> {left, []}
      [leaf | tail] -> {left, segments(leaf, tail, layer, [])}
    end
  end

  defp segments(leaf, rest, layer, acc) do
    {between, rest} = Enum.split_while(rest, fn {_k, depth, _v} -> depth != layer end)

    case rest do
      [] -> Enum.reverse([{leaf, between} | acc])
      [next | tail] -> segments(next, tail, layer, [{leaf, between} | acc])
    end
  end

  defp empty_node, do: Node.to_map(Node.empty())

  # Build a node map with prefix-compressed entries. Shared with the
  # incremental path (`Exosphere.ATProto.MST.Node.flush/2`) so a rebuilt tree
  # and an edited one encode identically — the property the whole design rests
  # on, and what `apply_ops/3`'s tests check against `build/1`.
  defp node(l_cid, entries) do
    Node.to_map(%Node{layer: 0, left: l_cid, entries: entries})
  end

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
