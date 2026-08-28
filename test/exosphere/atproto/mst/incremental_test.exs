defmodule Exosphere.ATProto.MST.IncrementalTest do
  @moduledoc """
  The incremental tree against the from-scratch one.

  An MST is a pure function of its key set, so `apply_ops/3` and `build/1` must
  agree on the root CID for the same keys — always, and node for node, not just
  "close enough". That single invariant is what these tests lean on: a
  splitting, merging or pruning bug in the node algebra shows up as a different
  root CID, and there is nowhere for it to hide.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Exosphere.ATProto.{CID, MST}

  defp path(i), do: "app.bsky.feed.post/3jqfcqzm3f" <> String.pad_leading("#{i}", 3, "0")
  defp value(n), do: CID.create!(%{"n" => n})

  defp apply_model(model, {:put, key, value}), do: Map.put(model, key, value)
  defp apply_model(model, {:delete, key}), do: Map.delete(model, key)

  # Replay `ops` through both paths and insist they agree at every step. New
  # blocks are merged in by hand, which is the whole contract: `apply_ops/3`
  # hands them back rather than writing anywhere.
  defp replay(ops) do
    Enum.reduce(ops, {nil, %{}, %{}}, fn op, {root, blocks, model} ->
      {:ok, new_root, written} = MST.apply_ops(root, blocks, [op])
      blocks = Map.merge(blocks, written)
      model = apply_model(model, op)

      {:ok, rebuilt, _blocks} = MST.build(model)

      assert new_root == rebuilt,
             "after #{inspect(op)} with #{map_size(model)} keys: " <>
               "incremental #{new_root} != rebuild #{rebuilt}"

      assert {:ok, ^model} = MST.read(new_root, blocks)

      {new_root, blocks, model}
    end)
  end

  # Build a tree from scratch through the incremental path.
  defp seed(keys) do
    ops = Enum.map(keys, &{:put, path(&1), value(&1)})
    {:ok, root, blocks} = MST.apply_ops(nil, %{}, ops)
    {root, blocks}
  end

  describe "apply_ops/3" do
    test "builds a tree from nothing" do
      cid = value(1)

      assert {:ok, root, blocks} = MST.apply_ops(nil, %{}, [{:put, path(1), cid}])

      assert {:ok, %{"app.bsky.feed.post/3jqfcqzm3f001" => ^cid}} = MST.read(root, blocks)
      assert Map.has_key?(blocks, root)
    end

    test "returns only the blocks it produced, and writes nothing" do
      {root, blocks} = seed(1..40)
      before = map_size(blocks)

      assert {:ok, _new_root, written} =
               MST.apply_ops(root, blocks, [{:put, path(41), value(41)}])

      # A one-key edit rewrites only the nodes on that key's path, not the tree.
      assert map_size(written) < before,
             "a single insert rewrote #{map_size(written)} of #{before} nodes"

      # The source map is untouched: nothing was written anywhere.
      assert map_size(blocks) == before
      assert map_size(written) > 0

      # Most of what came back is genuinely new. (Not all of it need be: nodes
      # are content-addressed, so a re-encoded node can hash to one that
      # already exists.)
      fresh = Enum.count(Map.keys(written), &(not Map.has_key?(blocks, &1)))
      assert fresh > 0
    end

    test "an update replaces the value and leaves the shape alone" do
      {root, blocks} = seed(1..20)

      {:ok, updated, written} = MST.apply_ops(root, blocks, [{:put, path(7), value(777)}])

      assert {:ok, records} = MST.read(updated, Map.merge(blocks, written))
      assert records[path(7)] == value(777)
      assert map_size(records) == 20
    end

    test "deleting every key returns the canonical empty root" do
      {root, blocks} = seed(1..30)
      {:ok, empty, _} = MST.build([])

      deletes = for i <- 1..30, do: {:delete, path(i)}
      assert {:ok, ^empty, _written} = MST.apply_ops(root, blocks, deletes)
    end

    test "a batch of operations applies in order" do
      # The same path created then deleted in one commit nets out to nothing.
      assert {:ok, root, blocks} =
               MST.apply_ops(nil, %{}, [
                 {:put, path(1), value(1)},
                 {:put, path(2), value(2)},
                 {:delete, path(1)}
               ])

      assert {:ok, records} = MST.read(root, blocks)
      assert Map.keys(records) == [path(2)]
    end

    test "rejects an invalid key and a missing one" do
      assert {:error, {:invalid_key, "no-slash"}} =
               MST.apply_ops(nil, %{}, [{:put, "no-slash", value(1)}])

      {root, blocks} = seed(1..1)

      assert {:error, {:key_not_found, _}} = MST.apply_ops(root, blocks, [{:delete, path(9)}])
    end

    test "reads through a function source, not just a map" do
      {root, blocks} = seed(1..50)

      # A repository too large to materialize hands over a lookup instead. Only
      # the nodes on the operated path are ever asked for, which is the point.
      asked = :counters.new(1, [])

      lookup = fn cid ->
        :counters.add(asked, 1, 1)
        Map.fetch(blocks, cid)
      end

      assert {:ok, root2, written} = MST.apply_ops(root, lookup, [{:put, path(51), value(51)}])

      {:ok, rebuilt, _} = MST.build(for i <- 1..51, into: %{}, do: {path(i), value(i)})
      assert root2 == rebuilt

      reads = :counters.get(asked, 1)
      assert reads > 0

      assert reads < map_size(blocks),
             "read #{reads} of #{map_size(blocks)} nodes for a one-key insert"

      assert {:ok, _} = MST.read(root2, Map.merge(blocks, written))
    end
  end

  describe "overlay/2" do
    test "layers new blocks over a map source" do
      {root, blocks} = seed(1..20)
      {:ok, next, written} = MST.apply_ops(root, blocks, [{:put, path(21), value(21)}])

      # The new root is unreadable from the original source alone.
      assert {:error, {:missing_block, _}} = MST.read(next, blocks)
      assert {:ok, records} = MST.read(next, MST.overlay(blocks, written))
      assert map_size(records) == 21
    end

    test "layers new blocks over a function source" do
      {root, blocks} = seed(1..20)
      lookup = &Map.fetch(blocks, &1)

      {:ok, next, written} = MST.apply_ops(root, lookup, [{:put, path(21), value(21)}])

      overlaid = MST.overlay(lookup, written)
      assert is_function(overlaid, 1)
      assert {:ok, %CID{}} = MST.fetch(next, overlaid, path(21))
      assert {:ok, proof} = MST.proof(next, overlaid, path(21))
      assert map_size(proof) > 0
    end
  end

  describe "apply_ops/3 against build/1" do
    test "a fixed sequence of inserts and deletes agrees at every step" do
      first_deletes = Enum.to_list(1..40//3)
      second_deletes = Enum.to_list(2..40//7) -- first_deletes

      ops =
        Enum.map(1..40, &{:put, path(&1), value(&1)}) ++
          Enum.map(first_deletes, &{:delete, path(&1)}) ++
          Enum.map(41..60, &{:put, path(&1), value(&1)}) ++
          Enum.map(second_deletes, &{:delete, path(&1)})

      {_root, _blocks, model} = replay(ops)
      assert map_size(model) > 0
    end

    property "any sequence of inserts and deletes agrees with a rebuild" do
      check all(
              indexes <- list_of(integer(1..60), min_length: 1, max_length: 60),
              deletes <- list_of(boolean(), length: length(indexes)),
              max_runs: 40
            ) do
        # Deletes are only meaningful for keys already present, so the model is
        # threaded through generation: an op is a delete when the flag says so
        # *and* the key exists.
        {ops, _present} =
          [indexes, deletes]
          |> Enum.zip()
          |> Enum.map_reduce(MapSet.new(), fn {i, delete?}, present ->
            key = path(i)

            if delete? and MapSet.member?(present, key) do
              {{:delete, key}, MapSet.delete(present, key)}
            else
              {{:put, key, value(i)}, MapSet.put(present, key)}
            end
          end)

        replay(ops)
      end
    end
  end

  describe "fetch/3" do
    setup do
      {root, blocks} = seed(1..50)
      {:ok, root: root, blocks: blocks}
    end

    test "finds a key's value", %{root: root, blocks: blocks} do
      assert {:ok, cid} = MST.fetch(root, blocks, path(17))
      assert cid == value(17)
    end

    test "returns nil for a key the tree does not hold", %{root: root, blocks: blocks} do
      assert {:ok, nil} = MST.fetch(root, blocks, path(99))
    end
  end

  describe "diff/3" do
    test "is the blocks reachable from one root and not the other" do
      {root, blocks} = seed(1..30)
      {:ok, next, written} = MST.apply_ops(root, blocks, [{:put, path(31), value(31)}])

      assert {:ok, diff} = MST.diff(root, next, MST.overlay(blocks, written))

      # The nodes the edit produced are exactly the nodes new to the tree.
      assert Enum.sort(Map.keys(diff)) == Enum.sort(Map.keys(written))
    end

    test "from nothing is the whole tree" do
      {root, blocks} = seed(1..20)

      assert {:ok, diff} = MST.diff(nil, root, blocks)
      assert map_size(diff) == map_size(blocks)
    end
  end
end
