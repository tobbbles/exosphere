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
  alias Exosphere.ATProto.MST.Store
  alias Exosphere.ATProto.MST.Store.ETS

  defp path(i), do: "app.bsky.feed.post/3jqfcqzm3f" <> String.pad_leading("#{i}", 3, "0")
  defp value(n), do: CID.create!(%{"n" => n})

  defp apply_model(model, {:put, key, value}), do: Map.put(model, key, value)
  defp apply_model(model, {:delete, key}), do: Map.delete(model, key)

  # Replay `ops` through both paths and insist they agree at every step.
  defp replay(ops) do
    Enum.reduce(ops, {nil, Store.new(), %{}}, fn op, {root, store, model} ->
      {:ok, new_root, store, _written} = MST.apply_ops(root, store, [op])
      model = apply_model(model, op)

      {:ok, rebuilt, _blocks} = MST.build(model)

      assert new_root == rebuilt,
             "after #{inspect(op)} with #{map_size(model)} keys: " <>
               "incremental #{new_root} != rebuild #{rebuilt}"

      assert {:ok, ^model} = MST.read(new_root, store)

      {new_root, store, model}
    end)
  end

  describe "apply_ops/3" do
    test "builds a tree from nothing" do
      cid = value(1)

      assert {:ok, root, store, written} =
               MST.apply_ops(nil, Store.new(), [{:put, path(1), cid}])

      assert {:ok, %{"app.bsky.feed.post/3jqfcqzm3f001" => ^cid}} = MST.read(root, store)
      assert Map.has_key?(written, root)
    end

    test "returns only the blocks it wrote" do
      ops = for i <- 1..40, do: {:put, path(i), value(i)}
      {:ok, root, store, _} = MST.apply_ops(nil, Store.new(), ops)

      before = map_size(store)

      {:ok, _new_root, store, written} =
        MST.apply_ops(root, store, [{:put, path(41), value(41)}])

      # A one-key edit rewrites only the nodes on that key's path, not the tree.
      assert map_size(written) < before,
             "a single insert rewrote #{map_size(written)} of #{before} nodes"

      assert Enum.all?(Map.keys(written), &Map.has_key?(store, &1))
    end

    test "an update replaces the value and leaves the shape alone" do
      ops = for i <- 1..20, do: {:put, path(i), value(i)}
      {:ok, root, store, _} = MST.apply_ops(nil, Store.new(), ops)

      {:ok, updated, store, _} = MST.apply_ops(root, store, [{:put, path(7), value(777)}])

      assert {:ok, records} = MST.read(updated, store)
      assert records[path(7)] == value(777)
      assert map_size(records) == 20
    end

    test "deleting every key returns the canonical empty root" do
      keys = for i <- 1..30, do: path(i)
      {:ok, empty, _} = MST.build([])

      {:ok, root, store, _} =
        MST.apply_ops(nil, Store.new(), for(k <- keys, do: {:put, k, value(1)}))

      assert {:ok, ^empty, _store, _} =
               MST.apply_ops(root, store, for(k <- keys, do: {:delete, k}))
    end

    test "a batch of operations applies in order" do
      # The same path created then deleted in one commit nets out to nothing.
      assert {:ok, root, store, _} =
               MST.apply_ops(nil, Store.new(), [
                 {:put, path(1), value(1)},
                 {:put, path(2), value(2)},
                 {:delete, path(1)}
               ])

      assert {:ok, records} = MST.read(root, store)
      assert Map.keys(records) == [path(2)]
    end

    test "rejects an invalid key and a missing one" do
      assert {:error, {:invalid_key, "no-slash"}} =
               MST.apply_ops(nil, Store.new(), [{:put, "no-slash", value(1)}])

      {:ok, root, store, _} = MST.apply_ops(nil, Store.new(), [{:put, path(1), value(1)}])

      assert {:error, {:key_not_found, _}} =
               MST.apply_ops(root, store, [{:delete, path(9)}])
    end

    test "works against an ETS store" do
      # The table is owned by this process and dies with it, so there is
      # nothing to clean up.
      store = ETS.new()

      ops = for i <- 1..50, do: {:put, path(i), value(i)}
      assert {:ok, root, store, _} = MST.apply_ops(nil, store, ops)

      {:ok, rebuilt, _} = MST.build(for i <- 1..50, into: %{}, do: {path(i), value(i)})
      assert root == rebuilt

      assert {:ok, records} = MST.read(root, ETS.snapshot(store))
      assert map_size(records) == 50
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

      {_root, _store, model} = replay(ops)
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
      ops = for i <- 1..50, do: {:put, path(i), value(i)}
      {:ok, root, store, _} = MST.apply_ops(nil, Store.new(), ops)
      {:ok, root: root, store: store}
    end

    test "finds a key's value", %{root: root, store: store} do
      assert {:ok, cid} = MST.fetch(root, store, path(17))
      assert cid == value(17)
    end

    test "returns nil for a key the tree does not hold", %{root: root, store: store} do
      assert {:ok, nil} = MST.fetch(root, store, path(99))
    end
  end

  describe "diff/3" do
    test "is the blocks reachable from one root and not the other" do
      {:ok, root, store, _} =
        MST.apply_ops(nil, Store.new(), for(i <- 1..30, do: {:put, path(i), value(i)}))

      {:ok, next, store, written} = MST.apply_ops(root, store, [{:put, path(31), value(31)}])

      assert {:ok, diff} = MST.diff(root, next, store)

      # The nodes the edit rewrote are exactly the nodes new to the tree.
      assert Map.keys(diff) |> Enum.sort() == Map.keys(written) |> Enum.sort()
    end

    test "from nothing is the whole tree" do
      {:ok, root, store, written} =
        MST.apply_ops(nil, Store.new(), for(i <- 1..20, do: {:put, path(i), value(i)}))

      assert {:ok, diff} = MST.diff(nil, root, store)
      assert map_size(diff) == map_size(written)
    end
  end
end
