defmodule Exosphere.ATProto.MST.ProofTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.{CID, MST}
  alias Exosphere.ATProto.MST.Store

  defp path(i), do: "app.bsky.feed.post/3jqfcqzm3f" <> String.pad_leading("#{i}", 3, "0")
  defp value(n), do: CID.create!(%{"n" => n})

  setup do
    ops = for i <- 1..60, do: {:put, path(i), value(i)}
    {:ok, root, store, _} = MST.apply_ops(nil, Store.new(), ops)
    {:ok, root: root, store: store}
  end

  describe "proof/3" do
    test "an inclusion proof reconstructs the key's value", %{root: root, store: store} do
      assert {:ok, blocks} = MST.proof(root, store, path(23))

      # The proof stands on its own: read the key back with nothing but the
      # proof blocks, and the root CID we were told to trust.
      assert {:ok, cid} = MST.fetch(root, blocks, path(23))
      assert cid == value(23)
    end

    test "an exclusion proof shows the key is absent", %{root: root, store: store} do
      assert {:ok, blocks} = MST.proof(root, store, path(999))
      assert {:ok, nil} = MST.fetch(root, blocks, path(999))
    end

    test "a proof is a fraction of the tree", %{root: root, store: store} do
      assert {:ok, blocks} = MST.proof(root, store, path(23))

      assert map_size(blocks) < map_size(store),
             "proof carried #{map_size(blocks)} of #{map_size(store)} nodes"
    end

    test "the root is always in the proof", %{root: root, store: store} do
      assert {:ok, blocks} = MST.proof(root, store, path(1))
      assert Map.has_key?(blocks, root)
    end

    test "several keys share their overlapping paths", %{root: root, store: store} do
      keys = Enum.map([3, 17, 42], &path/1)

      assert {:ok, blocks} = MST.proof(root, store, keys)

      for key <- keys do
        assert {:ok, %CID{}} = MST.fetch(root, blocks, key)
      end

      {:ok, singles} =
        Enum.reduce(keys, {:ok, %{}}, fn key, {:ok, acc} ->
          {:ok, one} = MST.proof(root, store, key)
          {:ok, Map.merge(acc, one)}
        end)

      assert blocks == singles
    end

    test "reports a block the store cannot supply", %{root: root, store: store} do
      {:ok, full} = MST.proof(root, store, path(23))
      # Drop everything below the root: the walk cannot get past it.
      partial = Map.take(full, [root])

      case MST.proof(root, partial, path(23)) do
        {:ok, ^partial} -> :ok
        {:error, {:missing_block, %CID{}}} -> :ok
        other -> flunk("expected a missing-block failure, got #{inspect(other)}")
      end
    end
  end

  describe "covering_proof/4" do
    test "carries enough to invert a create", %{root: root, store: store} do
      key = path(100)
      {:ok, next, store, _} = MST.apply_ops(root, store, [{:put, key, value(100)}])

      assert {:ok, blocks} = MST.covering_proof(root, next, store, [key])

      assert {:ok, ^root} =
               MST.invert(next, blocks, [%{action: :create, path: key, cid: value(100)}])
    end

    test "carries enough to invert a delete", %{root: root, store: store} do
      key = path(30)
      {:ok, next, store, _} = MST.apply_ops(root, store, [{:delete, key}])

      assert {:ok, blocks} = MST.covering_proof(root, next, store, [key])

      assert {:ok, ^root} =
               MST.invert(next, blocks, [
                 %{action: :delete, path: key, cid: nil, prev: value(30)}
               ])
    end

    test "carries enough to invert an update", %{root: root, store: store} do
      key = path(30)
      {:ok, next, store, _} = MST.apply_ops(root, store, [{:put, key, value(3000)}])

      assert {:ok, blocks} = MST.covering_proof(root, next, store, [key])

      assert {:ok, ^root} =
               MST.invert(next, blocks, [
                 %{action: :update, path: key, cid: value(3000), prev: value(30)}
               ])
    end

    test "includes the blocks the edit wrote", %{root: root, store: store} do
      key = path(100)
      {:ok, next, store, written} = MST.apply_ops(root, store, [{:put, key, value(100)}])

      {:ok, blocks} = MST.covering_proof(root, next, store, [key])

      for cid <- Map.keys(written) do
        assert Map.has_key?(blocks, cid), "covering proof is missing a node the edit wrote"
      end
    end

    test "handles a repository's first commit, where there is no previous tree" do
      key = path(1)

      {:ok, root, store, _} = MST.apply_ops(nil, Store.new(), [{:put, key, value(1)}])
      {:ok, empty, _} = MST.build([])

      assert {:ok, blocks} = MST.covering_proof(nil, root, store, [key])

      assert {:ok, ^empty} =
               MST.invert(root, blocks, [%{action: :create, path: key, cid: value(1)}])
    end
  end

  describe "invert/3" do
    test "undoes a batch in reverse order", %{root: root, store: store} do
      keys = Enum.map([5, 6, 7], &path/1)

      ops = [
        %{action: :delete, path: path(5), cid: nil, prev: value(5)},
        %{action: :update, path: path(6), cid: value(600), prev: value(6)},
        %{action: :create, path: path(200), cid: value(200)}
      ]

      {:ok, next, store, _} =
        MST.apply_ops(root, store, [
          {:delete, path(5)},
          {:put, path(6), value(600)},
          {:put, path(200), value(200)}
        ])

      {:ok, blocks} = MST.covering_proof(root, next, store, keys ++ [path(200)])

      assert {:ok, ^root} = MST.invert(next, blocks, ops)
    end

    test "refuses an update or delete with no prev to restore", %{root: root, store: store} do
      {:ok, blocks} = MST.proof(root, store, path(5))

      assert {:error, {:missing_prev, _}} =
               MST.invert(root, blocks, [%{action: :delete, path: path(5), cid: nil}])
    end

    test "rejects an operation it does not understand", %{root: root, store: store} do
      {:ok, blocks} = MST.proof(root, store, path(5))

      assert {:error, {:invalid_op, _}} =
               MST.invert(root, blocks, [%{action: :rebase, path: path(5)}])
    end
  end
end
