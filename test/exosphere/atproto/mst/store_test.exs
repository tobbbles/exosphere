defmodule Exosphere.ATProto.MST.StoreTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.CID
  alias Exosphere.ATProto.MST.Store
  alias Exosphere.ATProto.MST.Store.ETS

  defp block(term), do: {CID.create!(term), Exosphere.ATProto.CBOR.encode!(term)}

  describe "map store" do
    test "round-trips blocks" do
      {cid, bytes} = block(%{"a" => 1})
      store = Store.put(Store.new(), cid, bytes)

      assert Store.member?(store, cid)
      assert {:ok, ^bytes} = Store.fetch(store, cid)
    end

    test "a miss reports the CID it wanted" do
      {cid, _bytes} = block(%{"a" => 1})

      assert {:error, {:missing_block, ^cid}} = Store.fetch(Store.new(), cid)
      refute Store.member?(Store.new(), cid)
    end

    test "put_all/2 takes an enumerable of pairs" do
      blocks = Enum.map(1..5, &block(%{"n" => &1}))
      store = Store.put_all(Store.new(), blocks)

      for {cid, bytes} <- blocks do
        assert {:ok, ^bytes} = Store.fetch(store, cid)
      end
    end

    test "accepts decoded node maps, not just bytes" do
      # `CAR.decode/1` hands back decoded values; the tree reads those directly.
      cid = CID.create!(%{"l" => nil, "e" => []})
      store = %{cid => %{"l" => nil, "e" => []}}

      assert {:ok, %{"e" => []}} = Store.fetch(store, cid)
    end
  end

  describe "ETS store" do
    setup do
      # Owned by the test process, so it goes away with it.
      {:ok, store: ETS.new()}
    end

    test "round-trips blocks", %{store: store} do
      {cid, bytes} = block(%{"a" => 1})
      store = Store.put(store, cid, bytes)

      assert Store.member?(store, cid)
      assert {:ok, ^bytes} = Store.fetch(store, cid)
      assert ETS.size(store) == 1
    end

    test "a miss reports the CID it wanted", %{store: store} do
      {cid, _bytes} = block(%{"a" => 1})
      assert {:error, {:missing_block, ^cid}} = Store.fetch(store, cid)
    end

    test "writes are visible through every reference to the table", %{store: store} do
      # The table is shared and mutable — that is the point, and it is the one
      # way an ETS store differs from a map store, so it is worth pinning.
      {cid, bytes} = block(%{"a" => 1})
      other = ETS.wrap(store.table)

      Store.put(store, cid, bytes)

      assert {:ok, ^bytes} = Store.fetch(other, cid)
    end

    test "snapshot/1 freezes the blocks into a plain map", %{store: store} do
      blocks = Enum.map(1..3, &block(%{"n" => &1}))
      store = Store.put_all(store, blocks)

      snapshot = ETS.snapshot(store)

      assert map_size(snapshot) == 3
      assert snapshot == Map.new(blocks)

      # A snapshot is a value: later writes do not reach it.
      {cid, bytes} = block(%{"n" => 99})
      Store.put(store, cid, bytes)

      assert map_size(snapshot) == 3
    end

    test "a store that is not one raises rather than silently misbehaving" do
      assert_raise ArgumentError, ~r/does not implement/, fn ->
        Store.fetch(%URI{}, CID.create!(%{"a" => 1}))
      end
    end
  end
end
