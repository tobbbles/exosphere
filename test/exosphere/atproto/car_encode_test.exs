defmodule Exosphere.ATProto.CAREncodeTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.{CAR, CBOR, CID, MST}
  alias Exosphere.ATProto.MST.Store

  defp term(n), do: %{"n" => n, "text" => "block #{n}"}
  defp block(n), do: {CID.create!(term(n)), CBOR.encode!(term(n))}

  describe "encode/3" do
    test "round-trips through decode_full/1" do
      blocks = Enum.map(1..10, &block/1)
      {root, _} = hd(blocks)

      assert {:ok, car} = CAR.encode(root, blocks)
      assert {:ok, %{roots: [^root], blocks: decoded}} = CAR.decode_full(car)

      assert map_size(decoded) == 10

      for {cid, _bytes} <- blocks do
        assert decoded[cid] != nil
      end
    end

    test "encodes decoded terms as well as raw bytes" do
      cid = CID.create!(%{"hello" => "world"})

      # A binary value is written verbatim; anything else is DAG-CBOR encoded.
      assert {:ok, from_term} = CAR.encode(cid, %{cid => %{"hello" => "world"}})
      assert {:ok, from_bytes} = CAR.encode(cid, %{cid => CBOR.encode!(%{"hello" => "world"})})

      assert from_term == from_bytes
      assert {:ok, %{blocks: %{^cid => %{"hello" => "world"}}}} = CAR.decode_full(from_term)
    end

    test "accepts multiple roots" do
      [{a, _} = one, {b, _} = two] = Enum.map(1..2, &block/1)

      assert {:ok, car} = CAR.encode([a, b], [one, two])
      assert {:ok, %{roots: [^a, ^b]}} = CAR.decode_full(car)
    end

    test "writes list blocks in the order given" do
      blocks = Enum.map(1..5, &block/1)
      {root, _} = hd(blocks)

      {:ok, forwards} = CAR.encode(root, blocks)
      {:ok, backwards} = CAR.encode(root, Enum.reverse(blocks))

      # Same blocks, different bytes: order is the caller's to choose, which is
      # what lets a producer emit the commit first and the MST in pre-order.
      refute forwards == backwards

      assert {:ok, %{blocks: a}} = CAR.decode_full(forwards)
      assert {:ok, %{blocks: b}} = CAR.decode_full(backwards)
      assert a == b
    end

    test "a map serializes deterministically regardless of insertion order" do
      blocks = Enum.map(1..20, &block/1)
      {root, _} = hd(blocks)

      {:ok, one} = CAR.encode(root, Map.new(blocks))
      {:ok, two} = CAR.encode(root, Map.new(Enum.shuffle(blocks)))

      assert one == two
    end

    test "verify: true catches a block filed under the wrong CID" do
      {cid, bytes} = block(1)
      {other, _} = block(2)

      assert {:ok, _} = CAR.encode(cid, [{cid, bytes}], verify: true)
      assert {:error, {:cid_mismatch, ^other}} = CAR.encode(cid, [{other, bytes}], verify: true)

      # Off by default: a serving path has just computed those CIDs itself.
      assert {:ok, _} = CAR.encode(cid, [{other, bytes}])
    end

    test "rejects malformed roots and blocks" do
      {cid, bytes} = block(1)

      assert {:error, :invalid_roots} = CAR.encode("not-a-cid", [{cid, bytes}])
      assert {:error, :invalid_roots} = CAR.encode([cid, "not-a-cid"], [{cid, bytes}])
      assert {:error, {:invalid_block, _}} = CAR.encode(cid, [:nonsense])
    end

    test "encode!/3 raises on error" do
      {cid, bytes} = block(1)

      assert_raise ArgumentError, ~r/CAR encoding failed/, fn ->
        CAR.encode!("not-a-cid", [{cid, bytes}])
      end
    end
  end

  describe "encode_iodata/3" do
    test "is the same bytes without the final flatten" do
      blocks = Enum.map(1..8, &block/1)
      {root, _} = hd(blocks)

      assert {:ok, iodata} = CAR.encode_iodata(root, blocks)
      assert {:ok, binary} = CAR.encode(root, blocks)

      assert IO.iodata_to_binary(iodata) == binary
      # Deeply nested and unflattened — which is the point, for a large export.
      assert is_list(iodata)
    end
  end

  describe "a full repository archive" do
    test "serializes and verifies as a repository CAR" do
      records = for i <- 1..25, into: %{}, do: {"app.bsky.feed.post/3jqfcqzm3fx#{i}", term(i)}

      record_blocks =
        Map.new(records, fn {_path, record} -> {CID.create!(record), record} end)

      entries = Map.new(records, fn {path, record} -> {path, CID.create!(record)} end)

      {:ok, root, nodes, _store} = build_tree(entries)

      commit = %{
        "did" => "did:plc:44ybard66vv44zksje25o7dz",
        "version" => 3,
        "data" => root,
        "rev" => "3lbqmqtqhpk2a",
        "prev" => nil
      }

      commit_cid = CID.create!(commit)

      # Commit first, then MST nodes, then records: the order the spec prefers.
      {:ok, car} =
        CAR.encode(
          commit_cid,
          [{commit_cid, commit}] ++ Enum.to_list(nodes) ++ Enum.to_list(record_blocks),
          verify: true
        )

      assert {:ok, ^entries} = MST.from_repo_car(car)
    end
  end

  defp build_tree(entries) do
    ops = Enum.map(entries, fn {path, cid} -> {:put, path, cid} end)

    with {:ok, root, store, written} <- MST.apply_ops(nil, Store.new(), ops) do
      {:ok, root, written, store}
    end
  end
end
