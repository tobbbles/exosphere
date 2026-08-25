defmodule Exosphere.ATProto.MSTTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.{CBOR, CID, MST}

  # The fixed value CID used by the atproto MST interop test vectors.
  @value "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454"

  defp value, do: CID.decode!(@value)
  defp entries(keys), do: Enum.map(keys, &{&1, value()})

  describe "depth/1" do
    test "matches the reference layer algorithm" do
      # "Single Layer 2 Tree" key in the interop vectors sits at layer 2.
      assert MST.depth("com.example.record/3jqfcqzm3fx2j") == 2
      # "Trivial tree" key sits at layer 0.
      assert MST.depth("com.example.record/3jqfcqzm3fo2j") == 0
    end
  end

  describe "valid_key?/1" do
    test "accepts collection/rkey paths" do
      assert MST.valid_key?("com.example.record/3jqfcqzm3fo2j")
      assert MST.valid_key?("app.bsky.feed.post/self")
    end

    test "rejects malformed keys" do
      refute MST.valid_key?("noslash")
      refute MST.valid_key?("too/many/slashes")
      refute MST.valid_key?("/rkey")
      refute MST.valid_key?("collection/")
      refute MST.valid_key?("coll/bad rkey")
      refute MST.valid_key?("coll/rkey")
      refute MST.valid_key?("com.example.record/..")
      refute MST.valid_key?(String.duplicate("a", 600) <> "/" <> String.duplicate("b", 600))
      refute MST.valid_key?(nil)
    end
  end

  # These root CIDs are the canonical atproto interop fixtures. Matching them
  # byte-for-byte proves the depth algorithm, tree shape, prefix compression,
  # and DAG-CBOR node serialization are all spec-correct.
  describe "build/1 matches atproto golden root CIDs" do
    test "empty tree" do
      assert {:ok, root, _} = MST.build([])
      assert to_string(root) == "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"
    end

    test "single entry (trivial tree)" do
      assert {:ok, root, _} = MST.build(entries(["com.example.record/3jqfcqzm3fo2j"]))
      assert to_string(root) == "bafyreibj4lsc3aqnrvphp5xmrnfoorvru4wynt6lwidqbm2623a6tatzdu"
    end

    test "single layer-2 entry" do
      assert {:ok, root, _} = MST.build(entries(["com.example.record/3jqfcqzm3fx2j"]))
      assert to_string(root) == "bafyreih7wfei65pxzhauoibu3ls7jgmkju4bspy4t2ha2qdjnzqvoy33ai"
    end

    test "simple five-entry tree" do
      keys = [
        "com.example.record/3jqfcqzm3fp2j",
        "com.example.record/3jqfcqzm3fr2j",
        "com.example.record/3jqfcqzm3fs2j",
        "com.example.record/3jqfcqzm3ft2j",
        "com.example.record/3jqfcqzm4fc2j"
      ]

      assert {:ok, root, _} = MST.build(entries(keys))
      assert to_string(root) == "bafyreicmahysq4n6wfuxo522m6dpiy7z7qzym3dzs756t5n7nfdgccwq7m"
    end
  end

  describe "build/1 determinism" do
    test "root is independent of input order" do
      keys =
        for n <- 1..50, do: "com.example.record/key#{String.pad_leading("#{n}", 3, "0")}"

      {:ok, root_a, _} = MST.build(entries(keys))
      {:ok, root_b, _} = MST.build(entries(Enum.shuffle(keys)))
      assert root_a == root_b
    end

    test "accepts a map as input" do
      map = Map.new(entries(["com.example.record/aaa", "com.example.record/bbb"]))
      assert {:ok, _root, _} = MST.build(map)
    end
  end

  describe "build/1 input validation" do
    test "rejects invalid keys and values" do
      assert {:error, {:invalid_key, "noslash"}} = MST.build([{"noslash", value()}])

      assert {:error, {:invalid_value, "com.example.record/aaa"}} =
               MST.build([{"com.example.record/aaa", "not-a-cid"}])
    end

    test "rejects duplicate keys with conflicting values" do
      other = CID.decode!("bafyreih7wfei65pxzhauoibu3ls7jgmkju4bspy4t2ha2qdjnzqvoy33ai")

      assert {:error, {:duplicate_key, "com.example.record/aaa"}} =
               MST.build([{"com.example.record/aaa", value()}, {"com.example.record/aaa", other}])
    end

    test "dedupes identical duplicate entries" do
      assert {:ok, root, _} = MST.build(entries(["com.example.record/aaa"]))

      assert {:ok, ^root, _} =
               MST.build(List.duplicate({"com.example.record/aaa", value()}, 3))
    end

    test "rejects non-pair elements" do
      assert {:error, {:invalid_entry, :foo}} = MST.build([:foo])
    end
  end

  describe "read/2" do
    setup do
      keys = for n <- 1..40, do: "com.example.record/key#{String.pad_leading("#{n}", 3, "0")}"
      {:ok, root, blocks} = MST.build(entries(keys))
      %{keys: keys, root: root, blocks: blocks}
    end

    test "round-trips from encoded-bytes blocks", %{keys: keys, root: root, blocks: blocks} do
      assert {:ok, map} = MST.read(root, blocks)
      assert Enum.sort(Map.keys(map)) == Enum.sort(keys)
      assert Enum.all?(map, fn {_k, v} -> v == value() end)
    end

    test "reads from decoded (CAR-style) blocks", %{root: root, blocks: blocks} do
      decoded = Map.new(blocks, fn {cid, bytes} -> {cid, CBOR.decode!(bytes)} end)
      assert {:ok, map} = MST.read(root, decoded)
      assert {:ok, ^map} = MST.read(root, blocks)
    end

    test "reports a missing block", %{root: root, blocks: blocks} do
      [some | _] = Map.keys(blocks)
      assert {:error, {:missing_block, %CID{}}} = MST.read(root, Map.delete(blocks, some))
    end

    test "rejects cyclic block data instead of recursing forever", %{root: root, blocks: blocks} do
      decoded = Map.new(blocks, fn {cid, bytes} -> {cid, CBOR.decode!(bytes)} end)
      cyclic = Map.put(decoded, root, Map.put(decoded[root], "l", root))
      assert {:error, {:cycle, ^root}} = MST.read(root, cyclic)
    end

    test "empty tree reads back as an empty map" do
      {:ok, root, blocks} = MST.build([])
      assert {:ok, map} = MST.read(root, blocks)
      assert map == %{}
    end
  end
end
