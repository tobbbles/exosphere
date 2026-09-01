defmodule Exosphere.ATProto.MSTTest do
  use ExUnit.Case, async: true

  doctest Exosphere.ATProto.MST

  alias Exosphere.ATProto.{CAR, CBOR, CID, MST}
  alias Exosphere.ATProto.TestRepoCar

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

  describe "from_repo_car/1" do
    test "reads a full repository CAR back into the record set" do
      fixture = TestRepoCar.build()

      assert {:ok, records} = MST.from_repo_car(fixture.car)
      assert records == fixture.records
    end

    test "accepts a pre-decoded CAR map" do
      fixture = TestRepoCar.build()
      {:ok, car_map} = CAR.decode_full(fixture.car)

      assert {:ok, records} = MST.from_repo_car(car_map)
      assert records == fixture.records
    end

    test "reports missing blocks for an incomplete (incremental) CAR" do
      fixture = TestRepoCar.build()
      {:ok, car_map} = CAR.decode_full(fixture.car)

      # Drop the MST node blocks, as an incremental firehose CAR would for
      # unchanged subtrees: the tree walk now hits a missing node.
      stripped = Map.drop(car_map.blocks, Map.keys(fixture.node_blocks))

      assert {:error, {:missing_block, _cid}} =
               MST.from_repo_car(%{car_map | blocks: stripped})
    end

    test "errors without a single root" do
      assert {:error, :no_root} = MST.from_repo_car(%{roots: [], blocks: %{}})

      fixture = TestRepoCar.build()
      {:ok, car_map} = CAR.decode_full(fixture.car)

      assert {:error, :multiple_roots} =
               MST.from_repo_car(%{car_map | roots: car_map.roots ++ car_map.roots})
    end
  end

  describe "build/1 canonical tree shape" do
    # Regression test for the canonical (reference-implementation) shape: when
    # a key's depth skips layers, the layers in between are filled with *empty
    # shell* nodes (`e: []`, left link only) so every subtree link descends
    # exactly one layer. Skipping the shells produced different root CIDs from
    # the reference MST for any repo with a layer gap (caught live against a
    # 41k-record repository; the small interop vectors have no gaps).
    test "fills empty layers with shell nodes" do
      # depth 0
      shallow = "com.example.post/key0"
      # depth 3
      deep = "com.example.post/key78"
      assert MST.depth(shallow) == 0
      assert MST.depth(deep) == 3

      assert {:ok, root, blocks} = MST.build(entries([shallow, deep]))

      # Root node: single entry (the depth-3 key), left subtree holds the rest.
      root_node = CBOR.decode!(blocks[root])
      assert [%{"p" => 0, "k" => ^deep, "t" => nil, "v" => %CID{}}] = root_node["e"]
      %CID{} = shell2 = root_node["l"]

      # Two shells (layers 2 and 1), each empty with only a left link.
      shell_node = CBOR.decode!(blocks[shell2])
      assert shell_node["e"] == []
      %CID{} = shell1 = shell_node["l"]

      shell_node = CBOR.decode!(blocks[shell1])
      assert shell_node["e"] == []
      %CID{} = bottom = shell_node["l"]

      # Bottom node (layer 0) carries the depth-0 key.
      bottom_node = CBOR.decode!(blocks[bottom])
      assert [%{"p" => 0, "k" => ^shallow, "t" => nil, "v" => %CID{}}] = bottom_node["e"]
      assert bottom_node["l"] == nil
    end
  end
end
