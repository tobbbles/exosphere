defmodule Exosphere.ATProto.Spaces.RepoTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.{CBOR, CID, Crypto}
  alias Exosphere.ATProto.Spaces.Commit
  alias Exosphere.ATProto.Spaces.Lthash
  alias Exosphere.ATProto.Spaces.Repo

  @space "at://did:plc:spaceauthority/space/com.example.group/default"
  @author "did:plc:author"
  @ctx %{space: @space, author: @author}

  @records [
    {"com.example.groupPost", "3jwd1", %{"$type" => "com.example.groupPost", "text" => "hello"}},
    {"com.example.groupPost", "3jwd2", %{"$type" => "com.example.groupPost", "text" => "world"}},
    {"com.example.groupNote", "3jwd3", %{"$type" => "com.example.groupNote", "body" => "a note"}}
  ]

  setup do
    {:ok, keypair} = Crypto.generate_keypair(:secp256k1)
    hash = record_hash(@records)

    {:ok, commit} =
      Commit.sign(hash, Map.put(@ctx, :rev, "3kbcq3p7ad400"), keypair.private_key, :secp256k1)

    %{keypair: keypair, commit: commit, car: Repo.serialize(commit, @records)}
  end

  test "serialize/verify round-trips a full repo", %{keypair: keypair, commit: commit, car: car} do
    assert {:ok, verified} = Repo.verify_car(car, @ctx, keypair.public_key, :secp256k1)

    assert verified.commit == commit
    assert verified.rev == "3kbcq3p7ad400"
    assert map_size(verified.index) == 3
    assert length(verified.records) == 3

    # Records come back in index order (canonical: shortest path first, then
    # bytewise — the Note path sorts before the Post paths at equal length).
    assert Enum.map(verified.records, & &1.rkey) == ["3jwd3", "3jwd1", "3jwd2"]
    assert Enum.map(verified.records, & &1.collection) == ~w(com.example.groupNote com.example.groupPost com.example.groupPost)

    assert %{"text" => "hello"} = Enum.find(verified.records, &(&1.rkey == "3jwd1")).record

    # The folded set hash equals the commit's, and re-folding the verified
    # index reproduces it — the authenticated-sync invariant.
    assert Lthash.digest(verified.lthash) == commit["hash"]
    {:ok, refolded} = Repo.fold_index(verified.index)
    assert Lthash.equal?(refolded, verified.lthash)
  end

  test "an index-only CAR verifies without values", %{keypair: keypair, commit: commit, car: car} do
    index_only = Repo.serialize(commit, @records, exclude_values: true)

    assert {:ok, verified} =
             Repo.verify_car(index_only, @ctx, keypair.public_key, :secp256k1, expect_values: false)

    assert verified.records == []
    assert map_size(verified.index) == 3

    # Expecting values against an index-only car fails loudly...
    assert {:error, :record_count_mismatch} =
             Repo.verify_car(index_only, @ctx, keypair.public_key, :secp256k1)

    # ...and vice versa.
    assert {:error, :unexpected_record_blocks} =
             Repo.verify_car(car, @ctx, keypair.public_key, :secp256k1, expect_values: false)
  end

  test "a tampered record fails loudly (index no longer matches commit)", %{
    keypair: keypair,
    commit: commit
  } do
    evil =
      Enum.map(@records, fn {c, r, rec} ->
        {c, r, if(r == "3jwd2", do: Map.put(rec, "text", "EVIL"), else: rec)}
      end)

    assert {:error, :index_hash_mismatch} =
             Repo.verify_car(Repo.serialize(commit, evil), @ctx, keypair.public_key, :secp256k1)
  end

  test "a block whose bytes do not hash to its CID fails at decode", %{
    keypair: keypair,
    car: car
  } do
    {:ok, %{order: [_c, _i, _r1, r2, _r3], blocks: blocks}} = Repo.decode_car(car)
    {:ok, record} = CBOR.decode(Map.get(blocks, r2))
    evil_bytes = CBOR.encode!(Map.put(record, "text", "EVIL"))

    # The frame keeps its original CID; its contents no longer hash to it.
    assert {:error, :content_hash_mismatch} =
             Repo.verify_car(tampered_car(car, r2, evil_bytes), @ctx, keypair.public_key, :secp256k1)
  end

  test "record blocks must follow the index order", %{keypair: keypair, car: car} do
    {:ok, %{order: [_c, _i, r1, r2, r3], blocks: blocks}} = Repo.decode_car(car)

    # Swap the last two record blocks so positions no longer match the index.
    assert {:error, {:record_block_out_of_order, path}} =
             Repo.verify_car(
               rebuilt_car(car, [Map.get(blocks, r1), Map.get(blocks, r3), Map.get(blocks, r2)]),
               @ctx,
               keypair.public_key,
               :secp256k1
             )

    assert path =~ "3jwd"
  end

  test "a non-canonical index is rejected", %{keypair: keypair, car: car} do
    {:ok, %{order: [_c, index_cid | _record_cids], blocks: blocks}} = Repo.decode_car(car)
    {:ok, index_raw} = CBOR.decode(Map.get(blocks, index_cid))
    index = CBOR.transform_links(index_raw)

    # Same entries, encoded in a non-canonical key order — under a fresh index
    # CID so the content still hashes to its frame.
    paths = index |> Map.keys() |> Enum.sort()
    evil_bytes = map_bytes(index, Enum.reverse(paths))

    assert {:error, :index_not_canonical} =
             Repo.verify_car(retargeted_car(car, index_cid, evil_bytes), @ctx,
               keypair.public_key,
               :secp256k1
             )
  end

  test "verification is bound to space, author, and key", %{keypair: keypair, car: car} do
    assert {:error, :invalid_mac} =
             Repo.verify_car(
               car,
               %{space: "at://did:plc:x/space/com.example.group/other", author: @author},
               keypair.public_key,
               :secp256k1
             )

    assert {:error, :invalid_mac} =
             Repo.verify_car(car, %{space: @space, author: "did:plc:someone-else"},
               keypair.public_key,
               :secp256k1
             )

    {:ok, other} = Crypto.generate_keypair(:secp256k1)

    assert {:error, :invalid_signature} =
             Repo.verify_car(car, @ctx, other.public_key, :secp256k1)

    assert {:error, :invalid_context} = Repo.verify_car(car, %{space: @space}, nil, nil)
  end

  test "a single-root CAR is not a space repo", %{keypair: keypair, commit: commit} do
    commit_bytes = CBOR.encode!(commit)
    commit_cid = %CID{version: 1, codec: :dag_cbor, hash: :crypto.hash(:sha256, commit_bytes)}

    header = CBOR.encode!(%{"version" => 1, "roots" => [commit_cid]})
    entry = CID.to_bytes(commit_cid) <> commit_bytes
    car = IO.iodata_to_binary([varint(byte_size(header)), header, varint(byte_size(entry)), entry])

    assert {:error, {:expected_two_roots, 1}} =
             Repo.verify_car(car, @ctx, keypair.public_key, :secp256k1)
  end

  test "fold_index rejects malformed indexes" do
    assert {:ok, _} = Repo.fold_index(%{})
    assert {:error, :invalid_index} = Repo.fold_index(%{"no-slash" => CID.create!(%{})})
    assert {:error, :invalid_index} = Repo.fold_index(%{"c.a/1" => "not-a-cid"})
  end

  # Rewrite one frame's bytes in place, keeping every frame CID — for blocks
  # whose contents should no longer hash to their CID.
  defp tampered_car(car, target_cid, evil_bytes) do
    {:ok, %{order: order, blocks: blocks}} = Repo.decode_car(car)
    car_for_order(order, Map.put(blocks, target_cid, evil_bytes))
  end

  # Rewrite one frame's bytes under a fresh content CID (frame and roots), so
  # the block itself stays self-consistent.
  defp retargeted_car(car, target_cid, evil_bytes) do
    {:ok, %{order: order, blocks: blocks}} = Repo.decode_car(car)
    new_cid = raw_cid(evil_bytes)

    new_order = Enum.map(order, fn cid -> if cid == target_cid, do: new_cid, else: cid end)

    new_blocks = blocks |> Map.delete(target_cid) |> Map.put(new_cid, evil_bytes)
    car_for_order(new_order, new_blocks)
  end

  # Rebuild a CAR keeping the commit and index frames, with record blocks in
  # an explicit order.
  defp rebuilt_car(car, record_block_list) do
    {:ok, %{order: [c, i | _], blocks: blocks}} = Repo.decode_car(car)

    header = CBOR.encode!(%{"version" => 1, "roots" => [c, i]})

    body =
      for {cid, bytes} <- [
            {c, Map.get(blocks, c)},
            {i, Map.get(blocks, i)}
            | Enum.map(record_block_list, fn bytes -> {raw_cid(bytes), bytes} end)
          ] do
        entry = CID.to_bytes(cid) <> bytes
        [varint(byte_size(entry)), entry]
      end

    IO.iodata_to_binary([varint(byte_size(header)), header, body])
  end

  defp car_for_order(order, blocks) do
    {roots, _} = Enum.split(order, 2)
    header = CBOR.encode!(%{"version" => 1, "roots" => roots})

    body =
      for cid <- order do
        entry = CID.to_bytes(cid) <> Map.get(blocks, cid)
        [varint(byte_size(entry)), entry]
      end

    IO.iodata_to_binary([varint(byte_size(header)), header, body])
  end

  defp raw_cid(bytes), do: %CID{version: 1, codec: :dag_cbor, hash: :crypto.hash(:sha256, bytes)}

  # Encode a DAG-CBOR map with explicit key order: a definite-length map
  # header followed by the per-pair encodings (each derived from a single-pair
  # map encoding with its 0xA1 header byte stripped).
  defp map_bytes(index, ordered_paths) do
    pairs =
      for path <- ordered_paths do
        single = CBOR.encode!(Map.new([{path, index[path]}]))
        binary_part(single, 1, byte_size(single) - 1)
      end

    IO.iodata_to_binary([<<0xA0 + map_size(index)>> | pairs])
  end

  defp record_hash(records) do
    Enum.reduce(records, Lthash.new(), fn {c, r, rec}, h ->
      Commit.add_record(h, c, r, CID.encode(CID.create!(rec)))
    end)
  end

  defp varint(n) when n < 128, do: <<n>>
  defp varint(n), do: <<1::1, Integer.mod(n, 128)::7>> <> varint(div(n, 128))
end
