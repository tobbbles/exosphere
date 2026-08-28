defmodule Exosphere.ExternalRepoTest do
  @moduledoc """
  The serving primitives against a real repository.

  Everything in `mst_test.exs`, `car_encode_test.exs` and `emitter_test.exs`
  builds its own data with this library's own encoders — which proves internal
  consistency and nothing about interoperability. This suite fetches a real
  account's repository from a real PDS and runs the new serving code over it:
  the archive was produced by the reference implementation, so agreement here
  is agreement with the reference.

  Excluded from the default run. Opt in with:

      mix test --only external

  Requires the network. A failure that looks like a network or account problem
  (the test account moved, the PDS is down) is not a library failure — check
  the repository resolves before reading anything into it.
  """

  use ExUnit.Case, async: true

  alias Exosphere.ATProto.{CAR, CID, MST, Repo}
  alias Exosphere.ATProto.Identity.{DID, Handle}
  alias Exosphere.ATProto.MST.Store
  alias Exosphere.ATProto.Repo.Commit

  @moduletag :external
  @moduletag timeout: 180_000

  # A small, long-lived, well-known repository: the protocol's own account.
  @handle "atproto.com"

  setup_all do
    {:ok, did} = Handle.resolve(@handle)
    {:ok, document} = DID.resolve(did)

    {:ok, pds} = Exosphere.ATProto.Identity.Document.get_pds_endpoint(document)

    {:ok, %{status: 200, body: car}} =
      Exosphere.ATProto.HTTP.get(
        "#{pds}/xrpc/com.atproto.sync.getRepo?" <> URI.encode_query(%{"did" => did})
      )

    {:ok, did: did, document: document, pds: pds, car: car}
  end

  test "the repository verifies end to end", %{pds: pds, did: did, document: document} do
    assert {:ok, checkout} = Repo.verify_checkout(pds, did, did_document: document)

    assert checkout.did == did
    assert map_size(checkout.records) > 0
  end

  test "decode_raw/1 preserves the bytes the PDS served", %{car: car} do
    assert {:ok, %{roots: [commit_cid], blocks: blocks, order: order}} = CAR.decode_raw(car)

    assert length(order) == map_size(blocks)

    # Every block hashes to the CID it is filed under — the archive is
    # self-certifying, and our frame splitting agrees with the producer's.
    for {cid, bytes} <- blocks do
      assert :crypto.hash(:sha256, bytes) == cid.hash,
             "block #{cid} does not hash to its own CID"
    end

    assert Map.has_key?(blocks, commit_cid)
  end

  test "a real commit block survives a byte-preserving round trip", %{car: car} do
    {:ok, %{roots: [commit_cid], blocks: blocks, order: order}} = CAR.decode_raw(car)

    # Re-encode from the raw bytes and read it back: the blocks must be
    # identical. This is the serving path — import an archive, serve it again.
    ordered = Enum.map(order, &{&1, blocks[&1]})
    assert {:ok, reencoded} = CAR.encode(commit_cid, ordered, verify: true)

    assert {:ok, %{roots: [^commit_cid], blocks: back, order: ^order}} =
             CAR.decode_raw(reencoded)

    assert back == blocks
    # Same roots, same blocks, same order: byte-identical to what we were served.
    assert reencoded == car
  end

  test "the signed commit verifies from the raw bytes", %{car: car, document: document} do
    {:ok, %{roots: [commit_cid], blocks: blocks}} = CAR.decode_raw(car)

    {:ok, commit} = Exosphere.ATProto.CBOR.decode(blocks[commit_cid])

    assert commit["version"] == Commit.version()
    assert :ok = Commit.verify_with_document(commit, document)
  end

  test "the incremental tree rebuilds a real repository's signed root", %{car: car} do
    {:ok, %{roots: [commit_cid], blocks: blocks}} = CAR.decode_raw(car)
    {:ok, commit} = Exosphere.ATProto.CBOR.decode(blocks[commit_cid])

    %CID{} = signed_root = commit["data"]

    assert {:ok, records} = MST.read(signed_root, blocks)

    # Insert every record one at a time through the incremental path. Landing
    # on the reference implementation's root CID means the node algebra agrees
    # with the reference at every split, merge and layer — on real key
    # distributions, not ones this library chose.
    ops = Enum.map(records, fn {path, cid} -> {:put, path, cid} end)
    assert {:ok, built, _store, _written} = MST.apply_ops(nil, Store.new(), ops)

    assert built == signed_root,
           "incremental build produced #{built}, the PDS signed #{signed_root}"
  end

  test "a proof for a real record stands on its own", %{car: car} do
    {:ok, %{roots: [commit_cid], blocks: blocks}} = CAR.decode_raw(car)
    {:ok, commit} = Exosphere.ATProto.CBOR.decode(blocks[commit_cid])
    root = commit["data"]

    {:ok, records} = MST.read(root, blocks)
    {path, expected} = records |> Enum.sort() |> Enum.at(div(map_size(records), 2))

    assert {:ok, proof} = MST.proof(root, blocks, path)

    # Read the record back from the proof alone — this is what a PDS hands a
    # client that wants to check the answer rather than trust it.
    assert {:ok, ^expected} = MST.fetch(root, proof, path)

    assert map_size(proof) < map_size(blocks),
           "a proof carried #{map_size(proof)} of #{map_size(blocks)} blocks"
  end
end
