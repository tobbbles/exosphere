defmodule Exosphere.ATProto.Firehose.EmitterTest do
  @moduledoc """
  The producer against the consumer.

  The load-bearing test here is the inversion round trip: emit a `#commit`,
  then verify it the way a consumer holding *no* repository state would —
  decode the frame, check the signature, run the operations backwards against
  the blocks the message carried, and land on `prevData`. If the covering proof
  is short by even one MST node, the inversion fails with a missing block, so
  this is what proves the producer emits a complete slice rather than merely a
  plausible one.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Exosphere.ATProto.{CAR, CID, Crypto, MST}
  alias Exosphere.ATProto.Firehose.{Emitter, Frame, Message}
  alias Exosphere.ATProto.MST.Store
  alias Exosphere.ATProto.Repo.Commit

  @did "did:plc:z72i7hdynmk6r22z27h6tvur"

  setup_all do
    {:ok, keypair} = Crypto.generate_keypair(:secp256k1)
    {:ok, keypair: keypair}
  end

  defp path(i), do: "app.bsky.feed.post/3jqfcqzm3f" <> String.pad_leading("#{i}", 3, "0")

  defp record(i),
    do: %{
      "$type" => "app.bsky.feed.post",
      "text" => "post #{i}",
      "createdAt" => "2026-08-28T00:00:00.000Z"
    }

  defp emit(store, keypair, opts) do
    Emitter.commit(
      store,
      Keyword.merge(
        [did: @did, seq: 1, private_key: keypair.private_key, curve: :secp256k1],
        opts
      )
    )
  end

  # Everything a consumer knows: the frame bytes and the account's public key.
  # Returns the MST root the commit signed.
  defp verify_as_consumer(frame, public_key, expected_prev_root) do
    assert {:ok, %{op: 1, t: "#commit"}, payload} = Frame.decode(frame)
    assert {:ok, message} = Message.decode("#commit", payload)

    assert {:ok, %{roots: [root_cid], blocks: blocks}} = CAR.decode_full(message.blocks)
    assert root_cid == message.commit, "the CAR's root must be the commit the message names"

    commit = blocks[root_cid]

    assert :ok = Commit.verify(commit, public_key, :secp256k1),
           "the commit block must be signed by the account"

    assert %CID{} = data = commit["data"]

    assert message.prev_data == expected_prev_root,
           "prevData must name the root the repository was at"

    assert {:ok, recovered} = MST.invert(data, blocks, message.ops),
           "the carried blocks must be enough to invert the operations"

    expected = expected_prev_root || elem(MST.build([]), 1)

    assert recovered == expected,
           "inverting landed on #{recovered}, expected #{expected}"

    data
  end

  describe "commit/2" do
    test "emits a first commit for an empty repository", %{keypair: keypair} do
      assert {:ok, result} =
               emit(Store.new(), keypair, root: nil, writes: [{:create, path(1), record(1)}])

      assert %{frame: frame, commit: %CID{}, root: %CID{}, rev: rev} = result
      assert is_binary(rev)

      assert result.root == verify_as_consumer(frame, keypair.public_key, nil)
    end

    test "carries the record blocks it created", %{keypair: keypair} do
      {:ok, result} =
        emit(Store.new(), keypair, root: nil, writes: [{:create, path(1), record(1)}])

      {:ok, %{blocks: blocks}} = CAR.decode_full(result.message.blocks)

      assert blocks[CID.create!(record(1))] == record(1)
    end

    test "the message's ops mirror the writes", %{keypair: keypair} do
      {:ok, first} =
        emit(Store.new(), keypair, root: nil, writes: [{:create, path(1), record(1)}])

      {:ok, second} =
        emit(first.store, keypair,
          seq: 2,
          root: first.root,
          writes: [{:update, path(1), record(99)}, {:create, path(2), record(2)}]
        )

      assert [update, create] = second.message.ops

      assert update.action == :update
      assert update.path == path(1)
      assert update.cid == CID.create!(record(99))
      # `prev` is what lets a consumer invert an update.
      assert update.prev == CID.create!(record(1))

      assert create.action == :create
      assert create.prev == nil
    end

    test "a delete carries the record version it removed", %{keypair: keypair} do
      {:ok, first} =
        emit(Store.new(), keypair, root: nil, writes: [{:create, path(1), record(1)}])

      {:ok, second} =
        emit(first.store, keypair, seq: 2, root: first.root, writes: [{:delete, path(1)}])

      assert [%{action: :delete, cid: nil, prev: prev}] = second.message.ops
      assert prev == CID.create!(record(1))

      assert second.root == verify_as_consumer(second.frame, keypair.public_key, first.root)
    end

    test "the emitted tree agrees with a from-scratch build", %{keypair: keypair} do
      writes = for i <- 1..30, do: {:create, path(i), record(i)}
      {:ok, result} = emit(Store.new(), keypair, root: nil, writes: writes)

      expected_entries =
        for i <- 1..30, into: %{}, do: {path(i), CID.create!(record(i))}

      {:ok, rebuilt, _} = MST.build(expected_entries)
      assert result.root == rebuilt
    end

    test "requires the options it cannot invent" do
      assert {:error, {:missing_option, :did}} = Emitter.commit(Store.new(), seq: 1)

      assert {:error, {:missing_option, :seq}} =
               Emitter.commit(Store.new(), did: @did)
    end

    test "refuses more than 200 operations", %{keypair: keypair} do
      writes = for i <- 1..201, do: {:create, path(i), record(i)}

      assert {:error, {:too_many_ops, 201}} =
               emit(Store.new(), keypair, root: nil, writes: writes)
    end

    test "refuses an oversized record block", %{keypair: keypair} do
      huge = %{"text" => String.duplicate("x", 1_000_001)}

      assert {:error, {:record_too_large, _path, size}} =
               emit(Store.new(), keypair, root: nil, writes: [{:create, path(1), huge}])

      assert size > 1_000_000
    end
  end

  describe "a commit chain, verified the way a consumer would" do
    test "every frame inverts to its predecessor's root", %{keypair: keypair} do
      # Mixed creates, updates and deletes across several commits — the shapes
      # that make an MST split and merge.
      commits = [
        [{:create, path(1), record(1)}, {:create, path(2), record(2)}],
        [{:create, path(3), record(3)}, {:update, path(1), record(11)}],
        [{:delete, path(2)}],
        [{:create, path(4), record(4)}, {:create, path(5), record(5)}, {:delete, path(3)}],
        [{:update, path(4), record(44)}, {:delete, path(1)}]
      ]

      commits
      |> Enum.with_index(1)
      |> Enum.reduce({nil, Store.new()}, fn {writes, seq}, {root, store} ->
        {:ok, result} = emit(store, keypair, seq: seq, root: root, writes: writes)

        assert result.root == verify_as_consumer(result.frame, keypair.public_key, root)

        {result.root, result.store}
      end)
    end

    property "randomized commit chains all invert" do
      {:ok, keypair} = Crypto.generate_keypair(:secp256k1)

      check all(
              batches <-
                list_of(
                  list_of(tuple({integer(1..40), boolean()}), min_length: 1, max_length: 5),
                  min_length: 1,
                  max_length: 6
                ),
              max_runs: 15
            ) do
        batches
        |> Enum.with_index(1)
        |> Enum.reduce({nil, Store.new(), MapSet.new()}, fn {batch, seq},
                                                            {root, store, present} ->
          {writes, present} =
            batch
            |> Enum.uniq_by(&elem(&1, 0))
            |> Enum.map_reduce(present, fn {i, delete?}, present ->
              p = path(i)

              cond do
                delete? and MapSet.member?(present, p) ->
                  {{:delete, p}, MapSet.delete(present, p)}

                MapSet.member?(present, p) ->
                  {{:update, p, record(i * 7)}, present}

                true ->
                  {{:create, p, record(i)}, MapSet.put(present, p)}
              end
            end)

          {:ok, result} = emit(store, keypair, seq: seq, root: root, writes: writes)
          verify_as_consumer(result.frame, keypair.public_key, root)

          {result.root, result.store, present}
        end)
      end
    end
  end

  describe "sync/1" do
    test "carries only the commit block, rooted at it", %{keypair: keypair} do
      {:ok, result} =
        emit(Store.new(), keypair, root: nil, writes: [{:create, path(1), record(1)}])

      {:ok, commit_bytes} = Store.fetch(result.store, result.commit)

      assert {:ok, %{frame: frame, message: message}} =
               Emitter.sync(
                 did: @did,
                 seq: 2,
                 commit: result.commit,
                 commit_block: commit_bytes,
                 rev: result.rev
               )

      assert {:ok, %{op: 1, t: "#sync"}, payload} = Frame.decode(frame)
      assert {:ok, decoded} = Message.decode("#sync", payload)
      assert decoded.did == @did
      assert decoded.rev == message.rev

      assert {:ok, %{roots: [root], blocks: blocks}} = CAR.decode_full(decoded.blocks)
      assert root == result.commit
      # Deliberately just the commit: repository contents are not included.
      assert map_size(blocks) == 1
      assert :ok = Commit.verify(blocks[root], keypair.public_key, :secp256k1)
    end
  end

  describe "identity/1, account/1 and info/1" do
    test "identity round-trips" do
      assert {:ok, %{frame: frame}} =
               Emitter.identity(did: @did, seq: 7, handle: "alice.test")

      assert {:ok, %{op: 1, t: "#identity"}, payload} = Frame.decode(frame)
      assert {:ok, message} = Message.decode("#identity", payload)
      assert message.did == @did
      assert message.handle == "alice.test"
      assert message.seq == 7
    end

    test "account round-trips, including a takedown status" do
      assert {:ok, %{frame: frame}} =
               Emitter.account(did: @did, seq: 8, active: false, status: "takendown")

      assert {:ok, %{op: 1, t: "#account"}, payload} = Frame.decode(frame)
      assert {:ok, message} = Message.decode("#account", payload)
      assert message.active == false
      assert message.status == "takendown"
    end

    test "account requires the active flag" do
      assert {:error, {:missing_option, :active}} = Emitter.account(did: @did, seq: 1)
    end

    test "info round-trips" do
      assert {:ok, %{frame: frame}} = Emitter.info("OutdatedCursor", "cursor too old")

      assert {:ok, %{op: 1, t: "#info"}, payload} = Frame.decode(frame)
      assert {:ok, message} = Message.decode("#info", payload)
      assert message.name == "OutdatedCursor"
      assert message.message == "cursor too old"
    end
  end
end
