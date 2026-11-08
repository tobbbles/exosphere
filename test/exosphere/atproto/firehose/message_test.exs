defmodule Exosphere.ATProto.Firehose.MessageTest do
  use ExUnit.Case, async: true

  doctest Exosphere.ATProto.Firehose.Message

  alias Exosphere.ATProto.{CAR, CBOR, CID, TestRepoCar}
  alias Exosphere.ATProto.Firehose.Message

  test "decodes #account hosting status events" do
    payload = %{
      "seq" => 42,
      "did" => "did:plc:abc",
      "active" => false,
      "status" => "takendown",
      "time" => "2026-01-01T00:00:00Z"
    }

    assert {:ok, msg} = Message.decode("#account", payload)
    assert msg.type == :account
    assert msg.seq == 42
    assert msg.did == "did:plc:abc"
    assert msg.active == false
    assert msg.status == "takendown"
  end

  test "decodes #sync events with CAR blocks" do
    payload = %{"seq" => 7, "did" => "did:plc:abc", "rev" => "3kaa", "blocks" => <<1, 2, 3>>}

    assert {:ok, msg} = Message.decode("#sync", payload)
    assert msg.type == :sync
    assert msg.blocks == <<1, 2, 3>>
    assert msg.rev == "3kaa"
  end

  test "#identity includes the optional handle field" do
    assert {:ok, msg} =
             Message.decode("#identity", %{
               "seq" => 1,
               "did" => "did:plc:abc",
               "handle" => "alice.example.com",
               "time" => "2026-01-01T00:00:00Z"
             })

    assert msg.type == :identity
    assert msg.handle == "alice.example.com"
  end

  test "#commit exposes prev_data (MST root) when present" do
    assert {:ok, msg} =
             Message.decode("#commit", %{"seq" => 1, "repo" => "did:plc:abc", "ops" => []})

    assert msg.type == :commit
    assert msg.prev_data == nil
    assert Map.has_key?(msg, :prev_data)
  end

  test "legacy #handle and #tombstone still decode" do
    assert {:ok, %{type: :handle}} = Message.decode("#handle", %{"seq" => 1, "did" => "x"})
    assert {:ok, %{type: :tombstone}} = Message.decode("#tombstone", %{"seq" => 1, "did" => "x"})
  end

  describe "verify_commit/1" do
    setup do
      f = TestRepoCar.build()

      msg = %{
        type: :commit,
        seq: 42,
        repo: f.commit["did"],
        commit: f.commit_cid,
        rev: f.commit["rev"],
        since: nil,
        prev_data: nil,
        ops: [],
        blocks: f.car,
        time: nil
      }

      %{fixture: f, msg: msg}
    end

    test "verifies a complete-blocks commit and returns the record set", %{fixture: f, msg: msg} do
      assert {:ok, records} = Message.verify_commit(msg)
      assert records == f.records
    end

    test "rejects a CAR whose root disagrees with the message commit link", %{msg: msg} do
      assert {:error, :root_mismatch} =
               Message.verify_commit(%{msg | commit: CID.create!("fake")})
    end

    test "reports missing blocks for incremental CARs", %{fixture: f, msg: msg} do
      # Simulate an incremental firehose CAR: only the commit block, no MST nodes.
      {:ok, %{roots: [root], blocks: blocks}} = CAR.decode_full(f.car)
      commit_only = Map.take(blocks, [root])
      header = %{"v" => 1, "roots" => [root]}

      header_bin = CBOR.encode!(header)
      entry_bin = CBOR.encode!(commit_only[root])

      car =
        leb128(byte_size(header_bin)) <>
          header_bin <>
          leb128(byte_size(CID.to_bytes(root)) + byte_size(entry_bin)) <>
          CID.to_bytes(root) <> entry_bin

      assert {:error, {:missing_block, _cid}} = Message.verify_commit(%{msg | blocks: car})
    end

    test "rejects non-commit messages", %{fixture: _f} do
      assert {:error, :not_a_commit} = Message.verify_commit(%{type: :identity, did: "did:plc:x"})
    end
  end

  defp leb128(int) when int < 0x80, do: <<int>>
  defp leb128(int), do: <<1::1, Integer.mod(int, 0x80)::7, leb128(div(int, 128))::binary>>

  describe "encode/1" do
    test "round-trips a commit through decode/2" do
      message = %{
        type: :commit,
        seq: 12,
        repo: "did:plc:abc",
        commit: CID.create!(%{"a" => 1}),
        rev: "3lbqmqtqhpk2a",
        since: "3lbqmqtqhpk29",
        prev_data: CID.create!(%{"old" => true}),
        ops: [
          %{
            action: :create,
            path: "app.bsky.feed.post/a",
            cid: CID.create!(%{"r" => 1}),
            prev: nil
          },
          %{
            action: :update,
            path: "app.bsky.feed.post/b",
            cid: CID.create!(%{"r" => 2}),
            prev: CID.create!(%{"r" => 1})
          },
          %{
            action: :delete,
            path: "app.bsky.feed.post/c",
            cid: nil,
            prev: CID.create!(%{"r" => 3})
          }
        ],
        blocks: <<1, 2, 3>>,
        time: "2026-08-28T00:00:00.000Z"
      }

      assert {:ok, "#commit", payload} = Message.encode(message)
      assert {:ok, decoded} = Message.decode("#commit", transcode(payload))

      assert decoded == message
    end

    test "writes the deprecated fields the way a producer should" do
      {:ok, "#commit", payload} =
        Message.encode(%{type: :commit, seq: 1, repo: "did:plc:abc", ops: [], blocks: <<>>})

      assert payload["rebase"] == false
      assert payload["tooBig"] == false
      assert payload["blobs"] == []
    end

    test "decodes a commit with or without the deprecated rebase flag" do
      base = %{"seq" => 1, "repo" => "did:plc:abc", "ops" => [], "blocks" => <<>>}

      assert {:ok, with_flag} = Message.decode("#commit", Map.put(base, "rebase", false))
      assert {:ok, without_flag} = Message.decode("#commit", base)
      assert with_flag == without_flag
    end

    test "omits prev on a create and keeps it on update and delete" do
      prev = CID.create!(%{"r" => 1})

      {:ok, "#commit", payload} =
        Message.encode(%{
          type: :commit,
          ops: [
            %{action: :create, path: "c/a", cid: prev, prev: prev},
            %{action: :delete, path: "c/b", cid: nil, prev: prev}
          ]
        })

      [create, delete] = payload["ops"]

      # A create has no previous version, so `prev` would be meaningless.
      refute Map.has_key?(create, "prev")
      assert delete["prev"] == prev
    end

    test "round-trips sync, identity, account and info" do
      messages = [
        %{type: :sync, seq: 1, did: "did:plc:a", rev: "3l", blocks: <<9>>, time: "t"},
        %{type: :identity, seq: 2, did: "did:plc:a", handle: "a.test", time: "t"},
        %{
          type: :account,
          seq: 3,
          did: "did:plc:a",
          active: false,
          status: "suspended",
          time: "t"
        },
        %{type: :info, name: "OutdatedCursor", message: "too old"}
      ]

      for message <- messages do
        assert {:ok, type, payload} = Message.encode(message)
        assert {:ok, ^message} = Message.decode(type, transcode(payload))
      end
    end

    test "omits absent optional fields instead of writing null" do
      # prevData, handle, status and message are optional but not nullable in
      # the lexicon: a validating consumer rejects an explicit null.
      {:ok, "#commit", commit} =
        Message.encode(%{type: :commit, seq: 1, repo: "did:plc:a", ops: [], prev_data: nil})

      {:ok, "#identity", identity} =
        Message.encode(%{type: :identity, seq: 2, did: "did:plc:a", handle: nil, time: "t"})

      {:ok, "#account", account} =
        Message.encode(%{type: :account, seq: 3, did: "did:plc:a", active: true, time: "t"})

      {:ok, "#info", info} = Message.encode(%{type: :info, name: "OutdatedCursor"})

      refute Map.has_key?(commit, "prevData")
      refute Map.has_key?(identity, "handle")
      refute Map.has_key?(account, "status")
      refute Map.has_key?(info, "message")

      # ...and the absent fields still decode to nil.
      assert {:ok, %{prev_data: nil}} = Message.decode("#commit", transcode(commit))
      assert {:ok, %{handle: nil}} = Message.decode("#identity", transcode(identity))
      assert {:ok, %{status: nil}} = Message.decode("#account", transcode(account))
      assert {:ok, %{message: nil}} = Message.decode("#info", transcode(info))
    end

    test "keeps since as an explicit null on a first commit" do
      # `since` is required and nullable: absent and null are different.
      {:ok, "#commit", payload} =
        Message.encode(%{type: :commit, seq: 1, repo: "did:plc:a", ops: [], since: nil})

      assert Map.fetch(payload, "since") == {:ok, nil}
    end

    test "refuses a message it cannot put on the wire" do
      # `#handle` and `#tombstone` are decode-only: they are deprecated, and a
      # producer emitting them today would be wrong.
      assert {:error, {:unencodable_message, :handle}} = Message.encode(%{type: :handle})
      assert {:error, {:unencodable_message, :tombstone}} = Message.encode(%{type: :tombstone})
      assert {:error, :not_a_message} = Message.encode(%{})
    end

    test "rejects a malformed op" do
      assert {:error, {:invalid_op, _}} =
               Message.encode(%{type: :commit, ops: [%{action: :rebase, path: "c/a"}]})
    end
  end

  # Through the encoder and back, so byte-string tags and CID links are
  # exercised rather than assumed.
  defp transcode(payload) do
    {:ok, decoded} = Exosphere.ATProto.CBOR.decode(Exosphere.ATProto.CBOR.encode!(payload))
    decoded
  end
end
