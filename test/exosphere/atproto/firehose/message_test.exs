defmodule Exosphere.ATProto.Firehose.MessageTest do
  use ExUnit.Case, async: true

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
end
