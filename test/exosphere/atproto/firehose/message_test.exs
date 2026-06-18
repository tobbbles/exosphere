defmodule Exosphere.ATProto.Firehose.MessageTest do
  use ExUnit.Case, async: true

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
end
