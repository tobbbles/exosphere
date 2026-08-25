defmodule Exosphere.ATProto.Firehose.ConsumerTest do
  @moduledoc """
  Unit coverage for the reconnect contract.

  `handle_disconnect/2` is a plain function on the consumer module, so the
  WebSockex return-value contract (reconnect vs terminate, and the
  re-targeted subscription URL) can be checked without a live relay.
  """

  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Firehose.Consumer

  defp state(opts \\ []) do
    %Consumer{
      relay_url: Keyword.get(opts, :relay_url, "wss://relay.example.com"),
      cursor: Keyword.get(opts, :cursor),
      on_event: fn _msg, state -> state end,
      stats: %{frames: 0, messages: 0, errors: 0, started_at: 0}
    }
  end

  describe "handle_disconnect/2" do
    test "reconnects instead of terminating" do
      # {:ok, state} would make WebSockex continue process termination;
      # {:reconnect, ...} is what makes it dial again.
      assert {tag, _conn_or_state, _state} =
               Consumer.handle_disconnect(%{reason: :test, attempt_number: 1}, state())

      assert tag == :reconnect
    end

    test "re-targets the subscription at the tracked cursor" do
      assert {:reconnect, %WebSockex.Conn{} = conn, new_state} =
               Consumer.handle_disconnect(
                 %{reason: :test, attempt_number: 1},
                 state(relay_url: "wss://relay.example.com", cursor: 1234)
               )

      assert conn.host == "relay.example.com"
      assert conn.path == "/xrpc/com.atproto.sync.subscribeRepos"
      assert conn.query == "cursor=1234"
      assert new_state.cursor == 1234
    end

    test "omits the cursor query when none has been tracked" do
      assert {:reconnect, %WebSockex.Conn{} = conn, _state} =
               Consumer.handle_disconnect(%{reason: :test, attempt_number: 1}, state())

      assert conn.query == nil
    end

    test "re-targets at the latest cursor, not the starting one" do
      # A consumer that started at cursor 0 and has tracked seq 5678 must
      # re-subscribe at 5678 — replaying from 0 would reflood the callback.
      tracked = %{state(cursor: 0) | cursor: 5678}

      assert {:reconnect, %WebSockex.Conn{} = conn, _state} =
               Consumer.handle_disconnect(%{reason: :test, attempt_number: 1}, tracked)

      assert conn.query == "cursor=5678"
    end
  end
end
