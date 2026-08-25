defmodule Exosphere.ATProto.Firehose.Consumer do
  @moduledoc """
  Generic WebSocket consumer for the Exosphere.ATProto firehose using WebSockex.

  This module connects to a relay's `com.atproto.sync.subscribeRepos` endpoint,
  decodes frames into structured messages, and dispatches those messages via an
  `:on_event` callback.

  See the [Firehose guide](firehose.html) for a full walkthrough —
  message types, record extraction, verification, cursors, and production tips.

  The `:on_event` callback receives `(message, state)` and must return an
  updated state. **It must not raise** — the consumer does not catch exceptions
  from the callback. If your callback can fail, wrap the failing work in a
  `Task` (or your own supervised process) and return the original state.

  The consumer reconnects automatically on disconnect or connection error.
  A reconnect re-subscribes at the cursor the consumer has tracked in state
  (the `seq` of the last message dispatched), so it resumes where the stream
  left off rather than replaying from the original starting cursor. Reconnect
  attempts are spaced out with linear backoff plus jitter, capped at a few
  seconds. The tracked cursor is in-memory only — to resume a stream after a
  restart, persist `msg.seq` from your callback and pass it back via the
  `:cursor` option on next start.
  """

  use WebSockex

  require Logger

  alias Exosphere.ATProto.Firehose.{Frame, Message}

  @default_relay "wss://bsky.network"

  @type stats :: %{
          frames: non_neg_integer(),
          messages: non_neg_integer(),
          errors: non_neg_integer(),
          started_at: integer()
        }

  @type t :: %__MODULE__{
          relay_url: String.t(),
          cursor: integer() | nil,
          on_event: (map(), t() -> t()),
          stats: stats()
        }

  defstruct [:relay_url, :cursor, :on_event, :stats]

  @doc """
  Start the firehose consumer.

  ## Options

  - `:relay_url` - Relay WebSocket URL (default: `"wss://bsky.network"`)
  - `:cursor` - Starting cursor for resumption (optional)
  - `:on_event` - Callback invoked with each decoded message (required)
  - `:name` - Process name (optional)
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    relay_url = Keyword.get(opts, :relay_url, @default_relay)
    cursor = Keyword.get(opts, :cursor)

    on_event =
      case Keyword.fetch(opts, :on_event) do
        {:ok, fun} when is_function(fun, 2) ->
          fun

        _ ->
          raise ArgumentError,
                "Exosphere.ATProto.Firehose.Consumer requires an :on_event function (arity 2)"
      end

    uri = build_subscription_url(relay_url, cursor)

    state = %__MODULE__{
      relay_url: relay_url,
      cursor: cursor,
      on_event: on_event,
      stats: %{
        frames: 0,
        messages: 0,
        errors: 0,
        started_at: System.monotonic_time(:millisecond)
      }
    }

    ws_opts =
      case Keyword.get(opts, :name) do
        nil -> []
        name -> [name: name]
      end

    Logger.info("[Exosphere.ATProto.Firehose] Starting connection to #{uri}")
    WebSockex.start_link(uri, __MODULE__, state, ws_opts)
  end

  def child_spec(opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]},
      type: :worker,
      restart: :permanent
    }
  end

  # WebSockex callbacks. handle_disconnect/2 returns {:reconnect, conn, state}
  # (or {:ok, state} to terminate) — see the WebSockex docs for the contract;
  # WebSockex also answers protocol-level pings for us.

  @impl WebSockex
  def handle_connect(_conn, state) do
    Logger.info("[Exosphere.ATProto.Firehose] ✓ Connected to relay")
    {:ok, state}
  end

  @impl WebSockex
  def handle_frame({:binary, data}, state), do: {:ok, process_frame(data, state)}

  @impl WebSockex
  def handle_frame({:text, _data}, state), do: {:ok, state}

  @impl WebSockex
  def handle_frame({:ping, _data}, state), do: {:ok, state}

  @impl WebSockex
  def handle_frame({:pong, _data}, state), do: {:ok, state}

  @impl WebSockex
  def handle_info(msg, state) do
    Logger.debug("[Exosphere.ATProto.Firehose] Unhandled info: #{inspect(msg)}")
    {:ok, state}
  end

  @impl WebSockex
  def handle_disconnect(%{reason: reason, attempt_number: attempt}, state) do
    Logger.warning(
      "[Exosphere.ATProto.Firehose] Disconnected: #{inspect(reason)}, reconnecting (attempt ##{attempt})"
    )

    backoff_sleep(attempt)

    # Re-target the subscription at the tracked cursor so a reconnect resumes
    # where the stream left off instead of replaying from the original
    # starting cursor. {:reconnect, state} alone would re-open the original
    # URL, cursor and all.
    case WebSockex.Conn.new(build_subscription_url(state.relay_url, state.cursor)) do
      %WebSockex.Conn{} = conn ->
        {:reconnect, conn, state}

      {:error, error} ->
        Logger.error(
          "[Exosphere.ATProto.Firehose] Cannot rebuild subscription URL for #{state.relay_url}: #{inspect(error)}"
        )

        {:ok, state}
    end
  end

  # Private

  # Linear backoff with jitter, capped: failed reconnects wait progressively
  # longer (attempt_number comes from WebSockex's disconnect map) so a relay
  # outage doesn't turn into a hot reconnect loop, and the jitter keeps fleets
  # of consumers from reconnecting in lockstep.
  @backoff_base_ms 250
  @backoff_cap_ms 4_000

  defp backoff_sleep(attempt) do
    backoff = min(attempt * @backoff_base_ms, @backoff_cap_ms)
    jitter = :rand.uniform(div(backoff, 4) + 1)
    Process.sleep(backoff + jitter)
  end

  defp build_subscription_url(relay, nil),
    do: "#{relay}/xrpc/com.atproto.sync.subscribeRepos"

  defp build_subscription_url(relay, cursor),
    do: "#{relay}/xrpc/com.atproto.sync.subscribeRepos?cursor=#{cursor}"

  defp process_frame(data, state) do
    stats = %{state.stats | frames: state.stats.frames + 1}
    state = %{state | stats: stats}

    case Frame.decode(data) do
      {:ok, header, payload} ->
        Logger.debug(
          "[Exosphere.ATProto.Firehose] Frame ##{stats.frames}: op=#{header.op}, type=#{header.t}, size=#{byte_size(data)} bytes"
        )

        handle_message(header, payload, state)

      {:error, reason} ->
        Logger.warning(
          "[Exosphere.ATProto.Firehose] Frame decode error: #{inspect(reason)}, size=#{byte_size(data)}"
        )

        %{state | stats: %{stats | errors: stats.errors + 1}}
    end
  end

  defp handle_message(%{op: 1, t: type}, payload, state) do
    stats = %{state.stats | messages: state.stats.messages + 1}
    state = %{state | stats: stats}

    {:ok, message} = Message.decode(type, payload)

    state
    |> dispatch(message)
    |> update_cursor(message)
  end

  defp handle_message(%{op: -1}, payload, state) do
    Logger.error("[Exosphere.ATProto.Firehose] ✗ Server error: #{inspect(payload)}")
    %{state | stats: %{state.stats | errors: state.stats.errors + 1}}
  end

  defp handle_message(header, _payload, state) do
    Logger.debug("[Exosphere.ATProto.Firehose] Unknown message header: #{inspect(header)}")
    state
  end

  # Invoke the user-supplied callback. We deliberately do not catch — if the
  # callback raises, the consumer process will crash and WebSockex's reconnect
  # logic will restart it. See @moduledoc.
  defp dispatch(state, message) do
    state.on_event.(message, state)
  end

  defp update_cursor(state, %{seq: seq}) when is_integer(seq), do: %{state | cursor: seq}
  defp update_cursor(state, _), do: state
end
