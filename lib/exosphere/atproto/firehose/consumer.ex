defmodule Exosphere.ATProto.Firehose.Consumer do
  @moduledoc """
  Generic WebSocket consumer for the Exosphere.ATProto firehose using Fresh.

  This module connects to a relay's `com.atproto.sync.subscribeRepos` endpoint,
  decodes frames into structured messages, and dispatches those messages via an
  `:on_event` callback.

  The `:on_event` callback receives `(message, state)` and must return an
  updated state. **It must not raise** — the consumer does not catch exceptions
  from the callback. If your callback can fail, wrap the failing work in a
  `Task` (or your own supervised process) and return the original state.

  The cursor tracked in state is in-memory only. To resume a stream after a
  restart, persist `msg.seq` from your callback and pass it back via the
  `:cursor` option on next start.
  """

  use Fresh

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
          cursor: integer() | nil,
          on_event: (map(), t() -> t()),
          stats: stats()
        }

  defstruct [:cursor, :on_event, :stats]

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
      cursor: cursor,
      on_event: on_event,
      stats: %{
        frames: 0,
        messages: 0,
        errors: 0,
        started_at: System.monotonic_time(:millisecond)
      }
    }

    fresh_opts =
      case Keyword.get(opts, :name) do
        nil -> []
        name -> [name: name]
      end

    Logger.info("[Exosphere.ATProto.Firehose] Starting connection to #{uri}")
    Fresh.start_link(uri, __MODULE__, state, fresh_opts)
  end

  def child_spec(opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]},
      type: :worker,
      restart: :permanent
    }
  end

  # Fresh callbacks

  @impl Fresh
  def handle_connect(status, headers, state) do
    Logger.info("[Exosphere.ATProto.Firehose] ✓ Connected to relay (status: #{status})")
    Logger.debug("[Exosphere.ATProto.Firehose] Response headers: #{inspect(headers)}")
    {:ok, state}
  end

  @impl Fresh
  def handle_in({:binary, data}, state) do
    {:ok, handle_frame(data, state)}
  end

  @impl Fresh
  def handle_in({:text, _data}, state), do: {:ok, state}

  @impl Fresh
  def handle_control({:ping, _}, state), do: {:ok, state}

  @impl Fresh
  def handle_control({:pong, _}, state), do: {:ok, state}

  @impl Fresh
  def handle_info(msg, state) do
    Logger.debug("[Exosphere.ATProto.Firehose] Unhandled info: #{inspect(msg)}")
    {:ok, state}
  end

  @impl Fresh
  def handle_error(error, _state) do
    Logger.error("[Exosphere.ATProto.Firehose] Error: #{inspect(error)}")
    :reconnect
  end

  @impl Fresh
  def handle_disconnect(code, reason, _state) do
    Logger.warning(
      "[Exosphere.ATProto.Firehose] Disconnected: code=#{code}, reason=#{inspect(reason)}"
    )

    :reconnect
  end

  # Private

  defp build_subscription_url(relay, nil),
    do: "#{relay}/xrpc/com.atproto.sync.subscribeRepos"

  defp build_subscription_url(relay, cursor),
    do: "#{relay}/xrpc/com.atproto.sync.subscribeRepos?cursor=#{cursor}"

  defp handle_frame(data, state) do
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
  # callback raises, the consumer process will crash and Fresh's reconnect
  # logic will restart it. See @moduledoc.
  defp dispatch(state, message) do
    state.on_event.(message, state)
  end

  defp update_cursor(state, %{seq: seq}) when is_integer(seq), do: %{state | cursor: seq}
  defp update_cursor(state, _), do: state
end
