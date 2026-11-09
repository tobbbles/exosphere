defmodule Exosphere.ATProto.Firehose.Frame do
  @moduledoc """
  Decode and encode atproto event-stream WebSocket frames.

  Each binary WebSocket message holds two concatenated DAG-CBOR objects:

  1. A header with `op` (operation) and, for messages, `t` (type)
  2. A payload object with the message data

  A regular message has header `%{"op" => 1, "t" => "#labels"}`, where `t` is
  the fragment of the lexicon message def. An error has header
  `%{"op" => -1}` and payload `%{"error" => name, "message" => optional}`.

  `decode/1` is the client side, used by `Exosphere.ATProto.Firehose.Consumer`.
  The `encode_*` functions are the server side: they build the frames an app
  sends when it *serves* a subscription. The WebSocket transport stays in the
  app. Output goes through `Exosphere.ATProto.CBOR`, so it is canonical
  DAG-CBOR (map keys in length-first order, no floats).

  ## Serving `com.atproto.label.subscribeLabels`

  The stream carries `#labels` (a batch of labels at one `seq`) and `#info`
  messages, and declares one error, `FutureCursor`. The spec's cursor rules:

  - no cursor: start at the live position
  - a cursor older than what you keep: send `#info` with
    `name: "OutdatedCursor"` first, then stream from the oldest `seq` you have
  - a cursor ahead of your latest `seq`: send a `FutureCursor` error and close

  Labels may be given with `sig` as raw bytes or as `%{"$bytes" => base64}`;
  `encode_labels/2` always writes it as a CBOR byte string.

  A sketch of a handler built on `WebSock` (as used by Phoenix and Bandit).
  `MyApp.Labels` stands for wherever the app keeps its signed labels, and the
  route is `/xrpc/com.atproto.label.subscribeLabels`, upgraded with
  `WebSockAdapter.upgrade(conn, MyApp.LabelStream, %{cursor: cursor}, [])`:

      defmodule MyApp.LabelStream do
        @behaviour WebSock

        alias Exosphere.ATProto.Firehose.Frame

        @impl true
        def init(%{cursor: cursor}) do
          # Subscribe before reading the backfill, so nothing written in
          # between is missed; `sent` drops live batches already backfilled.
          Phoenix.PubSub.subscribe(MyApp.PubSub, "labels")
          latest = MyApp.Labels.latest_seq()

          if is_integer(cursor) and cursor > latest do
            {:ok, frame} = Frame.encode_error("FutureCursor", "Cursor is ahead of the stream")
            {:stop, :normal, {1000, "FutureCursor"}, [{:binary, frame}], %{}}
          else
            {frames, sent} = backfill(cursor, latest)
            {:push, frames, %{sent: sent}}
          end
        end

        @impl true
        def handle_info({:labels, seq, _labels}, %{sent: sent} = state) when seq <= sent,
          do: {:ok, state}

        def handle_info({:labels, seq, labels}, state) do
          {:ok, frame} = Frame.encode_labels(seq, labels)
          {:push, {:binary, frame}, %{state | sent: seq}}
        end

        # Servers ignore anything the client sends.
        @impl true
        def handle_in(_frame, state), do: {:ok, state}

        # No cursor: start at the live position.
        defp backfill(nil, latest), do: {[], latest}

        defp backfill(cursor, latest) do
          outdated =
            if cursor < MyApp.Labels.oldest_seq() do
              {:ok, info} = Frame.encode_info("OutdatedCursor")
              [{:binary, info}]
            else
              []
            end

          frames =
            for {seq, labels} <- MyApp.Labels.between(cursor, latest) do
              {:ok, frame} = Frame.encode_labels(seq, labels)
              {:binary, frame}
            end

          {outdated ++ frames, latest}
        end
      end

  A real handler should page the backfill rather than push it all at once.
  """

  # Aliased under a distinct name so the bare `CBOR` below still refers to the
  # `:cbor` library (whose decode/1 returns the trailing bytes we need).
  alias Exosphere.ATProto.CBOR, as: DagCBOR
  alias Exosphere.ATProto.Label

  @type header :: %{op: integer(), t: String.t() | nil}

  @type encode_error ::
          {:error,
           :invalid_type
           | :invalid_payload
           | :invalid_error_name
           | :invalid_seq
           | {:invalid_label, non_neg_integer(), :invalid_sig | :not_a_map}
           | :floats_not_allowed
           | Exception.t()}

  @doc """
  Decode a binary WebSocket frame into `{header, payload}`.
  """
  @spec decode(binary()) :: {:ok, header(), map()} | {:error, term()}
  def decode(data) when is_binary(data) do
    with {:ok, header, rest} <- decode_header(data),
         {:ok, payload} <- decode_payload(rest) do
      {:ok, header, payload}
    end
  end

  @doc """
  Encode a regular message frame: header `%{"op" => 1, "t" => type}`, then
  `payload`.

  `type` is the short type name, the fragment of the lexicon message def,
  such as `"#labels"`. `payload` must be a map; the spec says it should not
  carry `$type`. Values must already be in their CBOR form: byte strings as
  `%CBOR.Tag{tag: :bytes}`, links as `Exosphere.ATProto.CID` structs. (A bare
  Elixir binary is written as a text string.)

      iex> alias Exosphere.ATProto.Firehose.Frame
      iex> {:ok, frame} = Frame.encode_message("#info", %{"name" => "OutdatedCursor"})
      iex> Frame.decode(frame)
      {:ok, %{op: 1, t: "#info"}, %{"name" => "OutdatedCursor"}}
  """
  @spec encode_message(String.t(), map()) :: {:ok, binary()} | encode_error()
  def encode_message("#" <> name = type, payload) when name != "" and is_map(payload) do
    encode_frame(%{"op" => 1, "t" => type}, payload)
  end

  def encode_message(type, payload) when is_binary(type) and is_map(payload),
    do: {:error, :invalid_type}

  def encode_message(_type, _payload), do: {:error, :invalid_payload}

  @doc """
  Encode an error frame: header `%{"op" => -1}`, then
  `%{"error" => error, "message" => message}`.

  `error` is the bare error name from the lexicon, with no namespace or `#`,
  such as `"FutureCursor"`. A `nil` message is left out. The spec says to close
  the stream right after sending an error frame.
  """
  @spec encode_error(String.t(), String.t() | nil) :: {:ok, binary()} | encode_error()
  def encode_error(error, message \\ nil)

  def encode_error(error, message)
      when is_binary(error) and error != "" and (is_binary(message) or is_nil(message)) do
    if String.contains?(error, ["#", "."]) do
      {:error, :invalid_error_name}
    else
      encode_frame(%{"op" => -1}, compact(%{"error" => error, "message" => message}))
    end
  end

  def encode_error(_error, _message), do: {:error, :invalid_error_name}

  @doc """
  Encode a `com.atproto.label.subscribeLabels` `#labels` frame.

  `labels` are string-keyed label maps, as `Exosphere.ATProto.Label.sign/3`
  returns them. `sig` may be raw bytes or `%{"$bytes" => base64}` (padded or
  not); it is written as a CBOR byte string either way. Fields whose value is
  `nil` are left out, as the label's signature does not cover them.

  Returns `{:error, {:invalid_label, index, reason}}` for a label that is not a
  map or whose `sig` is neither bytes nor valid base64.
  """
  @spec encode_labels(pos_integer(), [Label.t()]) :: {:ok, binary()} | encode_error()
  def encode_labels(seq, labels) when is_integer(seq) and seq > 0 and is_list(labels) do
    with {:ok, labels} <- labels_to_cbor(labels) do
      encode_message("#labels", %{"seq" => seq, "labels" => labels})
    end
  end

  def encode_labels(_seq, labels) when is_list(labels), do: {:error, :invalid_seq}
  def encode_labels(_seq, _labels), do: {:error, :invalid_payload}

  @doc """
  Encode a `com.atproto.label.subscribeLabels` `#info` frame.

  The lexicon's one known name is `"OutdatedCursor"`: the requested cursor is
  older than the server keeps, and the stream continues from the oldest `seq`
  it has. A `nil` message is left out.
  """
  @spec encode_info(String.t(), String.t() | nil) :: {:ok, binary()} | encode_error()
  def encode_info(name, message \\ nil)

  def encode_info(name, message)
      when is_binary(name) and (is_binary(message) or is_nil(message)) do
    encode_message("#info", compact(%{"name" => name, "message" => message}))
  end

  def encode_info(_name, _message), do: {:error, :invalid_payload}

  defp encode_frame(header, payload) do
    with {:ok, header_bin} <- DagCBOR.encode(header),
         {:ok, payload_bin} <- DagCBOR.encode(payload) do
      {:ok, header_bin <> payload_bin}
    end
  end

  defp labels_to_cbor(labels) do
    labels
    |> Enum.with_index()
    |> Enum.reduce_while({:ok, []}, fn {label, index}, {:ok, acc} ->
      case label_to_cbor(label) do
        {:ok, label} -> {:cont, {:ok, [label | acc]}}
        {:error, reason} -> {:halt, {:error, {:invalid_label, index, reason}}}
      end
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      error -> error
    end
  end

  defp label_to_cbor(label) when is_map(label) do
    label = compact(label)

    case Map.fetch(label, "sig") do
      :error ->
        {:ok, label}

      {:ok, sig} ->
        with {:ok, bytes} <- Label.sig_bytes(sig) do
          {:ok, Map.put(label, "sig", %CBOR.Tag{tag: :bytes, value: bytes})}
        end
    end
  end

  defp label_to_cbor(_label), do: {:error, :not_a_map}

  defp compact(map), do: Map.reject(map, fn {_key, value} -> is_nil(value) end)

  defp decode_header(data) do
    # Use the raw CBOR decoder which returns remaining bytes
    case CBOR.decode(data) do
      {:ok, %{"op" => op} = header, rest} when is_integer(op) ->
        parsed = %{
          op: op,
          t: Map.get(header, "t")
        }

        {:ok, parsed, rest}

      {:ok, _, _rest} ->
        {:error, :invalid_header}

      {:error, reason} ->
        {:error, {:cbor_decode_error, reason}}
    end
  rescue
    e -> {:error, {:header_decode_failed, e}}
  end

  defp decode_payload(<<>>) do
    {:ok, %{}}
  end

  defp decode_payload(data) do
    case CBOR.decode(data) do
      {:ok, payload, _rest} ->
        {:ok, DagCBOR.transform_links(payload)}

      {:error, reason} ->
        {:error, {:payload_decode_error, reason}}
    end
  rescue
    e -> {:error, {:payload_decode_failed, e}}
  end
end
