defmodule Exosphere.ATProto.Firehose.Frame do
  @moduledoc """
  Encode and decode Exosphere.ATProto firehose WebSocket frames.

  Each frame contains two concatenated DAG-CBOR objects:

  1. Header with `op` (operation) and `t` (type) fields
  2. Payload with the actual message data

  `op` is `1` for a message — where `t` names the message type, `"#commit"` and
  friends — and `-1` for an error, where `t` is absent and the payload carries
  `error` and an optional `message`. A consumer that does not recognise an `op`
  or a `t` must ignore that frame rather than drop the connection; a frame that
  will not decode at all must drop it.

  ## Examples

      # Consuming
      {:ok, %{op: 1, t: "#commit"}, payload} = Frame.decode(binary)

      # Serving
      {:ok, binary} = Frame.encode_message("#commit", payload)
      {:ok, binary} = Frame.encode_error("FutureCursor", "cursor in the future")
  """

  # Aliased under a distinct name so the bare `CBOR` below still refers to the
  # `:cbor` library (whose decode/1 returns the trailing bytes we need).
  alias Exosphere.ATProto.CBOR, as: DagCBOR

  @type header :: %{op: integer(), t: String.t() | nil}

  @op_message 1
  @op_error -1

  # A firehose frame may not exceed 5 MB as a websocket frame. Enforced here so
  # a producer fails loudly at the boundary rather than having relays drop the
  # connection.
  @max_frame_bytes 5_000_000

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
  Encode a message frame: header `%{op: 1, t: type}` then `payload`.

  `payload` should omit `$type` — the header already carries the type.

  Returns `{:error, {:frame_too_large, bytes}}` past the spec's 5 MB limit.
  """
  @spec encode_message(String.t(), map()) :: {:ok, binary()} | {:error, term()}
  def encode_message(type, payload) when is_binary(type) and is_map(payload) do
    encode(%{op: @op_message, t: type}, payload)
  end

  @doc """
  Encode an error frame: header `%{op: -1}` then `%{"error" => ..., "message" => ...}`.

  `error` is the error name without namespace or `#` prefix. A connection-time
  error is sent as the first frame on the stream, before disconnecting.
  """
  @spec encode_error(String.t(), String.t() | nil) :: {:ok, binary()} | {:error, term()}
  def encode_error(error, message \\ nil) when is_binary(error) do
    payload =
      case message do
        nil -> %{"error" => error}
        message when is_binary(message) -> %{"error" => error, "message" => message}
      end

    encode(%{op: @op_error}, payload)
  end

  @doc """
  Encode an arbitrary `{header, payload}` frame.

  The two objects are concatenated with no separator or length prefix; the
  decoder tells them apart because DAG-CBOR is self-delimiting.
  """
  @spec encode(header() | map(), map()) :: {:ok, binary()} | {:error, term()}
  def encode(header, payload) when is_map(header) and is_map(payload) do
    with {:ok, header_map} <- header_map(header),
         {:ok, header_bytes} <- DagCBOR.encode(header_map),
         {:ok, payload_bytes} <- DagCBOR.encode(payload) do
      frame = header_bytes <> payload_bytes

      if byte_size(frame) > @max_frame_bytes do
        {:error, {:frame_too_large, byte_size(frame)}}
      else
        {:ok, frame}
      end
    end
  end

  @doc """
  The spec's hard frame size limit, in bytes.
  """
  @spec max_frame_bytes() :: pos_integer()
  def max_frame_bytes, do: @max_frame_bytes

  # `t` is required for a message and absent for an error — the decoder keys off
  # `op`, so an error frame carrying a `t` would be malformed.
  defp header_map(%{op: @op_error}), do: {:ok, %{"op" => @op_error}}

  defp header_map(%{op: op, t: t}) when is_integer(op) and is_binary(t),
    do: {:ok, %{"op" => op, "t" => t}}

  defp header_map(%{"op" => _} = header), do: {:ok, header}

  defp header_map(header), do: {:error, {:invalid_header, header}}

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
