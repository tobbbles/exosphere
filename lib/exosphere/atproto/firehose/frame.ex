defmodule Exosphere.ATProto.Firehose.Frame do
  @moduledoc """
  Decode Exosphere.ATProto firehose WebSocket frames.

  Each frame contains two concatenated DAG-CBOR objects:

  1. Header with `op` (operation) and `t` (type) fields
  2. Payload with the actual message data
  """

  # Aliased under a distinct name so the bare `CBOR` below still refers to the
  # `:cbor` library (whose decode/1 returns the trailing bytes we need).
  alias Exosphere.ATProto.CBOR, as: DagCBOR

  @type header :: %{op: integer(), t: String.t() | nil}

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
