defmodule Exosphere.ATProto.Firehose.Frame do
  @moduledoc """
  Decode Exosphere.ATProto firehose WebSocket frames.

  Each frame contains two concatenated DAG-CBOR objects:

  1. Header with `op` (operation) and `t` (type) fields
  2. Payload with the actual message data
  """

  alias Exosphere.ATProto.CID

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
        {:ok, transform_payload(payload)}

      {:error, reason} ->
        {:error, {:payload_decode_error, reason}}
    end
  rescue
    e -> {:error, {:payload_decode_failed, e}}
  end

  # Transform CBOR tags and nested structures after decoding
  defp transform_payload(term) when is_map(term) and not is_struct(term) do
    Map.new(term, fn {k, v} -> {k, transform_payload(v)} end)
  end

  defp transform_payload(term) when is_list(term) do
    Enum.map(term, &transform_payload/1)
  end

  # Handle byte strings (CBOR major type 2) - the :cbor library wraps these in a Tag
  defp transform_payload(%CBOR.Tag{tag: :bytes, value: bytes}) when is_binary(bytes) do
    bytes
  end

  # Handle CID tags (tag 42)
  defp transform_payload(%CBOR.Tag{tag: 42, value: <<0x00, cid_bytes::binary>>}) do
    case CID.from_bytes(cid_bytes) do
      {:ok, cid} -> cid
      {:error, _} -> nil
    end
  end

  defp transform_payload(%CBOR.Tag{tag: 42, value: cid_bytes}) when is_binary(cid_bytes) do
    # Some CIDs might not have the 0x00 prefix
    case CID.from_bytes(cid_bytes) do
      {:ok, cid} -> cid
      {:error, _} -> nil
    end
  end

  defp transform_payload(%CBOR.Tag{} = tag) do
    # Unknown tag, return the value
    tag.value
  end

  defp transform_payload(term), do: term
end
