defmodule Exosphere.ATProto.Base58 do
  @moduledoc """
  Minimal base58btc codec used for did:key and Multikey encoding.

  Implements the Bitcoin/IPFS base58 alphabet (see Multibase prefix `z`).
  This is intentionally small and is not exposed as a top-level Elixir
  `Base58` module to avoid namespace pollution for library consumers.
  """

  @alphabet ~c"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  @doc """
  Encode a binary to base58btc.
  """
  @spec encode(binary()) :: String.t()
  def encode(bytes) when is_binary(bytes) do
    bytes
    |> :binary.decode_unsigned()
    |> encode_int([])
    |> prepend_zeros(bytes)
    |> to_string()
  end

  defp encode_int(0, acc), do: acc

  defp encode_int(n, acc) do
    encode_int(div(n, 58), [Enum.at(@alphabet, rem(n, 58)) | acc])
  end

  defp prepend_zeros(acc, <<0, rest::binary>>), do: prepend_zeros([?1 | acc], rest)
  defp prepend_zeros(acc, _), do: acc

  @doc """
  Decode a base58btc string to a binary. Returns `{:ok, binary}` or `:error`.
  """
  @spec decode(String.t()) :: {:ok, binary()} | :error
  def decode(string) when is_binary(string) do
    chars = String.to_charlist(string)
    zeros = chars |> Enum.take_while(&(&1 == ?1)) |> length()

    case decode_chars(chars, 0) do
      {:ok, num} ->
        bytes = :binary.encode_unsigned(num)
        {:ok, :binary.copy(<<0>>, zeros) <> bytes}

      :error ->
        :error
    end
  end

  defp decode_chars([], acc), do: {:ok, acc}

  defp decode_chars([char | rest], acc) do
    case Enum.find_index(@alphabet, &(&1 == char)) do
      nil -> :error
      idx -> decode_chars(rest, acc * 58 + idx)
    end
  end
end
