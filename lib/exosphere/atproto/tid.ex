defmodule Exosphere.ATProto.TID do
  @moduledoc """
  Timestamp ID (TID) generation for Exosphere.ATProto records.

  TIDs are used as record keys in Exosphere.ATProto repositories. They are:
  - Lexicographically sortable
  - Collision-resistant (timestamp + random component)
  - Base32-sortable encoded (13 characters)

  ## Format

  A TID is a 64-bit value encoded as base32-sortable:
  - Bits 63-10: Microseconds since Unix epoch (54 bits)
  - Bits 9-0: Clock identifier (10 bits, random per process)

  ## Examples

      iex> Exosphere.ATProto.TID.generate()
      "3jui7kd2lry2e"

      iex> Exosphere.ATProto.TID.to_datetime("3jui7kd2lry2e")
      {:ok, ~U[2024-01-15 12:30:45.123456Z]}
  """

  import Bitwise

  # Base32 sortable alphabet (Crockford-like)
  @alphabet ~c"234567abcdefghijklmnopqrstuvwxyz"

  # Clock ID is random per process, used to reduce collision risk
  @clock_id_bits 10
  @clock_id_mask bsl(1, @clock_id_bits) - 1

  @doc """
  Generate a new TID.

  ## Examples

      iex> tid = Exosphere.ATProto.TID.generate()
      iex> String.length(tid)
      13
  """
  @spec generate() :: String.t()
  def generate do
    # Get current time in microseconds
    now_micros = System.system_time(:microsecond)

    # Get or create clock ID for this process
    clock_id = get_clock_id()

    # Combine timestamp and clock ID
    # Shift timestamp left by 10 bits, add clock ID
    value = bor(bsl(now_micros, @clock_id_bits), clock_id)

    encode(value)
  end

  @doc """
  Generate a TID for a specific datetime.

  Useful for testing or creating TIDs for past events.
  """
  @spec generate_for(DateTime.t()) :: String.t()
  def generate_for(%DateTime{} = dt) do
    micros = DateTime.to_unix(dt, :microsecond)
    clock_id = get_clock_id()
    value = bor(bsl(micros, @clock_id_bits), clock_id)
    encode(value)
  end

  @doc """
  Parse a TID and extract its timestamp.

  ## Examples

      iex> {:ok, dt} = Exosphere.ATProto.TID.to_datetime("3jui7kd2lry2e")
      iex> dt.year
      2024
  """
  @spec to_datetime(String.t()) :: {:ok, DateTime.t()} | {:error, :invalid_tid}
  def to_datetime(tid) when is_binary(tid) and byte_size(tid) == 13 do
    case decode(tid) do
      {:ok, value} ->
        # Extract timestamp (shift right to remove clock ID)
        micros = bsr(value, @clock_id_bits)
        {:ok, DateTime.from_unix!(micros, :microsecond)}

      :error ->
        {:error, :invalid_tid}
    end
  end

  def to_datetime(_), do: {:error, :invalid_tid}

  @doc """
  Validate a TID string.
  """
  @spec valid?(String.t()) :: boolean()
  def valid?(tid) when is_binary(tid) and byte_size(tid) == 13 do
    case decode(tid) do
      {:ok, _} -> true
      :error -> false
    end
  end

  def valid?(_), do: false

  @doc """
  Compare two TIDs chronologically.

  Returns `:lt`, `:eq`, or `:gt`.
  """
  @spec compare(String.t(), String.t()) :: :lt | :eq | :gt
  def compare(tid1, tid2) when is_binary(tid1) and is_binary(tid2) do
    # TIDs are lexicographically sortable, so string comparison works
    cond do
      tid1 < tid2 -> :lt
      tid1 > tid2 -> :gt
      true -> :eq
    end
  end

  # Encode a 64-bit value to base32-sortable
  defp encode(value) do
    encode_loop(value, 13, [])
    |> IO.iodata_to_binary()
  end

  defp encode_loop(_value, 0, acc), do: acc

  defp encode_loop(value, remaining, acc) do
    char_index = band(value, 0x1F)
    char = Enum.at(@alphabet, char_index)
    encode_loop(bsr(value, 5), remaining - 1, [char | acc])
  end

  # Decode base32-sortable to 64-bit value
  defp decode(string) do
    chars = String.to_charlist(string)
    decode_loop(chars, 0)
  end

  defp decode_loop([], acc), do: {:ok, acc}

  defp decode_loop([char | rest], acc) do
    case Enum.find_index(@alphabet, &(&1 == char)) do
      nil -> :error
      idx -> decode_loop(rest, bor(bsl(acc, 5), idx))
    end
  end

  # Get or generate clock ID for this process
  defp get_clock_id do
    case Process.get(:atproto_tid_clock_id) do
      nil ->
        clock_id = :rand.uniform(@clock_id_mask + 1) - 1
        Process.put(:atproto_tid_clock_id, clock_id)
        clock_id

      clock_id ->
        clock_id
    end
  end
end
