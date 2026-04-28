defmodule Exosphere.TID do
  @moduledoc """
  Convenience wrapper around `Exosphere.ATProto.TID`.
  """

  @doc """
  Generate a new TID string.
  """
  @spec generate() :: String.t()
  defdelegate generate(), to: Exosphere.ATProto.TID

  @doc """
  Generate a TID for a specific datetime.
  """
  @spec generate_for(DateTime.t()) :: String.t()
  defdelegate generate_for(dt), to: Exosphere.ATProto.TID

  @doc """
  Convert a TID string to a `DateTime`.
  """
  @spec to_datetime(String.t()) :: {:ok, DateTime.t()} | {:error, :invalid_tid}
  defdelegate to_datetime(tid), to: Exosphere.ATProto.TID

  @doc """
  Validate a TID string.
  """
  @spec valid?(String.t()) :: boolean()
  defdelegate valid?(tid), to: Exosphere.ATProto.TID

  @doc """
  Compare two TIDs chronologically. Returns `:lt`, `:eq`, or `:gt`.
  """
  @spec compare(String.t(), String.t()) :: :lt | :eq | :gt
  defdelegate compare(tid1, tid2), to: Exosphere.ATProto.TID
end
