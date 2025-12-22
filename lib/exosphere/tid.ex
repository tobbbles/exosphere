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
  Convert a TID string to a `DateTime`.
  """
  @spec to_datetime(String.t()) :: {:ok, DateTime.t()} | {:error, term()}
  defdelegate to_datetime(tid), to: Exosphere.ATProto.TID
end
