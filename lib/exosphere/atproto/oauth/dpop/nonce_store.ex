defmodule Exosphere.ATProto.OAuth.DPoP.NonceStore do
  @moduledoc """
  Per-authorization-server DPoP nonce cache.

  Authorization servers issue a nonce (in the `DPoP-Nonce` response header)
  that clients must echo in subsequent proof JWTs for that server. The nonce
  is shared state across requests, so it lives in a public ETS table owned by
  this small `GenServer`, keyed by server origin (`scheme://host[:port]`).

  Started by `Exosphere.Application` (which the Hex dependency starts
  automatically). Reads never fail when the table is missing; writes to a
  missing table return `{:error, :not_started}`.
  """

  use GenServer

  @table __MODULE__

  @type server :: GenServer.server()

  @doc false
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, :ok, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc """
  Fetch the current nonce for a server origin, if any.
  """
  @spec get(String.t()) :: String.t() | nil
  def get(origin) when is_binary(origin) do
    if table_exists?(), do: :ets.lookup_element(@table, origin, 2, nil)
  end

  @doc """
  Remember the nonce issued by a server origin.
  """
  @spec put(String.t(), String.t()) :: :ok | {:error, :not_started}
  def put(origin, nonce) when is_binary(origin) and is_binary(nonce) do
    if table_exists?() do
      :ets.insert(@table, {origin, nonce})
      :ok
    else
      {:error, :not_started}
    end
  end

  @doc """
  Forget the nonce for a server origin (e.g. after it is rejected).
  """
  @spec clear(String.t()) :: :ok | {:error, :not_started}
  def clear(origin) when is_binary(origin) do
    if table_exists?() do
      :ets.delete(@table, origin)
      :ok
    else
      {:error, :not_started}
    end
  end

  @impl GenServer
  def init(:ok) do
    if table_exists?() do
      # A previous owner crashed; reuse the table so nonces survive restarts
      :ok
    else
      :ets.new(@table, [:set, :named_table, :public, read_concurrency: true])
    end

    {:ok, %{}}
  end

  defp table_exists?, do: :ets.whereis(@table) != :undefined
end
