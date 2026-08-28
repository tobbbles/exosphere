defmodule Exosphere.ATProto.MST.Store.ETS do
  @moduledoc """
  An ETS-backed `Exosphere.ATProto.MST.Store`.

  A map store copies its whole block map on every write, which is fine for the
  handful of blocks in a firehose proof and wrong for a repository with a
  million nodes. This one keeps blocks in an ETS table, so writes are constant
  time and the tree code does not carry the repository through every call.

  The table is mutable and shared: `put/3` returns the same store, and every
  process holding it sees the write. That is the point (a PDS serves reads
  from many processes against one repository), but it also means a store is
  not a value you can roll back — take a `snapshot/1` if you need one.

      store = Exosphere.ATProto.MST.Store.ETS.new()
      {:ok, root, store, _new} = Exosphere.ATProto.MST.apply_ops(root, store, ops)

  ## Ownership

  `new/1` creates the table owned by the calling process, so it dies with that
  process. Pass `:public` access (the default) to let other processes read and
  write; pass an existing table with `wrap/1` to reuse one created elsewhere
  (for example by a supervisor, so the table outlives a crashing worker).
  """

  @behaviour Exosphere.ATProto.MST.Store

  alias Exosphere.ATProto.CID

  @enforce_keys [:table]
  defstruct [:table]

  @type t :: %__MODULE__{table: :ets.table()}

  @doc """
  Create a store backed by a fresh ETS table.

  ## Options

    * `:name` - a table name (default: an anonymous table)
    * `:access` - `:public` (default), `:protected`, or `:private`
    * `:compressed` - pass `true` to trade CPU for memory on large repositories
  """
  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    access = Keyword.get(opts, :access, :public)
    name = Keyword.get(opts, :name, __MODULE__)

    options =
      [:set, access, {:read_concurrency, true}] ++
        if(Keyword.get(opts, :compressed, false), do: [:compressed], else: [])

    %__MODULE__{table: :ets.new(name, options)}
  end

  @doc """
  Wrap an existing ETS table as a store.
  """
  @spec wrap(:ets.table()) :: t()
  def wrap(table), do: %__MODULE__{table: table}

  @doc """
  Copy the store's blocks into a plain map.

  Useful to freeze a value for comparison or to hand a bounded set of blocks
  to something that wants a map (`Exosphere.ATProto.CAR.encode/3` takes
  either).
  """
  @spec snapshot(t()) :: %{CID.t() => binary()}
  def snapshot(%__MODULE__{table: table}), do: Map.new(:ets.tab2list(table))

  @doc """
  Number of blocks held.
  """
  @spec size(t()) :: non_neg_integer()
  def size(%__MODULE__{table: table}), do: :ets.info(table, :size)

  @doc """
  Delete the underlying table.
  """
  @spec destroy(t()) :: :ok
  def destroy(%__MODULE__{table: table}) do
    :ets.delete(table)
    :ok
  end

  @impl true
  def fetch(%__MODULE__{table: table}, %CID{} = cid) do
    case :ets.lookup(table, cid) do
      [{^cid, bytes}] -> {:ok, bytes}
      [] -> :error
    end
  end

  @impl true
  def put(%__MODULE__{table: table} = store, %CID{} = cid, bytes) when is_binary(bytes) do
    :ets.insert(table, {cid, bytes})
    store
  end

  @impl true
  def put_all(%__MODULE__{table: table} = store, entries) do
    :ets.insert(table, Enum.to_list(entries))
    store
  end

  @impl true
  def member?(%__MODULE__{table: table}, %CID{} = cid), do: :ets.member(table, cid)
end
