defmodule Exosphere.ATProto.MST.Store do
  @moduledoc """
  A block store: CID → encoded block bytes.

  `Exosphere.ATProto.MST` reads nodes through this interface and writes new
  ones back through it, so the same tree code works over a handful of proof
  blocks in a map, a whole repository in ETS, or whatever you keep your blocks
  in — Postgres, S3, a cache in front of either. Two implementations ship (a
  plain map and `Exosphere.ATProto.MST.Store.ETS`); this behaviour is the seam
  for the rest.

  ## Shapes

  Three things are accepted anywhere a store is:

    * a plain map — `%{CID.t() => binary() | map()}`, which is what
      `Exosphere.ATProto.CAR.decode/1` hands back. Values may be encoded bytes
      or already-decoded node maps. Reads and writes are pure, so a map store
      is threaded through calls like any other immutable value.
    * `{module, state}` — any module implementing this behaviour, with
      whatever state it wants alongside.
    * a struct whose own module implements this behaviour, which is the tidier
      form when your state is already a struct: pass the struct on its own and
      it is both the implementation and the state.
      `Exosphere.ATProto.MST.Store.ETS` works this way.

  ## Writing an implementation

  Four callbacks, over whatever backing you like:

      defmodule MyStore do
        @behaviour Exosphere.ATProto.MST.Store

        @impl true
        def fetch(repo, cid), do: # {:ok, bytes} | :error

        @impl true
        def put(repo, cid, bytes), do: # the new state

        @impl true
        def put_all(repo, entries), do: # the new state

        @impl true
        def member?(repo, cid), do: # boolean
      end

  Then pass `{MyStore, state}` anywhere a store is taken:

      {:ok, root, store, written} =
        Exosphere.ATProto.MST.apply_ops(root, {MyStore, repo}, ops)

  If your state is a struct defined by the same module, pass it bare instead —
  `%MyStore{}` rather than `{MyStore, %MyStore{}}` — and it is recognised by
  its own module implementing `c:fetch/2`.

  Two rules bind an implementation:

    * `fetch/2` returns encoded block bytes (or an already-decoded node map).
      Do not decode and re-encode blocks on the way through — DAG-CBOR byte
      strings do not survive that round trip, and a commit block that makes it
      gets a different CID.
    * `put/3` and `put_all/2` return the (possibly new) state. An immutable
      backing returns an updated value; a mutable one (ETS, a database) returns
      its own state unchanged. Callers always use the returned value, so both
      work.

  Nothing here assumes the blocks are an MST: a store is a content-addressed
  bag of bytes, and is equally usable for record and blob blocks.
  """

  alias Exosphere.ATProto.CID
  alias Exosphere.ATProto.MST.Store.ETS

  @typedoc """
  Anything `fetch/2` and friends accept: a plain map, a `{module, state}`
  pair, or a struct whose module implements this behaviour.
  """
  @type t :: %{CID.t() => binary() | map()} | {module(), term()} | struct()

  @doc "Look up a block's bytes (or decoded node)."
  @callback fetch(state :: term(), CID.t()) :: {:ok, binary() | map()} | :error

  @doc "Store one block, returning the new state."
  @callback put(state :: term(), CID.t(), binary()) :: term()

  @doc "Store many blocks, returning the new state."
  @callback put_all(state :: term(), Enumerable.t()) :: term()

  @doc "Whether a block is present."
  @callback member?(state :: term(), CID.t()) :: boolean()

  @doc """
  Fetch a block, or `{:error, {:missing_block, cid}}`.

  The error shape matches `Exosphere.ATProto.MST.read/2` so a partial store
  (firehose proof blocks, an incremental CAR) reports the same missing-block
  failure wherever it is hit.
  """
  @spec fetch(t(), CID.t()) :: {:ok, binary() | map()} | {:error, {:missing_block, CID.t()}}
  def fetch(store, %CID{} = cid) do
    case do_fetch(store, cid) do
      {:ok, block} -> {:ok, block}
      :error -> {:error, {:missing_block, cid}}
    end
  end

  @doc """
  Store one block, returning the new store.
  """
  @spec put(t(), CID.t(), binary()) :: t()
  def put(store, %CID{} = cid, bytes) when is_binary(bytes) do
    case impl(store) do
      {module, state} -> rewrap(store, module.put(state, cid, bytes))
      :map -> Map.put(store, cid, bytes)
    end
  end

  @doc """
  Store many `{cid, bytes}` blocks, returning the new store.
  """
  @spec put_all(t(), Enumerable.t()) :: t()
  def put_all(store, entries) do
    case impl(store) do
      {module, state} -> rewrap(store, module.put_all(state, entries))
      :map -> Enum.into(entries, store)
    end
  end

  @doc """
  Whether a block is present, without decoding it.
  """
  @spec member?(t(), CID.t()) :: boolean()
  def member?(store, %CID{} = cid) do
    case impl(store) do
      {module, state} -> module.member?(state, cid)
      :map -> Map.has_key?(store, cid)
    end
  end

  @doc """
  An empty in-memory (map) store.
  """
  @spec new() :: %{CID.t() => binary()}
  def new, do: %{}

  defp do_fetch(store, cid) do
    case impl(store) do
      {module, state} -> module.fetch(state, cid)
      :map -> Map.fetch(store, cid)
    end
  end

  # `{module, state}` and structs carry their own implementation; anything else
  # map-shaped is a plain block map.
  defp impl({module, state}) when is_atom(module), do: {module, state}
  defp impl(%ETS{} = store), do: {ETS, store}
  defp impl(store) when is_map(store) and not is_struct(store), do: :map

  defp impl(%module{} = store) do
    if function_exported?(module, :fetch, 2) do
      {module, store}
    else
      raise ArgumentError, "#{inspect(module)} does not implement Exosphere.ATProto.MST.Store"
    end
  end

  # A `{module, state}` store keeps its wrapper; a struct store is its own state.
  defp rewrap({module, _old}, state), do: {module, state}
  defp rewrap(_store, state), do: state
end
