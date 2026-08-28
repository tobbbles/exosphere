defmodule Exosphere.ATProto.MST.Blocks do
  @moduledoc false
  # Reading a block source.
  #
  # The tree only ever *reads* blocks — new nodes are accumulated and returned
  # to the caller, never written back — so a source needs one operation, and
  # the two useful shapes for it are a map and a function.

  alias Exosphere.ATProto.CID

  @type source ::
          %{CID.t() => binary() | map()}
          | (CID.t() -> {:ok, binary() | map()} | :error | {:error, term()})

  @spec fetch(source(), CID.t()) ::
          {:ok, binary() | map()} | {:error, {:missing_block, CID.t()} | term()}
  def fetch(source, %CID{} = cid) when is_map(source) and not is_struct(source) do
    case Map.fetch(source, cid) do
      {:ok, block} -> {:ok, block}
      :error -> {:error, {:missing_block, cid}}
    end
  end

  def fetch(source, %CID{} = cid) when is_function(source, 1) do
    case source.(cid) do
      {:ok, block} -> {:ok, block}
      :error -> {:error, {:missing_block, cid}}
      {:error, _} = error -> error
    end
  end
end
