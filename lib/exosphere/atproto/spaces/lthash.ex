defmodule Exosphere.ATProto.Spaces.Lthash do
  @moduledoc """
  LtHash: the homomorphic set hash a permissioned repo commits to (atproto
  proposal 0016).

  The state is 1024 little-endian `u16` lanes. Each element — the string
  `"{collection}/{rkey}/{record_cid}"` — is expanded to 2048 bytes of BLAKE3
  XOF output and added into the lanes modulo 2¹⁶ (removed elements are
  subtracted). Addition commutes, so the state depends only on the current
  *set* of records, never on the order they were added, and it can be updated
  incrementally as records come and go. The commit digest is
  `sha256(state)`.

  Cross-checked against the reference implementation's vectors (generated with
  `@noble/hashes`, the library the reference uses): the empty digest, and the
  digest after folding the elements `"one"` and `"two"`.

  Expansion and lane folding both happen in the BLAKE3 NIF
  (`Exosphere.ATProto.Spaces.Blake3`), fused into one native call — a full-repo
  verification folds one element per record, so this is the sync path's hot
  loop. Use `add_many/2` and `remove_many/2` for bulk folds: they hand the
  whole batch to a single dirty-scheduled call instead of crossing the NIF
  boundary once per record.

  ## Examples

      iex> alias Exosphere.ATProto.Spaces.Lthash
      iex> Lthash.new() |> Lthash.digest() |> Base.encode16()
      "E5A00AA9991AC8A5EE3109844D84A55583BD20572AD3FFCD42792F3C36B183AD"
  """

  alias Exosphere.ATProto.Spaces.Blake3.Native

  @lanes 1024
  @lane_bytes 2
  @state_bytes @lanes * @lane_bytes

  @enforce_keys [:state]
  defstruct [:state]

  @type t :: %__MODULE__{state: binary()}

  @doc """
  The empty set hash: 2048 zero bytes.
  """
  @spec new() :: t()
  def new, do: %__MODULE__{state: :binary.copy(<<0>>, @state_bytes)}

  @doc """
  Resume from a persisted 2048-byte state, or start empty when `nil`.
  """
  @spec from_state(binary() | nil) :: {:ok, t()} | {:error, :invalid_state}
  def from_state(nil), do: {:ok, new()}

  def from_state(state) when is_binary(state) and byte_size(state) == @state_bytes,
    do: {:ok, %__MODULE__{state: state}}

  def from_state(_), do: {:error, :invalid_state}

  @doc """
  The raw 2048-byte state, for persistence between syncs.
  """
  @spec state(t()) :: binary()
  def state(%__MODULE__{state: state}), do: state

  @doc """
  Add an element to the set.
  """
  @spec add(t(), String.t()) :: t()
  def add(%__MODULE__{state: state}, element) when is_binary(element) do
    %__MODULE__{state: Native.lthash_fold(state, element, true)}
  end

  @doc """
  Add many elements in one native call.

  Equivalent to `Enum.reduce(elements, set, &add(&2, &1))`, but crosses the NIF
  boundary once — the difference matters when folding a whole repo.
  """
  @spec add_many(t(), [String.t()]) :: t()
  def add_many(%__MODULE__{} = set, []), do: set

  def add_many(%__MODULE__{state: state}, elements) when is_list(elements) do
    %__MODULE__{state: Native.lthash_fold_many(state, elements, true)}
  end

  @doc """
  Remove an element from the set.
  """
  @spec remove(t(), String.t()) :: t()
  def remove(%__MODULE__{state: state}, element) when is_binary(element) do
    %__MODULE__{state: Native.lthash_fold(state, element, false)}
  end

  @doc """
  Remove many elements in one native call.
  """
  @spec remove_many(t(), [String.t()]) :: t()
  def remove_many(%__MODULE__{} = set, []), do: set

  def remove_many(%__MODULE__{state: state}, elements) when is_list(elements) do
    %__MODULE__{state: Native.lthash_fold_many(state, elements, false)}
  end

  @doc """
  The commit digest: sha256 over the raw lane state (32 bytes).
  """
  @spec digest(t()) :: binary()
  def digest(%__MODULE__{state: state}), do: :crypto.hash(:sha256, state)

  @doc """
  Whether the set is empty (all lanes zero).
  """
  @spec empty?(t()) :: boolean()
  def empty?(%__MODULE__{state: state}),
    do: state == :binary.copy(<<0>>, @state_bytes)

  @doc """
  Whether two set hashes describe the same set.
  """
  @spec equal?(t(), t()) :: boolean()
  def equal?(%__MODULE__{state: a}, %__MODULE__{state: b}), do: a == b
end
