defmodule Exosphere.ATProto.CID do
  @moduledoc """
  Content Identifier (CID) handling for Exosphere.ATProto.

  CIDs are self-describing content-addressed identifiers used throughout Exosphere.ATProto
  for referencing data objects (DAG-CBOR) and blobs (raw bytes).

  ## Exosphere.ATProto CID Requirements

  Exosphere.ATProto uses a specific "blessed" CID format:

  - CIDv1
  - Multibase: `base32` for string encoding, binary for DAG-CBOR
  - Multicodec: `dag-cbor` (0x71) for data objects, `raw` (0x55) for blobs
  - Multihash: `sha-256` (0x12) with 256 bits

  ## Examples

      # Create a CID from data
      iex> {:ok, cid} = Exosphere.ATProto.CID.create(%{"hello" => "world"})
      iex> to_string(cid)
      "bafyreigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"

      # Parse a CID string
      iex> {:ok, cid} = Exosphere.ATProto.CID.decode("bafyreigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
      iex> cid.codec
      :dag_cbor

      # Create a CID for a blob
      iex> {:ok, cid} = Exosphere.ATProto.CID.create_raw(<<binary_data>>)
      iex> cid.codec
      :raw
  """

  alias Exosphere.ATProto.CBOR

  @enforce_keys [:version, :codec, :hash]
  defstruct [:version, :codec, :hash]

  @type t :: %__MODULE__{
          version: 1,
          codec: :dag_cbor | :raw,
          hash: binary()
        }

  # Multicodec codes
  @codec_dag_cbor 0x71
  @codec_raw 0x55

  # Multihash codes
  @hash_sha256 0x12
  @hash_sha256_length 32

  # Multibase prefixes
  @multibase_base32_lower "b"

  @doc """
  Create a CID for a DAG-CBOR encoded term.

  The term is encoded with `Exosphere.ATProto.CBOR.encode/1` and hashed with SHA-256.

  ## Examples

      iex> {:ok, cid} = Exosphere.ATProto.CID.create(%{"foo" => "bar"})
      iex> cid.codec
      :dag_cbor
  """
  @spec create(term()) :: {:ok, t()} | {:error, term()}
  def create(term) do
    case CBOR.hash(term) do
      {:ok, hash} ->
        {:ok,
         %__MODULE__{
           version: 1,
           codec: :dag_cbor,
           hash: hash
         }}

      error ->
        error
    end
  end

  @doc """
  Create a CID for a DAG-CBOR term, raising on error.
  """
  @spec create!(term()) :: t()
  def create!(term) do
    case create(term) do
      {:ok, cid} -> cid
      {:error, reason} -> raise ArgumentError, "CID creation failed: #{inspect(reason)}"
    end
  end

  @doc """
  Create a CID for raw binary data (blobs).

  ## Examples

      iex> {:ok, cid} = Exosphere.ATProto.CID.create_raw(<<1, 2, 3>>)
      iex> cid.codec
      :raw
  """
  @spec create_raw(binary()) :: {:ok, t()}
  def create_raw(data) when is_binary(data) do
    hash = :crypto.hash(:sha256, data)

    {:ok,
     %__MODULE__{
       version: 1,
       codec: :raw,
       hash: hash
     }}
  end

  @doc """
  Create a CID for raw binary data, raising on error.
  """
  @spec create_raw!(binary()) :: t()
  def create_raw!(data) do
    {:ok, cid} = create_raw(data)
    cid
  end

  @doc """
  Decode a CID from its string representation.

  Supports base32-encoded CIDv1 strings (prefix 'b').

  ## Examples

      iex> Exosphere.ATProto.CID.decode("bafyreigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
      {:ok, %Exosphere.ATProto.CID{...}}
  """
  @spec decode(String.t()) :: {:ok, t()} | {:error, term()}
  def decode(@multibase_base32_lower <> encoded) do
    case Base.decode32(String.upcase(encoded), padding: false) do
      {:ok, bytes} -> from_bytes(bytes)
      :error -> {:error, :invalid_base32}
    end
  end

  def decode(_), do: {:error, :unsupported_multibase}

  @doc """
  Decode a CID string, raising on error.
  """
  @spec decode!(String.t()) :: t()
  def decode!(string) do
    case decode(string) do
      {:ok, cid} -> cid
      {:error, reason} -> raise ArgumentError, "CID decode failed: #{inspect(reason)}"
    end
  end

  @doc """
  Create a CID from raw bytes (without multibase prefix).

  ## Examples

      iex> Exosphere.ATProto.CID.from_bytes(<<0x01, 0x71, 0x12, 0x20, hash::binary-32>>)
      {:ok, %Exosphere.ATProto.CID{...}}
  """
  @spec from_bytes(binary()) :: {:ok, t()} | {:error, term()}
  def from_bytes(<<0x01, codec, @hash_sha256, @hash_sha256_length, hash::binary-32>>) do
    case codec_from_int(codec) do
      {:ok, codec_atom} ->
        {:ok, %__MODULE__{version: 1, codec: codec_atom, hash: hash}}

      error ->
        error
    end
  end

  def from_bytes(_), do: {:error, :invalid_cid_bytes}

  @doc """
  Create a CID from raw bytes, raising on error.
  """
  @spec from_bytes!(binary()) :: t()
  def from_bytes!(bytes) do
    case from_bytes(bytes) do
      {:ok, cid} -> cid
      {:error, reason} -> raise ArgumentError, "CID from_bytes failed: #{inspect(reason)}"
    end
  end

  @doc """
  Convert a CID to its raw byte representation (without multibase prefix).
  """
  @spec to_bytes(t()) :: binary()
  def to_bytes(%__MODULE__{version: 1, codec: codec, hash: hash}) do
    codec_int = codec_to_int(codec)
    <<0x01, codec_int, @hash_sha256, @hash_sha256_length, hash::binary>>
  end

  @doc """
  Encode a CID to its string representation using base32.
  """
  @spec encode(t()) :: String.t()
  def encode(%__MODULE__{} = cid) do
    bytes = to_bytes(cid)
    @multibase_base32_lower <> String.downcase(Base.encode32(bytes, padding: false))
  end

  @doc """
  Check if a CID uses the dag-cbor codec.
  """
  @spec dag_cbor?(t()) :: boolean()
  def dag_cbor?(%__MODULE__{codec: :dag_cbor}), do: true
  def dag_cbor?(_), do: false

  @doc """
  Check if a CID uses the raw codec.
  """
  @spec raw?(t()) :: boolean()
  def raw?(%__MODULE__{codec: :raw}), do: true
  def raw?(_), do: false

  # Codec conversions
  defp codec_to_int(:dag_cbor), do: @codec_dag_cbor
  defp codec_to_int(:raw), do: @codec_raw

  defp codec_from_int(@codec_dag_cbor), do: {:ok, :dag_cbor}
  defp codec_from_int(@codec_raw), do: {:ok, :raw}
  defp codec_from_int(_), do: {:error, :unsupported_codec}

  defimpl String.Chars do
    alias Exosphere.ATProto.CID

    def to_string(cid), do: CID.encode(cid)
  end

  defimpl Jason.Encoder do
    alias Exosphere.ATProto.CID

    def encode(cid, opts) do
      # Exosphere.ATProto JSON encoding for CID links
      Jason.Encode.map(%{"$link" => CID.encode(cid)}, opts)
    end
  end

  defimpl Inspect do
    alias Exosphere.ATProto.CID

    def inspect(cid, _opts) do
      "#CID<#{CID.encode(cid)}>"
    end
  end
end
