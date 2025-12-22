defmodule Exosphere.ATProto.CBOR do
  @moduledoc """
  DAG-CBOR encoding and decoding with Exosphere.ATProto normalization.

  DAG-CBOR is a restricted subset of CBOR used for content-addressed data.
  This module wraps the `:cbor` library with Exosphere.ATProto-specific handling for:

  - CID links (CBOR tag 42)
  - Strict map key ordering (lexicographic)
  - No floating point numbers (Exosphere.ATProto disallows floats)
  - Bytes and link representation

  ## Examples

      iex> Exosphere.ATProto.CBOR.encode(%{"hello" => "world"})
      {:ok, <<...>>}

      iex> Exosphere.ATProto.CBOR.decode(cbor_bytes)
      {:ok, %{"hello" => "world"}}

  ## CID Links

  CID links are encoded with CBOR tag 42 and decoded as `Exosphere.ATProto.CID` structs:

      iex> cid = Exosphere.ATProto.CID.decode!("bafyreigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi")
      iex> Exosphere.ATProto.CBOR.encode(%{"ref" => cid})
      {:ok, <<...>>}  # Contains tag 42 with CID bytes
  """

  alias Exosphere.ATProto.CID

  # CBOR tag for CID links per DAG-CBOR spec
  @cid_tag 42

  @type encode_error :: {:error, term()}
  @type decode_error :: {:error, :invalid_cbor | :unsupported_type | term()}

  @doc """
  Encode a term to DAG-CBOR binary format.

  Maps are encoded with keys in sorted order (lexicographic byte ordering).
  CID structs are encoded with CBOR tag 42.

  ## Options

  - `:canonical` - Force canonical/deterministic encoding (default: true)

  ## Examples

      iex> Exosphere.ATProto.CBOR.encode(%{"b" => 1, "a" => 2})
      {:ok, binary}  # Keys sorted as "a", "b"

      iex> Exosphere.ATProto.CBOR.encode(3.14)
      {:error, :floats_not_allowed}
  """
  @spec encode(term(), keyword()) :: {:ok, binary()} | encode_error()
  def encode(term, opts \\ []) do
    canonical = Keyword.get(opts, :canonical, true)

    term
    |> prepare_for_encoding()
    |> do_encode(canonical)
  rescue
    e in [ArgumentError] ->
      if Exception.message(e) == "floats_not_allowed" do
        {:error, :floats_not_allowed}
      else
        {:error, e}
      end

    e ->
      {:error, e}
  end

  @doc """
  Encode a term to DAG-CBOR, raising on error.
  """
  @spec encode!(term(), keyword()) :: binary()
  def encode!(term, opts \\ []) do
    case encode(term, opts) do
      {:ok, binary} -> binary
      {:error, reason} -> raise ArgumentError, "CBOR encoding failed: #{inspect(reason)}"
    end
  end

  @doc """
  Decode DAG-CBOR binary to an Elixir term.

  CID links (tag 42) are decoded as `Exosphere.ATProto.CID` structs.

  ## Examples

      iex> Exosphere.ATProto.CBOR.decode(<<...>>)
      {:ok, %{"hello" => "world"}}

      iex> Exosphere.ATProto.CBOR.decode(<<0xFF>>)
      {:error, :invalid_cbor}
  """
  @spec decode(binary()) :: {:ok, term()} | decode_error()
  def decode(binary) when is_binary(binary) do
    case CBOR.decode(binary) do
      {:ok, term, _rest} ->
        {:ok, transform_after_decode(term)}

      {:error, _} = error ->
        error
    end
  rescue
    _ -> {:error, :invalid_cbor}
  end

  def decode(_), do: {:error, :invalid_cbor}

  @doc """
  Decode DAG-CBOR binary, raising on error.
  """
  @spec decode!(binary()) :: term()
  def decode!(binary) do
    case decode(binary) do
      {:ok, term} -> term
      {:error, reason} -> raise ArgumentError, "CBOR decoding failed: #{inspect(reason)}"
    end
  end

  # Prepare term for CBOR encoding by:
  # - Converting CID structs to tagged values
  # - Sorting map keys
  # - Validating no floats
  defp prepare_for_encoding(term) when is_map(term) and not is_struct(term) do
    term
    |> Enum.map(fn {k, v} -> {to_string(k), prepare_for_encoding(v)} end)
    |> Enum.sort_by(fn {k, _v} -> k end)
    |> Map.new()
  end

  defp prepare_for_encoding(term) when is_list(term) do
    Enum.map(term, &prepare_for_encoding/1)
  end

  defp prepare_for_encoding(%CID{} = cid) do
    # CID links are encoded as CBOR tag 42 with binary CID bytes
    # The bytes include multibase prefix 0x00 for binary
    cid_bytes = <<0x00>> <> CID.to_bytes(cid)
    %CBOR.Tag{tag: @cid_tag, value: cid_bytes}
  end

  defp prepare_for_encoding(term) when is_float(term) do
    raise ArgumentError, "floats_not_allowed"
  end

  defp prepare_for_encoding(term), do: term

  defp do_encode(term, true = _canonical) do
    {:ok, CBOR.encode(term)}
  end

  defp do_encode(term, false = _canonical) do
    {:ok, CBOR.encode(term)}
  end

  # Transform decoded CBOR, converting tag 42 to CID structs
  defp transform_after_decode(%CBOR.Tag{tag: @cid_tag, value: bytes}) when is_binary(bytes) do
    # Remove the 0x00 multibase prefix for binary encoding
    <<0x00, cid_bytes::binary>> = bytes
    CID.from_bytes!(cid_bytes)
  end

  defp transform_after_decode(term) when is_map(term) and not is_struct(term) do
    Map.new(term, fn {k, v} -> {k, transform_after_decode(v)} end)
  end

  defp transform_after_decode(term) when is_list(term) do
    Enum.map(term, &transform_after_decode/1)
  end

  defp transform_after_decode(term), do: term

  @doc """
  Hash the DAG-CBOR encoding of a term using SHA-256.

  This is used for generating CIDs of data objects.

  ## Examples

      iex> Exosphere.ATProto.CBOR.hash(%{"hello" => "world"})
      {:ok, <<sha256_bytes::binary-32>>}
  """
  @spec hash(term()) :: {:ok, binary()} | {:error, term()}
  def hash(term) do
    case encode(term) do
      {:ok, cbor} -> {:ok, :crypto.hash(:sha256, cbor)}
      error -> error
    end
  end
end
