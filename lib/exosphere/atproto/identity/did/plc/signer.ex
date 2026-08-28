defmodule Exosphere.ATProto.Identity.DID.PLC.Signer do
  @moduledoc """
  Signing, signature verification, and DID derivation for did:plc operations.

  did:plc is *self-certifying*: the identifier is derived from the signed
  genesis operation itself, so nothing pre-exists the key that controls it.

      did:plc:<first 24 chars of lowercase base32 of sha256(dagcbor(signed genesis))>

  ## What is signed

  The DAG-CBOR encoding of the operation with `sig` **omitted entirely** —
  see `Operation.unsigned_bytes/1`. Signatures are ECDSA-SHA256, low-S
  normalized, emitted as raw 32+32-byte big-endian R||S and encoded
  **base64url without padding**.

  Low-S handling is `Exosphere.ATProto.Crypto`'s job, not this module's:
  `Crypto.sign/3` normalizes and `Crypto.verify/4` rejects high-S. This
  module adds the base64url layer and the strictness the directory applies
  to it — a signature carrying padding characters, non-canonical padding
  bits, or whitespace is rejected before it ever reaches the curve.
  """

  alias Exosphere.ATProto.Crypto
  alias Exosphere.ATProto.Identity.DID.PLC.Operation

  @did_prefix "did:plc:"
  @did_length 24

  @whitespace ~r/\s/

  @doc """
  Sign an unsigned operation, returning it with `sig` set.

  ## Examples

      iex> {:ok, signed} = Signer.sign(op, private_key, :secp256k1)
      iex> is_binary(signed["sig"])
      true
  """
  @spec sign(Operation.t(), binary(), Crypto.curve()) ::
          {:ok, Operation.t()} | {:error, term()}
  def sign(op, private_key, curve) when is_map(op) do
    with {:ok, bytes} <- Operation.unsigned_bytes(op),
         {:ok, signature} <- Crypto.sign(bytes, private_key, curve) do
      {:ok, Map.put(op, "sig", encode_signature(signature))}
    end
  end

  @doc """
  Verify an operation's signature against a single `did:key`.

  Returns `:ok`, or `{:error, :invalid_signature}` for a bad signature —
  including a malformed base64url encoding, which the directory treats as
  invalid rather than as a decoding accident.
  """
  @spec verify(Operation.t(), String.t()) :: :ok | {:error, term()}
  def verify(op, did_key) when is_map(op) and is_binary(did_key) do
    with {:ok, signature} <- decode_signature(Map.get(op, "sig")),
         {:ok, public_key, curve} <- Crypto.from_did_key(did_key),
         {:ok, bytes} <- Operation.unsigned_bytes(op) do
      Crypto.verify(bytes, signature, public_key, curve)
    else
      {:error, _} -> {:error, :invalid_signature}
    end
  end

  @doc """
  Verify an operation against a list of candidate rotation keys, returning
  the index of the key that signed it.

  The index *is* the authority level — rotation keys are ordered by
  descending authority, so a lower index means a stronger key, which is what
  the nullification rules compare.
  """
  @spec verify_with_keys(Operation.t(), [String.t()]) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def verify_with_keys(op, keys) when is_map(op) and is_list(keys) do
    keys
    |> Enum.with_index()
    |> Enum.find_value({:error, :invalid_signature}, fn {key, index} ->
      case verify(op, key) do
        :ok -> {:ok, index}
        {:error, _} -> nil
      end
    end)
  end

  @doc """
  Derive the DID from a signed genesis operation.

  The operation must already carry its `sig`; the DID covers the *signed*
  bytes.

  ## Examples

      iex> Signer.derive_did(signed_genesis)
      {:ok, "did:plc:6adr3q2labdllanslzhqkqd3"}
  """
  @spec derive_did(Operation.t()) :: {:ok, String.t()} | {:error, term()}
  def derive_did(op) when is_map(op) do
    case Operation.signed_bytes(op) do
      {:ok, bytes} ->
        did =
          :sha256
          |> :crypto.hash(bytes)
          |> Base.encode32(case: :lower, padding: false)
          |> binary_part(0, @did_length)

        {:ok, @did_prefix <> did}

      error ->
        error
    end
  end

  @doc """
  The CID of a signed operation, as the directory reports it in an audit log.
  """
  @spec cid(Operation.t()) :: {:ok, String.t()} | {:error, term()}
  def cid(op) when is_map(op) do
    # CID.create encodes (and therefore validates encodability) itself.
    with {:ok, cid} <- Exosphere.ATProto.CID.create(op) do
      {:ok, Exosphere.ATProto.CID.encode(cid)}
    end
  end

  @doc """
  Encode a raw 64-byte signature as base64url without padding.
  """
  @spec encode_signature(binary()) :: String.t()
  def encode_signature(signature) when byte_size(signature) == 64 do
    Base.url_encode64(signature, padding: false)
  end

  @doc """
  Decode an operation signature, strictly.

  Rejects padding characters, whitespace/newlines, and non-canonical padding
  bits in the final sextet — all of which the directory's conformance
  fixtures exercise as invalid.
  """
  @spec decode_signature(term()) :: {:ok, binary()} | {:error, term()}
  def decode_signature(sig) when is_binary(sig) do
    cond do
      String.contains?(sig, "=") ->
        {:error, :signature_padding_chars}

      String.match?(sig, @whitespace) ->
        {:error, :signature_whitespace}

      true ->
        case Base.url_decode64(sig, padding: false) do
          {:ok, raw} -> check_canonical(sig, raw)
          :error -> {:error, :invalid_signature_encoding}
        end
    end
  end

  def decode_signature(_), do: {:error, :missing_signature}

  # Elixir's Base does not reject a final sextet whose unused low bits are
  # set, but the directory does. Re-encoding the decoded bytes and comparing
  # catches exactly that: a non-canonical encoding cannot round-trip.
  defp check_canonical(original, raw) do
    if Base.url_encode64(raw, padding: false) == original do
      {:ok, raw}
    else
      {:error, :signature_padding_bits}
    end
  end
end
