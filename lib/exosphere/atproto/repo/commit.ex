defmodule Exosphere.ATProto.Repo.Commit do
  @moduledoc """
  Repository commit signature verification.

  Every repository commit is a DAG-CBOR object carrying a `sig` field: the raw
  ECDSA signature, in low-S form, over the SHA-256 of the *unsigned* commit
  (the same object with the `sig` field removed) encoded as canonical DAG-CBOR.

  This module re-encodes the unsigned commit and verifies the signature against
  an account's signing key, tying together `Exosphere.ATProto.CBOR`,
  `Exosphere.ATProto.Crypto`, and `Exosphere.ATProto.Identity`.

  ## Examples

      # With an explicit public key + curve
      :ok = Exosphere.ATProto.Repo.Commit.verify(commit, public_key, :secp256k1)

      # Or resolve the signing key straight from a DID Document
      :ok = Exosphere.ATProto.Repo.Commit.verify_with_document(commit, did_document)
  """

  # Aliased under a distinct name so `%CBOR.Tag{}` still refers to the `:cbor`
  # library struct.
  alias Exosphere.ATProto.CBOR, as: DagCBOR
  alias Exosphere.ATProto.Crypto
  alias Exosphere.ATProto.Identity.Document

  @type commit :: %{optional(String.t()) => term()}

  @doc """
  Verify a decoded commit object against a public key.

  The commit is the map produced by decoding the commit block (e.g. via
  `Exosphere.ATProto.CBOR.decode/1` or extracted from a CAR file), with the
  `data` field as an `Exosphere.ATProto.CID` and `sig` as raw bytes.

  Returns `:ok`, or `{:error, reason}` if the signature is missing, malformed,
  or invalid.
  """
  @spec verify(commit(), binary(), Crypto.curve()) ::
          :ok | {:error, :missing_sig | :invalid_signature | term()}
  def verify(commit, public_key, curve) when is_map(commit) do
    with {:ok, sig} <- extract_sig(commit),
         {:ok, bytes} <- DagCBOR.encode(unsigned(commit)) do
      Crypto.verify(bytes, sig, public_key, curve)
    end
  end

  @doc """
  Verify a commit using the signing key advertised in a DID Document.
  """
  @spec verify_with_document(commit(), Document.t()) ::
          :ok | {:error, :missing_sig | :invalid_signature | :not_found | term()}
  def verify_with_document(commit, %Document{} = doc) do
    with {:ok, public_key, curve} <- Document.get_signing_key(doc) do
      verify(commit, public_key, curve)
    end
  end

  # The `sig` field, normalized to raw bytes. CBOR byte strings decode to raw
  # binaries via CBOR.transform_links/1, but tolerate a wrapping :bytes tag too.
  defp extract_sig(commit) do
    case Map.get(commit, "sig") do
      sig when is_binary(sig) -> {:ok, sig}
      %CBOR.Tag{tag: :bytes, value: sig} when is_binary(sig) -> {:ok, sig}
      _ -> {:error, :missing_sig}
    end
  end

  defp unsigned(commit), do: Map.delete(commit, "sig")
end
