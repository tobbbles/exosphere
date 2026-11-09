defmodule Exosphere.ATProto.Label do
  @moduledoc """
  Sign and verify `com.atproto.label.defs#label` objects.

  A label is a signed claim by a labeler about a record (`at://…`) or an
  account (`did:…`). Labels arrive from a labeler's
  `com.atproto.label.subscribeLabels` stream (see
  `Exosphere.ATProto.Firehose.Consumer` with
  `method: "com.atproto.label.subscribeLabels"`) or from `queryLabels`.

  Labels are handled as plain maps with string keys, the shape both the CBOR
  stream and the JSON query return. `sig` may be raw bytes (from CBOR) or
  `%{"$bytes" => base64}` (from JSON); both are accepted.

  ## Signing

  Per the label spec, the signed bytes are the DAG-CBOR encoding of the label's
  schema fields (`ver`, `src`, `uri`, `cid`, `val`, `neg`, `cts`, `exp`),
  without `sig` and without `$type`. The signature is ECDSA over the SHA-256 of
  those bytes, made with the `#atproto_label` key in the labeler's DID document.

  The spec says services should verify signatures when labels move between
  services, and that a document with no `#atproto_label` key cannot validate
  any label, so there is no fallback to `#atproto`.
  """

  alias Exosphere.ATProto.CBOR
  alias Exosphere.ATProto.Crypto
  alias Exosphere.ATProto.Identity.Document

  @type t :: %{required(String.t()) => term()}

  # The fields of com.atproto.label.defs#label other than sig. Only these are
  # signed: the spec warns that signatures are not domain-separated, so extra
  # fields must never be folded into the signing input.
  @signed_fields ~w(ver src uri cid val neg cts exp)

  @doc """
  The bytes a label's signature covers: its schema fields, DAG-CBOR encoded.

  Absent fields stay absent. A field that is present is kept as is, including
  `neg: false`, because a labeler that included it signed it.
  """
  @spec signing_input(t()) :: {:ok, binary()} | {:error, term()}
  def signing_input(label) when is_map(label) do
    label
    |> Map.take(@signed_fields)
    |> Map.reject(fn {_key, value} -> is_nil(value) end)
    |> CBOR.encode()
  end

  @doc """
  Sign a label with a labeler's `#atproto_label` private key.

  `label` should already carry `ver` (currently always `1`). Returns the label
  with `sig` set to the raw signature bytes.
  """
  @spec sign(t(), binary(), Crypto.curve()) :: {:ok, t()} | {:error, term()}
  def sign(label, private_key, curve) when is_map(label) do
    with {:ok, bytes} <- signing_input(label),
         {:ok, sig} <- Crypto.sign(bytes, private_key, curve) do
      {:ok, Map.put(label, "sig", sig)}
    end
  end

  @doc """
  Verify a label against its labeler's DID document.

  Checks that the document is the label's `src`, takes the `#atproto_label`
  key, and verifies the signature.

  Errors:

  - `:wrong_document` - the document is not the label's `src`
  - `:no_label_key` - the document has no `#atproto_label` key
  - `:unsigned` - the label has no usable `sig`
  - `:invalid_signature` - the signature does not match

  On `:invalid_signature`, the spec suggests re-resolving the labeler's DID
  once in case its key rotated, then trying again.
  """
  @spec verify(t(), Document.t()) ::
          :ok | {:error, :wrong_document | :no_label_key | :unsigned | :invalid_signature}
  def verify(%{"src" => src} = label, %Document{id: src} = doc) do
    case Document.get_label_key(doc) do
      {:ok, public_key, curve} -> verify_with_key(label, public_key, curve)
      {:error, :not_found} -> {:error, :no_label_key}
    end
  end

  def verify(_label, %Document{}), do: {:error, :wrong_document}

  @doc """
  Verify a label against an already-extracted public key.

  For callers that cache a labeler's key rather than its whole document.
  Checking that the key belongs to the label's `src` is the caller's job.
  """
  @spec verify_with_key(t(), binary(), Crypto.curve()) ::
          :ok | {:error, :unsigned | :invalid_signature}
  def verify_with_key(label, public_key, curve) when is_map(label) do
    with {:ok, sig} <- signature(label),
         {:ok, bytes} <- signing_input(label) do
      Crypto.verify(bytes, sig, public_key, curve)
    else
      {:error, :unsigned} -> {:error, :unsigned}
      {:error, _} -> {:error, :invalid_signature}
    end
  end

  @doc """
  Whether a label is in force at `now`: not a negation, and not expired.

  A negation (`neg: true`) withdraws an earlier label with the same `src`,
  `uri` and `val`; it is never itself "in force". An expired label should be
  kept but no longer applied.
  """
  @spec active?(t(), DateTime.t()) :: boolean()
  def active?(label, now \\ DateTime.utc_now())

  def active?(%{"neg" => true}, _now), do: false

  def active?(%{"exp" => exp}, now) when is_binary(exp) do
    case DateTime.from_iso8601(exp) do
      {:ok, expires_at, _offset} -> DateTime.compare(expires_at, now) == :gt
      # An unparseable expiry is treated as expired: better to stop applying a
      # malformed label than to apply it forever.
      {:error, _} -> false
    end
  end

  def active?(_label, _now), do: true

  defp signature(%{"sig" => %{"$bytes" => b64}}) when is_binary(b64) do
    case Base.decode64(b64, padding: false) do
      {:ok, sig} -> {:ok, sig}
      :error -> {:error, :unsigned}
    end
  end

  defp signature(%{"sig" => sig}) when is_binary(sig) and byte_size(sig) > 0, do: {:ok, sig}
  defp signature(_label), do: {:error, :unsigned}
end
