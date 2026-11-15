defmodule Exosphere.ATProto.Spaces.Kem do
  @moduledoc """
  The per-request shared secret that keys a repo host's MACs (proposal 0016,
  "Shared secret"; atproto `#5865`, in the November 12 alpha): HPKE secret
  export (RFC 9180 §6.2) in base mode, with DHKEM(P-256, HKDF-SHA256),
  HKDF-SHA256 and the Export-only AEAD (`Exosphere.ATProto.Crypto.HPKE`).

      # syncer
      enc, shared_secret = SendExportBase(author_kem_public_key, info="atproto-mac", exporter_context="", L=32)
      # repo host
      shared_secret = ReceiveExportBase(enc, author_kem_private_key, info="atproto-mac", exporter_context="", L=32)

  The repo host holds the private half of the author's `#atproto_kem` key
  (`Identity.Document.get_kem_key/1` resolves the public half). For every
  request — retries and each page included — the syncer runs `encapsulate/2`
  and sends `enc`, its ephemeral P-256 public key, as a compressed `did:key`:
  the `keyid` of its `Accept-Signature` MAC request (`Spaces.Mac`). HPKE
  itself hashes the uncompressed point, so both sides decompress it first.
  The host runs `decapsulate/2` and gets the same secret. Since the syncer
  could have computed the MAC itself, a leaked response proves nothing to
  anyone else.

  This replaces the November 5 derivation (a bare DHKEM `shared_secret`, with
  no key schedule or `info`), which gives a different secret for the same
  keys; the proposal says not to support it.
  """

  alias Exosphere.ATProto.Crypto
  alias Exosphere.ATProto.Crypto.HPKE

  @info "atproto-mac"
  @exporter_context ""
  @secret_length 32

  @typedoc """
  The syncer's side of one request: `key_share` is HPKE's `enc` as a P-256
  `did:key` (sent as the MAC request's `keyid`), `shared_secret` the exported
  secret that verifies the response.
  """
  @type encapsulation :: %{key_share: String.t(), shared_secret: <<_::256>>}

  @doc """
  Syncer side: `SendExportBase` against the author's KEM public key — a P-256
  `did:key`, or a compressed or uncompressed P-256 point.

  Returns `{:ok, %{key_share: did_key, shared_secret: secret}}`. Use a new
  one for every request.

  Option `:ephemeral_private_key` pins HPKE's `skE` (32 bytes) for
  reproducible test vectors; never pass it in production — a reused key share
  defeats the point of an ephemeral one.
  """
  @spec encapsulate(binary() | String.t(), keyword()) ::
          {:ok, encapsulation()} | {:error, :invalid_kem_key | :invalid_ephemeral_key}
  def encapsulate(author_kem_key, opts \\ []) do
    hpke_opts = Keyword.take(opts, [:ephemeral_private_key])

    with {:ok, author_public} <- p256_public_key(author_kem_key),
         {:ok, {enc, secret}} <-
           HPKE.send_export_base(
             author_public,
             @info,
             @exporter_context,
             @secret_length,
             hpke_opts
           )
           |> map_error(),
         {:ok, key_share} <- Crypto.to_did_key(enc, :p256) do
      {:ok, %{key_share: key_share, shared_secret: secret}}
    end
  end

  @doc """
  Repo host side: `ReceiveExportBase` with the author's KEM private key (32
  bytes) on the syncer's `key_share` (a P-256 `did:key`, or a raw P-256
  point). Returns `{:ok, secret}`.

  A key share that is not a valid P-256 key is `{:error, :invalid_kem_key}`;
  the host answers `InvalidSpaceMac` for it (`Spaces.Mac.decapsulate/2` does
  that mapping).
  """
  @spec decapsulate(binary(), String.t() | binary()) ::
          {:ok, <<_::256>>} | {:error, :invalid_kem_key | :invalid_kem_private_key}
  def decapsulate(<<_::binary-32>> = author_private_key, key_share) do
    with {:ok, enc} <- p256_public_key(key_share) do
      case HPKE.receive_export_base(
             enc,
             author_private_key,
             @info,
             @exporter_context,
             @secret_length
           ) do
        {:ok, secret} -> {:ok, secret}
        {:error, :invalid_private_key} -> {:error, :invalid_kem_private_key}
        {:error, _} -> {:error, :invalid_kem_key}
      end
    end
  end

  def decapsulate(_, _), do: {:error, :invalid_kem_private_key}

  defp map_error({:ok, _} = ok), do: ok
  defp map_error({:error, :invalid_private_key}), do: {:error, :invalid_ephemeral_key}
  defp map_error({:error, _}), do: {:error, :invalid_kem_key}

  # A KEM key must be P-256. did:key carries the compressed form; HPKE
  # decompresses (and validates) it.
  defp p256_public_key("did:key:" <> _ = did_key) do
    case Crypto.from_did_key(did_key) do
      {:ok, key, :p256} -> {:ok, key}
      _ -> {:error, :invalid_kem_key}
    end
  end

  defp p256_public_key(<<prefix, _::binary-32>> = key) when prefix in [0x02, 0x03], do: {:ok, key}
  defp p256_public_key(<<0x04, _::binary-64>> = key), do: {:ok, key}
  defp p256_public_key(_), do: {:error, :invalid_kem_key}
end
