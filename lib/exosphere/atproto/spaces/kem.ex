defmodule Exosphere.ATProto.Spaces.Kem do
  @moduledoc """
  The key encapsulation mechanism that gives a syncer and a repo host a
  per-request shared secret (proposal 0016, "Commit authenticity"; atproto
  `5791385`): ECDH on P-256, with the secret derived as in
  DHKEM(P-256, HKDF-SHA256) from RFC 9180 §4.1.

  The repo host holds the private half of the author's `#atproto_kem` key
  (`Identity.Document.get_kem_key/1` resolves the public half). For every
  request — retries and each page included — the syncer:

  1. generates a fresh ephemeral P-256 keypair,
  2. computes `dh = ECDH(ephemeral_private, author_kem_public)` (the 32-byte
     x-coordinate),
  3. derives

         prefix = "HPKE-v1" || "KEM" || uint16be(0x0010)
         input  = prefix || "eae_prk" || dh
         info   = uint16be(32) || prefix || "shared_secret" || syncer_pub || author_pub
         shared_secret = HKDF-SHA256(input, salt = "", info, 32)

     with both public keys in *uncompressed* form (`0x04 || x || y`), and
  4. sends the ephemeral public key as a `did:key` in the request's
     `key_share` (`Spaces.Mac.want_mac_header/2`).

  The host runs `decapsulate/2` with the author's private key and gets the
  same secret, which keys the MAC on what it serves (`Spaces.Mac`). Since the
  syncer could have computed that MAC itself, a leaked response proves
  nothing to anyone else.

  Only Erlang's `:crypto` is used (ECDH on `secp256r1`, HMAC-SHA256); HKDF
  (RFC 5869) is the two-step extract/expand built on that HMAC.
  """

  alias Exosphere.ATProto.Crypto

  @kem_prefix "HPKE-v1" <> "KEM" <> <<0x0010::unsigned-big-16>>

  @type encapsulation :: %{key_share: String.t(), shared_secret: <<_::256>>}

  @doc """
  Syncer side: derive a fresh shared secret against the author's KEM public
  key — a compressed or uncompressed P-256 key, or a P-256 `did:key`.

  Returns `{:ok, %{key_share: did_key, shared_secret: secret}}`. Use a new
  one for every request.

  Option `:ephemeral_private_key` pins the ephemeral key (32 bytes) for
  reproducible test vectors; never pass it in production — a reused key share
  defeats the point of an ephemeral one.
  """
  @spec encapsulate(binary() | String.t(), keyword()) :: {:ok, encapsulation()} | {:error, term()}
  def encapsulate(author_kem_key, opts \\ []) do
    with {:ok, author_bytes} <- p256_uncompressed(author_kem_key),
         {:ok, eph_public, eph_private} <- ephemeral(opts[:ephemeral_private_key]),
         {:ok, dh} <- ecdh(author_bytes, eph_private),
         {:ok, key_share} <- Crypto.to_did_key(eph_public, :p256) do
      {:ok,
       %{key_share: key_share, shared_secret: derive_shared_secret(dh, eph_public, author_bytes)}}
    end
  end

  @doc """
  Repo host side: derive the shared secret from the syncer's `key_share` (a
  P-256 `did:key`) with the author's KEM private key (32 bytes).
  """
  @spec decapsulate(binary(), String.t()) :: {:ok, <<_::256>>} | {:error, term()}
  def decapsulate(<<_::binary-32>> = author_private_key, key_share) do
    with {:ok, syncer_bytes} <- p256_uncompressed(key_share),
         {:ok, author_public} <- public_from_private(author_private_key),
         {:ok, dh} <- ecdh(syncer_bytes, author_private_key) do
      {:ok, derive_shared_secret(dh, syncer_bytes, author_public)}
    end
  end

  def decapsulate(_, _), do: {:error, :invalid_kem_private_key}

  @doc """
  The RFC 9180 derivation from a raw ECDH result and both uncompressed public
  keys (syncer's first). Exposed for test vectors and second implementations.
  """
  @spec derive_shared_secret(binary(), binary(), binary()) :: <<_::256>>
  def derive_shared_secret(dh, <<0x04, _::binary-64>> = syncer, <<0x04, _::binary-64>> = author) do
    input = @kem_prefix <> "eae_prk" <> dh
    info = <<32::unsigned-big-16>> <> @kem_prefix <> "shared_secret" <> syncer <> author
    hkdf_sha256(input, "", info, 32)
  end

  @doc "HKDF-SHA256 (RFC 5869): extract with `salt` (empty means 32 zero bytes), then expand."
  @spec hkdf_sha256(binary(), binary(), binary(), pos_integer()) :: binary()
  def hkdf_sha256(ikm, salt, info, length) when length <= 255 * 32 do
    salt = if salt == "", do: <<0::256>>, else: salt
    prk = :crypto.mac(:hmac, :sha256, salt, ikm)

    {okm, _} =
      Enum.reduce(1..ceil(length / 32)//1, {"", ""}, fn i, {acc, prev} ->
        block = :crypto.mac(:hmac, :sha256, prk, prev <> info <> <<i>>)
        {acc <> block, block}
      end)

    binary_part(okm, 0, length)
  end

  defp ephemeral(nil) do
    {public, private} = :crypto.generate_key(:ecdh, :secp256r1)
    {:ok, public, private}
  end

  defp ephemeral(<<_::binary-32>> = private) do
    with {:ok, public} <- public_from_private(private), do: {:ok, public, private}
  end

  defp ephemeral(_), do: {:error, :invalid_ephemeral_key}

  defp public_from_private(private) do
    {public, _} = :crypto.generate_key(:ecdh, :secp256r1, private)
    {:ok, public}
  rescue
    _ -> {:error, :invalid_kem_private_key}
  end

  defp ecdh(peer_uncompressed, private) do
    {:ok, :crypto.compute_key(:ecdh, peer_uncompressed, private, :secp256r1)}
  rescue
    _ -> {:error, :invalid_kem_key}
  end

  # A KEM key must be P-256; did:key and multikey carry the compressed form,
  # RFC 9180 hashes the uncompressed one.
  defp p256_uncompressed("did:key:" <> _ = did_key) do
    case Crypto.from_did_key(did_key) do
      {:ok, key, :p256} -> p256_uncompressed(key)
      _ -> {:error, :invalid_kem_key}
    end
  end

  defp p256_uncompressed(key) when is_binary(key) do
    case Crypto.decompress(key, :p256) do
      {:ok, <<0x04, _::binary-64>> = uncompressed} -> {:ok, uncompressed}
      _ -> {:error, :invalid_kem_key}
    end
  rescue
    _ -> {:error, :invalid_kem_key}
  end

  defp p256_uncompressed(_), do: {:error, :invalid_kem_key}
end
