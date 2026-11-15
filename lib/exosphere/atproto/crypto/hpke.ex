defmodule Exosphere.ATProto.Crypto.HPKE do
  @moduledoc """
  HPKE secret export (RFC 9180 §6.2) for exactly one ciphersuite:
  DHKEM(P-256, HKDF-SHA256) (`0x0010`), HKDF-SHA256 (`0x0001`) and the
  Export-only AEAD (`0xFFFF`), in base mode.

  atproto Spaces (proposal 0016, "Shared secret"; atproto `#5865`) derives the
  per-request secret that keys a repo host's MACs this way: the syncer runs
  `send_export_base/5` against the author's `#atproto_kem` key and sends
  `enc`; the repo host runs `receive_export_base/5` with the KEM private key
  and gets the same secret. Nothing is ever encrypted, which is why the
  Export-only AEAD is enough — and why this module implements no AEAD, no
  PSK or auth modes, and no other KEM.

  Erlang's `:crypto` has ECDH on `secp256r1` and HMAC-SHA256 but no HPKE, so
  the RFC's steps are spelled out here, one function per RFC function:

      Encap(pkR):          dh = DH(skE, pkR); enc = SerializePublicKey(pkE)
                           shared_secret = ExtractAndExpand(dh, enc || pkRm)
      KeySchedule(base):   key_schedule_context = 0x00 || psk_id_hash || info_hash
                           secret = LabeledExtract(shared_secret, "secret", "")
                           exporter_secret = LabeledExpand(secret, "exp", key_schedule_context, 32)
      Export(ctx, L):      LabeledExpand(exporter_secret, "sec", ctx, L)

  Public keys are serialized *uncompressed* (`0x04 || x || y`, RFC 9180
  §7.1.1), so `enc` is 65 bytes. Functions here also accept a compressed
  33-byte key (did:key carries that form) and decompress it first; the
  derivation always uses the uncompressed encoding. Every public key is
  validated as a point on the curve (§7.1.4) before use.

  Checked against the CFRG test vectors for this exact suite (the
  `test-vectors.json` entry with `kem_id` 16, `kdf_id` 1, `aead_id` 65535,
  `mode` 0), and against atproto's own vector computed with Go's
  `crypto/hpke`.
  """

  alias Exosphere.ATProto.Crypto

  @kem_id 0x0010
  @kdf_id 0x0001
  @aead_id 0xFFFF
  @mode_base 0x00

  @version "HPKE-v1"
  @kem_suite_id "KEM" <> <<@kem_id::unsigned-big-16>>
  @suite_id "HPKE" <>
              <<@kem_id::unsigned-big-16, @kdf_id::unsigned-big-16, @aead_id::unsigned-big-16>>

  # Nsecret and Nh for DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256.
  @n_secret 32
  @n_h 32
  # The longest export, 255 * Nh (RFC 9180 §5.3).
  @max_export 255 * @n_h

  # P-256 field prime, curve coefficients and group order.
  @p 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
  @a 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
  @b 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
  @n 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

  @typedoc "An uncompressed P-256 public key, `0x04 || x || y`."
  @type public_key :: <<_::520>>

  @typedoc "A P-256 private key scalar, 32 bytes big-endian."
  @type private_key :: <<_::256>>

  @type error :: {:error, :invalid_public_key | :invalid_private_key | :invalid_length}

  @doc """
  `SendExport` in base mode (RFC 9180 §6.2): encapsulate to `pk_r` and export
  `length` bytes under `exporter_context`. Returns `{:ok, {enc, secret}}` with
  `enc` the 65-byte uncompressed ephemeral public key.

  Option `:ephemeral_private_key` fixes `skE` (32 bytes) for test vectors.
  Never pass it in production: HPKE's security rests on a fresh ephemeral key.
  """
  @spec send_export_base(binary(), binary(), binary(), pos_integer(), keyword()) ::
          {:ok, {public_key(), binary()}} | error()
  def send_export_base(pk_r, info, exporter_context, length, opts \\ [])
      when is_binary(info) and is_binary(exporter_context) do
    with :ok <- check_length(length),
         {:ok, shared_secret, enc} <- encap(pk_r, opts) do
      %{exporter_secret: exporter_secret} = key_schedule_base(shared_secret, info)
      {:ok, {enc, export(exporter_secret, exporter_context, length)}}
    end
  end

  @doc """
  `ReceiveExport` in base mode (RFC 9180 §6.2): decapsulate `enc` with the
  recipient's private key `sk_r` and export `length` bytes under
  `exporter_context`. Returns `{:ok, secret}`.
  """
  @spec receive_export_base(binary(), binary(), binary(), binary(), pos_integer()) ::
          {:ok, binary()} | error()
  def receive_export_base(enc, sk_r, info, exporter_context, length)
      when is_binary(info) and is_binary(exporter_context) do
    with :ok <- check_length(length),
         {:ok, shared_secret} <- decap(enc, sk_r) do
      %{exporter_secret: exporter_secret} = key_schedule_base(shared_secret, info)
      {:ok, export(exporter_secret, exporter_context, length)}
    end
  end

  @doc """
  DHKEM `Encap(pkR)` (RFC 9180 §4.1). Returns `{:ok, shared_secret, enc}`.
  Takes the same `:ephemeral_private_key` option as `send_export_base/5`.
  """
  @spec encap(binary(), keyword()) :: {:ok, <<_::256>>, public_key()} | error()
  def encap(pk_r, opts \\ []) do
    with {:ok, pk_rm} <- public_key(pk_r),
         {:ok, sk_e} <- ephemeral(Keyword.get(opts, :ephemeral_private_key)),
         {:ok, pk_e} <- public_from_private(sk_e),
         {:ok, dh} <- dh(sk_e, pk_rm) do
      {:ok, extract_and_expand(dh, pk_e <> pk_rm), pk_e}
    end
  end

  @doc "DHKEM `Decap(enc, skR)` (RFC 9180 §4.1). Returns `{:ok, shared_secret}`."
  @spec decap(binary(), binary()) :: {:ok, <<_::256>>} | error()
  def decap(enc, sk_r) do
    with {:ok, pk_e} <- public_key(enc),
         {:ok, sk_r} <- private_key(sk_r),
         {:ok, pk_rm} <- public_from_private(sk_r),
         {:ok, dh} <- dh(sk_r, pk_e) do
      {:ok, extract_and_expand(dh, pk_e <> pk_rm)}
    end
  end

  @doc """
  The base-mode `KeySchedule` (RFC 9180 §5.1) for the Export-only AEAD, which
  derives no key or nonce. Returns the intermediate values the test vectors
  list, of which `exporter_secret` is the one `export/3` needs.
  """
  @spec key_schedule_base(binary(), binary()) :: %{
          key_schedule_context: binary(),
          secret: <<_::256>>,
          exporter_secret: <<_::256>>
        }
  def key_schedule_base(shared_secret, info) when is_binary(shared_secret) and is_binary(info) do
    psk_id_hash = labeled_extract(@suite_id, "", "psk_id_hash", "")
    info_hash = labeled_extract(@suite_id, "", "info_hash", info)
    context = <<@mode_base>> <> psk_id_hash <> info_hash
    secret = labeled_extract(@suite_id, shared_secret, "secret", "")

    %{
      key_schedule_context: context,
      secret: secret,
      exporter_secret: labeled_expand(@suite_id, secret, "exp", context, @n_h)
    }
  end

  @doc "`Context.Export(exporter_context, L)` (RFC 9180 §5.3)."
  @spec export(binary(), binary(), pos_integer()) :: binary()
  def export(exporter_secret, exporter_context, length)
      when is_binary(exporter_secret) and is_binary(exporter_context) and
             is_integer(length) and length >= 1 and length <= @max_export do
    labeled_expand(@suite_id, exporter_secret, "sec", exporter_context, length)
  end

  # -- RFC 9180 §4 ------------------------------------------------------------

  defp extract_and_expand(dh, kem_context) do
    eae_prk = labeled_extract(@kem_suite_id, "", "eae_prk", dh)
    labeled_expand(@kem_suite_id, eae_prk, "shared_secret", kem_context, @n_secret)
  end

  defp labeled_extract(suite_id, salt, label, ikm),
    do: Crypto.hkdf_extract_sha256(salt, @version <> suite_id <> label <> ikm)

  defp labeled_expand(suite_id, prk, label, info, length) do
    labeled_info = <<length::unsigned-big-16>> <> @version <> suite_id <> label <> info
    Crypto.hkdf_expand_sha256(prk, labeled_info, length)
  end

  defp check_length(length) when is_integer(length) and length >= 1 and length <= @max_export,
    do: :ok

  defp check_length(_), do: {:error, :invalid_length}

  # -- P-256 ------------------------------------------------------------------

  defp ephemeral(nil) do
    {_public, private} = :crypto.generate_key(:ecdh, :secp256r1)
    private_key(private)
  end

  defp ephemeral(private), do: private_key(private)

  # :crypto may return a scalar shorter than 32 bytes; RFC 9180 fixes Nsk = 32.
  defp private_key(<<_::binary-32>> = sk) do
    scalar = :binary.decode_unsigned(sk)
    if scalar > 0 and scalar < @n, do: {:ok, sk}, else: {:error, :invalid_private_key}
  end

  defp private_key(sk) when is_binary(sk) and byte_size(sk) < 32,
    do: private_key(<<0::size((32 - byte_size(sk)) * 8)>> <> sk)

  defp private_key(_), do: {:error, :invalid_private_key}

  defp public_from_private(sk) do
    {public, _} = :crypto.generate_key(:ecdh, :secp256r1, sk)
    {:ok, public}
  rescue
    _ -> {:error, :invalid_private_key}
  end

  # DH(sk, pk) for P-256 is the 32-byte x-coordinate of the shared point.
  defp dh(sk, pk) do
    {:ok, :crypto.compute_key(:ecdh, pk, sk, :secp256r1)}
  rescue
    _ -> {:error, :invalid_public_key}
  end

  defp public_key(<<prefix, _::binary-32>> = compressed) when prefix in [0x02, 0x03] do
    with {:ok, uncompressed} <- Crypto.decompress(compressed, :p256), do: public_key(uncompressed)
  end

  defp public_key(<<0x04, x::unsigned-big-256, y::unsigned-big-256>> = key) do
    if on_curve?(x, y), do: {:ok, key}, else: {:error, :invalid_public_key}
  end

  defp public_key(_), do: {:error, :invalid_public_key}

  defp on_curve?(x, y) when x < @p and y < @p do
    rem(y * y, @p) == rem(rem(x * x * x, @p) + @a * x + @b, @p)
  end

  defp on_curve?(_, _), do: false
end
