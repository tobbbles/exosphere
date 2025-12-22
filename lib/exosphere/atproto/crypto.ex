defmodule Exosphere.ATProto.Crypto do
  @moduledoc """
  Cryptographic operations for Exosphere.ATProto.

  Handles signing and verification using the two key types supported by Exosphere.ATProto:

  - **secp256k1 (K-256)**: Used for signing keys, compatible with Bitcoin/Ethereum
  - **NIST P-256 (secp256r1)**: Alternative curve, widely supported

  ## Key Representation

  Public keys are represented in `did:key` format for interoperability:

      did:key:zQ3shXjHeiBuRCKmM36cuYnm7YEMzhGnCmCyW92sRJ9pribSF

  The multicodec prefixes are:
  - `0xe7` for secp256k1 (compressed)
  - `0x80 0x24` (varint) for P-256 (compressed)

  ## Examples

      # Generate a new keypair
      {:ok, keypair} = Exosphere.ATProto.Crypto.generate_keypair(:secp256k1)

      # Sign data
      {:ok, signature} = Exosphere.ATProto.Crypto.sign(data, keypair.private_key, :secp256k1)

      # Verify signature
      :ok = Exosphere.ATProto.Crypto.verify(data, signature, keypair.public_key, :secp256k1)

      # Convert to did:key
      did_key = Exosphere.ATProto.Crypto.to_did_key(keypair.public_key, :secp256k1)
  """

  @type curve :: :secp256k1 | :p256
  @type keypair :: %{public_key: binary(), private_key: binary()}
  @type signature :: binary()

  # Multicodec prefixes for did:key encoding
  @multicodec_secp256k1 0xE7
  @multicodec_p256 <<0x80, 0x24>>

  # Multibase prefix for base58btc
  @multibase_base58btc "z"

  @doc """
  Generate a new keypair for the specified curve.

  ## Examples

      iex> {:ok, keypair} = Exosphere.ATProto.Crypto.generate_keypair(:secp256k1)
      iex> byte_size(keypair.private_key)
      32
  """
  @spec generate_keypair(curve()) :: {:ok, keypair()} | {:error, term()}
  def generate_keypair(:secp256k1) do
    # Generate 32 random bytes for the private key
    private_key = :crypto.strong_rand_bytes(32)

    case ExSecp256k1.create_public_key(private_key) do
      {:ok, public_key} ->
        {:ok, compressed} = ExSecp256k1.public_key_compress(public_key)
        {:ok, %{private_key: private_key, public_key: compressed}}

      {:error, _} = error ->
        error
    end
  end

  def generate_keypair(:p256) do
    # Generate P-256 keypair using Erlang crypto
    {public_key, private_key} = :crypto.generate_key(:ecdh, :secp256r1)
    compressed = compress_p256_public_key(public_key)

    {:ok, %{private_key: private_key, public_key: compressed}}
  end

  @doc """
  Sign data using ECDSA-SHA256.

  Returns the signature in "low-S" canonical form as required by Exosphere.ATProto.
  The signature is encoded as raw (r, s) bytes (64 bytes total).

  ## Examples

      iex> {:ok, sig} = Exosphere.ATProto.Crypto.sign("hello", private_key, :secp256k1)
      iex> byte_size(sig)
      64
  """
  @spec sign(binary(), binary(), curve()) :: {:ok, signature()} | {:error, term()}
  def sign(data, private_key, :secp256k1) do
    hash = :crypto.hash(:sha256, data)

    case ExSecp256k1.sign_compact(hash, private_key) do
      {:ok, {signature, _recovery_id}} ->
        # Ensure low-S form
        {:ok, ensure_low_s_secp256k1(signature)}

      {:error, _} = error ->
        error
    end
  end

  def sign(data, private_key, :p256) do
    hash = :crypto.hash(:sha256, data)
    # Sign with P-256
    signature_der = :crypto.sign(:ecdsa, :sha256, {:digest, hash}, [private_key, :secp256r1])
    # Convert from DER to raw (r, s) format
    raw_sig = der_to_raw_signature(signature_der)
    {:ok, ensure_low_s_p256(raw_sig)}
  end

  @doc """
  Verify an ECDSA-SHA256 signature.

  ## Examples

      iex> Exosphere.ATProto.Crypto.verify("hello", signature, public_key, :secp256k1)
      :ok

      iex> Exosphere.ATProto.Crypto.verify("tampered", signature, public_key, :secp256k1)
      {:error, :invalid_signature}
  """
  @spec verify(binary(), signature(), binary(), curve()) :: :ok | {:error, :invalid_signature}
  def verify(data, signature, public_key, :secp256k1) when byte_size(signature) == 64 do
    hash = :crypto.hash(:sha256, data)

    # Decompress public key if needed
    full_public_key =
      case public_key do
        <<prefix, _::binary-32>> when prefix in [0x02, 0x03] ->
          {:ok, decompressed} = ExSecp256k1.public_key_decompress(public_key)
          decompressed

        <<0x04, _::binary-64>> ->
          public_key

        _ ->
          public_key
      end

    case ExSecp256k1.verify(hash, signature, full_public_key) do
      {:ok, true} -> :ok
      {:ok, false} -> {:error, :invalid_signature}
      {:error, _} -> {:error, :invalid_signature}
    end
  end

  def verify(data, signature, public_key, :p256) when byte_size(signature) == 64 do
    hash = :crypto.hash(:sha256, data)
    # Decompress public key
    full_public_key = decompress_p256_public_key(public_key)
    # Convert raw signature to DER for Erlang crypto
    der_sig = raw_to_der_signature(signature)

    case :crypto.verify(:ecdsa, :sha256, {:digest, hash}, der_sig, [full_public_key, :secp256r1]) do
      true -> :ok
      false -> {:error, :invalid_signature}
    end
  end

  def verify(_, _, _, _), do: {:error, :invalid_signature}

  @doc """
  Convert a public key to did:key format.

  ## Examples

      iex> Exosphere.ATProto.Crypto.to_did_key(public_key, :secp256k1)
      "did:key:zQ3shXjHeiBuRCKmM36cuYnm7YEMzhGnCmCyW92sRJ9pribSF"
  """
  @spec to_did_key(binary(), curve()) :: String.t()
  def to_did_key(public_key, :secp256k1) do
    # Compress if not already
    compressed =
      case public_key do
        <<prefix, _::binary-32>> when prefix in [0x02, 0x03] -> public_key
        _ -> compress_secp256k1_public_key(public_key)
      end

    bytes = <<@multicodec_secp256k1>> <> compressed
    encoded = Base58.encode(bytes)
    "did:key:" <> @multibase_base58btc <> encoded
  end

  def to_did_key(public_key, :p256) do
    # Compress if not already
    compressed =
      case public_key do
        <<prefix, _::binary-32>> when prefix in [0x02, 0x03] -> public_key
        _ -> compress_p256_public_key(public_key)
      end

    bytes = @multicodec_p256 <> compressed
    encoded = Base58.encode(bytes)
    "did:key:" <> @multibase_base58btc <> encoded
  end

  @doc """
  Parse a did:key string to extract the public key and curve type.

  ## Examples

      iex> {:ok, public_key, :secp256k1} = Exosphere.ATProto.Crypto.from_did_key("did:key:zQ3sh...")
  """
  @spec from_did_key(String.t()) :: {:ok, binary(), curve()} | {:error, term()}
  def from_did_key("did:key:" <> @multibase_base58btc <> encoded) do
    case Base58.decode(encoded) do
      {:ok, <<@multicodec_secp256k1, public_key::binary-33>>} ->
        {:ok, public_key, :secp256k1}

      {:ok, <<0x80, 0x24, public_key::binary-33>>} ->
        {:ok, public_key, :p256}

      {:ok, _} ->
        {:error, :unsupported_key_type}

      :error ->
        {:error, :invalid_base58}
    end
  end

  def from_did_key(_), do: {:error, :invalid_did_key_format}

  @doc """
  Convert a public key to multibase format for DID documents.

  Uses the Multikey format with base58btc encoding.
  """
  @spec to_multibase(binary(), curve()) :: String.t()
  def to_multibase(public_key, curve) do
    # Extract just the encoded part from did:key
    "did:key:" <> key_part = to_did_key(public_key, curve)
    key_part
  end

  # Helper functions

  defp compress_secp256k1_public_key(<<0x04, x::binary-32, y::binary-32>>) do
    prefix = if :binary.decode_unsigned(y) |> rem(2) == 0, do: 0x02, else: 0x03
    <<prefix, x::binary>>
  end

  defp compress_secp256k1_public_key(compressed) when byte_size(compressed) == 33, do: compressed

  defp compress_p256_public_key(<<0x04, x::binary-32, y::binary-32>>) do
    prefix = if :binary.decode_unsigned(y) |> rem(2) == 0, do: 0x02, else: 0x03
    <<prefix, x::binary>>
  end

  defp compress_p256_public_key(compressed) when byte_size(compressed) == 33, do: compressed

  defp decompress_p256_public_key(<<prefix, x::binary-32>>) when prefix in [0x02, 0x03] do
    # P-256 curve parameters
    p =
      0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF

    a =
      0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC

    b =
      0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

    x_int = :binary.decode_unsigned(x)

    # y² = x³ + ax + b mod p
    y_squared = mod(mod(x_int * x_int * x_int, p) + mod(a * x_int, p) + b, p)
    y = mod_sqrt(y_squared, p)

    # Choose correct y based on prefix
    y_final =
      case {prefix, rem(y, 2)} do
        {0x02, 0} -> y
        {0x02, 1} -> p - y
        {0x03, 1} -> y
        {0x03, 0} -> p - y
      end

    y_bytes = :binary.encode_unsigned(y_final) |> pad_to_32()
    <<0x04, x::binary, y_bytes::binary>>
  end

  defp decompress_p256_public_key(<<0x04, _::binary>> = key), do: key

  defp mod(a, m) when a >= 0, do: rem(a, m)
  defp mod(a, m), do: rem(rem(a, m) + m, m)

  # Tonelli-Shanks algorithm for modular square root
  defp mod_sqrt(n, p) do
    # For P-256, p ≡ 3 (mod 4), so we can use the simple formula
    pow_mod(n, div(p + 1, 4), p)
  end

  defp pow_mod(_base, 0, _mod), do: 1

  defp pow_mod(base, exp, mod) do
    :crypto.mod_pow(base, exp, mod) |> :binary.decode_unsigned()
  end

  defp pad_to_32(bytes) when byte_size(bytes) >= 32, do: bytes
  defp pad_to_32(bytes), do: :binary.copy(<<0>>, 32 - byte_size(bytes)) <> bytes

  # Ensure "low-S" form for secp256k1 (BIP-62)
  defp ensure_low_s_secp256k1(<<r::binary-32, s::binary-32>>) do
    s_int = :binary.decode_unsigned(s)
    # secp256k1 order / 2
    half_order =
      0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0

    if s_int > half_order do
      # secp256k1 order
      order =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

      new_s = order - s_int
      new_s_bytes = :binary.encode_unsigned(new_s) |> pad_to_32()
      <<r::binary, new_s_bytes::binary>>
    else
      <<r::binary, s::binary>>
    end
  end

  # Ensure "low-S" form for P-256
  defp ensure_low_s_p256(<<r::binary-32, s::binary-32>>) do
    s_int = :binary.decode_unsigned(s)
    # P-256 order / 2
    half_order =
      0x7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8

    if s_int > half_order do
      # P-256 order
      order =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

      new_s = order - s_int
      new_s_bytes = :binary.encode_unsigned(new_s) |> pad_to_32()
      <<r::binary, new_s_bytes::binary>>
    else
      <<r::binary, s::binary>>
    end
  end

  # Convert DER signature to raw (r, s) format
  defp der_to_raw_signature(
         <<0x30, _len, 0x02, r_len, r::binary-size(r_len), 0x02, s_len, s::binary-size(s_len)>>
       ) do
    r_padded = pad_or_trim_to_32(r)
    s_padded = pad_or_trim_to_32(s)
    <<r_padded::binary, s_padded::binary>>
  end

  defp pad_or_trim_to_32(bytes) when byte_size(bytes) == 32, do: bytes
  defp pad_or_trim_to_32(bytes) when byte_size(bytes) < 32, do: pad_to_32(bytes)
  defp pad_or_trim_to_32(<<0, rest::binary>>), do: pad_or_trim_to_32(rest)
  defp pad_or_trim_to_32(bytes), do: binary_part(bytes, byte_size(bytes) - 32, 32)

  # Convert raw (r, s) format to DER signature
  defp raw_to_der_signature(<<r::binary-32, s::binary-32>>) do
    r_int = encode_der_integer(r)
    s_int = encode_der_integer(s)
    contents = <<0x02, byte_size(r_int), r_int::binary, 0x02, byte_size(s_int), s_int::binary>>
    <<0x30, byte_size(contents), contents::binary>>
  end

  defp encode_der_integer(bytes) do
    # Remove leading zeros
    trimmed = trim_leading_zeros(bytes)

    # Add leading zero if high bit is set (to keep positive)
    if :binary.first(trimmed) >= 0x80 do
      <<0x00, trimmed::binary>>
    else
      trimmed
    end
  end

  defp trim_leading_zeros(<<0, rest::binary>>) when byte_size(rest) > 0,
    do: trim_leading_zeros(rest)

  defp trim_leading_zeros(bytes), do: bytes
end

# Simple Base58 implementation for did:key encoding
defmodule Base58 do
  @moduledoc false

  @alphabet ~c"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  def encode(bytes) when is_binary(bytes) do
    bytes
    |> :binary.decode_unsigned()
    |> encode_int([])
    |> prepend_zeros(bytes)
    |> to_string()
  end

  defp encode_int(0, acc), do: acc

  defp encode_int(n, acc) do
    encode_int(div(n, 58), [Enum.at(@alphabet, rem(n, 58)) | acc])
  end

  defp prepend_zeros(acc, <<0, rest::binary>>), do: prepend_zeros([?1 | acc], rest)
  defp prepend_zeros(acc, _), do: acc

  def decode(string) when is_binary(string) do
    chars = String.to_charlist(string)
    zeros = Enum.take_while(chars, &(&1 == ?1)) |> length()

    case decode_chars(chars, 0) do
      {:ok, num} ->
        bytes = :binary.encode_unsigned(num)
        {:ok, :binary.copy(<<0>>, zeros) <> bytes}

      :error ->
        :error
    end
  end

  defp decode_chars([], acc), do: {:ok, acc}

  defp decode_chars([char | rest], acc) do
    case Enum.find_index(@alphabet, &(&1 == char)) do
      nil -> :error
      idx -> decode_chars(rest, acc * 58 + idx)
    end
  end
end
