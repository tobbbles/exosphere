defmodule Exosphere.ATProto.OAuth.JWK do
  @moduledoc """
  JSON Web Keys (RFC 7517) for the ATProto OAuth profile.

  ATProto OAuth uses elliptic-curve JWKs — `P-256` for the spec-required
  ES256 (and optionally `secp256k1` for ES256K) — as the client's long-term
  authentication key and as the per-session DPoP key.

  Keys are represented as plain maps (`%{"kty" => "EC", "crv" => ..., "x" =>
  ..., "y" => ..., "d" => ...}` with `x`/`y`/`d` base64url-encoded
  coordinates); private keys additionally carry `"d"` and must never be
  embedded in a client metadata document or DPoP proof header.

  ## Examples

      {:ok, jwk} = Exosphere.ATProto.OAuth.JWK.generate(:p256)
      public = Exosphere.ATProto.OAuth.JWK.to_public(jwk)
  """

  alias Exosphere.ATProto.Crypto

  @type curve :: :p256 | :secp256k1
  @type t :: %{optional(binary()) => binary()}

  @crv_p256 "P-256"
  @crv_secp256k1 "secp256k1"

  @doc """
  Generate a new keypair as a private JWK map.
  """
  @spec generate(curve()) :: {:ok, t()}
  def generate(curve) when curve in [:p256, :secp256k1] do
    {:ok, keypair} = Crypto.generate_keypair(curve)
    from_keypair(keypair, curve)
  end

  @doc """
  Convert an `ATProto.Crypto` keypair into a private JWK map.

  The public key may be compressed (33 bytes) or uncompressed (65 bytes).
  """
  @spec from_keypair(Crypto.keypair(), curve()) :: {:ok, t()} | {:error, term()}
  def from_keypair(%{public_key: public, private_key: private}, curve)
      when curve in [:p256, :secp256k1] do
    with {:ok, <<0x04, x::binary-32, y::binary-32>>} <- Crypto.decompress(public, curve) do
      {:ok,
       %{
         "kty" => "EC",
         "crv" => crv(curve),
         "x" => b64(x),
         "y" => b64(y),
         "d" => b64(private)
       }}
    end
  end

  @doc """
  Strip the private `"d"` member, returning the public JWK map.
  """
  @spec to_public(t()) :: t()
  def to_public(jwk) when is_map(jwk) do
    Map.delete(jwk, "d")
  end

  @doc """
  Parse a public JWK map back into an `ATProto.Crypto` compressed public key.

  Only elliptic-curve keys on the supported curves parse.
  """
  @spec to_public_key(t()) :: {:ok, binary(), Crypto.curve()} | {:error, term()}
  def to_public_key(%{"kty" => "EC", "crv" => crv, "x" => x, "y" => y})
      when crv in [@crv_p256, @crv_secp256k1] do
    with {:ok, x_bin} <- unb64(x),
         {:ok, y_bin} <- unb64(y),
         {:ok, curve} <- curve(crv),
         :ok <- validate_point(x_bin, y_bin),
         {:ok, compressed} <-
           Crypto.compress_public_key(<<0x04, x_bin::binary, y_bin::binary>>, curve) do
      {:ok, compressed, curve}
    else
      _ -> {:error, :invalid_jwk}
    end
  end

  def to_public_key(_), do: {:error, :invalid_jwk}

  @doc """
  RFC 7638 JWK thumbprint: `BASE64URL(SHA256(canonical JSON))` over the
  required members for the key type, in lexicographic order.
  """
  @spec thumbprint(t()) :: {:ok, String.t()} | {:error, :invalid_jwk}
  def thumbprint(%{"kty" => "EC", "crv" => crv, "x" => x, "y" => y}) do
    canonical = ~s({"crv":"#{crv}","kty":"EC","x":"#{x}","y":"#{y}"})
    {:ok, :crypto.hash(:sha256, canonical) |> b64()}
  end

  def thumbprint(_), do: {:error, :invalid_jwk}

  defp crv(:p256), do: @crv_p256
  defp crv(:secp256k1), do: @crv_secp256k1

  defp curve(@crv_p256), do: {:ok, :p256}
  defp curve(@crv_secp256k1), do: {:ok, :secp256k1}
  defp curve(_), do: {:error, :invalid_jwk}

  defp validate_point(<<_::binary-32>>, <<_::binary-32>>), do: :ok
  defp validate_point(_, _), do: {:error, :invalid_jwk}

  defp b64(bytes), do: Base.url_encode64(bytes, padding: false)
  defp unb64(s), do: Base.url_decode64(s, padding: false)
end
