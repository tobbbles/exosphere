defmodule Exosphere.ATProto.OAuth.JWS do
  @moduledoc """
  Compact JWS signing and verification (RFC 7515) for the ATProto OAuth
  profile.

  Only elliptic-curve algorithms are supported — the spec-required `ES256`
  and the optional `ES256K` — because those are the only algorithms ATProto
  allows for client assertions and DPoP proofs.

  ## Examples

      {:ok, jwk} = Exosphere.ATProto.OAuth.JWK.generate(:p256)
      {:ok, jwt} = Exosphere.ATProto.OAuth.JWS.sign(jwk, %{"alg" => "ES256"}, %{"sub" => "did:plc:abc"})
      {:ok, %{"sub" => "did:plc:abc"}} = Exosphere.ATProto.OAuth.JWS.verify(Exosphere.ATProto.OAuth.JWK.to_public(jwk), jwt, ["ES256"])
  """

  alias Exosphere.ATProto.Crypto
  alias Exosphere.ATProto.OAuth.JWK

  @type alg :: :ES256 | :ES256K

  @doc """
  Sign `claims` as a compact JWS (`header.payload.signature`).

  `headers` must include `"alg"`; it overrides JOSE's defaults so that
  non-standard JOSE headers (`typ: dpop+jwt`, `jwk`, …) round-trip.

  The signature is always low-S. JOSE's ECDSA signer leaves S wherever it
  falls, so about half its output is the upper-half twin that the atproto
  cryptography spec forbids and strict verifiers (`Crypto.verify/4`,
  `@atproto/crypto`) refuse. The JWS ES256/ES256K encoding is raw
  `r || s`, so S is folded with `Crypto.to_low_s/2` after signing. Service
  auth, space credentials and delegation tokens, DPoP proofs and client
  assertions all sign here.
  """
  @spec sign(JWK.t(), map(), map()) :: {:ok, binary()} | {:error, term()}
  def sign(private_jwk, headers, claims)
      when is_map(private_jwk) and is_map_key(private_jwk, "d") do
    alg = Map.get(headers, "alg") || Map.get(headers, :alg)

    if alg in ["ES256", "ES256K"] do
      signer = JOSE.JWK.from_map(private_jwk)
      {_, jwt} = JOSE.JWT.sign(signer, headers, claims) |> JOSE.JWS.compact()
      {:ok, to_low_s(jwt, curve(private_jwk))}
    else
      {:error, :unsupported_alg}
    end
  rescue
    _ -> {:error, :signing_failed}
  end

  def sign(_, _, _), do: {:error, :not_a_private_key}

  defp curve(%{"crv" => "secp256k1"}), do: :secp256k1
  defp curve(%{"crv" => "P-256"}), do: :p256

  # JOSE always emits `header.payload.signature` with a 64-byte `r || s`
  # for these algorithms; a match failure is a bug and lands in `rescue`.
  defp to_low_s(jwt, curve) do
    [header, payload, signature] = String.split(jwt, ".")
    {:ok, <<_::binary-64>> = raw} = Base.url_decode64(signature, padding: false)
    folded = Crypto.to_low_s(raw, curve)
    header <> "." <> payload <> "." <> Base.url_encode64(folded, padding: false)
  end

  @doc """
  Verify a compact JWS against a public JWK, restricting `algs` per RFC 8725
  (explicit algorithm selection).

  Returns `{:ok, claims}` when the signature is valid.
  """
  @spec verify(JWK.t(), binary(), [String.t()]) ::
          {:ok, map()} | {:error, :invalid_signature | :invalid_token}
  def verify(public_jwk, jwt, algs) when is_map(public_jwk) and is_binary(jwt) do
    key = JOSE.JWK.from_map(public_jwk)

    case JOSE.JWT.verify_strict(key, algs, jwt) do
      {true, %JOSE.JWT{fields: fields}, _} -> {:ok, fields}
      _ -> {:error, :invalid_signature}
    end
  rescue
    _ -> {:error, :invalid_token}
  end

  @doc """
  Decode a compact JWS without verifying it — for inspecting headers/claims
  (e.g. the `jwk` header of an incoming DPoP proof) before verification.
  """
  @spec decode(binary()) :: {:ok, map(), map()} | {:error, :invalid_token}
  def decode(jwt) when is_binary(jwt) do
    case String.split(jwt, ".") do
      [header_b64, payload_b64 | _rest] ->
        with {:ok, header} <- decode_part(header_b64),
             {:ok, payload} <- decode_part(payload_b64) do
          {:ok, header, payload}
        else
          _ -> {:error, :invalid_token}
        end

      _ ->
        {:error, :invalid_token}
    end
  end

  def decode(_), do: {:error, :invalid_token}

  defp decode_part(part) do
    with {:ok, raw} <- Base.url_decode64(part, padding: false),
         {:ok, decoded} <- Jason.decode(raw) do
      {:ok, decoded}
    else
      _ -> {:error, :invalid_token}
    end
  end
end
