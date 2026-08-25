defmodule Exosphere.ATProto.OAuth.PKCE do
  @moduledoc """
  PKCE (RFC 7636) code verifiers and challenges.

  ATProto OAuth requires the S256 challenge method: the verifier never travels
  over the wire, and the authorization server only ever sees
  `BASE64URL(SHA256(verifier))`.
  """

  @verifier_bytes 32

  @doc """
  Generate a random code verifier.

  Returns 43 unreserved characters (`BASE64URL` of 32 random bytes, no
  padding), the minimum length allowed by RFC 7636.
  """
  @spec generate_verifier() :: String.t()
  def generate_verifier do
    @verifier_bytes
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  @doc """
  Compute the S256 code challenge for a verifier.
  """
  @spec challenge(String.t()) :: String.t()
  def challenge(verifier) when is_binary(verifier) do
    :crypto.hash(:sha256, verifier)
    |> Base.url_encode64(padding: false)
  end

  @doc """
  Check that a verifier is syntactically valid per RFC 7636: 43–128
  characters from the unreserved set `ALPHA / DIGIT / "-" / "." / "_" / "~"`.
  """
  @spec valid_verifier?(term()) :: boolean()
  def valid_verifier?(verifier) when is_binary(verifier) do
    byte_size(verifier) in 43..128 and
      Regex.match?(~r/^[A-Za-z0-9\-._~]+$/, verifier)
  end

  def valid_verifier?(_), do: false
end
