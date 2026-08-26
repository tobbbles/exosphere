defmodule Exosphere.ATProto.Spaces.Credential do
  @moduledoc """
  The client side of the space credential flow (atproto proposal 0016):
  fetch a delegation token from the user's PDS, exchange it with the space
  host for a DPoP-bound credential, and — because a credential's consumer is
  often a host — verify credentials as the space authority's issuer.

  The flow, end to end:

      # 1. On the user's PDS, under a space-scoped OAuth session
      {:ok, delegation} =
        Credential.get_delegation_token("https://pds.example.com", space_ref,
          headers: [{"authorization", "Bearer " <> session.access_token}]
        )

      # 2. At the space host: a fresh DPoP keypair per credential
      {:ok, dpop_key} = OAuth.DPoP.generate_key()

      {:ok, attestation} =
        Credential.mint_client_attestation(
          "https://app.example.com/client-metadata.json",
          Token.space_host_aud(authority_did),
          app_private_jwk
        )

      {:ok, %{credential: jwt}} =
        Credential.mint("https://space-host.example.com", space_ref, delegation,
          dpop_key: dpop_key,
          client_attestation: attestation
        )

      # 3. Present the credential to a repo host: per-request DPoP proof
      #    with the credential bound in as `ath`
      {:ok, proof} = OAuth.DPoP.proof(dpop_key, "GET", repo_url, ath: jwt)

  exosphere is the *client* here: minting delegation tokens is the PDS's job
  and minting credentials is the space host's — both bespoke services stay
  app-side. `verify/2` is the exception: exosphere consumers host spaces too,
  so credential verification ships in the client library.

  All HTTP goes through `Exosphere.ATProto.HTTP.Behaviour` (pass `:http` to
  substitute a mock), so the whole flow tests offline.
  """

  alias Exosphere.ATProto.{Crypto, HTTP}
  alias Exosphere.ATProto.Identity.Document
  alias Exosphere.ATProto.OAuth.{DPoP, JWK}
  alias Exosphere.ATProto.Spaces.Token

  @delegation_nsid "com.atproto.space.getDelegationToken"
  @credential_nsid "com.atproto.space.getSpaceCredential"

  @doc """
  Fetch a delegation token from the user's PDS
  (`com.atproto.space.getDelegationToken`, OAuth-authenticated).

  The caller supplies the space-scoped OAuth authorization, typically
  `headers: [{"authorization", "Bearer " <> session.access_token}]`. The
  token is single-use and lives ~60s: exchange it immediately via `mint/4`.
  """
  @spec get_delegation_token(String.t(), String.t(), keyword()) ::
          {:ok, String.t()} | {:error, term()}
  def get_delegation_token(pds_url, space_ref, opts \\ []) do
    http = Keyword.get(opts, :http, HTTP)

    url =
      "#{String.trim_trailing(pds_url, "/")}/xrpc/#{@delegation_nsid}?space=" <>
        URI.encode_www_form(space_ref)

    case http.get(url, headers: Keyword.get(opts, :headers, [])) do
      {:ok, %{status: 200, body: %{"token" => token}}} when is_binary(token) ->
        {:ok, token}

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      error ->
        error
    end
  end

  @doc """
  Mint a client attestation: proof of the *app's* identity for spaces that
  gate on it (`appAccess: #allowList`).

  `client_id` is the app's OAuth client_id (its client-metadata URL); the
  audience is the space host (see `Token.space_host_aud/1`). Signed with the
  app's client-authentication JWK — the same key that signs its
  `private_key_jwt` client assertions.
  """
  @spec mint_client_attestation(String.t(), String.t(), map(), keyword()) ::
          {:ok, String.t()} | {:error, term()}
  def mint_client_attestation(client_id, aud, private_jwk, opts \\ []) do
    Token.sign(
      :client_attestation,
      [iss: client_id, sub: client_id, aud: aud] ++ opts,
      private_jwk
    )
  end

  @doc """
  Exchange a delegation token for a space credential at the space host
  (`com.atproto.space.getSpaceCredential`).

  Requires `:dpop_key` — a fresh `OAuth.DPoP.generate_key/0` keypair the
  credential binds to; keep it for the credential's lifetime and discard it
  after. Pass `:client_attestation` only when the space gates on app
  identity.

  On success, verifies the minted credential really binds to `dpop_key`'s
  thumbprint before returning it, so a misbehaving host is caught immediately.
  """
  @spec mint(String.t(), String.t(), String.t(), keyword()) ::
          {:ok, %{credential: String.t()}} | {:error, term()}
  def mint(space_host_url, space_ref, delegation_jwt, opts \\ []) do
    http = Keyword.get(opts, :http, HTTP)
    url = String.trim_trailing(space_host_url, "/") <> "/xrpc/" <> @credential_nsid

    with {:ok, dpop_key} <- fetch_dpop_key(opts),
         {:ok, proof} <- DPoP.proof(dpop_key, "POST", url),
         {:ok, jwt} <- post_exchange(http, url, delegation_jwt, proof, space_ref, opts),
         {:ok, parsed} <- Token.parse(:credential, jwt),
         :ok <- check_binding(parsed, dpop_key) do
      {:ok, %{credential: jwt}}
    else
      {:error, _} = error -> error
    end
  end

  @doc """
  Verify a space credential as its consumer — the host-side half that ships
  with the client because exosphere consumers host spaces too.

  Two key sources:

  - `verify(jwt, %Identity.Document{})` — resolve through the authority's DID
    document: the `#atproto_space` verification method, falling back to
    `#atproto` (both via `Document.get_space_signing_key/1`)
  - `verify(jwt, get_signing_key: fun)` — an `(iss, kid, force_refresh)`
    callback for hosts with their own (cached) key source; see
    `Token.verify/3`

  Options: `:sub` (the expected space URI), `:now`.
  """
  @spec verify(String.t(), Document.t() | keyword()) :: {:ok, map()} | {:error, term()}
  def verify(jwt, %Document{} = doc) do
    with {:ok, public_key, curve} <- Document.get_space_signing_key(doc),
         {:ok, public_jwk} <- public_jwk(public_key, curve) do
      Token.verify(:credential, jwt,
        get_signing_key: fn _iss, _kid, _refresh -> {:ok, public_jwk} end
      )
    end
  end

  def verify(jwt, opts) when is_list(opts), do: Token.verify(:credential, jwt, opts)

  defp post_exchange(http, url, delegation_jwt, proof, space_ref, opts) do
    with {:ok, attestation} <- client_attestation(opts),
         {:ok, %{status: 200, body: %{"credential" => jwt}}} when is_binary(jwt) <-
           http.post(url,
             headers: [
               {"authorization", "DPoP " <> delegation_jwt},
               {"dpop", proof}
             ],
             json: Map.merge(%{"space" => space_ref}, attestation_body(attestation))
           ) do
      {:ok, jwt}
    else
      {:ok, %{status: status, body: body}} when is_map(body) ->
        {:error, {:http_error, status, body["error"]}}

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, _} = error ->
        error
    end
  end

  defp check_binding(%{payload: %{"cnf" => %{"jkt" => jkt}}}, dpop_key) do
    with {:ok, own_jkt} <- JWK.thumbprint(JWK.to_public(dpop_key)) do
      if jkt == own_jkt, do: :ok, else: {:error, :credential_bound_to_other_key}
    end
  end

  defp check_binding(_, _), do: {:error, :missing_cnf}

  defp client_attestation(opts) do
    case Keyword.get(opts, :client_attestation) do
      nil -> {:ok, nil}
      {:ok, jwt} when is_binary(jwt) -> {:ok, jwt}
      jwt when is_binary(jwt) -> {:ok, jwt}
      _ -> {:error, :invalid_client_attestation}
    end
  end

  defp attestation_body(nil), do: %{}
  defp attestation_body(jwt), do: %{"clientAttestation" => jwt}

  defp fetch_dpop_key(opts) do
    case Keyword.fetch(opts, :dpop_key) do
      {:ok, key} -> {:ok, key}
      :error -> {:error, :missing_dpop_key}
    end
  end

  # A DID document yields a compressed public key; the token machinery wants
  # the public JWK.
  defp public_jwk(public_key, curve) when curve in [:p256, :secp256k1] do
    with {:ok, <<0x04, x::binary-32, y::binary-32>>} <- Crypto.decompress(public_key, curve) do
      {:ok,
       %{
         "kty" => "EC",
         "crv" => crv(curve),
         "x" => b64url(x),
         "y" => b64url(y)
       }}
    end
  end

  defp crv(:p256), do: "P-256"
  defp crv(:secp256k1), do: "secp256k1"

  defp b64url(bin), do: Base.url_encode64(bin, padding: false)
end
