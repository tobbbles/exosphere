defmodule Exosphere.ATProto.Spaces.Credential do
  @moduledoc """
  The space credential flow (atproto proposal 0016, "Access control"): fetch
  a delegation token from the user's PDS, exchange it at the space host for a
  key-bound credential, present that credential with an HTTP Message
  Signature — and, because a credential's consumer is often a host, verify
  such requests.

  The flow, end to end:

      # 1. On the user's PDS, under a space-scoped OAuth session
      #    (skip for a space that does not gate on the user, e.g. a
      #    memberspace with public_read)
      {:ok, delegation} =
        Credential.get_delegation_token("https://pds.example.com", space_ref,
          session: session
        )

      # 2. At the space host, binding a fresh P-256 key per credential
      {:ok, key} = Spaces.HttpSignature.generate_key()

      {:ok, cred} =
        Credential.mint("https://space-host.example.com", space_ref, delegation,
          key: key,
          client_attestation: attestation   # only when the space gates on the app
        )

      # 3. Present it: Authorization + Atproto-Space-Audience + an RFC 9421
      #    signature by `key` (Spaces.Sync does this for every request)
      {:ok, headers} = Credential.presentation_headers(cred, repo_owner_did)

  Since atproto `57b24c6`/`7b8e094` (2026-10) the exchange carries no
  Authorization header and no DPoP proof: the key to bind (`credentialKey`,
  the key's `did:key`; the field was `credentialKid` until atproto
  `atproto-spaces-lexicon-review`) and the optional delegation token and
  client attestation travel in the JSON body. The credential is bound to that key by
  `cnf.kid`, lives 600 seconds, and every use is signed — see
  `Spaces.HttpSignature`. A public space needs no delegation token.

  exosphere is the *client* here: minting delegation tokens is the PDS's job
  and minting credentials is the space host's. `verify/2` and
  `verify_request/2` are the exception: exosphere consumers host spaces too,
  so the receiving half ships in the client library.

  All HTTP goes through `Exosphere.ATProto.HTTP.Behaviour` (pass `:http` to
  substitute a mock), so the whole flow tests offline. Request options
  (`:timeout`, `:follow_redirects`) travel in the same keyword list and are
  forwarded to the transport — see `Exosphere.ATProto.HTTP` on what a
  `:timeout` actually bounds.
  """

  alias Exosphere.ATProto.{Crypto, HTTP}
  alias Exosphere.ATProto.Identity.Document
  alias Exosphere.ATProto.OAuth.{Request, Session}
  alias Exosphere.ATProto.Spaces.{HttpSignature, Token, XRPC}

  @delegation_nsid "com.atproto.space.getDelegationToken"
  @credential_nsid "com.atproto.space.getSpaceCredential"

  @exchange_errors %{
    "SpaceDeleted" => :space_deleted,
    "RepoTakendown" => :repo_takendown,
    "RepoDeactivated" => :repo_deactivated,
    "AccountNotAuthorized" => :account_not_authorized,
    "AppNotAuthorized" => :app_not_authorized
  }

  @typedoc "A minted credential with the key it is bound to — what `Spaces.Sync` takes."
  @type t :: %{credential: String.t(), key: HttpSignature.key()}
  @doc """
  Fetch a delegation token from the user's PDS
  (`com.atproto.space.getDelegationToken`, OAuth-authenticated).

  The caller supplies the space-scoped OAuth authorization: pass
  `session: session` (an `Exosphere.ATProto.OAuth.Session`) and the request
  is DPoP-signed — `Authorization: DPoP …` plus a per-request proof, using
  the PDS's DPoP nonce and retrying a `use_dpop_nonce` challenge once. An
  atproto OAuth access token is DPoP-bound, so sending it as `Bearer` is
  refused. `headers: [...]` is still accepted and passed through verbatim,
  for other authorization schemes. The token is single-use and lives ~60s:
  exchange it immediately via `mint/4`.
  """
  @spec get_delegation_token(String.t(), String.t(), keyword()) ::
          {:ok, String.t()} | {:error, term()}
  def get_delegation_token(pds_url, space_ref, opts \\ []) do
    http = Keyword.get(opts, :http, HTTP)

    url =
      "#{String.trim_trailing(pds_url, "/")}/xrpc/#{@delegation_nsid}?space=" <>
        URI.encode_www_form(space_ref)

    case delegation_request(http, url, opts) do
      {:ok, %{status: 200, body: %{"token" => token}}} when is_binary(token) ->
        {:ok, token}

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      error ->
        error
    end
  end

  defp delegation_request(http, url, opts) do
    request_opts = HTTP.take_request_opts(opts)

    case Keyword.get(opts, :session) do
      %Session{} = session ->
        Request.authorized(http, :get, url, request_opts, session.dpop_key, session.access_token)

      nil ->
        http.get(url, Keyword.put(request_opts, :headers, Keyword.get(opts, :headers, [])))
    end
  end

  @doc """
  Mint a client attestation: proof of the *app's* identity for spaces that
  gate on it (a memberspace with `allowed_apps`).

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
  Request a space credential from the space host
  (`com.atproto.space.getSpaceCredential`).

  `delegation_jwt` is the delegation token from `get_delegation_token/3`, or
  `nil` for a space that does not gate on the user (a public space). Options:

  - `:key` (required) — a fresh `Spaces.HttpSignature.generate_key/0` key; its
    `did:key` is sent as `credentialKey` and becomes the credential's
    `cnf.kid`. Keep it for the credential's lifetime and discard it after.
  - `:client_attestation` — only when the space gates on app identity.

  The request is unauthenticated: everything travels in the JSON body. On
  success the minted credential is checked to be bound to `key` before it is
  returned, so a misbehaving host is caught immediately. Returns
  `{:ok, %{credential: jwt, key: key}}`, ready for `Spaces.Sync`.

  Refusals that change what a syncer should do are typed:

  - `{:error, :space_deleted}` (`SpaceDeleted`) — the space is gone: delete
    every copy of its data (proposal 0016, "Space deletion"). Any *other*
    renewal failure says nothing about the space.
  - `{:error, :repo_takendown}` / `{:error, :repo_deactivated}`
    (`RepoTakendown` / `RepoDeactivated`, atproto `99bf6e2`) — the space
    authority's account is taken down or deactivated.

  - `{:error, :account_not_authorized}` (`AccountNotAuthorized`, which was
    `UserNotAuthorized` until atproto `atproto-spaces-lexicon-review`) — the
    policy does not let this account read the space.
  - `{:error, :app_not_authorized}` (`AppNotAuthorized`) — the policy does not
    let this app read the space (`allowed_apps`).

  Other refusals (`SpaceNotFound`, `InvalidDelegationToken`, …) come back as
  `{:error, {:http_error, status, code}}`.
  """
  @spec mint(String.t(), String.t(), String.t() | nil, keyword()) ::
          {:ok, t()} | {:error, term()}
  def mint(space_host_url, space_ref, delegation_jwt, opts \\ []) do
    http = Keyword.get(opts, :http, HTTP)
    url = String.trim_trailing(space_host_url, "/") <> "/xrpc/" <> @credential_nsid

    with {:ok, key} <- fetch_key(opts),
         {:ok, attestation} <- client_attestation(opts),
         body = exchange_body(space_ref, key, delegation_jwt, attestation),
         {:ok, jwt} <- post_exchange(http, url, body, opts),
         {:ok, parsed} <- Token.parse(:credential, jwt),
         :ok <- check_binding(parsed, key) do
      {:ok, %{credential: jwt, key: key}}
    end
  end

  @doc """
  The headers that present `cred` to `audience` — the repo owner's DID when
  syncing a repo, the space authority's DID for a request to the space host:
  `Authorization: Atproto-Space-Credential …`, `Atproto-Space-Audience`, and
  the RFC 9421 `Signature-Input`/`Signature` pair.
  """
  @spec presentation_headers(t(), String.t()) :: {:ok, [{String.t(), String.t()}]}
  def presentation_headers(%{credential: jwt, key: key}, audience),
    do: HttpSignature.headers(key, jwt, audience)

  @doc """
  Verify a space credential token as its consumer — signature, type,
  `kid`, expiry, lifetime, binding claim — without the request around it
  (see `verify_request/2` for the whole presentation).

  Two key sources:

  - `verify(jwt, %Identity.Document{})` — resolve through the authority's DID
    document: the `#atproto` key, which is the only `kid` a credential may
    carry since atproto `432ef66` (`Document.get_space_signing_key/2`).
  - `verify(jwt, get_signing_key: fun)` — an `(iss, kid, force_refresh)`
    callback for hosts with their own (cached) key source; see
    `Token.verify/3`. The `kid` it receives has already been checked to be
    `"#atproto"`.

  Options: `:sub` (the expected space URI), `:now`, and `:revoked?` — see
  "Revocation" in `verify_request/2`.
  """
  @spec verify(String.t(), Document.t() | keyword()) :: {:ok, map()} | {:error, term()}
  def verify(jwt, %Document{} = doc), do: verify(jwt, document: doc)

  def verify(jwt, opts) when is_list(opts) do
    {revoked?, opts} = Keyword.pop(opts, :revoked?)

    with {:ok, %{payload: payload} = verified} <- verify_token(jwt, opts),
         :ok <- check_revoked(revoked?, payload) do
      {:ok, verified}
    end
  end

  defp verify_token(jwt, opts) do
    case Keyword.pop(opts, :document) do
      {%Document{} = doc, opts} ->
        # Resolved up front rather than inside the callback so an unresolvable
        # `kid` surfaces as itself; `Token.verify/3` flattens a failed key fetch
        # into `:signing_key_unavailable`.
        with {:ok, %{header: header}} <- Token.parse(:credential, jwt),
             {:ok, public_key, curve} <- Document.get_space_signing_key(doc, header["kid"]),
             {:ok, public_jwk} <- public_jwk(public_key, curve) do
          Token.verify(
            :credential,
            jwt,
            [get_signing_key: fn _iss, _kid, _refresh -> {:ok, public_jwk} end] ++ opts
          )
        end

      {nil, opts} ->
        Token.verify(:credential, jwt, opts)
    end
  end

  @doc """
  Verify a request presenting a space credential — everything the proposal
  requires of a receiving host ("Presenting a space credential"):

  1. an `Authorization` header in the `Atproto-Space-Credential` scheme
     (recognised case-insensitively) and an `Atproto-Space-Audience` header;
  2. the credential itself (`verify/2`: type, issuer key, signature, `kid`,
     expiry and lifetime, and the subject space when `:sub` is given);
  3. the HTTP Message Signature, against the credential's `cnf.kid`
     (`Spaces.HttpSignature.verify/2`);
  4. `Atproto-Space-Audience` equals `:audience`, the DID the host derives
     from the request (the repo owner, or the authority for host methods).

  `headers` is the request's headers (`[{name, value}]` or a lowercase-keyed
  map). Options: `:audience` (required), `:sub`, `:now`, `:revoked?`, and the
  key source — `document: %Identity.Document{}` or `get_signing_key: fun` as
  for `verify/2`. Returns `{:ok, %{header:, payload:}}`.

  ## Revocation

  A space authority may revoke outstanding credentials early with
  `com.atproto.space.notifyCredentialsRevoked` (atproto `a571a93fc`, renamed
  from `notifyCredentialRevoked` by `atproto-spaces-lexicon-review`;
  `notify_credentials_revoked/5` sends it, `decode_revocation/1` reads it). A
  repo host MUST then reject a credential whose `jti` was revoked for that
  space, and keep the revocation for at least 60 minutes — after which no
  credential carrying that `jti` can still be valid (the 3600-second lifetime
  cap). Pass `revoked?: fn space, jti -> boolean end` backed by that store;
  a revoked credential is `{:error, :credential_revoked}`.
  """
  @spec verify_request(HttpSignature.headers(), keyword()) :: {:ok, map()} | {:error, term()}
  def verify_request(headers, opts) do
    headers = normalize_headers(headers)
    audience = Keyword.fetch!(opts, :audience)

    with {:ok, jwt} <- credential_from_authorization(headers["authorization"]),
         {:ok, %{payload: payload} = verified} <-
           verify(jwt, Keyword.drop(opts, [:audience])),
         :ok <- HttpSignature.verify(headers, payload["cnf"]["kid"]),
         :ok <- check_audience(headers["atproto-space-audience"], audience) do
      {:ok, verified}
    end
  end

  @doc """
  Notify a repo host that the authority revoked credentials
  (`com.atproto.space.notifyCredentialsRevoked`; it was
  `notify_credential_revoked/5` / `notifyCredentialRevoked` before atproto
  `atproto-spaces-lexicon-review`), identified by `jti` — 1 to 100 per call.
  Revocation is idempotent, so retrying delivery is safe.

  The call is authenticated with service auth from the space authority,
  addressed to the bare repo DID (the reference host looks the audience up as
  an account it hosts). Pass `service_auth: [iss: authority_did, aud:
  repo_did, key: authority_signing_jwk]` to mint it per request
  (`XRPC.ServiceAuth`, `lxm` set for you), or a pre-minted
  `headers: [{"authorization", "Bearer " <> service_jwt}]`. Fanning
  revocations out to the repo hosts of a space is the authority's job and its
  prerogative.
  """
  @spec notify_credentials_revoked(String.t(), String.t(), [String.t()], keyword(), keyword()) ::
          :ok | {:error, term()}
  def notify_credentials_revoked(repo_host, space_ref, jtis, auth, opts \\ []) do
    with :ok <- check_jtis(jtis) do
      body = %{"space" => space_ref, "credentials" => jtis}

      case XRPC.procedure(
             repo_host,
             "com.atproto.space.notifyCredentialsRevoked",
             body,
             auth,
             opts
           ) do
        {:ok, _} -> :ok
        error -> error
      end
    end
  end

  @doc """
  Decode a received `notifyCredentialsRevoked` body into
  `{:ok, %{space: space_ref, jtis: [jti]}}`, validating its shape (1–100
  non-empty `jti` strings). Checking the request's service auth — that it is
  from the space's authority and addressed to this repo — is the host's job.
  """
  @spec decode_revocation(map()) ::
          {:ok, %{space: String.t(), jtis: [String.t()]}} | {:error, term()}
  def decode_revocation(%{"space" => space, "credentials" => jtis}) when is_binary(space) do
    with :ok <- check_jtis(jtis), do: {:ok, %{space: space, jtis: jtis}}
  end

  def decode_revocation(_), do: {:error, :invalid_revocation}

  defp check_jtis(jtis) when is_list(jtis) and jtis != [] and length(jtis) <= 100 do
    if Enum.all?(jtis, &(is_binary(&1) and &1 != "")),
      do: :ok,
      else: {:error, :invalid_revocation}
  end

  defp check_jtis(_), do: {:error, :invalid_revocation}

  defp check_revoked(nil, _payload), do: :ok

  defp check_revoked(revoked?, %{"sub" => space, "jti" => jti}) when is_function(revoked?, 2) do
    if revoked?.(space, jti), do: {:error, :credential_revoked}, else: :ok
  end

  defp credential_from_authorization(value) when is_binary(value) do
    case String.split(value, " ", parts: 2) do
      [scheme, jwt] when jwt != "" ->
        if String.downcase(scheme) == "atproto-space-credential",
          do: {:ok, String.trim(jwt)},
          else: {:error, :wrong_auth_scheme}

      _ ->
        {:error, :wrong_auth_scheme}
    end
  end

  defp credential_from_authorization(_), do: {:error, {:missing_header, "authorization"}}

  defp check_audience(audience, audience) when is_binary(audience), do: :ok
  defp check_audience(nil, _), do: {:error, {:missing_header, "atproto-space-audience"}}
  defp check_audience(_, _), do: {:error, :bad_audience}

  defp normalize_headers(headers) when is_map(headers),
    do: Map.new(headers, fn {k, v} -> {String.downcase(k), v} end)

  defp normalize_headers(headers) when is_list(headers),
    do: Enum.reduce(headers, %{}, fn {k, v}, acc -> Map.put_new(acc, String.downcase(k), v) end)

  defp exchange_body(space_ref, key, delegation_jwt, attestation) do
    %{"space" => space_ref, "credentialKey" => key.did_key}
    |> maybe_put("delegationToken", delegation_jwt)
    |> maybe_put("clientAttestation", attestation)
  end

  # The caller's request options ride along with the flow's own; the body is
  # ours and is not the caller's to override.
  defp post_exchange(http, url, body, opts) do
    request_opts = opts |> HTTP.take_request_opts() |> Keyword.put(:json, body)

    case http.post(url, request_opts) do
      {:ok, %{status: 200, body: %{"credential" => jwt}}} when is_binary(jwt) ->
        {:ok, jwt}

      {:ok, %{body: %{"error" => code}}} when is_map_key(@exchange_errors, code) ->
        {:error, Map.fetch!(@exchange_errors, code)}

      {:ok, %{status: status, body: %{} = body}} ->
        {:error, {:http_error, status, body["error"]}}

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, _} = error ->
        error
    end
  end

  defp check_binding(%{payload: %{"cnf" => %{"kid" => kid}}}, %{did_key: kid}), do: :ok

  defp check_binding(%{payload: %{"cnf" => %{"kid" => _}}}, _key),
    do: {:error, :credential_bound_to_other_key}

  defp check_binding(_, _), do: {:error, :missing_cnf}

  defp client_attestation(opts) do
    case Keyword.get(opts, :client_attestation) do
      nil -> {:ok, nil}
      {:ok, jwt} when is_binary(jwt) -> {:ok, jwt}
      jwt when is_binary(jwt) -> {:ok, jwt}
      _ -> {:error, :invalid_client_attestation}
    end
  end

  defp fetch_key(opts) do
    case Keyword.fetch(opts, :key) do
      {:ok, %{private_key: _, did_key: did_key} = key} when is_binary(did_key) ->
        if HttpSignature.p256_did_key?(did_key), do: {:ok, key}, else: {:error, :invalid_key}

      {:ok, _} ->
        {:error, :invalid_key}

      :error ->
        {:error, :missing_key}
    end
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

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
