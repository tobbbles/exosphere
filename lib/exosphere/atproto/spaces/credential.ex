defmodule Exosphere.ATProto.Spaces.Credential do
  @moduledoc """
  The space credential flow (atproto proposal 0016, "Access control";
  November 12 alpha, atproto `d4def6e`): fetch a delegation token from the
  user's PDS, authorize syncing the space at its host for a key-bound
  credential (optionally registering for notifications), present that
  credential with an HTTP Message Signature — and, because a credential's
  consumer is often a host, verify such requests.

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

      {:ok, %{credential: _, key: _, space_rev: space_rev} = cred} =
        Credential.authorize_space_sync("https://space-host.example.com", space_ref, delegation,
          key: key,
          client_attestation: attestation,  # only when the space gates on the app
          notify: [endpoint: "https://syncer.example.com", token: per_space_token]
        )

      # 3. Present it: Authorization + Atproto-Space-Audience + an RFC 9421
      #    signature by `key` (Spaces.Sync does this for every request)
      {:ok, headers} = Credential.presentation_headers(cred, repo_owner_did)

  `com.atproto.space.authorizeSpaceSync` (it was `getSpaceCredential` before
  the November 12 alpha) is unauthenticated: the key to bind
  (`credentialKey`, the key's `did:key`), the optional delegation token and
  client attestation, and the optional `notify` registration travel in the
  JSON body. The credential is bound to that key by `cnf.kid`, lives 600
  seconds by default (at most 3600), and every use is signed — see
  `Spaces.HttpSignature`. A public space needs no delegation token. The
  answer carries the space's current revision, `spaceRev`, omitted before
  the space's first update.

  ## Reauthorizing and notifications

  Calling `authorize_space_sync/4` again before the credential expires is
  *reauthorizing*; it works the same as the first call. A syncer registers
  for `com.atproto.space.notifySpaceUpdate` by passing `notify:` — an
  `endpoint` (a base URL the host calls XRPC methods against) and an opaque
  `token` of at most 512 bytes, different per space and stable across
  authorizations (the pair identifies the registration). Before creating a
  new registration the host calls `com.atproto.space.confirmRegistration` on
  the endpoint, and fails the authorization with `RegistrationNotConfirmed`
  if the syncer does not echo the challenge. A registration lives only as
  long as the credential from its latest authorization, so a syncer wanting
  continuous notifications keeps reauthorizing with the same `notify` before
  each credential expires. Compare the returned `space_rev` with the
  checkpoint to detect missed updates. (`registerNotify` / `unregisterNotify`
  are gone; to unregister, stop reauthorizing.)

  ## Both sides

  The client half is `get_delegation_token/3`, `authorize_space_sync/4` and
  `presentation_headers/2`. Minting delegation tokens is the PDS's job and
  minting credentials the space host's (`Spaces.Token.sign/3`), but exosphere
  consumers host spaces too, so the receiving half ships here as well:
  `decode_authorization_request/1` and `authorization_response/2` for the
  space host's `authorizeSpaceSync` handler, and `verify/2` /
  `verify_request/2` for a repo host checking a presented credential.

  All HTTP goes through `Exosphere.ATProto.HTTP.Behaviour` (pass `:http` to
  substitute a mock), so the whole flow tests offline. Request options
  (`:timeout`, `:follow_redirects`) travel in the same keyword list and are
  forwarded to the transport — see `Exosphere.ATProto.HTTP` on what a
  `:timeout` actually bounds.
  """

  alias Exosphere.ATProto.{Crypto, HTTP, TID}
  alias Exosphere.ATProto.Identity.Document
  alias Exosphere.ATProto.OAuth.{Request, Session}
  alias Exosphere.ATProto.Spaces.{HttpSignature, Token, XRPC}

  @delegation_nsid "com.atproto.space.getDelegationToken"
  @authorize_nsid "com.atproto.space.authorizeSpaceSync"
  @max_notify_token_bytes 512

  # The refusals that change what a syncer does, typed. `NotAuthorized` is
  # the lexicon's generic refusal (a host may answer it in place of
  # `AccountNotAuthorized` or `AppNotAuthorized`); `UpstreamFailure` is the
  # reference host's answer when a managed space's managing app can't decide,
  # which — unlike a refusal — leaves a notify registration in place.
  @authorize_errors %{
    "SpaceDeleted" => :space_deleted,
    "RepoTakendown" => :repo_takendown,
    "RepoDeactivated" => :repo_deactivated,
    "AccountNotAuthorized" => :account_not_authorized,
    "AppNotAuthorized" => :app_not_authorized,
    "NotAuthorized" => :not_authorized,
    "RegistrationNotConfirmed" => :registration_not_confirmed,
    "UpstreamFailure" => :upstream_failure
  }

  @typedoc """
  An authorized credential with the key it is bound to — what `Spaces.Sync`
  takes — and the space's revision at authorization (`nil` before the
  space's first update).
  """
  @type t :: %{
          required(:credential) => String.t(),
          required(:key) => HttpSignature.key(),
          optional(:space_rev) => String.t() | nil
        }

  @typedoc """
  A notification registration: `endpoint` is the syncer's base URL, `token`
  an opaque secret of at most 512 bytes. Given as a map or keyword list.
  """
  @type notify ::
          %{endpoint: String.t(), token: String.t()} | [endpoint: String.t(), token: String.t()]

  @typedoc "A decoded `authorizeSpaceSync` request, as the space host sees it."
  @type authorization_request :: %{
          space: String.t(),
          credential_key: String.t(),
          delegation_token: String.t() | nil,
          client_attestation: String.t() | nil,
          notify: %{endpoint: String.t(), token: String.t()} | nil
        }
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
  use it immediately with `authorize_space_sync/4`.
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
  Authorize syncing a space at its host (`com.atproto.space.authorizeSpaceSync`,
  which was `getSpaceCredential` before the November 12 alpha), returning a
  fresh credential. Call it again before the credential expires to
  reauthorize.

  `delegation_jwt` is the delegation token from `get_delegation_token/3`, or
  `nil` for a space that does not gate on the user (a public space). Options:

  - `:key` (required) — a fresh `Spaces.HttpSignature.generate_key/0` key; its
    `did:key` is sent as `credentialKey` and becomes the credential's
    `cnf.kid`. Keep it for the credential's lifetime and discard it after.
  - `:client_attestation` — only when the space gates on app identity.
  - `:notify` — register (or renew the registration of) an endpoint for
    `notifySpaceUpdate`: `[endpoint: base_url, token: secret]` or the same as
    a map (see "Reauthorizing and notifications" above). The endpoint must be
    an absolute `http(s)` URL and the token at most 512 bytes, else
    `{:error, :invalid_notify}` before anything is sent. The reference host
    fetches the endpoint with SSRF protection, so outside dev mode it must be
    HTTPS on a public address.

  The request is unauthenticated: everything travels in the JSON body. On
  success the credential is checked to be bound to `key` before it is
  returned, so a misbehaving host is caught immediately. Returns
  `{:ok, %{credential: jwt, key: key, space_rev: tid | nil}}`, ready for
  `Spaces.Sync`; a `spaceRev` that is not a TID is
  `{:error, :invalid_space_rev}`.

  Refusals that change what a syncer should do are typed:

  - `{:error, :space_deleted}` (`SpaceDeleted`, answered before the request's
    authorization is checked) — the space is gone: drop every copy of its
    data (proposal 0016, "Space deletion"). This answer, not a
    `#spaceDeleted` notice alone, is what confirms the deletion.
  - `{:error, :repo_takendown}` / `{:error, :repo_deactivated}` — the space
    authority's account is taken down or deactivated. A notify registration
    is kept (lapsed) through the suspension.
  - `{:error, :account_not_authorized}` (`AccountNotAuthorized`, which was
    `UserNotAuthorized`), `{:error, :app_not_authorized}`
    (`AppNotAuthorized`, the policy's `allowed_apps`), and
    `{:error, :not_authorized}` (`NotAuthorized`, the generic refusal) — the
    policy denies this syncer; a registration carried by the request is
    withdrawn.
  - `{:error, :registration_not_confirmed}` (`RegistrationNotConfirmed`) —
    the `notify` endpoint did not answer `confirmRegistration` with the
    challenge.
  - `{:error, :upstream_failure}` (`UpstreamFailure`) — the host could not
    decide (a managed space's managing app failed). Not a denial: no
    credential, but the registration stays; retry later.

  Other refusals (`SpaceNotFound`, `InvalidDelegationToken`,
  `InvalidClientAttestation`, …) come back as
  `{:error, {:http_error, status, code}}`.
  """
  @spec authorize_space_sync(String.t(), String.t(), String.t() | nil, keyword()) ::
          {:ok, t()} | {:error, term()}
  def authorize_space_sync(space_host_url, space_ref, delegation_jwt, opts \\ []) do
    http = Keyword.get(opts, :http, HTTP)
    url = String.trim_trailing(space_host_url, "/") <> "/xrpc/" <> @authorize_nsid

    with {:ok, key} <- fetch_key(opts),
         {:ok, attestation} <- client_attestation(opts),
         {:ok, notify} <- notify_opt(opts),
         body = authorize_body(space_ref, key, delegation_jwt, attestation, notify),
         {:ok, jwt, space_rev} <- post_authorize(http, url, body, opts),
         {:ok, parsed} <- Token.parse(:credential, jwt),
         :ok <- check_binding(parsed, key) do
      {:ok, %{credential: jwt, key: key, space_rev: space_rev}}
    end
  end

  @doc """
  Decode a received `com.atproto.space.authorizeSpaceSync` body for a space
  host: `{:ok, %{space:, credential_key:, delegation_token:,
  client_attestation:, notify:}}`, the optional fields `nil` when absent and
  `notify` as `%{endpoint:, token:}`.

  Checked here: `space` is a space ref, `credentialKey` a P-256 `did:key`
  (`{:error, :invalid_credential_key}`, which the reference answers as
  `InvalidRequest`), the tokens are strings, and `notify` has an `endpoint`
  that is a URI and a `token` of at most 512 bytes
  (`{:error, :invalid_notify}`). Any other malformation is
  `{:error, :invalid_request}`.

  Left to the host, in the reference's order: answer `SpaceDeleted` for a
  deleted space before anything else; verify the delegation token
  (`Spaces.Token.verify/3`, its `sub` must equal `space`) and the client
  attestation; apply the policy, withdrawing the request's registration on a
  refusal but not on `UpstreamFailure`; confirm a *new* registration with
  `confirmRegistration` (a 10-second bound in the reference) or fail with
  `RegistrationNotConfirmed`; mint the credential (`Spaces.Token.sign/3`,
  600 seconds by default) and renew the registration's expiry to the
  credential's `exp`; read `spaceRev` after registering. Fetch the endpoint
  as an untrusted URL.
  """
  @spec decode_authorization_request(map()) ::
          {:ok, authorization_request()}
          | {:error, :invalid_request | :invalid_credential_key | :invalid_notify}
  def decode_authorization_request(%{"space" => space, "credentialKey" => key} = body)
      when is_binary(key) do
    delegation = Map.get(body, "delegationToken")
    attestation = Map.get(body, "clientAttestation")

    with true <- XRPC.space_ref?(space) || {:error, :invalid_request},
         true <- optional_string?(delegation) || {:error, :invalid_request},
         true <- optional_string?(attestation) || {:error, :invalid_request},
         true <- HttpSignature.p256_did_key?(key) || {:error, :invalid_credential_key},
         {:ok, notify} <- decode_notify(Map.get(body, "notify")) do
      {:ok,
       %{
         space: space,
         credential_key: key,
         delegation_token: delegation,
         client_attestation: attestation,
         notify: notify
       }}
    end
  end

  def decode_authorization_request(_), do: {:error, :invalid_request}

  @doc """
  The space host's `authorizeSpaceSync` answer in its wire shape:
  `%{"credential" => jwt, "spaceRev" => rev}`, with `spaceRev` omitted when
  `nil` (before the space's first update).
  """
  @spec authorization_response(String.t(), String.t() | nil) :: map()
  def authorization_response(credential, space_rev \\ nil) when is_binary(credential),
    do: maybe_put(%{"credential" => credential}, "spaceRev", space_rev)

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
  `com.atproto.space.notifyCredentialsRevoked` (`notify_credentials_revoked/5`
  sends it, `decode_revocation/1` reads it). A revoked credential also drops
  the notify registrations it renewed — that is the space host's job. A
  repo host MUST then reject a credential whose `jti` was revoked for that
  space, and keep the revocation for at least 60 minutes — after which no
  credential carrying that `jti` can still be valid (the 3600-second lifetime
  cap). Pass `revoked?: fn space, jti -> boolean end` backed by that store;
  a revoked credential is `{:error, :credential_revoked}`.
  """
  @spec verify_request(HttpSignature.headers(), keyword()) :: {:ok, map()} | {:error, term()}
  def verify_request(headers, opts) do
    # The same normalization `HttpSignature.verify/2` applies: repeated
    # Signature-Input/Signature field lines are joined rather than dropped, so
    # a second credential-tagged signature is seen and refused, and list
    # values (as Req returns them) reduce to one string.
    headers = HttpSignature.normalize_headers(headers)
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
  (`com.atproto.space.notifyCredentialsRevoked`), identified by `jti` — 1 to
  100 per call.
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

  defp authorize_body(space_ref, key, delegation_jwt, attestation, notify) do
    %{"space" => space_ref, "credentialKey" => key.did_key}
    |> maybe_put("delegationToken", delegation_jwt)
    |> maybe_put("clientAttestation", attestation)
    |> maybe_put("notify", notify && %{"endpoint" => notify.endpoint, "token" => notify.token})
  end

  # The caller's request options ride along with the flow's own; the body is
  # ours and is not the caller's to override.
  defp post_authorize(http, url, body, opts) do
    request_opts = opts |> HTTP.take_request_opts() |> Keyword.put(:json, body)

    case http.post(url, request_opts) do
      {:ok, %{status: 200, body: %{"credential" => jwt} = resp}} when is_binary(jwt) ->
        case Map.get(resp, "spaceRev") do
          nil -> {:ok, jwt, nil}
          rev when is_binary(rev) -> if TID.valid?(rev), do: {:ok, jwt, rev}, else: bad_rev()
          _ -> bad_rev()
        end

      {:ok, %{body: %{"error" => code}}} when is_map_key(@authorize_errors, code) ->
        {:error, Map.fetch!(@authorize_errors, code)}

      {:ok, %{status: status, body: %{} = body}} ->
        {:error, {:http_error, status, body["error"]}}

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, _} = error ->
        error
    end
  end

  defp bad_rev, do: {:error, :invalid_space_rev}

  defp notify_opt(opts) do
    case Keyword.get(opts, :notify) do
      nil ->
        {:ok, nil}

      notify when is_list(notify) or is_map(notify) ->
        endpoint = notify[:endpoint]
        token = notify[:token]

        if http_url?(endpoint) and notify_token?(token),
          do: {:ok, %{endpoint: endpoint, token: token}},
          else: {:error, :invalid_notify}

      _ ->
        {:error, :invalid_notify}
    end
  end

  # The syncer's own endpoint: an absolute http(s) URL with a host.
  defp http_url?(value) when is_binary(value) do
    case URI.new(value) do
      {:ok, %URI{scheme: scheme, host: host}}
      when scheme in ["https", "http"] and is_binary(host) and host != "" ->
        true

      _ ->
        false
    end
  end

  defp http_url?(_), do: false

  defp notify_token?(token),
    do: is_binary(token) and byte_size(token) <= @max_notify_token_bytes

  # The host side follows the lexicon: `endpoint` a `uri`, `token` a string of
  # at most 512 bytes. Whether to insist on HTTPS / a public address is the
  # host's fetch policy, not the request shape.
  defp decode_notify(nil), do: {:ok, nil}

  defp decode_notify(%{"endpoint" => endpoint, "token" => token}) do
    if XRPC.uri?(endpoint) and notify_token?(token),
      do: {:ok, %{endpoint: endpoint, token: token}},
      else: {:error, :invalid_notify}
  end

  defp decode_notify(_), do: {:error, :invalid_notify}

  defp optional_string?(value), do: is_nil(value) or is_binary(value)

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
