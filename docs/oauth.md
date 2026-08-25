# OAuth (DPoP-bound ATProto sessions)

Exosphere implements the [ATProto OAuth profile](https://atproto.com/specs/oauth):
OAuth 2.0 with PAR (Pushed Authorization Requests), PKCE (S256), DPoP-bound
access tokens, `private_key_jwt` client authentication, and identity-based
authorization-server discovery. This is the supported way to obtain a
session; app-password `createSession` still works but is deprecated
upstream.

The implementation lives in two layers, like the rest of exosphere:

- `Exosphere.ATProto.OAuth.*` — protocol-level building blocks
  (`PKCE`, `JWK`, `JWS`, `DPoP`, `Client`, `ClientMetadata`,
  `ServerMetadata`, `Discovery`, `RequestContext`, `Flow`, `Session`)
- `Exosphere.OAuth.Session` — a GenServer wrapper that keeps a session
  fresh and makes DPoP-signed XRPC calls

## The shape of the flow

```
handle/DID ──Discovery──► PDS ──protected-resource──► authorization server
     │                                                    │
     ▼                                                    ▼
 authorize_url (PAR + DPoP proof + nonce handling)   request_uri
     │                                                    │
     ▼                                                    ▼
 browser redirect ──────────────────► redirect_uri?code&state&iss
                                                          │
                                                          ▼
                                     Flow.callback ──► %Session{} (DPoP-bound)
```

## Confidential web client

A confidential client serves a metadata document at its `client_id` URL and
holds an ES256 private key. Build the configuration once (e.g. at compile
time) and serve `to_document/1` at that URL:

```elixir
alias Exosphere.ATProto.OAuth.{Client, ClientMetadata, JWK}

{:ok, client_key} = JWK.generate(:p256)

metadata =
  ClientMetadata.new!(
    client_id: "https://app.example.com/oauth-client-metadata.json",
    client_name: "My App",
    redirect_uris: ["https://app.example.com/oauth/callback"],
    scope: ["atproto", "transition:generic"],
    jwk: JWK.to_public(client_key)     # published in the document
  )

client = Client.new!(metadata: metadata, key: client_key, redirect_uri: "https://app.example.com/oauth/callback")

# in your router: GET "/oauth-client-metadata.json"
#   json(conn, ClientMetadata.to_document(metadata))
```

Keep `client_key` in configuration/secrets — every client assertion is
signed with it.

## Starting the flow

```elixir
alias Exosphere.ATProto.OAuth.{Discovery, Flow, RequestContext}

{:ok, resolved} = Discovery.resolve("alice.example.com")   # handle, DID, or server URL
{:ok, {authorize_url, ctx}} = Flow.authorize_url(client, resolved)

# Store ctx server-side (Plug session, DB…), then redirect the browser:
# redirect(conn, external: authorize_url)
```

`ctx` (a `RequestContext`) contains the PKCE verifier and the session DPoP
private key — store it server-side, never in a browser-readable cookie.
For persistence across processes, `RequestContext.to_map/1` and
`from_map/1` round-trip through plain JSON-encodable maps.

## Completing the flow

```elixir
{:ok, session} = Flow.callback(ctx, conn.query_params)
# %Session{sub: "did:plc:...", access_token: ..., pds: "https://...", ...}
```

`callback/3` verifies the `state` and `iss` parameters, exchanges the code
(with PKCE `code_verifier`, the client assertion, and a DPoP proof), and
validates the response: `token_type` must be `DPoP`, the scope must include
`atproto`, and `sub` must match the identity you resolved (for server-URL
flows the subject's PDS is resolved and checked against the issuer).

## Using the session

Park it under your supervision tree and make XRPC calls:

```elixir
{:ok, pid} = Exosphere.OAuth.Session.start_link(
  session: session,
  on_refresh: {MyApp.Accounts, :oauth_session_refreshed, []},
  name: {:via, Registry, {MyApp.Registry, "oauth:" <> session.sub}}
)

{:ok, profile} = Exosphere.OAuth.Session.query(pid, "app.bsky.actor.getProfile", actor: session.sub)
{:ok, _} = Exosphere.OAuth.Session.procedure(pid, "com.atproto.repo.createRecord", %{...})
```

Every request is DPoP-signed (proof header + `Authorization: DPoP ...`);
nonce challenges are retried automatically. The GenServer refreshes tokens
when they near expiry (and once more on an `ExpiredToken` response) and
serializes refreshes so the rotating refresh token is never used twice.

`Exosphere.ATProto.Repo` accepts the session directly:

```elixir
{:ok, %{uri: uri, cid: cid}} =
  Exosphere.ATProto.Repo.put_record(session, session.pds, session.sub,
    "app.bsky.actor.profile", "self", %{"displayName" => "Alice"})
```

Or build a plain XRPC client — it carries the DPoP key and signs per
request:

```elixir
xrpc = Exosphere.OAuth.Session.xrpc_client(session)
{:ok, %{"did" => did}} = Exosphere.ATProto.XRPC.Client.query(xrpc, "com.atproto.identity.resolveHandle", handle: "atproto.com")
```

## Persistence

The session is plain data. Persist it with
`Exosphere.ATProto.OAuth.Session.to_map/1` (JSON-encodable) and restore
with `from_map/1`. Refresh tokens are single-use and rotating: after every
refresh, replace your stored copy — use the `:on_refresh` callback (or
`handle/2` the GenServer's state) to write the new tokens back. A refresh
failing with `invalid_grant` means the refresh token was reused or revoked:
discard the session and re-authorize.

## Local development (loopback clients)

For local development there is a special loopback client identifier — no
hosted document, no client key:

```elixir
{:ok, client_id} = ClientMetadata.localhost_client_id(["http://localhost:4000/oauth/callback"])
metadata = ClientMetadata.new!(client_id: client_id, redirect_uris: ["http://localhost:4000/oauth/callback"])
client = Client.new!(metadata: metadata, redirect_uri: "http://localhost:4000/oauth/callback")
```

Redirect URIs must be loopback (`localhost`/`127.0.0.1`); any port matches
at authorization time (RFC 8252).

## E2E testing your integration

`test/support/mock_pds.ex` contains a dependency-free mock PDS +
authorization server that implements the profile faithfully enough to
exercise the full flow in-process: metadata discovery, PAR with nonce
challenges, PKCE verification, client-assertion verification, DPoP proof
verification (including `ath` and key continuity), rotating refresh tokens,
and a DPoP-protected XRPC endpoint. See
`test/exosphere/e2e/oauth_e2e_test.exs` for usage. The mock is test-support
code (not shipped with the Hex package) — copy it if you want it in your
own project.

Live discovery checks against bsky.social exist too:

```
mix test --only live
```

## Spec conformance notes

- **ES256 (P-256)** is the required-and-default algorithm for DPoP proofs
  and client assertions; ES256K is also supported for DPoP.
- **PAR is mandatory**: `Flow.authorize_url/3` pushes all request parameters
  form-encoded to the PAR endpoint and returns a `request_uri`-only
  authorize URL, per the profile.
- **Nonce handling** is centralized in `Exosphere.ATProto.OAuth.Request`:
  `400 use_dpop_nonce` / nonce-bearing `401` responses are retried once
  with the server-issued nonce, cached per-origin in
  `DPoP.NonceStore` (an ETS table owned by `Exosphere.Application`, which
  the dependency starts).
- **Metadata validation** enforces every ATProto AS-metadata requirement
  (issuer origin match, PAR required, `none` + `private_key_jwt` auth,
  ES256 signing, `atproto` scope, authorization-response `iss` support)
  before any endpoint is used.
- `ATProto.Repo`'s hand-rolled DPoP implementation was replaced by the
  shared one; it now accepts either a map with `access_token` +
  `dpop_private_key` (base64 JSON JWK, the historical shape) or an
  `%Exosphere.ATProto.OAuth.Session{}`.
