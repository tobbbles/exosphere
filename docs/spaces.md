# Spaces: permissioned data in atproto

Exosphere ships client support for [atproto Spaces][proposal] (proposal 0016,
at the November 12 alpha — the surface the Spaces public beta launches on):
permissioned data — a **space** is an authorisation and sync boundary
identified by `(authority DID, space type, skey)`. Members keep their records
in per-user *space repos* on their own repo hosts; the space authority issues
short-lived, key-bound **space credentials**; writes go through the user's own
PDS under space-scoped OAuth; sync runs over dedicated XRPC with LtHash commit
digests authenticated by per-request MACs, so a synced copy is also an
*authenticated* copy — and a leaked one proves nothing to anyone else.

The moving parts, and where exosphere draws the client/host line:

| Role | Who | Exosphere support |
|------|-----|-------------------|
| Space authority | the DID at the root of a space; issues credentials | resolve its `#atproto` key and `#atproto_pds` endpoint (`Identity.Document`) |
| Space host | the authority's PDS: credential issuance, writer set, notifications | **bespoke, app-side** — but the building blocks ship: `Credential.decode_authorization_request/1`, `verify_request/2`, `Sync.confirm_registration/4`, `notify_space_update/5`, `decode_notify_repo_update/1`, `list_writers_output/1`, `Memberspace.decode_put_members/1`, … |
| Repo host | stores and serves space repos | served by PDSs; exosphere verifies everything they serve, and ships the host halves (`Spaces.Kem.decapsulate/2`, `Spaces.Mac.parse_request/2`, `Commit.mac_headers/2`, `Sync.notify_repo_update/4`) |
| PDS | mints delegation tokens, administers spaces (baseline policies), accepts space writes | full client support |
| Syncer / reader | an app presenting a space | the main exosphere use case |

## The moving parts

- **Space AT-URIs** (`AtUri`): `at://{authority}/space/{spaceType}/{skey}[/{authorDid}/{collection}/{rkey}]`
  — a tagged variant on the ordinary grammar; `space?/1` tells them apart, and the
  two can never be confused (`space` is not a valid NSID).
- **Identity** (`Identity.Document`): the space host is the authority's
  `#atproto_pds` endpoint and credentials are signed by its `#atproto` key
  (`get_space_host_endpoint/1`, `get_space_signing_key/1,2`); each author
  publishes a P-256 `#atproto_kem` key for the MAC handshake (`get_kem_key/1`).
- **Verification core** (`Spaces.LtHash`, `Spaces.Commit`, `Spaces.Kem`,
  `Spaces.Mac`, `Spaces.Repo`): the homomorphic set hash (BLAKE3-XOF-expanded
  lanes); the unsigned `defs#commit{ver, repo, space, rev, data}`; the HPKE
  secret export (RFC 9180 §6.2, DHKEM(P-256, HKDF-SHA256), Export-only,
  `info` `"atproto-mac"`; `Crypto.HPKE`) a syncer derives per request; the
  commit and record MACs as RFC 9421 `hmac-sha256` HTTP Message Signatures,
  requested with `Accept-Signature` and answered with a signed
  `Atproto-Space-Commit` / `Atproto-Space-Record` header; and the
  `atproto-space-repo` STAR archive (`application/vnd.dasl.star`) —
  `Spaces.Repo.verify/4` runs the whole pipeline and fails loudly on any
  tamper. STAR itself is `Exosphere.ATProto.Star`. BLAKE3 ships as a NIF
  with a pure-Elixir reference; HPKE, HKDF and HMAC use only Erlang
  `:crypto`.
- **Credentials** (`Spaces.Token`, `Spaces.Credential`, `Spaces.HttpSignature`):
  delegation tokens (60s, single-use, from the user's PDS), space credentials
  (600s by default, at most 3600s, multi-use, bound to a P-256 `did:key` via
  `cnf.kid`, from `authorizeSpaceSync`), and client attestations (app
  identity). Every use of a credential carries an RFC 9421 HTTP Message
  Signature by the bound key over the credential and its audience DID, under
  the label `sig`; hosts find it by its tag (`atproto-space-credential`), and
  verify the whole presentation — honouring revocations by `jti` — with
  `Credential.verify_request/2`.
- **Service auth** (`XRPC.ServiceAuth`): the atproto inter-service JWT
  (`iss` a bare DID, `kid`, `aud` as `did#serviceId`, `lxm`, 60-second
  `exp`, `jti`), minted and verified with the same JWS machinery.
  `notifyRepoUpdate` (repo host → space host), `notifyCredentialsRevoked`
  (space host → repo host) and the managing-app `checkAccess` use it; the
  admin calls take it as `service_auth: [iss:, aud:, key:]`.
  `confirmRegistration` and `notifySpaceUpdate` (space host → syncer) carry
  none: the registration token in the body authenticates them.
- **Scopes** (`OAuth.Scope`): the `space:{spaceType}?…` grammar (or the
  named form `space?spaceType=…`) — `read` (implies `read_self`),
  collection-constrained writes, `manage=` for administration.
- **Sync** (`Spaces.Sync`): the writer set (`list_writers/4`, `repoWrite`
  and `repoRemoved` entries), oplog paging (`list_repo_ops/5`, a MAC'd commit
  on every page) and catch-up (`sync_repo/6`), record reads, and full-archive
  recovery — every request presented with the signed credential, every
  commit or record checked against a MAC keyed by a fresh HPKE secret; the
  running set hash decides *synced and authenticated* vs diverged. Oplogs are
  a transport optimisation (they compact and reset on migration); the full
  archive is the source of truth.
- **Notifications** (`Spaces.Credential`, `Spaces.Sync`): a syncer registers
  by passing `notify: [endpoint:, token:]` to
  `Credential.authorize_space_sync/4` and keeps reauthorizing; the space host
  confirms new registrations (`confirmRegistration`) and sends
  `notifySpaceUpdate` with one of four updates. Both sides' bodies are built
  and read here.
- **Administration** (`Spaces.Space`, `Spaces.Policy`, `Spaces.Memberspace`,
  `Spaces.Managedspace`): spaces are created with a single `policy` object —
  one of the three baseline policies every PDS supports (`personalspace`,
  `memberspace`, `managedspace`) — and replaced wholesale on update; the
  member list (batched `put_members/5` / `remove_members/5`) and the
  managing-app check (`check_access/4`, answering read and write) live with
  their policies; `remove_writer/5` prunes the writer set.
- **Writes** (`Spaces.Writes`): `createRecord` / `putRecord` / `deleteRecord` /
  `applyWrites` / `clearRecords` on the user's own PDS, under a space-scoped
  OAuth session.
- **Migration** (`Spaces.SpaceMeta`, `Space.export_space_meta/4`,
  `import_space_meta/4`, `Writes.import_repo/4`): the space meta archive and
  repo archives an account carries to a new host.

## A reader's flow, end to end

      # 1. Resolve the space authority: its space host is its PDS
      {:ok, doc} = resolve(authority_did)
      {:ok, space_host} = Document.get_space_host_endpoint(doc)

      # 2. A delegation token from the user's PDS (space-scoped OAuth). Skip
      #    for a space that does not gate on the user (e.g. public_read).
      {:ok, delegation} =
        Spaces.Credential.get_delegation_token(pds, space_ref, session: session)

      # 3. Authorize sync at the space host: a credential bound to a fresh
      #    key, optionally registering for notifications
      {:ok, key} = Spaces.HttpSignature.generate_key()

      {:ok, cred} =
        Spaces.Credential.authorize_space_sync(space_host, space_ref, delegation,
          key: key,
          notify: [endpoint: "https://syncer.example.com", token: token_for(space_ref)]
        )

      # 4. Follow the writer set, sync each member repo still in it
      {:ok, %{repos: repos}} = Spaces.Sync.list_writers(space_host, space_ref, cred)

      for %{type: :repo_write, repo: repo_did} <- repos do
        # The author's KEM key authenticates what their repo host serves; a
        # resolver lets a failed MAC re-resolve it (it may have rotated)
        {:ok, author_doc} = resolve(repo_did)
        {:ok, repo_host} = Document.get_pds_endpoint(author_doc)
        kem_key = fn refresh? -> author_doc |> maybe_refresh(refresh?) |> Document.get_kem_key() end

        # Full archive first (verified end to end), then oplog deltas
        {:ok, verified} =
          Spaces.Sync.get_repo(repo_host, space_ref, repo_did, cred, kem_key: kem_key)

        {:ok, %{lthash: running, commit: commit}} =
          Spaces.Sync.sync_repo(repo_host, space_ref, repo_did, cred,
            %{rev: verified.rev, lthash: verified.lthash},
            kem_key: kem_key
          )

        Spaces.Sync.synced?(running, commit) #=> true: synced *and authenticated*
      end

Divergence (a compacted oplog, a migrated account) surfaces as
`sync_repo/6` answering `{:error, {:diverged, commit}}`,
`{:error, :ops_out_of_order}` or `{:error, {:since_out_of_bounds, _}}` —
recover with another full archive. `{:error, :repo_not_found}` means the host
never had the repo, or emptied and collected it: treat it as empty. A MAC
that fails is `{:error, {:invalid_space_mac, reason}}`; with a `kem_key:`
resolver the client re-resolves the key and retries once by itself, each
attempt with a new HPKE secret.

To follow a space live, serve two XRPC procedures at the `notify` endpoint
and keep reauthorizing with the same `notify` before each credential expires:

- `com.atproto.space.confirmRegistration`: `Sync.decode_confirm_registration/1`,
  check the token is the one you issued for that space
  (`Sync.token_matches?/2`), answer `Sync.confirm_registration_response/1`.
- `com.atproto.space.notifySpaceUpdate`: `Sync.decode_space_update/1`, check
  the token, then act on the update — `:repo_write` (sync the repo),
  `:repo_removed` (stop treating it as part of the space), `:space_deleted`
  (reauthorize; only a `SpaceDeleted` answer confirms it), or
  `:registration_expired` (reauthorize with `notify:` and catch up through
  `list_writers/4` from the checkpoint — or reject with a 400 to
  unregister). A `prev_space_rev` that is not your last `space_rev` means a
  gap: catch up with `list_writers/4`'s `cursor:`. A checkpoint more than
  72 hours old should list the whole writer set instead, as removed and
  emptied repos may have been collected.

## What deliberately stays app-side

The services themselves: exosphere is a library, and hosts are bespoke (the
consumer's job). The host-side halves that *do* ship — credential and
HTTP-signature verification with a revocation hook, `authorizeSpaceSync`
request decoding, KEM decapsulation, MAC request parsing and response
headers, the notification bodies on both ends (`confirmRegistration`,
`notifySpaceUpdate`, `notifyRepoUpdate` with its service-auth check),
`listWriters` output, member-list request decoding, STAR and space-meta
serialization — are there because exosphere consumers host spaces too.
Storing registrations, sequencing the writer set, delivering and retrying
notifications, and serving the HTTP endpoints stay in the consumer's process
tree.

### What this follows upstream

| Source | Ref |
|---|---|
| Lexicons, PDS behaviour and `@atproto/space` | bluesky-social/atproto branch `permissioned-data` at `d4def6e` (the November 12 alpha, `0.0.0-spaces-alpha-20261112204144`); the branch's later commits up to `16bfeba` (2026-11-13) leave the lexicons unchanged |
| Normative November 5 → 12 delta | `alpha-migrations/prompt-11-12-26.md` at that commit |
| Proposal text | bluesky-social/proposals `main` at `0634c26`, with proposals#143 (README at `b54ec68`) carrying the November 12 changes |

The `:external` spec-pins suite reads the lexicons at `d4def6e` and checks
that the space namespaces hold exactly the methods exosphere knows, that every
method it calls still exists with the parameters it sends, and the shapes it
reads (`defs#repoWrite`/`#repoRemoved`, the `notifySpaceUpdate` union,
`listRepoOps`' commit on every page). Set `EXOSPHERE_SPEC_PINS_REF` to a
branch to see how far the client is from where that branch is now.

## Conformance: the counterparty corpus and the second encoder

The spaces wire format is pinned three independent ways, all running in the
default CI suite:

1. **The counterparty corpus** (`test/fixtures/spaces-corpora/`): bytes
   generated by the official reference implementation — `@atproto/space` at
   bluesky-social/atproto `4037310` with `@atproto/star` from `98ef3a6`
   grafted in (MIT). It predates the November 12 alpha, which replaced the
   KEM derivation and the MAC format; the corpus's November 5 secrets and
   MACs are no longer asserted until it is regenerated (see the fixture
   directory's `SOURCE.md`). The rest is asserted byte for byte by
   `test/interop/spaces_corpus_test.exs`, and the reference's commits,
   records and archives are verified under November 12 MACs computed there:

   | Fixture | Pins |
   |---|---|
   | `lthash.json` | 10 cases: empty/multi-element states and digests, add-remove cycles, multiset double-add, underflow wrap, a 512-byte rkey element |
   | `commit-mac.json` | commits built from set-hash elements (incl. a 532-byte space URI) and record values' CIDs; its KEM secrets and MAC headers are November 5 history |
   | `repo-star.json` | the `atproto-space-repo` STAR archive, populated and empty, with a record pair whose length-first and bytewise orders differ — exosphere's serializer reproduces it byte-identically and its verifier accepts it |
   | `credentials.json` | the three token classes (typ/kid, claims, TTLs, `cnf.kid`, `jti`) by shape and signature, and the RFC 9421 presentation signature: exosphere verifies the reference's by tag and signs the same covered components and parameters |
   | `space-meta.json` | an `atproto-space-meta` archive (writers keyed `repoRev`), decoded and re-encoded byte-identically |

   The generic STAR container rules are pinned separately by the upstream
   STAR interop fixtures (`test/fixtures/star/`: 19 valid archives
   round-trip, 37 invalid ones are rejected).

2. **The reference's own test vectors** for the November 12 bytes: the CFRG
   export-only DHKEM(P-256) HPKE vector and atproto's Go-computed
   `atproto-mac` secret (`Crypto.HPKE`, `Spaces.Kem`), and the exact
   `Accept-Signature`, `Atproto-Space-Commit`, `Signature-Input` and
   signature-base strings of `packages/space/tests/mac.test.ts`
   (`Spaces.Mac`).

3. **The G6 second encoder** (`test/support/spaces_spec_encoder.ex`): a
   test-only reimplementation written from the proposal and the RFCs it
   defers to — lane math, the HPKE secret export (RFC 9180 §4–§5.3), the MAC
   request, covered headers and RFC 9421 signature base, and the STAR repo
   and space-meta archives with its own minimal DAG-CBOR writer. It
   reproduces the HPKE vectors and the reference's MAC strings by itself,
   is differentially checked against the production modules with
   stream_data properties (`spec_encoder_test.exs`), and re-derives every
   deterministic corpus fixture it covers. BLAKE3-XOF, P-256 ECDH and
   HMAC-SHA256 are the shared primitives, each pinned independently.

**What the corpus cannot prove:** live-wire interop (HTTP layers against a
running reference PDS — the `:external`-tagged live suite stays
skip-until-green), the credential *exchange* round trip, notification
delivery, and blob sync. Exosphere's P-256 signatures use a random nonce
where the reference uses RFC 6979, so presentation signatures are compared by
verification, not by bytes. The reference PDS neither declares nor emits
`SinceOutOfBounds`; exosphere's client types it for hosts that signal the
oplog-window floor explicitly, per the proposal's "cannot find its `since`
revision" guidance.

[proposal]: https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data
