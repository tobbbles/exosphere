# Spaces: permissioned data in atproto

Exosphere ships client support for [atproto Spaces][proposal] (proposal 0016,
alpha): permissioned data — a **space** is an authorisation and sync boundary
identified by `(authority DID, space type, skey)`. Members keep their records
in per-user *space repos* on their own repo hosts; the space authority mints
short-lived, key-bound **space credentials**; writes go through the user's own
PDS under space-scoped OAuth; sync runs over dedicated XRPC with LtHash commit
digests authenticated by per-request MACs, so a synced copy is also an
*authenticated* copy — and a leaked one proves nothing to anyone else.

The moving parts, and where exosphere draws the client/host line:

| Role | Who | Exosphere support |
|------|-----|-------------------|
| Space authority | the DID at the root of a space; issues credentials | resolve its `#atproto` key and `#atproto_pds` endpoint (`Identity.Document`) |
| Space host | the authority's PDS: credential exchange, writer set, notify routing | **bespoke, app-side** — but `Spaces.Credential.verify_request/2`, `Spaces.HttpSignature`, `Spaces.Kem.decapsulate/2` and `Spaces.Mac` ship so consumers can host |
| Repo host | stores and serves space repos | served by PDSs; exosphere verifies everything they serve |
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
  lanes); the unsigned `defs#commit{ver, repo, space, rev, data}`; the
  RFC 9180 DHKEM(P-256) shared secret a syncer derives per request; the commit
  and record MACs carried in `Atproto-Space-Mac`; and the `atproto-space-repo`
  STAR archive — `Spaces.Repo.verify/4` runs the whole pipeline and fails
  loudly on any tamper. STAR itself is `Exosphere.ATProto.Star`. BLAKE3 ships
  as a NIF with a pure-Elixir reference; KEM and HKDF use only Erlang
  `:crypto`.
- **Credentials** (`Spaces.Token`, `Spaces.Credential`, `Spaces.HttpSignature`):
  delegation tokens (60s, single-use, from the user's PDS), space credentials
  (600s by default, at most 3600s, multi-use, bound to a P-256 `did:key` via
  `cnf.kid`), and client attestations (app identity). Every use of a
  credential carries an RFC 9421 HTTP Message Signature by the bound key over
  the credential and its audience DID. Hosts verify the whole presentation —
  and honour revocations by `jti` — with `Credential.verify_request/2`.
- **Scopes** (`OAuth.Scope`): the `space:{type}?…` grammar — `read` (implies
  `read_self`), collection-constrained writes, `manage=` for administration.
- **Sync** (`Spaces.Sync`): the writer set, oplog paging, record reads, and
  full-archive recovery — every request presented with the signed credential,
  every commit or record checked against its MAC; the running set hash
  decides *synced and authenticated* vs diverged. Oplogs are a transport
  optimisation (they compact and reset on migration); the full archive is the
  source of truth.
- **Administration** (`Spaces.Space`, `Spaces.Policy`, `Spaces.Memberspace`,
  `Spaces.Managedspace`): spaces are created with a single `policy` object —
  one of the three baseline policies every PDS supports (`personalspace`,
  `memberspace`, `managedspace`) — and replaced wholesale on update; the
  member list and the managing-app check live with their policies;
  `remove_writer/5` prunes the writer set.
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

      # 3. Exchange it at the space host for a credential bound to a fresh key
      {:ok, key} = Spaces.HttpSignature.generate_key()
      {:ok, cred} = Spaces.Credential.mint(space_host, space_ref, delegation, key: key)

      # 4. Follow the writer set, sync each member repo
      {:ok, %{repos: repos}} = Spaces.Sync.list_repos(space_host, space_ref, cred)

      for repo <- repos do
        # The author's KEM key authenticates what their repo host serves
        {:ok, author_doc} = resolve(repo.did)
        {:ok, kem_key} = Document.get_kem_key(author_doc)

        # Full archive first (verified end to end), then oplog deltas
        {:ok, verified} =
          Spaces.Sync.get_repo(repo_host, space_ref, repo.did, cred, kem_key: kem_key)

        {:ok, %{ops: ops, commit: commit}} =
          Spaces.Sync.list_repo_ops(repo_host, space_ref, repo.did, cred,
            kem_key: kem_key,
            since: verified.rev
          )

        running = Spaces.Sync.apply_ops(verified.lthash, ops)

        Spaces.Sync.synced?(running, commit) #=> true: synced *and authenticated*
      end

Divergence (a compacted oplog, a migrated account) surfaces as
`synced?/2` turning false — recover with another full archive. A MAC that
fails (`{:error, :invalid_mac}`) usually means the author's KEM key rotated:
refresh their DID document and retry.

## What deliberately stays app-side

The space-host service itself: exosphere is the client library, and hosts are
bespoke (the consumer's job). The host-side halves that *do* ship — credential
and HTTP-signature verification with a revocation hook, KEM decapsulation,
commit/record MACs and their headers, STAR and space-meta serialization — are
there because exosphere consumers host spaces too. Delivery of `notifyWrite`
stays in the consumer's process tree; `Spaces.Sync` exposes registration and
`decode_notify_write/1`, and leaves receiving to the app.

Spec cross-checks in the tests are pinned to the alpha lexicons (atproto
`permissioned-data` at `98ef3a6`, re-checked by the `:external` spec-pins
suite) and to the reference implementation's bytes (the corpus, also at
`98ef3a6` — see below); the proposal is young, so expect drift and re-verify
against published lexicons before locking anything downstream. Known pending
upstream renames (unmerged review branches at the time of this pin) are listed
in the CHANGELOG.

## Conformance: the counterparty corpus and the second encoder

The spaces wire format is pinned two independent ways, both running in the
default CI suite:

1. **The counterparty corpus** (`test/fixtures/spaces-corpora/`): bytes
   generated by the official reference implementation — `@atproto/space` and
   `@atproto/star` (MIT) at bluesky-social/atproto `98ef3a6`, branch
   `permissioned-data`. Every fixture is asserted against exosphere's
   primitives by `test/interop/spaces_corpus_test.exs`:

   | Fixture | Pins |
   |---|---|
   | `lthash.json` | 10 cases: empty/multi-element states and digests, add-remove cycles, multiset double-add, underflow wrap, a 512-byte rkey element |
   | `commit-mac.json` | KEM shared secrets from fixed ephemeral keys, commits, commit MACs (incl. a 532-byte space URI), record MACs, and the exact `Atproto-Space-Want-Mac` / `Atproto-Space-Mac` header strings — exosphere reproduces every byte |
   | `repo-star.json` | the `atproto-space-repo` STAR archive, populated and empty, with a record pair whose length-first and bytewise orders differ — exosphere's serializer reproduces it byte-identically and its verifier accepts it |
   | `credentials.json` | the three token classes (typ/kid, claims, TTLs, `cnf.kid`, `jti`) by shape and signature, and the RFC 9421 presentation signature: exosphere verifies the reference's and produces the same signature input and base |
   | `space-meta.json` | an `atproto-space-meta` archive, decoded and re-encoded byte-identically |

   Regeneration is byte-deterministic for everything except token
   `iat`/`jti`; see the fixture directory's `SOURCE.md`. The generic STAR
   container rules are pinned separately by the upstream STAR interop
   fixtures (`test/fixtures/star/`: 19 valid archives round-trip, 37 invalid
   ones are rejected).

2. **The G6 second encoder** (`test/support/spaces_spec_encoder.ex`): a
   test-only reimplementation written from the proposal README alone (at
   bluesky-social/proposals `0634c26`) — lane math, the RFC 9180 shared
   secret, commit and record MACs and their headers, and the STAR repo and
   space-meta archives with its own minimal DAG-CBOR writer. Differentially
   checked against the production modules with stream_data properties
   (`spec_encoder_test.exs`) and independently re-derives every
   deterministic corpus fixture. BLAKE3-XOF and P-256 ECDH are the shared
   primitives, each pinned independently (official BLAKE3 vectors and a
   pure-Elixir differential; the RFC 9180 A.3.1 DHKEM(P-256) vector).

**What the corpus cannot prove:** live-wire interop (HTTP layers against a
running reference PDS — the `:external`-tagged live suites stay
skip-until-green), the credential *exchange* round trip, and blob sync.
Exosphere's P-256 signatures use a random nonce where the reference uses
RFC 6979, so presentation signatures are compared by verification, not by
bytes. The reference PDS neither declares nor emits `SinceOutOfBounds`;
exosphere's client types it for hosts that signal the oplog-window floor
explicitly, per the proposal's "cannot find its `since` revision" guidance.

[proposal]: https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data
