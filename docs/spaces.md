# Spaces: permissioned data in atproto

Exosphere ships client support for [atproto Spaces][proposal] (proposal 0016,
alpha): permissioned data — a **space** is an authorisation and sync boundary
identified by `(authority DID, space type, skey)`. Members keep their records
in per-user *permissioned repos* on their own repo hosts; the space authority
mints short-lived, DPoP-bound **space credentials**; writes go through the
user's own PDS under space-scoped OAuth; sync runs over dedicated XRPC with
LtHash commit digests, so a synced copy is also an *authenticated* copy.

The moving parts, and where exosphere draws the client/host line:

| Role | Who | Exosphere support |
|------|-----|-------------------|
| Space authority | the DID at the root of a space; issues credentials | resolve its `#atproto_space` key / `#atproto_space_host` endpoint (`Identity.Document`) |
| Space host | answers for a space: credential exchange, writer set, notify routing | **bespoke, app-side** — but `Spaces.Credential.verify/2` and `OAuth.DPoP.verify_proof/4` ship so consumers can host |
| Repo host | stores and serves permissioned repos | served by PDSs; exosphere verifies everything they serve |
| PDS | mints delegation tokens, serves simplespace, accepts space writes | full client support |
| Syncer / reader | an app presenting a space | the main exosphere use case |

## The moving parts

- **Space AT-URIs** (`AtUri`): `at://{authority}/space/{spaceType}/{skey}[/{authorDid}/{collection}/{rkey}]`
  — a tagged variant on the ordinary grammar; `space?/1` tells them apart, and the
  two can never be confused (`space` is not a valid NSID).
- **Identity** (`Identity.Document`): `get_space_signing_key/1` and
  `get_space_host_endpoint/1`, each falling back to `#atproto` / `#atproto_pds`.
- **Verification core** (`Spaces.LtHash`, `Spaces.Commit`, `Spaces.Repo`): the
  homomorphic set hash (BLAKE3-XOF-expanded lanes), deniable commit signatures
  (the signature covers only a context string; a symmetric MAC binds the repo
  hash), and the two-root DRISL CAR with its index — `Spaces.Repo.verify_car/5`
  runs the whole pipeline and fails loudly on any tamper.
  BLAKE3 is pure Elixir (`Spaces.Blake3`) — verified against the official
  vectors; no new dependency.
- **Credentials** (`Spaces.Token`, `Spaces.Credential`): delegation tokens
  (60s, single-use, from the user's PDS), space credentials (2h, multi-use,
  DPoP-bound via `cnf.jkt`, minted at the space host), and client attestations
  (app identity for `#allowList` spaces). Built on the OAuth client's
  JWS/JWK/DPoP machinery.
- **Scopes** (`OAuth.Scope`): the `space:{type}?…` grammar — `read` (implies
  `read_self`), collection-constrained writes, `manage=` for administration.
- **Sync** (`Spaces.Sync`): the writer set, oplog paging, record reads, and
  full-CAR recovery — every request credential-authed with a per-request DPoP
  proof; the running set hash decides *synced and authenticated* vs diverge.
  Oplogs are a transport optimisation (they compact and reset on migration);
  the full CAR is the source of truth.
- **Administration** (`Spaces.SimpleSpace`): the reference simplespace calls
  with typed policies (`:public` / `:member_list` / `{:managing_app, did}`) and
  app access (`:open` / `{:allow_list, […]}`).
- **Writes** (`Spaces.Writes`): `createRecord` / `putRecord` / `deleteRecord` /
  `applyWrites` on the user's own PDS, under a space-scoped OAuth session.

## A reader's flow, end to end

      # 1. Resolve the space authority (its DID document)
      {:ok, doc} = resolve(authority_did)
      space_host = Document.get_space_host_endpoint(doc)

      # 2. Get a delegation token from the user's PDS (space-scoped OAuth)
      {:ok, delegation} =
        Spaces.Credential.get_delegation_token(pds, space_ref,
          headers: [{"authorization", "Bearer " <> session.access_token}]
        )

      # 3. Exchange it at the space host for a DPoP-bound credential
      {:ok, dpop_key} = OAuth.DPoP.generate_key()

      {:ok, %{credential: jwt}} =
        Spaces.Credential.mint(space_host, space_ref, delegation, dpop_key: dpop_key)

      cred = %{credential: jwt, dpop_key: dpop_key}

      # 4. Follow the writer set, sync each member repo
      {:ok, %{repos: repos}} = Spaces.Sync.list_repos(space_host, space_ref, cred)

      for repo <- repos do
        # Full CAR first (verified end to end), then oplog deltas
        {:ok, verified} =
          Spaces.Sync.get_repo(repo_host, space_ref, repo.did, ctx, author_pub, :secp256k1, cred)

        running = verified.lthash

        {:ok, %{ops: ops, commit: commit}} =
          Spaces.Sync.list_repo_ops(repo_host, space_ref, repo.did, cred, since: verified.rev)

        running = Spaces.Sync.apply_ops(running, ops)

        Spaces.Sync.synced?(running, commit) #=> true: synced *and authenticated*
      end

Divergence (a compacted oplog, a migrated account) surfaces as
`synced?/2` turning false — recover with another full CAR.

## What deliberately stays app-side

The space-host service itself: exosphere is the client library, and hosts are
bespoke (the consumer's job). The host-side halves that *do* ship — credential
verification, DPoP proof verification, CAR serialization/verification — are
there because exosphere consumers host spaces too. Websocket delivery of
`notifyWrite` stays in the consumer's process tree; `Spaces.Sync` exposes
registration and leaves receiving to the app, on the firehose consumer's
reconnect discipline.

Spec cross-checks in the tests are pinned to the alpha lexicons and the
reference implementation (atproto tree at commit `5fbc9a0`); the proposal is
young, so expect drift and re-verify against published lexicons before
locking anything downstream.

[proposal]: https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data
