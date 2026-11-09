// Generates the exosphere spaces conformance corpus from the official
// reference implementation (@atproto/space and @atproto/star from
// bluesky-social/atproto).
//
// The pinned tree is the `atproto-spaces-cleanup` branch at 4037310 (which
// carries `atproto-spaces-lexicon-review` at 7089c42) with `packages/star`
// from `permissioned-data` at 98ef3a6 grafted in by `graft-star.mjs` — the
// cleanup branch forked before STAR moved into its own package and gained its
// control byte, so neither upstream tip has both. See SOURCE.md.
//
// Everything below is fixed here (keys, ephemeral keys, contexts, records) so
// re-running the script reproduces the committed fixtures exactly. The one
// exception is the token JWTs (fresh `iat`/`jti` per run), marked
// `nondeterministic` in credentials.json and asserted by shape, never bytes.
// HTTP message signatures ARE deterministic (RFC 6979 P-256 in the reference)
// and are pinned byte-for-byte.
//
// Usage (from the grafted tree, deps installed and `packages/space` built —
// see SOURCE.md):
//
//   node /path/to/exosphere/test/fixtures/spaces-corpora/generate.mjs \
//     --atproto /path/to/atproto --out /path/to/exosphere/test/fixtures/spaces-corpora
//
// The script imports each package's built dist directly, so workspace
// dependencies resolve from the checkout's own node_modules.

import { parseArgs } from 'node:util'
import { pathToFileURL } from 'node:url'
import { resolve } from 'node:path'
import { mkdir, writeFile } from 'node:fs/promises'

const { values: args } = parseArgs({
  options: {
    atproto: { type: 'string', default: process.env.ATPROTO_PD ?? '/tmp/atproto-pd' },
    out: { type: 'string', default: new URL('.', import.meta.url).pathname },
  },
})

const atprotoDir = resolve(args.atproto)
const outDir = resolve(args.out)

const fromDist = (rel) => import(pathToFileURL(resolve(atprotoDir, rel)))

const space = await fromDist('packages/space/dist/index.js')
const crypto = await fromDist('packages/crypto/dist/index.js')
const star = await fromDist('packages/star/dist/index.js')

const {
  LtHash,
  RepoCommit,
  writeRepoStar,
  serializeRecord,
  verifyRepoStarFull,
  verifyCommit,
  computeCommitMac,
  computeRecordMac,
  formatWantMacHeader,
  formatMacHeader,
  decapsulate,
  createDelegationToken,
  createSpaceCredential,
  createClientAttestation,
  createSpaceSigHeaders,
  verifyCredentialSig,
  spaceHostAud,
  writeSpaceMetaStar,
  readSpaceMetaStar,
} = space
const { Secp256k1Keypair, P256Keypair } = crypto
const { readStar } = star

// `${collection}/${rkey}/${cid}` — the set-hash element, as the reference's
// `formatSetHashElement` builds it (no longer exported since the cleanup
// branch; `formatRecordPath` still is).
const formatSetHashElement = (collection, rkey, cid) => `${space.formatRecordPath(collection, rkey)}/${cid.toString()}`

const REFERENCE = {
  repository: 'https://github.com/bluesky-social/atproto',
  branch: 'atproto-spaces-cleanup',
  commit: '4037310976201ee057f1b06aeef04a3cdc080258',
  includes: 'atproto-spaces-lexicon-review@7089c42',
  star: 'packages/star from permissioned-data@98ef3a6b9d1364f0543f137dd024de9651b21c4c (graft-star.mjs)',
  package: '@atproto/space@0.0.1, @atproto/star (MIT)',
  generatedAt: new Date().toISOString().slice(0, 10),
}

// -- helpers ---------------------------------------------------------------------

const b64 = (bytes) => Buffer.from(bytes).toString('base64')
const hex = (bytes) => Buffer.from(bytes).toString('hex')
const unhex = (s) => Uint8Array.from(Buffer.from(s, 'hex'))

const assert = (cond, msg) => {
  if (!cond) throw new Error(`assertion failed: ${msg}`)
}

const collect = async (chunks) => {
  const parts = []
  for await (const chunk of chunks) parts.push(chunk)
  return Uint8Array.from(Buffer.concat(parts.map((p) => Buffer.from(p))))
}

const uncompressed = (curve, compressed) => curve.ProjectivePoint.fromHex(compressed).toRawBytes(false)

const p256 = (await fromDist('packages/crypto/node_modules/@noble/curves/esm/p256.js')).p256
const k256 = (await fromDist('packages/crypto/node_modules/@noble/curves/esm/secp256k1.js')).secp256k1

const jwkFromCompressed = (curve, compressed) => {
  const full = uncompressed(curve, compressed)
  return {
    kty: 'EC',
    crv: curve === k256 ? 'secp256k1' : 'P-256',
    x: Buffer.from(full.subarray(1, 33)).toString('base64url'),
    y: Buffer.from(full.subarray(33, 65)).toString('base64url'),
  }
}

// -- fixture 1: LtHash (unchanged since 787a730) ---------------------------------

const ELEMENTS = {
  one: 'one',
  two: 'two',
  thread:
    'com.example.thread/3jzfcgty2a2h/bafyreidykglsfhoixmivffc5uwhcgshx4j465xwqntbmu43nb2dzqwfvae',
  reaction:
    'com.example.reaction/3jzfcafyaa2a/bafyreig7r4nwnfm2js2xclv2fbkchqqqet3labzv2emvm2dmvzw4q3b5xq',
  note: 'a.foo.bar/abcdefgh/bafyreiczsscdmousfcmdhhejit2vwjhkecyoxapcyhmsvbrmnpcn3ganu',
  longRkey: `com.example.thread/${'k'.repeat(512)}/bafyreidykglsfhoixmivffc5uwhcgshx4j465xwqntbmu43nb2dzqwfvae`,
}

const fold = (ops) => {
  let state = new LtHash()
  for (const [op, element] of ops) state = state[op](element)
  return state
}

const lthashCase = (name, ops) => {
  const state = fold(ops)
  return {
    name,
    ops: ops.map(([op, element]) => ({ op, element })),
    state: b64(state.state()),
    digest: hex(state.digest()),
    isEmpty: state.isEmpty(),
  }
}

const lthash = {
  generator: REFERENCE,
  cases: [
    lthashCase('empty', []),
    lthashCase('noble-elements-one-two', [
      ['add', ELEMENTS.one],
      ['add', ELEMENTS.two],
    ]),
    lthashCase('noble-elements-order-reversed', [
      ['add', ELEMENTS.two],
      ['add', ELEMENTS.one],
    ]),
    lthashCase('single-record-element', [['add', ELEMENTS.thread]]),
    lthashCase('three-records-across-collections', [
      ['add', ELEMENTS.thread],
      ['add', ELEMENTS.reaction],
      ['add', ELEMENTS.note],
    ]),
    lthashCase('add-remove-returns-to-empty', [
      ['add', ELEMENTS.thread],
      ['remove', ELEMENTS.thread],
    ]),
    lthashCase('update-remove-prev-add-new', [
      ['add', ELEMENTS.thread],
      ['remove', ELEMENTS.thread],
      ['add', ELEMENTS.reaction],
    ]),
    lthashCase('multiset-double-add-single-remove', [
      ['add', ELEMENTS.thread],
      ['add', ELEMENTS.thread],
      ['remove', ELEMENTS.thread],
    ]),
    lthashCase('remove-before-add-underflows-to-same-state', [
      ['remove', ELEMENTS.thread],
      ['add', ELEMENTS.thread],
    ]),
    lthashCase('max-length-rkey-element', [['add', ELEMENTS.longRkey]]),
  ],
}

// -- fixed keys, spaces and records ---------------------------------------------------

const SPACE = 'at://did:plc:spaceauthority/space/com.example.group/default'
const AUTHOR = 'did:plc:author'
const LONG_SPACE = `at://did:plc:spaceauthority/space/com.example.group/${'k'.repeat(512)}`

// The author's #atproto_kem keypair (held by the repo host) and fixed syncer
// ephemeral keys. The reference's own `encapsulate` draws a random ephemeral
// key, so the shared secrets are derived with its exported host-side
// `decapsulate(authorKemKeypair, keyShare)` from the fixed ephemeral did:keys —
// the same RFC 9180 derivation, reproducible.
const KEM_PRIV = unhex('5f8a4c3b2e1d0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f51')
const kemKeypair = await P256Keypair.import(KEM_PRIV)
const EPHEMERAL_PRIVS = [
  '0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff1',
  'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f91',
  '3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c',
]

const kemVector = async (ephPrivHex) => {
  const eph = await P256Keypair.import(unhex(ephPrivHex))
  const keyShare = eph.did()
  const sharedSecret = decapsulate(kemKeypair, keyShare)
  return {
    ephemeralPrivateKey: ephPrivHex,
    ephemeralPublicKeyUncompressed: hex(uncompressed(p256, eph.publicKeyBytes())),
    keyShare,
    sharedSecret: hex(sharedSecret),
  }
}

const KEM = {
  author: {
    privateKey: hex(KEM_PRIV),
    publicKeyCompressed: hex(kemKeypair.publicKeyBytes()),
    publicKeyUncompressed: hex(uncompressed(p256, kemKeypair.publicKeyBytes())),
    didKey: kemKeypair.did(),
  },
  vectors: await Promise.all(EPHEMERAL_PRIVS.map(kemVector)),
}

const RECORDS = [
  // Deliberately fed in non-sorted order; "z.foo.bar/a" sorts after
  // "a.foo.bar/abcdefgh" bytewise but before it by length — the old CAR
  // index's rule. The STAR profile is strict bytewise order.
  {
    collection: 'com.example.thread',
    rkey: '3jzfcgty2a2h',
    record: {
      $type: 'com.example.thread',
      text: 'spaces interop corpus',
      createdAt: '2026-11-06T00:00:00.000Z',
      counts: { likes: 3, shares: 0 },
      tags: ['interop', 'lthash'],
      pinned: true,
    },
  },
  {
    collection: 'z.foo.bar',
    rkey: 'a',
    record: { $type: 'z.foo.bar', note: 'short path, sorts last bytewise' },
  },
  {
    collection: 'a.foo.bar',
    rkey: 'abcdefgh',
    record: { $type: 'a.foo.bar', note: 'longer path, sorts first bytewise' },
  },
]

const serialized = []
for (const { collection, rkey, record } of RECORDS) {
  serialized.push(await serializeRecord(collection, rkey, record))
}
const sortedRecords = [...serialized].sort((a, b) =>
  Buffer.compare(Buffer.from(`${a.collection}/${a.rkey}`), Buffer.from(`${b.collection}/${b.rkey}`)),
)

const ELEMENTS_OF_RECORDS = serialized.map((r) => formatSetHashElement(r.collection, r.rkey, r.cid))

const commitOver = (ctx, records) => RepoCommit.fromRecords(records).toCommit(ctx)

// -- fixture 2: commit and record MACs ---------------------------------------------

const secretOf = (i) => unhex(KEM.vectors[i].sharedSecret)

const commitVariant = (name, ctx, records, secretIndex) => {
  const commit = commitOver(ctx, records)
  const sharedSecret = secretOf(secretIndex)
  const mac = computeCommitMac(sharedSecret, commit)
  // Throws on any mismatch (it returned a boolean before the cleanup branch).
  verifyCommit(commit, { space: ctx.space, repo: ctx.repo, sharedSecret, mac })
  return {
    name,
    ctx,
    kemVector: secretIndex,
    sharedSecret: hex(sharedSecret),
    elements: records.map((r) => formatSetHashElement(r.collection, r.rkey, r.cid)),
    commit: { ...commit, data: hex(commit.data) },
    mac: hex(mac),
    macHeader: formatMacHeader('atproto-space-repo', mac),
    wantMacHeader: formatWantMacHeader('atproto-space-repo', KEM.vectors[secretIndex].keyShare),
  }
}

const recordVariant = (name, uri, rec, secretIndex) => {
  const sharedSecret = secretOf(secretIndex)
  const mac = computeRecordMac(sharedSecret, uri, rec.cid)
  return {
    name,
    uri,
    cid: rec.cid.toString(),
    cidBytes: hex(rec.cid.bytes),
    value: rec.record ?? null,
    kemVector: secretIndex,
    mac: hex(mac),
    macHeader: formatMacHeader('atproto-space-record', mac),
    wantMacHeader: formatWantMacHeader('atproto-space-record', KEM.vectors[secretIndex].keyShare),
  }
}

const commitMac = {
  generator: REFERENCE,
  kem: KEM,
  commits: [
    commitVariant('basic', { space: SPACE, repo: AUTHOR, rev: '3kbcq3p7ad2c2' }, serialized, 0),
    commitVariant('next-rev', { space: SPACE, repo: AUTHOR, rev: '3kbcq3p7ad2k4' }, serialized, 1),
    commitVariant('empty-repo', { space: SPACE, repo: AUTHOR, rev: '3kbcq3p7ad2c2' }, [], 0),
    commitVariant(
      'edge-length-space-uri',
      { space: LONG_SPACE, repo: AUTHOR, rev: '3kbcq3p7ad2c2' },
      [serialized[1]],
      2,
    ),
  ],
  records: [
    recordVariant(
      'thread',
      `${SPACE}/${AUTHOR}/com.example.thread/3jzfcgty2a2h`,
      { ...serialized[0], record: RECORDS[0].record },
      0,
    ),
    recordVariant('short-path', `${SPACE}/${AUTHOR}/z.foo.bar/a`, { ...serialized[1], record: RECORDS[1].record }, 2),
  ],
}

// -- fixture 3: the repo STAR archive ---------------------------------------------------

const starCtx = { space: SPACE, repo: AUTHOR, rev: '3kbcq3p7ad2c2' }
const starCommit = commitOver(starCtx, serialized)
const starBytes = await collect(writeRepoStar(starCommit, sortedRecords))
const emptyCommit = commitOver(starCtx, [])
const emptyStarBytes = await collect(writeRepoStar(emptyCommit, []))

// Self-check with the reference consumer before pinning anything.
const starSecret = secretOf(0)
const starMac = computeCommitMac(starSecret, starCommit)
const verifiedStar = await verifyRepoStarFull([starBytes], {
  space: SPACE,
  repo: AUTHOR,
  sharedSecret: starSecret,
  mac: starMac,
})
assert(verifiedStar.records.length === 3, 'reference consumer saw the wrong record count')

const starReader = await readStar([starBytes])
const starPairs = []
for await (const { key, value } of starReader.pairs) {
  starPairs.push({ key: Buffer.from(key).toString('utf8'), value: hex(value) })
}

const repoStar = {
  generator: REFERENCE,
  ctx: starCtx,
  commit: { ...starCommit, data: hex(starCommit.data) },
  kemVector: 0,
  mac: hex(starMac),
  recordsInputOrder: RECORDS.map((r) => `${r.collection}/${r.rkey}`),
  records: RECORDS,
  setHashElements: ELEMENTS_OF_RECORDS,
  pairs: starPairs,
  star: b64(starBytes),
  empty: {
    commit: { ...emptyCommit, data: hex(emptyCommit.data) },
    mac: hex(computeCommitMac(starSecret, emptyCommit)),
    star: b64(emptyStarBytes),
  },
}

// -- fixture 4: credential token classes and the HTTP message signature ---------------

const USER_PRIV = unhex('d1a92a44ff780b5f9e2f3e94a06fbcbcb31a1f5a4df8e3d9c2d1a5a1c9d3aab1')
const userKeypair = await Secp256k1Keypair.import(USER_PRIV)
const AUTH_PRIV = unhex('4b6f2a9e0e6b4b8e9a2c1d3f5b7a9c1e3d5f7a9b1c3e5d7f9a1b3c5d7e9f1a3b')
const authorityKeypair = await Secp256k1Keypair.import(AUTH_PRIV)
const ATTEST_PRIV = unhex('8f2a1b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f0')
const attestationKeypair = await P256Keypair.import(ATTEST_PRIV)
// The syncer's credential key: the P-256 key bound by cnf.kid.
const CRED_KEY_PRIV = unhex('7c1e5a3f9b2d4c6e8a0f1b3d5c7e9a2b4d6f8a0c2e4b6d8f0a1c3e5b7d9f2a4c')
const credentialKey = await P256Keypair.import(CRED_KEY_PRIV)

const AUTHORITY = 'did:plc:spaceauthority'
const AUD = spaceHostAud(AUTHORITY)

const keyInfo = (curve, priv, keypair) => ({
  curve: curve === k256 ? 'secp256k1' : 'p256',
  privateKey: hex(priv),
  publicKeyCompressed: hex(keypair.publicKeyBytes()),
  didKey: keypair.did(),
  jwk: jwkFromCompressed(curve, keypair.publicKeyBytes()),
})

const delegationJwt = await createDelegationToken({ iss: AUTHOR, sub: SPACE, aud: AUD, keypair: userKeypair })
const credentialJwt = await createSpaceCredential({
  iss: AUTHORITY,
  sub: SPACE,
  keyId: credentialKey.did(),
  keypair: authorityKeypair,
})
const attestationJwt = await createClientAttestation({
  clientId: 'https://app.example.com/client-metadata.json',
  aud: AUD,
  keypair: attestationKeypair,
})

const decodeJwt = (jwt) => {
  const [h, p] = jwt.split('.')
  const dec = (part) => JSON.parse(Buffer.from(part, 'base64url').toString('utf8'))
  return { header: dec(h), payload: dec(p) }
}

// The signature is over the Authorization value and the audience only, so a
// fixed credential string pins it byte-for-byte (RFC 6979 in the reference).
const SIG_AUTHORIZATION = 'Atproto-Space-Credential eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJhdHByb3RvLXNwYWNlLWNyZWRlbnRpYWwrand0In0.e30.c2ln'
const { headers: sigHeaders } = await createSpaceSigHeaders({
  authorization: SIG_AUTHORIZATION,
  audience: AUTHOR,
  keypair: credentialKey,
})
await verifyCredentialSig(sigHeaders, credentialKey.did())

const credentials = {
  generator: REFERENCE,
  nondeterministic: 'token iat/jti are fresh per run — assert shape and signature, not bytes',
  tokens: [
    {
      class: 'delegation',
      jwt: delegationJwt,
      ...decodeJwt(delegationJwt),
      signingKey: keyInfo(k256, USER_PRIV, userKeypair),
      expected: { typ: 'atproto-space-delegation+jwt', kid: '#atproto', expMinusIat: 60, iss: AUTHOR, sub: SPACE, aud: AUD },
    },
    {
      class: 'credential',
      jwt: credentialJwt,
      ...decodeJwt(credentialJwt),
      signingKey: keyInfo(k256, AUTH_PRIV, authorityKeypair),
      expected: {
        typ: 'atproto-space-credential+jwt',
        kid: '#atproto',
        expMinusIat: 600,
        iss: AUTHORITY,
        sub: SPACE,
        cnfKid: credentialKey.did(),
        noAud: true,
      },
    },
    {
      class: 'clientAttestation',
      jwt: attestationJwt,
      ...decodeJwt(attestationJwt),
      signingKey: keyInfo(p256, ATTEST_PRIV, attestationKeypair),
      expected: {
        typ: 'atproto-client-attestation+jwt',
        noKid: true,
        expMinusIat: 60,
        iss: 'https://app.example.com/client-metadata.json',
        sub: 'https://app.example.com/client-metadata.json',
        aud: AUD,
      },
    },
  ],
  httpSignature: {
    key: keyInfo(p256, CRED_KEY_PRIV, credentialKey),
    authorization: SIG_AUTHORIZATION,
    audience: AUTHOR,
    headers: sigHeaders,
  },
}

// -- fixture 5: the space meta archive -----------------------------------------------

const metaArchive = {
  space: SPACE,
  policy: { $type: 'com.atproto.memberspace.policy', publicRead: false, publicWrite: false, publishMembers: true },
  policyState: [
    { key: 'com.atproto.memberspace.member/did:plc:carol', value: { $type: 'com.atproto.memberspace.member', read: true, write: false } },
    { key: 'com.atproto.memberspace.member/did:plc:alice', value: { $type: 'com.atproto.memberspace.member', read: true, write: true } },
  ],
  writers: [
    // `repoRev`, not `rev`, since the cleanup branch (matching listWriters).
    { did: 'did:plc:bob', repoRev: '3kbcq3p7ad2k4', data: starCommit.data, spaceRev: '3kbcq3p7ad3a2' },
    { did: AUTHOR, repoRev: '3kbcq3p7ad2c2', data: emptyCommit.data, spaceRev: '3kbcq3p7ad3a4' },
  ],
}
const metaBytes = await collect(writeSpaceMetaStar(metaArchive))
const metaRead = await readSpaceMetaStar([metaBytes])
assert(metaRead.writers.length === 2, 'reference meta reader saw the wrong writer count')

const spaceMeta = {
  generator: REFERENCE,
  archive: {
    space: SPACE,
    policy: metaArchive.policy,
    // In archive order (sorted), as the reference reads them back.
    policyState: metaRead.policyState,
    writers: metaRead.writers.map((w) => ({ ...w, data: hex(w.data) })),
  },
  star: b64(metaBytes),
}

// -- write -------------------------------------------------------------------------------

await mkdir(outDir, { recursive: true })
for (const [name, fixture] of [
  ['lthash.json', lthash],
  ['commit-mac.json', commitMac],
  ['repo-star.json', repoStar],
  ['credentials.json', credentials],
  ['space-meta.json', spaceMeta],
]) {
  await writeFile(resolve(outDir, name), JSON.stringify(fixture, null, 2) + '\n')
  console.log(`wrote ${name}`)
}
