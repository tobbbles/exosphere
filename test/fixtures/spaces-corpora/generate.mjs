// Generates the exosphere spaces conformance corpus from the official
// reference implementation (@atproto/space, the `permissioned-data` branch of
// bluesky-social/atproto).
//
// Everything byte-deterministic below is fixed here (keys, ikm, contexts,
// records) so re-running the script reproduces the committed fixtures exactly;
// the one exception (credential JWTs carry a fresh `iat`/`jti`) is marked
// `nondeterministic` in its fixture and asserted by shape, not by bytes.
//
// Usage (from a checkout of atproto with deps installed and packages built):
//
//   cd /path/to/atproto
//   node /path/to/exosphere/test/fixtures/spaces-corpora/generate.mjs \
//     --out /path/to/exosphere/test/fixtures/spaces-corpora
//
// The atproto checkout defaults to $ATPROTO_PD or /tmp/atproto-pd. The script
// imports each package's built dist directly, so workspace dependencies
// resolve from the checkout's own node_modules.

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
const car = await fromDist('packages/car/dist/car-block.js')
const k256 = (await fromDist('packages/crypto/node_modules/@noble/curves/esm/secp256k1.js')).secp256k1
const p256 = (await fromDist('packages/crypto/node_modules/@noble/curves/esm/p256.js')).p256

const {
  LtHash,
  RepoCommit,
  encodeCommitCtx,
  verifyCommit,
  formatSetHashElement,
  serializeRepo,
  serializeRecord,
  verifyRepoCarFull,
  createSpaceToken,
} = space
const { Secp256k1Keypair, P256Keypair, hkdfSha256, hmacSha256 } = crypto
const { buildCarBlock } = car

const REFERENCE = {
  repository: 'https://github.com/bluesky-social/atproto',
  branch: 'permissioned-data',
  commit: '787a730fcd22ed7791e2636beb509a943017ba1c',
  package: '@atproto/space@0.0.1 (MIT)',
  generatedAt: new Date().toISOString().slice(0, 10),
}

// -- helpers ---------------------------------------------------------------------

const b64 = (bytes) => Buffer.from(bytes).toString('base64')
const hex = (bytes) => Buffer.from(bytes).toString('hex')
const unhex = (s) => Uint8Array.from(Buffer.from(s, 'hex'))

const assert = (cond, msg) => {
  if (!cond) throw new Error(`assertion failed: ${msg}`)
}

// An uncompressed point (0x04||x||y) as the x/y pair of an EC JWK.
const jwkFromCompressed = (curve, compressed) => {
  const full = curve.ProjectivePoint.fromHex(compressed).toRawBytes(false)
  return {
    kty: 'EC',
    crv: compressed.length === 33 && curve === k256 ? 'secp256k1' : 'P-256',
    x: Buffer.from(full.subarray(1, 33)).toString('base64url'),
    y: Buffer.from(full.subarray(33, 65)).toString('base64url'),
  }
}

// -- fixture 1: LtHash -------------------------------------------------------------

// Fixed elements: the two strings the reference test suite itself uses (also
// pinned in exosphere's lthash_test snapshot vectors), realistic record
// elements across three collections, and a 512-byte rkey at the grammar's
// length limit.
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

// -- fixed key, contexts, records (fixtures 2 and 3) --------------------------------

// A fixed secp256k1 keypair, recorded so exosphere can both verify these
// signatures and reproduce them (RFC 6979 deterministic ECDSA on both sides).
const PRIV = unhex('d1a92a44ff780b5f9e2f3e94a06fbcbcb31a1f5a4df8e3d9c2d1a5a1c9d3aab1')
const keypair = await Secp256k1Keypair.import(PRIV)
assert(keypair.publicKeyBytes().length === 33, 'expected a compressed pubkey')

const KEY = {
  curve: 'secp256k1',
  privateKey: hex(PRIV),
  publicKeyCompressed: hex(keypair.publicKeyBytes()), // what Crypto.verify takes
  didKey: keypair.did(), // what the reference's verifyCommit takes
  jwk: jwkFromCompressed(k256, keypair.publicKeyBytes()), // what Token.verify takes
}

const SPACE = 'at://did:plc:spaceauthority/space/com.example.group/default'
const AUTHOR = 'did:plc:author'
const LONG_SPACE = `at://did:plc:spaceauthority/space/com.example.group/${'k'.repeat(512)}`

const CAR_RECORDS = [
  // Deliberately fed in NON-canonical order: the index order must come from
  // the canonical (shortest-path-first) rule, not from input order. "z.foo.bar/a"
  // (10 bytes) sorts before "a.foo.bar/abcdefgh" (19) under length-first
  // ordering but AFTER it under plain bytewise ordering — the pair exists to
  // tell the two rules apart.
  {
    collection: 'com.example.thread',
    rkey: '3jzfcgty2a2h',
    record: {
      $type: 'com.example.thread',
      text: 'spaces interop corpus',
      createdAt: '2026-09-22T00:00:00.000Z',
      counts: { likes: 3, shares: 0 },
      tags: ['interop', 'lthash'],
      pinned: true,
    },
  },
  {
    collection: 'z.foo.bar',
    rkey: 'a',
    record: { $type: 'z.foo.bar', note: 'short path, sorts first by length' },
  },
  {
    collection: 'a.foo.bar',
    rkey: 'abcdefgh',
    record: { $type: 'a.foo.bar', note: 'longer path, sorts second by length' },
  },
]

const serializedRecords = []
for (const { collection, rkey, record } of CAR_RECORDS) {
  serializedRecords.push(await serializeRecord(collection, rkey, record))
}

const CAR_ELEMENTS = serializedRecords.map((rec) =>
  formatSetHashElement(rec.collection, rec.rkey, rec.cid),
)

// -- fixture 2: signedCommit ---------------------------------------------------------

// RepoCommit.sign() draws a fresh random ikm; for byte-determinism the commits
// are assembled from the same exported primitives sign() itself uses
// (encodeCommitCtx, keypair.sign, hkdfSha256, hmacSha256) with fixed ikm, then
// double-checked with verifyCommit.
const buildCommit = async (name, ctx, ikm, elements) => {
  const repo = new RepoCommit()
  for (const element of elements) repo.setHash.add(element)
  const hash = repo.setHash.digest()
  const ctxBytes = encodeCommitCtx(ctx, ikm)
  const commit = {
    ver: 1,
    hash,
    ikm,
    mac: hmacSha256(hkdfSha256(ikm, ctxBytes), hash),
    sig: await keypair.sign(ctxBytes),
    rev: ctx.rev,
  }
  assert(await verifyCommit(commit, ctx, KEY.didKey), `verifyCommit rejected ${name}`)
  return {
    name,
    ctx,
    ikm: hex(ikm),
    ctxBytes: hex(ctxBytes),
    commit: {
      ver: 1,
      hash: hex(hash),
      ikm: hex(ikm),
      sig: hex(commit.sig),
      mac: hex(commit.mac),
      rev: ctx.rev,
    },
  }
}

const signedCommit = {
  generator: REFERENCE,
  key: KEY,
  variants: [
    await buildCommit(
      'basic',
      { space: SPACE, author: AUTHOR, rev: '3kbcq3p7ad2c2' },
      unhex('2f9a1b77c11e4f0fde13b8a29d1c47e56a33f2ac1d0e7b44c9a2f6b3d5e8f701'),
      CAR_ELEMENTS,
    ),
    await buildCommit(
      'next-rev',
      { space: SPACE, author: AUTHOR, rev: '3kbcq3p7ad2k4' },
      unhex('101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f'),
      CAR_ELEMENTS,
    ),
    await buildCommit(
      'empty-repo',
      { space: SPACE, author: AUTHOR, rev: '3kbcq3p7ad2c2' },
      unhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'),
      [],
    ),
    await buildCommit(
      'edge-length-space-uri',
      { space: LONG_SPACE, author: AUTHOR, rev: '3kbcq3p7ad2c2' },
      unhex('f0e0d0c0b0a09080706050403020100112233445566778899aabbccddeeff00'),
      [CAR_ELEMENTS[1]],
    ),
  ],
}

// -- fixture 3: the two-root CAR -------------------------------------------------------

const carCtx = { space: SPACE, author: AUTHOR, rev: '3kbcq3p7ad2c2' }
const basicVariant = signedCommit.variants.find((v) => v.name === 'basic')
const carCommit = basicVariant.commit
const carCommitWire = {
  ver: carCommit.ver,
  hash: unhex(carCommit.hash),
  ikm: unhex(carCommit.ikm),
  sig: unhex(carCommit.sig),
  mac: unhex(carCommit.mac),
  rev: carCommit.rev,
}

const carFrom = async (opts) => {
  const chunks = []
  for await (const chunk of serializeRepo(carCommitWire, serializedRecords, opts)) {
    chunks.push(chunk)
  }
  const total = chunks.reduce((n, c) => n + c.length, 0)
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.length
  }
  return bytes
}

const carBytes = await carFrom({})
const carIndexOnlyBytes = await carFrom({ excludeValues: true })

// Self-check with the reference consumer before pinning anything.
const verified = await verifyRepoCarFull(carBytes, {
  space: carCtx.space,
  author: carCtx.author,
  didKey: KEY.didKey,
})
assert(verified.records.length === 3, 'reference consumer saw wrong record count')
assert(verified.repo.matches(carCommitWire), 'reference consumer: index/hash mismatch')

const verifiedIndexOnly = await verifyRepoCarFull(carIndexOnlyBytes, {
  space: carCtx.space,
  author: carCtx.author,
  didKey: KEY.didKey,
  expectValues: false,
})
assert(verifiedIndexOnly.records.length === 0, 'index-only car carried records')

// Roots and block bytes straight from the provider's own block builder.
const commitBlock = await buildCarBlock(carCommitWire)
const indexBlock = await buildCarBlock(verified.index)
const recordBlocks = new Map(
  serializedRecords.map((rec) => [rec.collection + '/' + rec.rkey, rec]),
)

const repoCar = {
  generator: REFERENCE,
  key: KEY,
  ctx: carCtx,
  commit: carCommit,
  // Input order is deliberately non-canonical (see CAR_RECORDS above); the
  // index below is the canonical DRISL order the provider emitted.
  recordsInputOrder: CAR_RECORDS.map((r) => r.collection + '/' + r.rkey),
  records: CAR_RECORDS,
  setHashElements: CAR_ELEMENTS,
  indexEntries: Object.entries(verified.index).map(([path, cid]) => [path, cid.toString()]),
  roots: { commit: commitBlock.cid.toString(), index: indexBlock.cid.toString() },
  blocks: [
    { role: 'commit', cid: commitBlock.cid.toString(), bytes: hex(commitBlock.bytes) },
    { role: 'index', cid: indexBlock.cid.toString(), bytes: hex(indexBlock.bytes) },
    ...Object.entries(verified.index).map(([path, cid]) => {
      const rec = recordBlocks.get(path)
      return { role: 'record', path, cid: cid.toString(), bytes: hex(rec.bytes) }
    }),
  ],
  car: b64(carBytes),
  carIndexOnly: b64(carIndexOnlyBytes),
}

// -- fixture 4: credential token classes -----------------------------------------------

// createSpaceToken fixes nothing about iat/jti, so these JWTs are NOT
// byte-reproducible across runs; the fixture records the decoded classes and
// the signing keys, and exosphere asserts shape + signature, not bytes.
const delegationJwt = await createSpaceToken(
  'delegation',
  { iss: AUTHOR, sub: SPACE, aud: 'did:plc:spaceauthority#atproto_space_host' },
  keypair,
)

const CRED_PRIV = unhex('4b6f2a9e0e6b4b8e9a2c1d3f5b7a9c1e3d5f7a9b1c3e5d7f9a1b3c5d7e9f1a3b')
const credentialKeypair = await Secp256k1Keypair.import(CRED_PRIV)
const DPOP_JKT = '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I'
const credentialJwt = await createSpaceToken(
  'credential',
  { iss: 'did:plc:spaceauthority', sub: SPACE, dpopJkt: DPOP_JKT },
  credentialKeypair,
)

const ATTEST_PRIV = unhex('8f2a1b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f0')
const attestationKeypair = await P256Keypair.import(ATTEST_PRIV)
const attestationJwt = await createSpaceToken(
  'clientAttestation',
  {
    iss: 'https://app.example.com/client-metadata.json',
    sub: 'https://app.example.com/client-metadata.json',
    aud: 'did:plc:spaceauthority#atproto_space_host',
  },
  attestationKeypair,
)

const decodeJwt = (jwt) => {
  const [h, p] = jwt.split('.')
  const dec = (part) => JSON.parse(Buffer.from(part, 'base64url').toString('utf8'))
  return { header: dec(h), payload: dec(p) }
}

const credentials = {
  generator: REFERENCE,
  nondeterministic: 'iat/jti are fresh per run — assert shape and signature, not bytes',
  tokens: [
    {
      class: 'delegation',
      jwt: delegationJwt,
      ...decodeJwt(delegationJwt),
      signingKey: KEY,
      expected: {
        typ: 'atproto-space-delegation+jwt',
        kid: '#atproto',
        expMinusIat: 60,
        iss: AUTHOR,
        sub: SPACE,
        aud: 'did:plc:spaceauthority#atproto_space_host',
      },
    },
    {
      class: 'credential',
      jwt: credentialJwt,
      ...decodeJwt(credentialJwt),
      signingKey: {
        curve: 'secp256k1',
        privateKey: hex(CRED_PRIV),
        publicKeyCompressed: hex(credentialKeypair.publicKeyBytes()),
        didKey: credentialKeypair.did(),
        jwk: jwkFromCompressed(k256, credentialKeypair.publicKeyBytes()),
      },
      expected: {
        typ: 'atproto-space-credential+jwt',
        kid: '#atproto',
        expMinusIat: 7200,
        iss: 'did:plc:spaceauthority',
        sub: SPACE,
        cnfJkt: DPOP_JKT,
        noAud: true,
      },
    },
    {
      class: 'clientAttestation',
      jwt: attestationJwt,
      ...decodeJwt(attestationJwt),
      signingKey: {
        curve: 'p256',
        privateKey: hex(ATTEST_PRIV),
        publicKeyCompressed: hex(attestationKeypair.publicKeyBytes()),
        didKey: attestationKeypair.did(),
        jwk: jwkFromCompressed(p256, attestationKeypair.publicKeyBytes()),
      },
      expected: {
        typ: 'atproto-client-attestation+jwt',
        noKid: true,
        expMinusIat: 60,
        iss: 'https://app.example.com/client-metadata.json',
        sub: 'https://app.example.com/client-metadata.json',
        aud: 'did:plc:spaceauthority#atproto_space_host',
      },
    },
  ],
}

// -- write -------------------------------------------------------------------------------

await mkdir(outDir, { recursive: true })
for (const [name, fixture] of [
  ['lthash.json', lthash],
  ['signed-commit.json', signedCommit],
  ['repo-car.json', repoCar],
  ['credentials.json', credentials],
]) {
  await writeFile(resolve(outDir, name), JSON.stringify(fixture, null, 2) + '\n')
  console.log(`wrote ${name}`)
}
