# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Internal
- BLAKE3 NIF now ships as precompiled, checksummed artifacts (rustler_precompiled) for Linux, macOS, and Windows targets; a Rust toolchain is only needed to build from source

## [0.6.0] - 2026-08-30

### Added
- operation construction, signing, submission and audit-log validation (#28)

### Fixed
- put kid on the client assertion header (#30)

## [0.5.0] - 2026-08-26

### Fixed
- vendor the full com.atproto lexicon corpus (incl. moderation defs) (#23)

## [0.4.0] - 2026-08-26

### Added
- ATProto DPoP-bound OAuth client — discovery, PAR, PKCE, sessions (#18)
- lexicon registration, runtime type-checking, and PDS publishing (#19)

## [0.3.0] - 2026-08-25

Spec-conformance pass against the [AT Protocol specifications](https://atproto.com/specs).
Fixes several DAG-CBOR / cryptography correctness bugs (some of which change
wire output or reject previously-accepted input) and adds the AT-URI, NSID, and
record-key primitives plus commit-signature verification.

### Fixed (breaking — output / acceptance changes)

- **MST canonical tree shape.** `MST.build/1` now fills empty layers with
  *shell nodes* (`e: []`, left link only) so every subtree link descends
  exactly one layer, matching the reference implementation. Previously the
  builder skipped layers with no keys, producing **different root CIDs** than
  the reference MST for any record set with a layer gap — meaning commits
  verified against real repositories failed `data_mismatch`. The four interop
  golden vectors have no gaps, so this was only caught live against a real
  41k-record repository, which now rebuilds byte-for-byte to the same root.
  Roots produced by previous versions for gap-trees are not canonical.

- **DAG-CBOR canonical encoding.** `Exosphere.ATProto.CBOR.encode/1` now sorts
  map keys with RFC 8949 *length-first* ordering (shorter keys first, ties
  broken bytewise) instead of pure lexicographic ordering, and encodes CID
  links (tag 42) as CBOR **byte strings** instead of text strings. The previous
  behaviour produced non-spec bytes and therefore **incorrect CIDs** for any
  record containing a map with differing-length keys or a CID link. CIDs for
  such values will change. The manual encoder no longer delegates map/list/CID
  serialization to the `:cbor` library (which neither sorts keys nor emits byte
  strings for binaries).
- **Real CID-link decoding.** `CBOR.decode/1`, `Firehose.Frame`, and `CAR` now
  decode CID links produced by other implementations (byte strings, which the
  `:cbor` library surfaces as nested `%CBOR.Tag{tag: :bytes}`). Previously these
  were silently dropped, so firehose commit operations and record links lost
  their CIDs. Link transformation is centralized in
  `Exosphere.ATProto.CBOR.transform_links/1`.
- **High-S signature rejection.** `Exosphere.ATProto.Crypto.verify/4` now
  rejects non-low-S ("malleable") signatures for both secp256k1 and p256, as
  required by the cryptography spec. Callers relying on high-S signatures being
  accepted will now get `{:error, :invalid_signature}`.
- **Strict TID validation.** `Exosphere.ATProto.TID.valid?/1` enforces the spec
  regex `/^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/`,
  including the restricted leading character. Strings that merely base32-decode
  are no longer considered valid.
- **Handle TLD rule.** `Exosphere.ATProto.Identity.Handle.valid?/1` now rejects
  handles whose final (TLD) segment starts with a digit.
- **secp256k1 did:key multicodec.** `Crypto.to_did_key/2`, `to_multibase/2`,
  `from_did_key/1`, and `Identity.Document` now use the correct unsigned-varint
  multicodec prefix `0xe7 0x01` for secp256k1 (previously a bare `0xe7`). The old
  encoding was self-consistent but **not interoperable** with other atproto
  implementations; secp256k1 `did:key` strings produced/parsed before this change
  were wrong. Verified against the interop crypto fixtures.
- **NSID length rule.** `NSID.valid?/1` no longer imposes a 253-character cap on
  the domain-authority portion (only the spec's 317-character total and the
  per-segment rules apply), matching the interop `nsid_syntax` tables.
- **AT-URI fragments.** `AtUri.parse/1` now rejects URIs with more than one `#`,
  empty fragments, and fragments containing whitespace, matching the interop
  `aturi_syntax` tables.

### Added

- **Lexicon integration feedback fixes** (from the first host-app integration):
  - `Registry.register/1` unwraps `%Lexicon.Schema{}` structs instead of
    storing them where parsed IR belongs (registering a schema used to
    poison the registry — every later validation failed).
  - `strict: true` validation now errors on refs (and union refs) whose
    target lexicon is not registered; the permissive mode still skips
    them, and the `Validator` moduledoc says so.
  - `Registry.load_dir/1` registers a directory of lexicon JSON (host
    apps no longer hand-roll parse-and-register); `load_vendored/0` is
    defined in terms of it. `register_all/1` accepts the
    `%{nsid => lexicon}` map `Parser.parse_dir/1` returns.
  - Implemented the remaining spec string formats — `language`, `tid`,
    `record-key`, `at-identifier` — and `mix exosphere.lint.lexicons`
    warns on string formats outside the spec set (typos included).
  - Record `key` validated against the spec values (`tid`, `nsid`,
    `any`, `literal:<value>`) instead of "any non-empty string".
  - `Schema.new/1` returns an error tuple for malformed top-level keys
    instead of raising.
  - `Lexicon.publish(session, schema)` / `delete(session, nsid)` read
    the PDS URL and DID from the session (`session.pds`/`session.sub`);
    the explicit-argument arities remain.
  - `Lexicon.validate_with/2,4` type-checks against a schema (or its
    parsed IR) without registering it.
  - `Resolver.list/3` returns `{:ok, %{schemas: ..., invalid: ...}}` so
    it composes with `with`.
  - `mix exosphere.gen.lexicons --dir/--out/--namespace/--map` for host
    apps: `--dir` scopes generation to the app's own lexicon directory
    while the vendored corpus — resolved absolutely from the exosphere
    dependency's priv, not the caller's relative path — is parsed for
    ref resolution. Refs into the corpus point at the library's
    compiled modules instead of generating duplicates under the host
    namespace (a record referencing
    `com.atproto.repo.strongRef` gets `Exosphere.ATProto.Repo.StrongRef`).
    `--out` sets the output tree (default `lib/exosphere`),
    `--namespace` the module root (default `Exosphere`), and
    `--map authority=Suffix` (repeatable) strips host authority
    segments the way the built-in rules do for `app.bsky`
    (`--namespace Oysters --map pub.oysters=Lexicons` →
    `Oysters.Lexicons.Post`). `Generator.generate/2` exposes the same
    via `base:`/`seeds:`/`rules:`/`external:` opts. Unresolved-ref
    warnings are scoped to the seeded lexicons when generating from
    `--dir`.
- **Lexicon registration, type-checking, and publishing** — first-class
  lexicon support beyond compile-time codegen:
  - `Exosphere.Lexicon` — entry point: `register/1`, `validate/3`,
    `publish/4`, `delete/4`.
  - `Exosphere.Lexicon.Schema` — the `com.atproto.lexicon.schema` record
    type: builds and validates lexicon documents against the meta-rules
    (lexicon version, NSID id, single primary def, record `key`, ref
    targets), round-trips wire records, and derives the record key (the
    NSID) for publishing.
  - `Exosphere.Lexicon.Validator` — runtime validation of wire-format
    values against parsed lexicon IR: required/nullable distinction,
    unknown fields ignored permissively (or `strict: true`), open/closed
    unions with `$type` discrimination, byte-vs-grapheme string limits,
    format checks (datetime, at-uri, nsid, did, cid, ...), cross-lexicon
    ref resolution, and data-model conformance.
  - `Exosphere.Lexicon.Registry` — process-free runtime NSID → lexicon
    registry (`:persistent_term`), loadable from the vendored corpus;
    `validate/3` type-checks by NSID, with an `optimistic: true` mode
    mirroring PDS fail-open behavior.
  - `Exosphere.Lexicon.Resolver` — fetch published lexicons: `fetch/4`
    via `com.atproto.repo.getRecord`, `list/3` via `listRecords`, and
    `resolve/2` via NSID authority (DNS TXT `_lexicon.<domain>` → DID →
    PDS), per the lexicon resolution spec.
  - `mix exosphere.lint.lexicons` — lints lexicon JSON documents against
    the spec rules (via `Parser` + `Schema.validate_document/1`) with
    style-guide warnings (missing descriptions); `--strict` fails on
    warnings too.
  - `mix exosphere.gen.lexicons --from did:plc:… [--pds …]` — vendors a
    repo's published lexicons then generates typed modules for them;
    unresolved corpus refs now print warnings instead of silently
    degrading to `term()`.
  - Vendored `com/atproto/lexicon/schema.json` (the meta-schema itself).
- **Repository verification pipeline** — the trustless read path:
  - `Exosphere.ATProto.Repo.verify_checkout/3` — downloads
    `com.atproto.sync.getRepo` from a PDS, reads the record set out of the
    MST, confirms it against the commit's signed root, resolves the DID
    document, and verifies the commit signature. Returns the full
    `path => CID` record set with the commit revision. Verified live against
    a real 41k-record repository (root + signature both check out).
  - `Exosphere.ATProto.Repo.Commit.verify_checkout/2` — the structural half:
    blocks ↔ signed MST root, returning the record set. Catches hostile
    non-canonical trees served under a signed root CID.
  - `Exosphere.ATProto.Firehose.Message.verify_commit/1` — verifies a
    `#commit` message's incremental CAR against its MST root (succeeds when
    all referenced nodes are present, e.g. initial snapshots; reports
    `{:missing_block, cid}` otherwise).
  - `Exosphere.ATProto.CAR.decode_full/1` — CAR archive → header roots (as
    CIDs) + block map; `decode/1` is unchanged and delegates.
  - `Exosphere.ATProto.MST.from_repo_car/1` — record set straight from a
    repository CAR (bytes or decoded form).
- **Lexicons hexdocs guide** (`docs/lexicons.md`, wired into `mix docs`
  extras) — the developer guide for the lexicon workflow: authoring and
  meta-rule validation, linting, registration and validation semantics
  (permissive vs strict, unresolved refs), publishing and safe
  modification (spec evolution rules), fetching/resolution, host-app
  code generation, and the limits of what schemas can express.
- **Firehose hexdocs guide** (`docs/firehose.md`, wired into `mix docs`
  extras) — a standalone page covering consumer setup, message types, record
  extraction, verification, cursors/reconnection, and production tips.

- `Exosphere.ATProto.AtUri` — parse/validate/render `at://` URIs (authority,
  collection, rkey, fragment), with the authority validated as a DID or handle.
- `Exosphere.ATProto.NSID` — NSID syntax validation and parsing.
- `Exosphere.ATProto.RecordKey` — record-key syntax validation.
- `Exosphere.ATProto.Repo.Commit` — verify a repository commit's signature
  against a public key (`verify/3`) or a DID document's signing key
  (`verify_with_document/2`), tying together `CBOR`, `Crypto`, and `Identity`.
- Firehose `#account` (hosting status) and `#sync` event decoding in
  `Exosphere.ATProto.Firehose.Message`; the optional `handle` field on
  `#identity`; and `prev_data` (MST root) on `#commit` plus `prev` on commit
  operations.
- **Interop conformance suite** (`test/interop/`) running Exosphere against a
  vendored, pinned snapshot of
  [`bluesky-social/atproto-interop-tests`](https://github.com/bluesky-social/atproto-interop-tests)
  (CC0): syntax tables (handle, DID, NSID, record-key, TID, AT-URI), the crypto
  signature fixtures (valid, high-S, and DER-encoded), and the DAG-CBOR
  data-model fixtures (exact bytes + CID). Documented gaps (general CID-string
  syntax, full record/data-model validation) are tracked as skips.
- `Exosphere.ATProto.MST` — Merkle Search Tree support: `build/1` constructs an
  MST from `path => CID` entries (returning the root CID and encoded node
  blocks), `read/2` walks a tree from a root CID and block store back into a
  `path => CID` map (accepting raw bytes or decoded nodes), and `depth/1` /
  `valid_key?/1` expose the layer algorithm and key validation. Verified
  byte-for-byte against the atproto interop root-CID vectors. Hardened after
  review: `read/2` detects cycles in hostile block data (`{:error, {:cycle, cid}}`)
  instead of recursing forever; `build/1` rejects duplicate paths with conflicting
  CIDs (`{:error, {:duplicate_key, key}}`), dedupes identical entries, returns
  `{:error, {:invalid_entry, term}}` for non-pair input instead of raising, and
  validates keys with the full `NSID` / `RecordKey` grammars (stricter than the
  previous charset check). Key depths are computed once per build instead of
  once per layer comparison.
- `Exosphere.ATProto.Repo.Commit.verify_data/2` — confirm a commit's `data`
  (MST root) matches a set of records, completing repository verification
  alongside `verify/3`.
- repository verification pipeline + MST canonical shape fix + firehose guide (#9)
- data-model validation, README verification quickstart, CI matrix 1.20 (#11)
- bump the README install snippet when cutting a release (#12)
- lexicon-driven code generation for bsky + community types (#13)

### Changed

- `Exosphere.ATProto.HTTP` now follows GET/HEAD redirects (301/302/303/307/308,
  up to 5 hops; disable with `follow_redirects: false`). A relay answering
  `getRepo` for a repo it doesn't host with a 302 to the real PDS is normal,
  and the verification pipeline depends on following it. Response bodies are
  also received with batched mailbox drains.

- **`fresh` replaced with `websockex` (~> 0.5).** Fresh is unmaintained (last
  release April 2024) and its mix.exs no longer compiles on Elixir 1.20.
  `Exosphere.ATProto.Firehose.Consumer` keeps the same public API and
  callback semantics; WebSockex answers protocol-level pings and reconnects
  automatically on disconnect (replaying the original subscription URL).
  Verified live against `wss://bsky.network`. Also fixed a latent compile
  error in the `#error`-message path (`stats` was unbound) that had been
  masked by stale build caches.
- `Exosphere.ATProto.Identity.Document.get_handle/1` now extracts the handle via
  `AtUri` parsing rather than naive string-prefix stripping.
- `Exosphere.ATProto.Firehose.Message` documents `#handle` and `#tombstone` as
  deprecated (superseded by `#identity` and `#account`); they are still decoded
  for backwards compatibility. Commit operations gained a `prev` field and the
  commit map gained `prev_data`.

### Fixed
- run the release pipeline on GITHUB_TOKEN with a deploy key for pushes (#15)
- harden firehose reconnect, socket cleanup, DID injection, and validation edges (#14)
- normalize the deploy key secret and validate it before pushing (#16)
- repair cut workflow, key parsing, and backfill lost entries (#17)

### Internal

- Corrected the canonical CID example in `CID`/`CBOR` moduledocs
  (`{"hello":"world"}` → `bafyreidykglsfhoixmivffc5uwhcgshx4j465xwqntbmu43nb2dzqwfvae`);
  the previous value was wrong and never exercised by a doctest.
- Added `elixirc_paths` for `test/support` (interop fixture helpers).
- Bumped `credo` to 1.7.19 (fixes Elixir 1.20 crashes in its token analysis)
  and pinned three `size(...)` variables in `CAR` that Elixir 1.20 flags as
  warnings, restoring a clean `--warnings-as-errors` build.
- New `test/support/repo_car.ex` builder constructs complete signed repository
  CARs (records → MST → signed commit → CARv1) entirely offline, so the
  verification pipeline is tested without network access. A shell-node
  regression test pins the canonical tree shape.
- `mix compile --warnings-as-errors`, `mix credo --strict`, `mix dialyzer`, and
  `mix format --check-formatted` all clean. Test suite at 158 tests, 0 failures
  (1 pre-existing skip).
- cut releases from main via changelog queue and mix tasks (#8)
- fix Dialyzer CI failing on open PRs (#7)

## [0.2.0] - 2026-04-28

Hardening pass following a full package audit. Several public functions in
`Crypto` and `CBOR` now return `{:error, reason}` tuples instead of raising or
silently corrupting state, which is a breaking change for callers that only
matched on `{:ok, _}`.

### Added

- `Exosphere.ATProto.Base58` — extracted from `Crypto` into its own module so
  the published library no longer pollutes the top-level `Base58` namespace.
- `Exosphere.TID` facade now delegates `generate_for/1`, `valid?/1`, and
  `compare/2` (parity with `Exosphere.ATProto.TID`).
- `Exosphere.ATProto.CBOR.transform_after_decode/1` now has a fallback head
  for tag-42 values without the `0x00` multibase prefix, matching the
  behaviour of `Frame` and `CAR`.
- 16 tests covering `Crypto`: keypair generation, sign/verify round-trips for
  secp256k1 and P-256, low-S property, did:key round-trips, and error paths.

### Changed (breaking)

- `Exosphere.ATProto.Crypto.to_did_key/2` and `to_multibase/2` now return
  `{:error, :invalid_public_key}` for malformed inputs instead of raising
  `FunctionClauseError`. Callers that only matched `{:ok, _}` must add an
  error clause.
- `Exosphere.ATProto.Crypto.from_did_key/1` now distinguishes
  `:invalid_did_key_format` (missing `did:key:` prefix) from
  `:unsupported_multibase` (wrong/missing `z` prefix).
- `Exosphere.ATProto.CBOR.encode/1` no longer accepts the `:canonical` option
  (it was dead — both branches did the same thing). Encoding is always
  canonical. Calls passing the option will fail with an arity error.
- `Exosphere.ATProto.Firehose.Consumer` no longer swallows exceptions raised
  by user-supplied `:on_event` callbacks. A crashing callback now crashes the
  consumer (which Fresh restarts and reconnects). The module documentation
  states this contract explicitly.

### Fixed

- `Exosphere.ATProto.Firehose.Message.extract_records/1` no longer crashes
  with `MatchError` on malformed op paths (paths missing `/` or `nil`).
  Malformed entries are logged and dropped.
- `Exosphere.ATProto.CBOR.encode/1` no longer raises an internal
  `ArgumentError` and recovers it via string matching. Floats are rejected
  with `{:error, :floats_not_allowed}` returned directly.
- HTTP `User-Agent` header is now `Exosphere/<version>` (was a stale
  `MediaLibrary/0.1.0` string from a previous project).
- Example NSID in `Exosphere.ATProto.Repo` moduledoc now uses
  `app.bsky.actor.profile` instead of a stale `media.library.profile`.
- `Exosphere.TID.to_datetime/1` typespec narrowed to
  `{:ok, DateTime.t()} | {:error, :invalid_tid}`.

### Removed

- Dead legacy clause in `Exosphere.ATProto.CID.decode/1` that could never be
  reached.
- Top-level `Base58` module (moved to `Exosphere.ATProto.Base58`).
- `:canonical` option from `Exosphere.ATProto.CBOR.encode/1`.

### Internal

- Resolved all 8 `Credo --strict` `Design.AliasUsage` findings across
  `cid.ex`, `firehose/frame.ex`, and `xrpc/client.ex`.
- Bumped `ex_doc` from `~> 0.31` to `~> 0.40`.
- Tooling baseline: `mix compile --warnings-as-errors`, `mix credo --strict`,
  and `mix dialyzer` are all clean. Test suite at 44 tests, 0 failures.

## [0.1.0] - 2026-04-28

Initial release.
