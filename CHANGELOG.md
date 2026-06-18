# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Spec-conformance pass against the [AT Protocol specifications](https://atproto.com/specs).
Fixes several DAG-CBOR / cryptography correctness bugs (some of which change
wire output or reject previously-accepted input) and adds the AT-URI, NSID, and
record-key primitives plus commit-signature verification.

### Fixed (breaking — output / acceptance changes)

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
  byte-for-byte against the atproto interop root-CID vectors.
- `Exosphere.ATProto.Repo.Commit.verify_data/2` — confirm a commit's `data`
  (MST root) matches a set of records, completing repository verification
  alongside `verify/3`.

### Changed

- `Exosphere.ATProto.Identity.Document.get_handle/1` now extracts the handle via
  `AtUri` parsing rather than naive string-prefix stripping.
- `Exosphere.ATProto.Firehose.Message` documents `#handle` and `#tombstone` as
  deprecated (superseded by `#identity` and `#account`); they are still decoded
  for backwards compatibility. Commit operations gained a `prev` field and the
  commit map gained `prev_data`.

### Internal

- Corrected the canonical CID example in `CID`/`CBOR` moduledocs
  (`{"hello":"world"}` → `bafyreidykglsfhoixmivffc5uwhcgshx4j465xwqntbmu43nb2dzqwfvae`);
  the previous value was wrong and never exercised by a doctest.
- Added `elixirc_paths` for `test/support` (interop fixture helpers).
- `mix compile --warnings-as-errors`, `mix credo --strict`, `mix dialyzer`, and
  `mix format --check-formatted` all clean.

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
