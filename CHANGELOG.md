# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
