# AT Protocol interop test fixtures

These files are a **vendored, pinned snapshot** of the official, implementation-neutral
conformance suite:

- Upstream: <https://github.com/bluesky-social/atproto-interop-tests>
- Pinned commit: `968f3906986bca45885a27f5c6307249d3ee8ff6`
- License: CC0 1.0 (public domain dedication)

They are vendored (rather than used as a git submodule) so the test suite runs
offline and deterministically in CI with no extra checkout steps. Only the
fixture categories currently exercised by Exosphere are included.

## To update

Re-fetch the desired files at a newer commit and update the pinned SHA above,
e.g.:

```sh
SHA=<new-commit-sha>
gh api "repos/bluesky-social/atproto-interop-tests/contents/syntax/handle_syntax_valid.txt?ref=$SHA" \
  --jq '.content' | base64 -d > test/fixtures/interop/syntax/handle_syntax_valid.txt
```

## Coverage

| Fixtures | Exercised by | Module |
|---|---|---|
| `syntax/handle_syntax_*` | `interop/syntax_test.exs` | `Identity.Handle` |
| `syntax/did_syntax_*` | `interop/syntax_test.exs` | `Identity.DID` |
| `syntax/nsid_syntax_*` | `interop/syntax_test.exs` | `NSID` |
| `syntax/recordkey_syntax_*` | `interop/syntax_test.exs` | `RecordKey` |
| `syntax/tid_syntax_*` | `interop/syntax_test.exs` | `TID` |
| `syntax/aturi_syntax_*` | `interop/syntax_test.exs` | `AtUri` |
| `syntax/cid_syntax_*` | `interop/syntax_test.exs` | `CID` |
| `crypto/signature-fixtures.json` | `interop/crypto_test.exs` | `Crypto` |
| `data-model/data-model-*` | `interop/data_model_test.exs` | `CBOR` |

Categories in the upstream suite that Exosphere does not yet implement
(datetime, language tags, full lexicon validation, firehose commit proofs, MST
key-height tables) are not vendored here; see the test files for the tracked
gaps.
