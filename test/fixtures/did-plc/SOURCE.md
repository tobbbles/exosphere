# did:plc conformance fixtures

A **vendored, pinned snapshot** of the reference did:plc implementation's
conformance corpus:

- Upstream: <https://github.com/did-method-plc/go-didplc> (`testdata/`)
- Pinned commit: `82d6a6176133e9a49f88e09029266646b0069c8a`
- License: MIT

Vendored rather than submoduled so the suite runs offline and
deterministically in CI, and — more to the point here — so a change in the
corpus is a reviewable diff rather than a silent shift under a passing
build.

Each `log_*.json` is in the format of the directory's `/:did/log/audit`
endpoint: an array of `{did, operation, cid, nullified, createdAt}` entries.

## To update

```sh
SHA=<new-commit-sha>
for f in $(gh api repos/did-method-plc/go-didplc/contents/testdata --jq '.[].name' | grep '^log_'); do
  gh api "repos/did-method-plc/go-didplc/contents/testdata/$f?ref=$SHA" \
    --jq '.content' | base64 -d > "test/fixtures/did-plc/$f"
done
```

Then update the pinned SHA above.

## Coverage

Exercised by `test/interop/did_plc_test.exs` against
`Identity.DID.PLC.{Operation,Signer,AuditLog}`.

| Fixture | Expectation | What it pins down |
|---|---|---|
| `log_bskyapp` | valid | Real-world log, modern operations |
| `log_bnewbold_robocracy` | valid | Real-world log |
| `log_legacy_dholms` | valid | Legacy `create` genesis — signature and DID derive from the *original* bytes, not the normalized form |
| `log_tombstone` | valid | `plc_tombstone` terminates a chain |
| `log_nullification` | valid | Higher-authority fork nullifies the displaced operation |
| `log_nullification_nontrivial` | valid | Multi-fork graph; only some operations nullify |
| `log_nullification_at_exactly_72h` | valid | The recovery window is **inclusive** at exactly 72h |
| `log_nullified_tombstone` | valid | A tombstone may itself be nullified |
| `log_invalid_nullification_too_slow` | invalid | 72h + 1s — outside the window |
| `log_invalid_nullification_reused_key` | invalid | Fork not signed by a *strictly* higher-authority key |
| `log_invalid_update_nullified` | invalid | Building on a nullified operation |
| `log_invalid_update_tombstoned` | invalid | Building on a tombstone |
| `log_invalid_sig_k256_high_s` | invalid | High-S signature, secp256k1 |
| `log_invalid_sig_p256_high_s` | invalid | High-S signature, P-256 |
| `log_invalid_sig_der` | invalid | DER-encoded rather than raw R\|\|S |
| `log_invalid_sig_b64_padding_chars` | invalid | `=` padding in the base64url signature |
| `log_invalid_sig_b64_padding_bits` | invalid | Non-canonical final sextet |
| `log_invalid_sig_b64_newline` | invalid | Whitespace in the signature |
| `log_duplicate_rotation_keys` | invalid | Duplicate entries in `rotationKeys` |
| `log_empty_rotation_keys` | invalid | Empty `rotationKeys` |

`known_bad_cids.json` / `known_bad_dids.json` are **not vendored**: they
enumerate malformed operations already stored by `plc.directory` by CID/DID
reference only, so without the operations themselves they are not testable
offline. They matter for anyone validating a full directory export, which
this suite deliberately does not do.
