# STAR interop fixtures

`valid-star-fixtures.json` and `invalid-star-fixtures.json` are copied
unmodified from bluesky-social/atproto at `98ef3a6`
(`packages/star/tests/interop/`, branch `permissioned-data`), which in turn
copied them unmodified from
[microcosm.blue/star](https://tangled.org/microcosm.blue/star/tree/main/interop)
at commit `41bdec1fd1be7f6f30a1f961a01442b2fa2ec3c1`, under that project's
MIT / Apache-2.0 license.

They are asserted by `test/exosphere/atproto/star_test.exs`: every valid
archive decodes to its recorded metadata and pairs and re-encodes to the same
bytes; every invalid archive is rejected. Update them by copying from
upstream, not by editing them here.
