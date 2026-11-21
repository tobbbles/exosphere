# Lexicon sources

Vendored lexicon JSON files are snapshots of upstream sources, refreshed
with `mix exosphere.lexicons.sync`. Regenerate modules with
`mix exosphere.gen.lexicons` after syncing.

All sources are equal citizens: regenerate everything with
`mix exosphere.gen.lexicons`, or scope to one source with
`mix exosphere.gen.lexicons app.bsky | community.lexicon | com.atproto`.

| NSID prefix | Vendored at | Generated into | Upstream | Pin |
|-------------|-------------|----------------|----------|-----|
| `app.bsky.*` (164 files) | `app/bsky/**` | `lib/exosphere/bsky` | https://github.com/bluesky-social/atproto/tree/main/lexicons | 4d2097ff37e0 |
| `com.atproto.*` (95 files) | `com/atproto/**` | `lib/exosphere/atproto` | same atproto repo as above | 4d2097ff37e0 |
| `com.atproto.{space,memberspace,managedspace,personalspace}.*` (39 files) | `com/atproto/{space,memberspace,managedspace,personalspace}/**` | `lib/exosphere/atproto` (records only; the methods are hand-written in `Exosphere.ATProto.Spaces`) | same atproto repo, branch `permissioned-data` (the Spaces November 12 alpha), not `main` | d4def6e9f521 |
| `community.lexicon.*` (17 files) | `community/**` | `lib/exosphere/community` | https://tangled.org/lexicon.community/lexicons/tree/main/community (canonical; github.com/lexicon-community/lexicon is a mirror) | synced 2026-08-26 |
