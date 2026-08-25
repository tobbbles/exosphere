# Lexicon sources

Vendored lexicon JSON files are snapshots of upstream sources, refreshed
with `mix exosphere.lexicons.sync`. Regenerate modules with
`mix exosphere.gen.lexicons` after syncing.

All sources are equal citizens: regenerate everything with
`mix exosphere.gen.lexicons`, or scope to one source with
`mix exosphere.gen.lexicons app.bsky | community.lexicon | com.atproto`.

| NSID prefix | Vendored at | Generated into | Upstream | Pin |
|-------------|-------------|----------------|----------|-----|
| `app.bsky.*` | `app/bsky/**` | `lib/exosphere/bsky` | https://github.com/bluesky-social/atproto/tree/main/lexicons | 79d911fc2bd7 |
| `com.atproto.*` (curated, 3 files) | `com/atproto/**` | `lib/exosphere/atproto` | same atproto repo as above | 79d911fc2bd7 (refresh-in-place) |
| `community.lexicon.*` (17 files) | `community/**` | `lib/exosphere/community` | https://tangled.org/lexicon.community/lexicons/tree/main/community (canonical; github.com/lexicon-community/lexicon is a mirror) | synced 2026-08-25 |
