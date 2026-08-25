# Lexicon sources

Vendored lexicon JSON files are snapshots of upstream sources, refreshed
with `mix exosphere.lexicons.sync`. Regenerate modules with
`mix exosphere.gen.bsky` after syncing.

| Path | Source | Pin |
|------|--------|-----|
| `app/bsky/**`, `com/atproto/**` | https://github.com/bluesky-social/atproto/tree/main/lexicons | 79d911fc2bd7 |
| `com/atproto/**` (15 files), `community/**` (17 files) | https://tangled.org/lexicon.community/lexicons/tree/main/community (canonical; github.com/lexicon-community/lexicon is a mirror) | synced 2026-08-25 |
