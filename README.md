# Exosphere

[![Hex.pm](https://img.shields.io/hexpm/v/exosphere.svg)](https://hex.pm/packages/exosphere)
[![HexDocs](https://img.shields.io/badge/docs-hexdocs-blue.svg)](https://hexdocs.pm/exosphere)

![Logo](./docs/static/banner.png)

Exosphere is a collection of AT Protocol clients and utilities.

## Documentation

- **HexDocs**: https://hexdocs.pm/exosphere

## What’s inside

- `Exosphere.ATProto.*`: lower-level, spec-aligned implementation building blocks (see [atproto.com](https://atproto.com/))
- `Exosphere.*`: public-facing API modules built on top of `Exosphere.ATProto.*` (XRPC client, OAuth session, firehose consumer, etc.)

## Getting started

### Installation

Add `exosphere` to your dependencies:

```elixir
def deps do
  [
    {:exosphere, "~> 0.3"}
  ]
end
```

### Quickstart: XRPC client

`Exosphere.XRPC.Client` is a small wrapper around `Exosphere.ATProto.XRPC.Client`.

```elixir
# Create an unauthenticated client for a PDS
client = Exosphere.XRPC.Client.new("https://bsky.social")

{:ok, %{"did" => did}} =
  Exosphere.XRPC.Client.query(client, "com.atproto.identity.resolveHandle",
    handle: "atproto.com"
  )
```

## OAuth (DPoP-bound sessions)

`Exosphere.ATProto.OAuth.*` implements the full [ATProto OAuth
profile](https://atproto.com/specs/oauth): identity-to-server discovery,
client metadata documents, PAR, PKCE, `private_key_jwt`, DPoP-bound tokens
with nonce handling, token exchange, and rotating refresh tokens.
`Exosphere.OAuth.Session` wraps the result in a GenServer that keeps the
session fresh and signs XRPC calls.

```elixir
alias Exosphere.ATProto.OAuth.{Client, ClientMetadata, Discovery, Flow, JWK}

client = Client.new!(
  metadata: ClientMetadata.new!(
    client_id: "https://app.example.com/oauth-client-metadata.json",
    client_name: "My App",
    redirect_uris: ["https://app.example.com/oauth/callback"],
    scope: ["atproto", "transition:generic"],
    jwk: JWK.to_public(client_key)
  ),
  key: client_key,
  redirect_uri: "https://app.example.com/oauth/callback"
)

{:ok, resolved} = Discovery.resolve("alice.example.com")
{:ok, {authorize_url, ctx}} = Flow.authorize_url(client, resolved)
# ... browser round-trip; store ctx server-side ...
{:ok, session} = Flow.callback(ctx, callback_params)

{:ok, pid} = Exosphere.OAuth.Session.start_link(session: session)
{:ok, profile} = Exosphere.OAuth.Session.query(pid, "app.bsky.actor.getProfile", actor: session.sub)
```

See the [OAuth guide](oauth.html) for the complete walk-through, including
local-development loopback clients and the in-process mock PDS for e2e
testing.

## Firehose (subscribeRepos)

Use `Exosphere.Firehose.Consumer` to connect to a relay’s
`com.atproto.sync.subscribeRepos` WebSocket endpoint, decode frames into
structured messages, and dispatch them to your callback.

### Running under a supervisor

The consumer **requires** an `:on_event` callback with arity 2: `(message, state) -> state`.

```elixir
children = [
  {Exosphere.Firehose.Consumer,
   relay_url: "wss://bsky.network",
   cursor: nil,
   on_event: &MyApp.Firehose.on_event/2,
   name: MyApp.FirehoseConsumer}
]

Supervisor.start_link(children, strategy: :one_for_one)
```

### Handling events

Messages are decoded into maps with a `:type` key (for example `:commit`, `:identity`, `:handle`).
For commit messages, you can extract record data from the embedded CAR blocks via
`Exosphere.ATProto.Firehose.Message.extract_records/1`.

```elixir
defmodule MyApp.Firehose do
  require Logger
  alias Exosphere.ATProto.Firehose.Message

  def on_event(%{type: :commit} = msg, state) do
    # Persist msg.seq somewhere if you want resumable consumption (cursor).
    case Message.extract_records(msg) do
      {:ok, records} ->
        Logger.info("commit seq=#{msg.seq} records=#{length(records)}")
        state

      {:error, reason} ->
        Logger.warning("commit seq=#{msg.seq} extract_records failed: #{inspect(reason)}")
        state
    end
  end

  def on_event(msg, state) do
    Logger.debug("firehose event: #{inspect(msg.type)}")
    state
  end
end
```

## Verifying repositories

You don't have to trust a PDS's word for what's in a repository. Exosphere can
fetch a full repository archive and prove it against the key the account
advertises in its DID document:

```elixir
{:ok, %{rev: rev, records: records}} =
  Exosphere.ATProto.Repo.verify_checkout("https://bsky.network", "did:plc:abc123")
```

That one call downloads `com.atproto.sync.getRepo`, reads every record out of
the Merkle Search Tree, confirms the record set matches the commit's signed
root, resolves the DID document, and verifies the commit signature. If it
returns `{:ok, _}`, the records provably come from the account controlling
that DID.

For firehose events, `Exosphere.ATProto.Firehose.Message.verify_commit/1`
checks a `#commit` message's embedded blocks against its signed MST root —
see the [Firehose guide](firehose.html) for when that succeeds (incremental
CARs only carry new blocks) and how to build on it.

## Lexicons: register, type-check, and publish

Exosphere ships compile-time typed modules for the vendored bsky/community
lexicons, and a runtime workflow for lexicons of your own — or anyone else's.

Define (or fetch) a lexicon, type-check records against it, and publish it to
a PDS as a `com.atproto.lexicon.schema` record:

```elixir
{:ok, schema} = Exosphere.Lexicon.Schema.new(%{
  "lexicon" => 1,
  "id" => "com.example.post",
  "defs" => %{"main" => %{
    "type" => "record", "key" => "tid",
    "record" => %{"type" => "object",
      "required" => ["text"],
      "properties" => %{"text" => %{"type" => "string", "maxGraphemes" => 100}}}
  }}
})

# Type-check records at runtime (spec semantics: unknown fields ignored,
# open unions, byte-vs-grapheme string limits; pass strict: true to reject)
:ok = Exosphere.Lexicon.register(schema)
:ok = Exosphere.Lexicon.validate("com.example.post", %{
  "$type" => "com.example.post", "text" => "hello"
})

# Publish: record key is the NSID, so it lives at
# at://<did>/com.atproto.lexicon.schema/com.example.post
{:ok, %{uri: uri, cid: cid}} =
  Exosphere.Lexicon.publish(session, pds_url, did, schema)
```

Lexicons published by any repository can be fetched back and registered:

```elixir
# From a known repo
{:ok, schema} =
  Exosphere.Lexicon.Resolver.fetch(pds_url, did, "com.example.post", register: true)

# Or every lexicon a repo publishes
{:ok, schemas, _} = Exosphere.Lexicon.Resolver.list(pds_url, did)

# Or via NSID authority (DNS TXT _lexicon.<domain> → DID → PDS)
{:ok, schema} = Exosphere.Lexicon.Resolver.resolve("com.example.post")
```

To go back to compile-time safety, vendor a repo's lexicons and generate
typed modules for them:

```console
$ mix exosphere.gen.lexicons --from did:plc:abc123
```

## Notes

- The consumer **reconnects automatically** on disconnects and errors,
  re-subscribing at the last cursor it tracked (with capped, jittered
  backoff between attempts).
- For more control (or lower-level access), use the `Exosphere.ATProto.*` modules directly.

## CI / Releases

This project uses GitHub Actions:

- **CI**: runs `mix format --check-formatted`, `mix credo --strict`, `mix test`, and `mix dialyzer` on pushes + PRs.
- **Auto-versioning on merge**: when a PR is merged into `main`, a workflow requires exactly one label: `major`, `minor`, or `patch`. It bumps `mix.exs`, commits, tags `vX.Y.Z`, and pushes (which triggers the Hex release workflow).
- **Release**: pushing a tag like `v0.1.0` publishes the package + docs to Hex.

To enable publishing, add a repository secret named `HEX_API_KEY` (generate one via `mix hex.user key generate`).

