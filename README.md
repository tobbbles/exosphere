# Exosphere

[![Hex.pm](https://img.shields.io/hexpm/v/exosphere.svg)](https://hex.pm/packages/exosphere)
[![HexDocs](https://img.shields.io/badge/docs-hexdocs-blue.svg)](https://hexdocs.pm/exosphere)

![Logo](./docs/static/banner.png)

Exosphere is a collection of AT Protocol clients and utilities.

## Documentation

- **HexDocs**: https://hexdocs.pm/exosphere

## What’s inside

- `Exosphere.ATProto.*`: lower-level, spec-aligned implementation building blocks (see [atproto.com](https://atproto.com/))
- `Exosphere.*`: public-facing API modules built on top of `Exosphere.ATProto.*` (XRPC client, firehose consumer, etc.)

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

