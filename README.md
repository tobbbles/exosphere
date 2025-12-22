# Exosphere

[![Hex.pm](https://img.shields.io/hexpm/v/exosphere.svg)](https://hex.pm/packages/exosphere)
[![HexDocs](https://img.shields.io/badge/docs-hexdocs-blue.svg)](https://hexdocs.pm/exosphere)

![Logo](./docs/static/banner.png)

Exosphere is a collection of protocol clients and utilities.

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
    {:exosphere, "~> 0.1.0"}
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

## Notes

- The consumer will attempt to **reconnect** on disconnects and errors.
- For more control (or lower-level access), use the `Exosphere.ATProto.*` modules directly.

## CI / Releases

This project uses GitHub Actions:

- **CI**: runs `mix format --check-formatted`, `mix credo --strict`, `mix test`, and `mix dialyzer` on pushes + PRs.
- **Auto-versioning on merge**: when a PR is merged into `main`, a workflow requires exactly one label: `major`, `minor`, or `patch`. It bumps `mix.exs`, commits, tags `vX.Y.Z`, and pushes (which triggers the Hex release workflow).
- **Release**: pushing a tag like `v0.1.0` publishes the package + docs to Hex.

To enable publishing, add a repository secret named `HEX_API_KEY` (generate one via `mix hex.user key generate`).

