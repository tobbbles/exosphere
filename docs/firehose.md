# Firehose

The firehose is AT Protocol's global event stream. Every action on the network —
posts, likes, follows, identity changes — is published as an event by the
originating PDS and relayed to consumers over a WebSocket connection to the
`com.atproto.sync.subscribeRepos` endpoint. Exosphere ships a consumer for
subscribing to this stream, message decoding, and — uniquely — cryptographic
verification of the events you receive.

## Quick start

Start a consumer with an `:on_event` callback:

```elixir
{:ok, pid} =
  Exosphere.ATProto.Firehose.Consumer.start_link(
    on_event: fn message, state ->
      IO.inspect(message.type, label: "event")
      state
    end
  )
```

This connects to `wss://bsky.network` (the public relay) and begins dispatching
decoded messages. The callback receives each message plus your state and returns
an updated state — a classic fold.

Add it to a supervision tree instead of starting it manually:

```elixir
children = [
  {Exosphere.ATProto.Firehose.Consumer,
   relay_url: "wss://bsky.network",
   cursor: last_seen_seq,
   on_event: {MyApp.EventHandler, :handle}}
]
```

(When using `{module, function}` tuples like this, wrap them in your own
capture: `on_event: &MyApp.EventHandler.handle/2`.)

## Options

- `:relay_url` — WebSocket base URL (default `wss://bsky.network`).
- `:cursor` — sequence number to resume from. Persist `msg.seq` in your
  callback and pass it back on restart to avoid replaying the whole stream.
- `:on_event` — required arity-2 function `(message, state -> state)`.
- `:name` — registered process name.

## Message types

| Type | Meaning |
|------|---------|
| `#commit` | Repository write: record creates/updates/deletes, with CAR blocks |
| `#identity` | Handle or DID document change |
| `#account` | Hosting status change (deactivated, suspended, taken down, deleted) |
| `#sync` | Repository state assertion (mostly seen by relays) |
| `#info` | Informational (e.g. a new upstream commit from the PDS) |

`#handle` and `#tombstone` are deprecated but still decoded for older relays.

`#commit` messages carry:

- `commit` — the CID of the commit object (in `blocks`)
- `rev` / `since` — revision strings (TIDs) for this commit and the last one seen
- `ops` — the writes in this commit: `%{action: :create | :update | :delete, path: path, cid: cid, prev: prev}`
- `blocks` — raw CAR bytes containing the new/changed blocks

## Reading records out of a commit

```elixir
{:ok, records} = Exosphere.ATProto.Firehose.Message.extract_records(message)
# [%{collection: "app.bsky.feed.post", rkey: "3l...", cid: %CID{}, record: %{...}}]
```

## Verifying what you receive

By default a firehose consumer trusts the relay. Exosphere lets you do better.

### Verify a commit's structure

`Message.verify_commit/1` decodes the embedded CAR and proves the blocks form
exactly the Merkle Search Tree the commit's signature covers:

```elixir
{:ok, records} = Exosphere.ATProto.Firehose.Message.verify_commit(message)
# records: %{path => %CID{}} for the repository
```

**Important:** firehose commit CARs are *incremental* — they only include
blocks new in that commit, so this succeeds only when every referenced MST
node is present (typically an initial snapshot). For steady-state commits
you'll get `{:error, {:missing_block, cid}}`; that's expected, not a failure.

### Verify a whole repository

For complete verification — structure *and* signature — fetch the full
repository archive from a PDS and check it against the key the account
advertises in its DID document:

```elixir
{:ok, %{rev: rev, records: records}} =
  Exosphere.ATProto.Repo.verify_checkout("https://bsky.network", "did:plc:abc123")
```

This downloads `com.atproto.sync.getRepo`, reads the record set out of the
Merkle tree, rebuilds the tree to confirm the record set matches the signed
root, resolves the DID document, and verifies the commit signature
(ECDSA, low-S) against the advertised key. If it returns `{:ok, _}`, the
records provably come from the account that controls that DID.

Lower-level pieces, if you want to build your own flow:

- `Exosphere.ATProto.CAR.decode_full/1` — CAR archive → roots + blocks
- `Exosphere.ATProto.MST.read/2`, `MST.from_repo_car/1` — walk the record tree
- `Exosphere.ATProto.Repo.Commit.verify_checkout/2` — blocks ↔ signed root
- `Exosphere.ATProto.Repo.Commit.verify/3` — commit signature check

## Reliability notes

- **Reconnection**: the consumer reconnects automatically on disconnect or
  error, replaying the original subscription URL (including the starting
  cursor). In-flight cursor updates aren't pushed into the URL — persist the
  latest `msg.seq` yourself and restart with it for gap-free resumes.
- **Your callback must not raise.** The consumer doesn't catch exceptions; a
  raise crashes the process and supervision restarts it (losing in-memory
  cursor state). Do slow or fallible work in a `Task` or your own process.
- **Backpressure**: the callback runs inline in the socket process. If
  processing is slower than the firehose (a busy relay emits thousands of
  events per second), buffer into a GenStage/`:queue` and process downstream.

## Scaling down: filtering

The relay sends everything. Filter in your callback:

```elixir
on_event: fn msg, state ->
  case msg do
    %{type: :commit, repo: did} ->
      if MyApp.InterestingAccount.tracked?(did), do: MyApp.Store.apply(msg)
      state

    _ ->
      state
  end
end
```

For collection-level checks, `Message.has_collection?(msg, "app.bsky.feed.post")`
is a cheap pre-filter before pulling records.
