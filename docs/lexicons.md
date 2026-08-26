# Lexicons

Lexicons are AT Protocol's schema language: a JSON document that defines a
record type, an XRPC endpoint, or a set of shared definitions, named by an
NSID (`com.example.post`). They are how the protocol stays extensible —
anyone who controls a domain can define new types, publish them as records
on their PDS, and anyone else can fetch and validate against them.

Exosphere covers the whole lifecycle:

- **Author** — validate documents against the lexicon meta-rules
- **Lint** — spec errors plus style warnings, before anything is published
- **Type-check** — validate records against any lexicon at runtime, with
  the spec's permissive semantics (or `strict: true`)
- **Publish** — write lexicons to `com.atproto.lexicon.schema` on a PDS
- **Fetch** — pull published lexicons back by repo or by NSID authority
- **Generate** — compile-time typed modules from your own or anyone's
  lexicons

## The document

A lexicon is a single JSON object with a version, an NSID, and definitions:

```json
{
  "lexicon": 1,
  "id": "com.example.post",
  "defs": {
    "main": {
      "type": "record",
      "key": "tid",
      "record": {
        "type": "object",
        "required": ["text", "createdAt"],
        "properties": {
          "text": { "type": "string", "maxGraphemes": 600 },
          "createdAt": { "type": "string", "format": "datetime" },
          "subject": { "type": "ref", "ref": "com.atproto.repo.strongRef" },
          "tags": { "type": "array", "items": { "type": "string", "maxGraphemes": 32 } }
        }
      }
    }
  }
}
```

`Lexicon.Schema.new/1` parses and validates the document, enforcing the
rules the spec places on lexicons themselves — version 1, a simple NSID
`id` with no fragment, at most one primary definition per file, record
definitions carrying a `key` (`tid`, `nsid`, `any`, or `literal:<value>`),
and refs never targeting refs, unions, or tokens:

```elixir
{:ok, schema} = Exosphere.Lexicon.Schema.new(json)
{:error, errors} = Exosphere.Lexicon.Schema.new(broken_json)
# [{"defs.main.key", "invalid key format \"banana\"; expected tid, nsid, any, or literal:<value>"}]
```

The struct round-trips losslessly: `Schema.to_record/1` produces the wire
record (injecting `$type`), `Schema.from_record/1` decodes one back, and
the `defs` you put in are the `defs` you get out. `Schema.record_key/1` is
the NSID itself — a published lexicon lives at
`at://<did>/com.atproto.lexicon.schema/<nsid>`.

## Linting

Before publishing — the artifact is permanent once others depend on it —
lint the documents:

```console
$ mix exosphere.lint.lexicons priv/lexicons
linted 2 lexicons, 0 error(s) 0 warning(s)
```

Errors are spec violations (the same rules `Schema.new/1` enforces, plus
invalid JSON and parser-level node checks). Warnings are style-guide
suggestions: definitions and record properties without `description`s,
and `format` values outside the spec set — a typo like `"datetim"` is
otherwise silently never checked. `--strict` fails on warnings too; the
task takes individual files or directories and exits non-zero on errors.

## Registering and type-checking

The runtime registry maps NSIDs to parsed lexicons and backs validation:

```elixir
{:ok, _} = Exosphere.Lexicon.Registry.load_vendored()  # bsky + community + curated atproto
:ok = Exosphere.Lexicon.register(schema)               # your own (parsed, %Schema{}, or raw JSON)

:ok = Exosphere.Lexicon.validate("com.example.post", %{
  "$type" => "com.example.post",
  "text" => "hello",
  "createdAt" => "2026-08-25T12:00:00.000Z"
})
```

A host app with its own lexicon directory loads it in one call:

```elixir
{:ok, _} = Exosphere.Lexicon.Registry.load_dir("priv/lexicons")
```

### Validation semantics

`Lexicon.Validator` implements the spec's permissive-by-default posture:

- **Unknown fields are ignored** — schema evolution means readers see
  fields they don't know yet. `strict: true` rejects them.
- **Unions are open** — a `$type` outside the declared refs passes as long
  as the value satisfies the data model. Closed unions (`"closed": true`)
  always reject unknown variants; `strict: true` rejects them in open
  unions too.
- **`enum` is closed; `knownValues` is advisory** and never fails.
- **`maxLength` counts UTF-8 bytes, `maxGraphemes` counts grapheme
  clusters** — the distinction matters the moment text isn't ASCII.
- **Required fields may be null only when listed in `nullable`** —
  omitted, null, and empty are three different states.
- Format checks cover all spec formats: `datetime`, `uri`, `at-uri`,
  `nsid`, `did`, `cid`, `handle`, `language`, `tid`, `record-key`,
  `at-identifier`.

One permissive behavior deserves its own headline: **a ref whose target
lexicon is not registered is skipped** — that field passes unchecked.
Register the referenced lexicons (the vendored corpus covers the
protocol's own types, `com.atproto.repo.strongRef` included) or run with
`strict: true`, which makes unresolved refs — and unresolved union
variants — errors:

```elixir
{:error, [{"subject", "unresolved ref com.atproto.repo.strongRef (lexicon not registered)"}]} =
  Exosphere.Lexicon.validate(nsid, record, strict: true)
```

To check a schema you haven't registered (a fetched document, say)
without touching global state, use `Lexicon.validate_with/2`:

```elixir
:ok = Exosphere.Lexicon.validate_with(schema, record)
```

The registry lives in `:persistent_term`: no process to supervise, reads
are free, and it suits a load-once schema set. `Exosphere.Lexicon.Registry.validate/3`
also takes `optimistic: true`, mirroring the PDS "fail-open" mode —
unregistered NSIDs pass rather than error.

Errors are `[{path, message}]` tuples with dotted paths and array
indices (`"tags[0]"`, `"subject.uri"`), directly renderable in forms or
API responses.

## Publishing

With an OAuth session (see the [OAuth guide](oauth.html)), publishing is
one call:

```elixir
{:ok, %{uri: uri, cid: cid}} = Exosphere.Lexicon.publish(session, schema)
# uri: "at://did:plc:.../com.atproto.lexicon.schema/com.example.post"
```

`publish/2` takes the PDS URL and DID from the session
(`session.pds` / `session.sub`); `publish/4` accepts them explicitly.
The record key is the lexicon's NSID, so **publishing a revised document
for the same NSID updates the record in place** — the natural unit of
modification. `Lexicon.delete(session, nsid)` removes it.

### Modifying without breaking consumers

The spec's evolution rules are strict, and for good reason — records
already written against the old schema keep existing:

- New fields must be optional (never added to `required`).
- Fields cannot be renamed or change type; deprecate instead of removing.
- Union variants can be added to an open union, never removed.
- A closed union's variant set is fixed.
- Anything else — including narrowing constraints in ways existing
  records violate — requires a **new NSID**.

A safe update loop fetches what is published, applies your changes, and
re-publishes:

```elixir
{:ok, current} = Exosphere.Lexicon.Resolver.fetch(session.pds, session.sub, "com.example.post")
{:ok, revised} = Exosphere.Lexicon.Schema.new(update(current.defs))
{:ok, _} = Exosphere.Lexicon.publish(session, revised)
```

Exosphere does not yet diff revisions for you — breaking-change
detection is on the roadmap — so for now the rules above are the
checklist.

## Fetching and resolving

Lexicons published by any repository can be fetched back:

```elixir
# From a known repo; register: true also puts it in the registry
{:ok, schema} =
  Exosphere.Lexicon.Resolver.fetch(pds_url, did, "com.example.post", register: true)

# Everything a repo publishes
{:ok, %{schemas: schemas, invalid: []}} = Exosphere.Lexicon.Resolver.list(pds_url, did)

# Via NSID authority: DNS TXT _lexicon.<reversed-authority-domain> → DID → PDS
{:ok, schema} = Exosphere.Lexicon.Resolver.resolve("com.example.post")
```

Authority resolution follows the lexicon resolution spec: it is
deliberately non-recursive (no probing up or down the DNS tree — a failed
TXT lookup is a failed resolution), and DNS changes are not announced on
the firehose, so don't cache authority results long-term.

## Compile-time modules

For lexicons you control — or third-party ones you've vendored — the
generator produces typed struct modules with `new/1` (build + validate),
`to_map/1` (wire encoding with `$type`), `from_map/1`, and `type_id/0`.
The library's own `app.bsky.*`, `community.lexicon.*`, and curated
`com.atproto.*` modules are generated this way from `priv/lexicons`.

A host app generates modules for its own lexicons without touching the
library's tree:

```console
$ mix exosphere.gen.lexicons --dir priv/lexicons \
    --out lib/my_app --namespace MyApp --map com.example=Schemas
```

- `--dir` scopes *generation* to that directory; the library's vendored
  corpus is still parsed alongside, and refs into it (like
  `com.atproto.repo.strongRef`) point at the library's compiled modules
  rather than duplicating them under your namespace.
- `--map com.example=Schemas` strips the authority segments the way the
  built-in rules do for `app.bsky`: `com.example.post` becomes
  `MyApp.Schemas.Post`, not `MyApp.Com.Example.Post`.
- To vendor a repo's published lexicons first:
  `mix exosphere.gen.lexicons --from did:plc:abc123`.

Generation is deterministic — regenerate and `git diff` shows exactly
what the schema change bought you.

## What the JSON can't say

Lexicons constrain types and bounds, not relationships between fields.
"A post has a URL or a text body or both" cannot be expressed, so a
generated module's `new/1` will happily build a post with neither. The
pattern that works: generate (or register) the schema for the wire
contract, and hand-write the constructor that enforces your invariants
on top:

```elixir
defmodule MyApp.Post do
  alias MyApp.Schemas.Post, as: Schema

  def new(attrs) do
    with :ok <- validate_invariants(attrs),
         {:ok, post} <- Schema.new(attrs) do
      {:ok, post}
    end
  end
end
```

The generated (or registry-validated) layer still buys you everything
the schema *can* say — lengths, formats, refs, unions — and your
hand-written layer says the rest.

## Reference

| Module | Purpose |
|--------|---------|
| `Exosphere.Lexicon` | Facade: `register/1`, `validate/3`, `validate_with/2`, `publish/2`, `delete/2` |
| `Exosphere.Lexicon.Schema` | The `com.atproto.lexicon.schema` record type; meta-rule validation |
| `Exosphere.Lexicon.Validator` | Runtime validation of wire values against parsed IR |
| `Exosphere.Lexicon.Registry` | NSID → lexicon registry (`:persistent_term`) |
| `Exosphere.Lexicon.Resolver` | Fetch by repo (`getRecord`, `listRecords`) or NSID authority (DNS TXT) |
| `Exosphere.Lexicon.Parser` | Lexicon JSON → normalized IR |
| `Exosphere.Lexicon.Generator` | Typed module generation (`base:`, `seeds:`, `rules:`, `external:`) |
| `Mix.Tasks.Exosphere.Lint.Lexicons` | `mix exosphere.lint.lexicons` |
| `Mix.Tasks.Exosphere.Gen.Lexicons` | `mix exosphere.gen.lexicons` |
| `Mix.Tasks.Exosphere.Lexicons.Sync` | `mix exosphere.lexicons.sync` (vendored corpus refresh) |
