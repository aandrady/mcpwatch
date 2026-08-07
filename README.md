# MCPWatch

Longitudinal observatory measuring how MCP server tool definitions mutate after publication.
See `BUILD-PLAN.md` for the decomposition and `PROMPTS.md` for per-package briefs.

## `mcpwatch.store` — the storage foundation (WP1)

Everything else in MCPWatch appends to this. It is stdlib-only (`sqlite3`, `hashlib`, `gzip`,
`json`) so the corpus never depends on a collector's HTTP stack.

```python
from mcpwatch.store import Corpus, Layer, ObservationStatus

with Corpus("~/mcpwatch-corpus") as corpus:
    with corpus.run("registry", "0.1.0") as run_id:
        corpus.upsert_server(
            server_key="ac.inference.sh/mcp",
            registry_name="ac.inference.sh/mcp",
            repo_url="https://github.com/example/mcp",
            primary_endpoint="https://api.inference.sh/mcp",
        )
        write = corpus.record_snapshot(
            run_id=run_id,
            server_key="ac.inference.sh/mcp",
            layer=Layer.REGISTRY,
            document=parsed_record,
            raw_bytes=response_body,  # always pass the wire bytes when you have them
        )
        # write.changed  -> candidate mutation
        # write.bytes_written == 0 -> nothing about this server changed today
```

Failures are recorded, never skipped:

```python
corpus.record_failure(
    run_id=run_id,
    server_key=key,
    layer=Layer.MANIFEST,
    status=ObservationStatus.TIMEOUT,
    error_class="ReadTimeout",
)
```

### On-disk layout

```
<root>/
  blobs/<aa>/<bb>/<full-sha256>.json.gz    content-addressed, gzipped, dedup by content
  index.db                                  SQLite (WAL), plus -wal / -shm
```

Production root is `~/mcpwatch-corpus` on the VPS — deliberately outside the deploy work tree
so no `git clean` or `checkout -f` can reach it.

### The four properties that matter

**1. An unchanged snapshot costs zero bytes.** Blobs are addressed by the sha256 of their
content; re-storing content already present does not touch the file. Thirty days of an
unchanged server is one blob, not thirty.

**2. `observation` is append-only, by trigger.** `BEFORE UPDATE` and `BEFORE DELETE` triggers
`RAISE(ABORT, …)`. A longitudinal corpus whose history can be edited is not evidence of
anything, so this is a guarantee rather than a convention. `server_identity` is likewise
append-only. `run` and `server` are mutable by design — a run is closed out when it finishes,
and `server` is a projection of the append-only identity history.

**3. Normalization is versioned, and raw bytes are always kept.** Each observation stores
`raw_sha` (bytes exactly as received) *and* `norm_sha` (canonical bytes) plus the
`norm_version` they were hashed under. A future normalization change is replayed over the raw
blobs; nothing is ever destroyed to make a hash come out differently.

**4. Hash stability is defended against phantom mutations.** `mcpwatch.store.canonical` sorts
object keys recursively, sorts `tools`/`resources`/`resourceTemplates`/`prompts` and JSON
Schema `required` arrays, strips a volatile-field denylist (session ids, nonces, request ids,
server-emitted clock stamps), and applies NFC to all text. Without this, a server that
randomizes tool order or embeds a session id in a description registers a mutation every
single day and silently corrupts the headline base rate.

### Two normalization decisions worth knowing about

**The volatile-key denylist does not apply inside `properties`, `$defs`, `patternProperties`,
or other name-spaces.** A tool parameter legitimately named `timestamp` or `sessionId` must
survive; stripping it would silently delete real schema content. Subtrees under `default`,
`const`, `enum`, and `examples` are treated as opaque author data for the same reason — object
keys inside are still sorted, which is always safe, but nothing is stripped or reordered.

**The registry's own `publishedAt` / `updatedAt` are deliberately *not* stripped.** They move
only when a server is republished, which is exactly the Layer-1 signal being measured. A
collector that wants them gone should declare them in `volatile_paths` under a new
`norm_version` rather than widen the global key denylist.

Any behavioural change to `DEFAULT_POLICY` **must** bump `NORM_VERSION`. Changing normalization
under a fixed version number invents mutations that never happened.

### Reordering costs one raw blob

A server that shuffles its tool order daily produces a stable `norm_sha` (no phantom mutation)
but a new *raw* blob each day, since the wire bytes genuinely differ. That is the price of
retroactive replayability and it is worth paying — a few KB per affected server per day.

## Development

```bash
uv sync
```

```bash
uv run pytest
```

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

Authoring happens on Windows; execution is on Linux. `.gitattributes` forces `eol=lf`.
