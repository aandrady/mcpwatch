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

## `mcpwatch.collect` — the collectors (WP2, WP3)

Both obey the same non-negotiable rules: an identifying User-Agent carrying a reachable contact
(`mcpwatch@iyre.com`, refused if blank), conservative self-imposed rate limits, backoff on
429/5xx, and failures recorded as observations rather than skipped. Crawl reliability is a
reported metric, so a silent gap is worse than a logged error.

### Layer 1 — registry (`mcpwatch.collect.registry`)

```bash
uv run python -m mcpwatch.collect.registry --mode incremental
```

One observation per server per run holding its complete latest-version record. `--mode full`
walks every page (~206 pages, ~350s); `--mode incremental` uses `updated_since` watermarked from
the last *complete* run (~1 page, ~1.5s). Only a full crawl can observe absence, so only a full
crawl records it.

Version-level history is not this collector's job — the registry keeps it retrospectively at
`/v0/servers/{name}/versions`, and WP5 backfills it.

**`version=latest` is an optimization, never a correctness dependency.** It cuts the walk from
~675 pages to ~206, but the registry silently ignores unknown query parameters, so if it were
ever dropped we would quietly start ingesting version rows as if they were servers. Every record
is re-checked against `isLatest` on our side and non-latest rows are counted into run stats.

**A truncated crawl (`--max-pages`) never anchors a watermark.** It finishes cleanly, so without
that exclusion it would anchor the next incremental run — which asks only for *changed* records,
permanently skipping every page the truncated crawl never reached.

### Layer 2 — live manifests (`mcpwatch.collect.manifest`)

```bash
uv run python -m mcpwatch.collect.manifest --concurrency 50
```

The irreplaceable one. Every server is probed **twice per run**, in two separate passes so the
observations are separated by the whole cycle rather than by milliseconds:

| Outcome | Recorded as |
|---|---|
| Both probes agree | `ok` |
| Both succeed, hashes differ | `nondeterministic` — manifest still stored, quarantined from statistics |
| Only one probe succeeded | `ok` + `error_class=determinism_unverified` |
| Both failed | the failure status, with the other probe's verdict in `error_detail` |

Safety is structural, not procedural: the MCP client implements no code path that can call a
tool, so `tools/call` cannot be issued even by mistake. No credentials are ever sent.
Observations commit as each server's second probe lands, so a cycle that dies halfway keeps what
it collected.

**Endpoints are not evenly spread across hosts, and that drives cycle time.** In the day-zero
census one gateway (`gateway.pipeworx.io`) accounted for 1,311 of 10,373 targets — 12.6% — and
the top six hosts for 1,797 between them. Serializing each host completely would make the whole
cycle's wall-time hostage to its busiest host, and turn a bad day there into a runaway: 1,311
probes timing out at 20s each is over seven hours for that host alone, per pass. So concurrency
is capped *twice* — globally (`--concurrency`, default 50) and per host
(`--per-host-concurrency`, default 4). A host never sees a fan-out proportional to how many
servers it publishes, and any host with a handful of servers is still effectively serialized.
`busiest_host_targets` is recorded per run as a health metric: if it climbs, the cycle is one bad
day away from running long, and a Layer-2 cycle that overruns eats the next one.

TLS failures land under `unreachable` because the WP1 status enum has no `tls_error` member,
with `error_class` preserving the distinction — the enum stays stable and precision lives where
it costs nothing.

## Operations

```bash
bash deploy/install-timers.sh
```

systemd **user** timers (sudo needs a password on the collection host; `Linger=yes` is enabled):
registry delta daily 03:00 UTC, registry full reconciliation Sunday 02:00 UTC, manifest probe
daily 03:30 UTC. `Persistent=true` so a run missed during downtime fires on next boot instead of
leaving a hole in the series.

```bash
systemctl --user list-timers 'mcpwatch-*'
```

```bash
journalctl --user -u mcpwatch-manifest.service -n 50
```

An **unfinished run** (`finished_at IS NULL`) is the signal that a cycle died. Collectors
deliberately never auto-close a crashed run, because that would make a broken collector look
healthy.

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
