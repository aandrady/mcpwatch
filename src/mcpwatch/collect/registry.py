"""Layer-1 collector: the official MCP registry.

Appends one observation per server per run, holding that server's complete
latest-version record. Version-level history is not this collector's job — the
registry keeps it retrospectively at ``/v0/servers/{name}/versions`` and WP5
backfills it.

Two modes:

* **full** — walk every page. The bootstrap, and the weekly reconciliation that
  catches anything the incremental path drifted past. Only a full crawl can
  observe *absence*, so only a full crawl records it.
* **incremental** — ``updated_since`` watermarked from the last successful run.
  The daily path, and cheap: a few pages instead of a couple of hundred.

Verified API behaviour this collector depends on (re-probed 2026-08-07, see
``census-baseline.md``)::

    GET /v0/servers?limit=100&version=latest&cursor=<c>
      -> {"servers": [{"server": {...}, "_meta": {...}}],
          "metadata": {"nextCursor": "<name>:<version>", "count": N}}

``version=latest`` is honoured and cuts the walk from ~675 pages to ~205. It is
treated strictly as an optimization: the registry silently ignores unknown query
parameters, so if it were ever dropped we would quietly start receiving all
67k version rows instead of 20k servers. Every record is therefore re-checked
against ``isLatest`` on our side, and anything non-latest is counted into run
stats rather than silently discarded.
"""

import argparse
import datetime as dt
import json
import os
import sys
import time
from collections.abc import Iterator, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path

from mcpwatch.store import (
    Corpus,
    JsonValue,
    Layer,
    ObservationStatus,
    from_iso,
    to_iso,
    utcnow,
)

from .errors import CollectorError, ResumeError
from .http import DEFAULT_CONTACT, PoliteClient

__all__ = [
    "COLLECTOR",
    "COLLECTOR_VERSION",
    "REGISTRY_BASE",
    "CrawlStats",
    "RegistryCollector",
    "main",
]

COLLECTOR = "registry"
COLLECTOR_VERSION = "0.1.0"
REGISTRY_BASE = "https://registry.modelcontextprotocol.io"
REGISTRY_META_KEY = "io.modelcontextprotocol.registry/official"

PAGE_SIZE = 100
WATERMARK_OVERLAP_SECONDS = 3600.0
"""Re-fetch an hour either side of the watermark, to absorb clock skew."""

_REMOTE_TYPE_PREFERENCE = ("streamable-http", "sse")


@dataclass
class CrawlStats:
    """Per-run counters, serialized into ``run.stats_json``.

    Errors are counted, not raised past the page they occurred on: a single
    malformed record must not abort a 200-page crawl, but it must also not
    vanish.
    """

    mode: str = "full"
    pages: int = 0
    rows: int = 0
    servers_seen: int = 0
    servers_new: int = 0
    changed: int = 0
    unchanged: int = 0
    absent: int = 0
    non_latest_skipped: int = 0
    malformed: int = 0
    blobs_written: int = 0
    bytes_written: int = 0
    requests: int = 0
    retries: int = 0
    rate_limit_hits: int = 0
    wall_seconds: float = 0.0
    watermark: str | None = None
    truncated: bool = False
    registry_status_counts: dict[str, int] = field(default_factory=dict)
    schema_versions: dict[str, int] = field(default_factory=dict)
    errors_by_class: dict[str, int] = field(default_factory=dict)

    def as_json(self) -> dict[str, JsonValue]:
        """Render as a plain JSON-safe mapping."""
        return dict(asdict(self).items())


def _text_or_none(value: JsonValue) -> str | None:
    """Coerce a JSON value to a non-empty string, or None."""
    return value.strip() or None if isinstance(value, str) else None


def repo_url_of(server: Mapping[str, JsonValue]) -> str | None:
    """Extract the repository URL from a registry server record.

    Accepts both the observed ``{"url": ..., "source": ...}`` object and a bare
    string, since the field is optional and the schema has moved before.
    """
    repository = server.get("repository")
    if isinstance(repository, str):
        return _text_or_none(repository)
    if isinstance(repository, dict):
        return _text_or_none(repository.get("url"))
    return None


def primary_endpoint_of(server: Mapping[str, JsonValue]) -> str | None:
    """Pick the endpoint WP3 should probe, preferring streamable-http over sse.

    A server may declare several remotes. The choice is recorded as secondary
    identity, so it needs to be deterministic rather than merely reasonable —
    picking a different one each run would look like an endpoint swap.
    """
    remotes = server.get("remotes")
    if not isinstance(remotes, list):
        return None
    candidates: list[tuple[int, int, str]] = []
    for position, remote in enumerate(remotes):
        if not isinstance(remote, dict):
            continue
        url = _text_or_none(remote.get("url"))
        if url is None:
            continue
        remote_type = remote.get("type")
        rank = (
            _REMOTE_TYPE_PREFERENCE.index(remote_type)
            if isinstance(remote_type, str) and remote_type in _REMOTE_TYPE_PREFERENCE
            else len(_REMOTE_TYPE_PREFERENCE)
        )
        candidates.append((rank, position, url))
    if not candidates:
        return None
    return min(candidates)[2]


def registry_meta_of(entry: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    """Return the registry's own ``_meta`` block for an entry, or an empty dict."""
    meta = entry.get("_meta")
    if isinstance(meta, dict):
        official = meta.get(REGISTRY_META_KEY)
        if isinstance(official, dict):
            return official
    return {}


@dataclass(frozen=True, slots=True)
class _Checkpoint:
    """Mid-crawl cursor state, so a 200-page walk never restarts from scratch."""

    run_id: str
    cursor: str | None
    pages: int
    mode: str

    def to_json(self) -> dict[str, JsonValue]:
        """Render for the checkpoint file."""
        return {
            "run_id": self.run_id,
            "cursor": self.cursor,
            "pages": self.pages,
            "mode": self.mode,
        }


class RegistryCollector:
    """Crawls the MCP registry and appends Layer-1 observations."""

    def __init__(
        self,
        corpus: Corpus,
        client: PoliteClient,
        *,
        base_url: str = REGISTRY_BASE,
        page_size: int = PAGE_SIZE,
        state_dir: Path | None = None,
    ) -> None:
        """Bind a collector to a corpus and an HTTP client.

        Args:
            corpus: Destination corpus.
            client: A configured :class:`~mcpwatch.collect.http.PoliteClient`.
            base_url: Registry root.
            page_size: Rows per page; the registry caps this at 100.
            state_dir: Where the resume checkpoint lives. Defaults to
                ``<corpus root>/state``.
        """
        self.corpus = corpus
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.page_size = page_size
        self.state_dir = state_dir or (corpus.root / "state")
        self.state_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------- watermark ---

    @property
    def _checkpoint_path(self) -> Path:
        return self.state_dir / "registry-crawl.json"

    def last_successful_run_start(self) -> str | None:
        """Return the ``started_at`` of the most recent complete registry run.

        A *truncated* run does not count, even though it finished cleanly. Using
        one as the watermark anchor would be silently destructive: the next
        incremental run asks only for records changed since the watermark, so
        every server the truncated crawl never reached would be skipped forever
        unless it happened to change on its own.
        """
        row = self.corpus.index.connection.execute(
            """
            SELECT max(started_at) AS started FROM run
            WHERE collector = ?
              AND finished_at IS NOT NULL
              AND coalesce(json_extract(stats_json, '$.truncated'), 0) = 0
            """,
            (COLLECTOR,),
        ).fetchone()
        return None if row is None else row["started"]

    def watermark(self) -> str:
        """Compute the ``updated_since`` value for an incremental run.

        Anchored on the last successful run's *start*, not its finish, and
        rolled back by an overlap window. A record updated while the previous
        run was mid-walk could have been missed, and re-fetching an unchanged
        record is free thanks to blob deduplication — whereas missing one is a
        hole in the time series.

        Raises:
            CollectorError: If no registry run has ever completed. Bootstrapping
                with a fabricated watermark would silently skip the entire
                existing population.
        """
        started = self.last_successful_run_start()
        if started is None:
            msg = (
                "no completed registry run to watermark from; run a full crawl first (--mode full)"
            )
            raise CollectorError(msg)
        anchor = from_iso(started).timestamp() - WATERMARK_OVERLAP_SECONDS
        return to_iso(dt.datetime.fromtimestamp(anchor, tz=dt.UTC))

    # ----------------------------------------------------------- checkpoints ---

    def _read_checkpoint(self) -> _Checkpoint | None:
        """Load the resume checkpoint, if one is present and still valid."""
        path = self._checkpoint_path
        if not path.is_file():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            msg = f"unreadable crawl checkpoint at {path}: {exc}"
            raise ResumeError(msg) from exc
        run_id = payload.get("run_id")
        run = self.corpus.get_run(run_id) if isinstance(run_id, str) else None
        if run is None or run.finished_at is not None:
            # Stale: the run it names either never existed here or already
            # completed. Drop it rather than resuming into a finished run.
            path.unlink(missing_ok=True)
            return None
        return _Checkpoint(
            run_id=run_id,
            cursor=payload.get("cursor"),
            pages=int(payload.get("pages", 0)),
            mode=str(payload.get("mode", "full")),
        )

    def _write_checkpoint(self, checkpoint: _Checkpoint) -> None:
        """Persist the resume checkpoint atomically."""
        path = self._checkpoint_path
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(checkpoint.to_json()), encoding="utf-8")
        os.replace(tmp, path)  # noqa: PTH105 - Path has no atomic-replace method

    def _clear_checkpoint(self) -> None:
        """Remove the checkpoint once a crawl has completed."""
        self._checkpoint_path.unlink(missing_ok=True)

    # ---------------------------------------------------------------- crawl ---

    def _pages(
        self,
        *,
        updated_since: str | None,
        cursor: str | None,
        max_pages: int | None,
    ) -> Iterator[tuple[list[JsonValue], str | None]]:
        """Yield ``(rows, next_cursor)`` for each page, following the cursor."""
        pages_read = 0
        while True:
            params: dict[str, str | int] = {"limit": self.page_size, "version": "latest"}
            if cursor:
                params["cursor"] = cursor
            if updated_since:
                params["updated_since"] = updated_since

            payload = self.client.get(f"{self.base_url}/v0/servers", params).json()
            rows = payload.get("servers") if isinstance(payload, dict) else None
            if not isinstance(rows, list):
                msg = f"registry returned no 'servers' array: {str(payload)[:200]}"
                raise CollectorError(msg)
            metadata = payload.get("metadata") if isinstance(payload, dict) else {}
            next_cursor = metadata.get("nextCursor") if isinstance(metadata, dict) else None
            next_cursor = next_cursor if isinstance(next_cursor, str) and next_cursor else None

            yield rows, next_cursor
            pages_read += 1

            if next_cursor is None:
                return
            if max_pages is not None and pages_read >= max_pages:
                return
            cursor = next_cursor

    def crawl(
        self,
        *,
        mode: str = "incremental",
        max_pages: int | None = None,
        resume: bool = True,
    ) -> CrawlStats:
        """Run one crawl and return its statistics.

        Args:
            mode: ``"full"`` or ``"incremental"``.
            max_pages: Stop after this many pages. For smoke tests only — a
                truncated crawl is marked ``truncated`` in stats and never
                records absence, because it has not seen the whole population.
            resume: Continue an interrupted full crawl from its checkpoint.

        Returns:
            The run's :class:`CrawlStats`.

        Raises:
            CollectorError: On an unrecoverable protocol or configuration error.
            RateLimitStop: If the registry's 429 budget for this run runs out.
        """
        if mode not in {"full", "incremental"}:
            msg = f"unknown crawl mode {mode!r}"
            raise CollectorError(msg)

        started = time.monotonic()
        stats = CrawlStats(mode=mode)
        updated_since = self.watermark() if mode == "incremental" else None
        stats.watermark = updated_since

        checkpoint = self._read_checkpoint() if (resume and mode == "full") else None
        if checkpoint is not None and checkpoint.mode == mode:
            run_id = checkpoint.run_id
            cursor = checkpoint.cursor
            stats.pages = checkpoint.pages
        else:
            run_id = self.corpus.start_run(COLLECTOR, COLLECTOR_VERSION)
            cursor = None

        try:
            for rows, next_cursor in self._pages(
                updated_since=updated_since, cursor=cursor, max_pages=max_pages
            ):
                stats.pages += 1
                for row in rows:
                    self._ingest(row, run_id=run_id, stats=stats)
                self._write_checkpoint(
                    _Checkpoint(run_id=run_id, cursor=next_cursor, pages=stats.pages, mode=mode)
                )
                stats.truncated = next_cursor is not None
        except BaseException:
            # Leave the run open and the checkpoint in place. An unfinished run
            # is WP4's signal that a cycle died, and the checkpoint is what makes
            # the retry cheap instead of a full restart.
            self._record_client_stats(stats, started)
            raise

        if mode == "full" and not stats.truncated:
            stats.absent = self._record_absences(run_id)

        self._record_client_stats(stats, started)
        self.corpus.finish_run(run_id, stats=stats.as_json())
        self._clear_checkpoint()
        return stats

    def _record_client_stats(self, stats: CrawlStats, started: float) -> None:
        """Fold HTTP counters and wall-time into the run stats."""
        stats.requests = self.client.request_count
        stats.retries = self.client.retry_count
        stats.rate_limit_hits = self.client.rate_limit_hits
        stats.wall_seconds = round(time.monotonic() - started, 3)

    def _ingest(self, row: JsonValue, *, run_id: str, stats: CrawlStats) -> None:
        """Record one registry row as a Layer-1 observation."""
        stats.rows += 1
        if not isinstance(row, dict):
            stats.malformed += 1
            self._count_error(stats, "row_not_object")
            return

        server = row.get("server")
        if not isinstance(server, dict):
            stats.malformed += 1
            self._count_error(stats, "missing_server_object")
            return

        name = _text_or_none(server.get("name"))
        if name is None:
            stats.malformed += 1
            self._count_error(stats, "missing_name")
            return

        meta = registry_meta_of(row)
        if meta.get("isLatest") is False:
            # `version=latest` was ignored, or updated_since surfaced a
            # withdrawn older version. Either way this row is not the server's
            # current state, so it is not what we snapshot.
            stats.non_latest_skipped += 1
            return

        status_value = meta.get("status")
        if isinstance(status_value, str):
            stats.registry_status_counts[status_value] = (
                stats.registry_status_counts.get(status_value, 0) + 1
            )
        schema = server.get("$schema")
        if isinstance(schema, str):
            # A registry-wide $schema bump would flip every server's hash on the
            # same day. Counting it here makes that visible in run health
            # instead of surfacing months later as an unexplained mutation spike.
            stats.schema_versions[schema] = stats.schema_versions.get(schema, 0) + 1

        existing = self.corpus.get_server(name)
        self.corpus.upsert_server(
            server_key=name,
            registry_name=name,
            repo_url=repo_url_of(server),
            primary_endpoint=primary_endpoint_of(server),
        )
        if existing is None:
            stats.servers_new += 1

        # No raw_bytes: the wire unit is the page, not the record, so the corpus
        # re-serializes the parsed entry. json.loads preserves key order, so the
        # round trip differs from the wire only in whitespace and escaping.
        write = self.corpus.record_snapshot(
            run_id=run_id, server_key=name, layer=Layer.REGISTRY, document=row
        )
        stats.servers_seen += 1
        stats.blobs_written += int(write.raw.created) + int(write.normalized.created)
        stats.bytes_written += write.bytes_written
        if write.changed:
            stats.changed += 1
        else:
            stats.unchanged += 1

    def _record_absences(self, run_id: str) -> int:
        """Append an explicit absent observation for every server not seen.

        A server that silently stops appearing is indistinguishable from a
        collector bug. Recording absence makes disappearance a datum that WP6
        can reason about.

        The set of servers seen this run is read back from the observation
        table rather than tracked in memory, so a crawl that was interrupted and
        resumed still computes it correctly.
        """
        rows = self.corpus.index.connection.execute(
            """
            SELECT server_key FROM server
            WHERE server_key NOT IN (
                SELECT server_key FROM observation
                WHERE run_id = ? AND layer = 'registry'
            )
            """,
            (run_id,),
        ).fetchall()
        for row in rows:
            self.corpus.record_failure(
                run_id=run_id,
                server_key=row["server_key"],
                layer=Layer.REGISTRY,
                status=ObservationStatus.SKIPPED,
                error_class="absent",
                error_detail="not returned by a complete full crawl",
            )
        return len(rows)

    @staticmethod
    def _count_error(stats: CrawlStats, error_class: str) -> None:
        stats.errors_by_class[error_class] = stats.errors_by_class.get(error_class, 0) + 1


def _default_corpus_root() -> Path:
    """Corpus location: env override, else the documented production path."""
    override = os.environ.get("MCPWATCH_CORPUS")
    return Path(override) if override else Path.home() / "mcpwatch-corpus"


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns 0 clean, 1 failed, 2 completed with errors.

    WP4 replaces this with a unified ``mcpwatch run`` entry point; until then
    this is what the systemd timer would call.
    """
    parser = argparse.ArgumentParser(
        prog="python -m mcpwatch.collect.registry",
        description="Crawl the MCP registry and append Layer-1 observations.",
    )
    parser.add_argument("--corpus", type=Path, default=_default_corpus_root())
    parser.add_argument("--mode", choices=("full", "incremental"), default="incremental")
    parser.add_argument(
        "--max-pages", type=int, default=None, help="stop early; for smoke tests only"
    )
    parser.add_argument(
        "--contact",
        default=os.environ.get("MCPWATCH_CONTACT", DEFAULT_CONTACT),
        help="contact address advertised in the User-Agent",
    )
    parser.add_argument("--base-url", default=REGISTRY_BASE)
    parser.add_argument("--page-size", type=int, default=PAGE_SIZE)
    parser.add_argument("--no-resume", action="store_true", help="ignore any crawl checkpoint")
    args = parser.parse_args(argv)

    client = PoliteClient(contact=args.contact, version=COLLECTOR_VERSION)
    with Corpus(args.corpus) as corpus:
        collector = RegistryCollector(
            corpus, client, base_url=args.base_url, page_size=args.page_size
        )
        try:
            stats = collector.crawl(
                mode=args.mode, max_pages=args.max_pages, resume=not args.no_resume
            )
        except CollectorError as exc:
            print(f"{utcnow().isoformat()} registry crawl FAILED: {exc}", file=sys.stderr)
            return 1

    print(json.dumps(stats.as_json(), indent=2, sort_keys=True))
    return 2 if (stats.errors_by_class or stats.malformed) else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
