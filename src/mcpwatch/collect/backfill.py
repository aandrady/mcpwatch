"""Retrospective backfill: Layer-1 history from the registry's own version record.

WP2 collects the present, one snapshot per server per day, and the corpus grows
a day at a time. This module collects the *past* in a single afternoon: the
registry retains every version ever published, each with its own ``publishedAt``,
so roughly 47,000 real mutation transitions already exist and are simply sitting
there waiting to be read. That is a corpus of historical mutations available
immediately rather than after a year of watching, and it is what WP6 and WP7 get
calibrated against instead of synthetic fixtures.

Layer 2 has no equivalent and never will. Live tool manifests are not retained by
anyone, which is why a missed day there is permanent while this can be run
whenever we like.

**Two phases, because the two endpoints know different things.**

*Walk* — ``GET /v0/servers`` with no ``version`` filter returns every version row
of every server, ~675 pages for the whole population. Same envelope as WP2's
crawl, ~100 rows per request instead of one server per request. Passing
``include_deleted=true`` is the only way to see withdrawn servers at all, and a
server that was published and then withdrawn is signal, not noise.

*Verify* — ``GET /v0/servers/{name}/versions`` returns one server's complete
chain in a single response, authoritatively. The walk is a cursor over a dataset
that mutates underneath it, so a server republishing mid-walk can shift rows past
the cursor; this phase re-reads every multi-version server and fills whatever the
walk missed. It costs ~8,300 requests and it is what makes "complete, gap-free
chains" a checked property rather than a hope.

The order matters: the walk is what identifies which servers are multi-version in
the first place. Verifying all 20,453 would spend 12,159 requests on servers with
a single version and nothing to say.

**Timestamps.** Every observation this module writes carries ``published_at``
from the registry and an ``observed_at`` of now. It never backdates
``observed_at``: we did not observe anything in 2024, we read a record about 2024
today, and the corpus says exactly that. ``effective_at`` — the derived column
the whole store orders by — resolves to the publication date, so the history
lands in the right order regardless.

**Idempotency** keys on content *and* publication date together, and the "and"
was learned the hard way. Keying on content alone looks right — a registry record
embeds its own version string, so identical canonical bytes mean the same
version — but the daily crawl stores that same version *undated*, so a
content-only check let every server's current version suppress the backfill row
that would have carried its publication date. A production run lost exactly the
most recent transition of every server before the numbers gave it away: 12,341
servers reporting zero dated versions when they each have one.

The two rows are not duplicates. One says "this is how the server looked when we
crawled it"; the other says "this version was published on this date". Only the
second can order history, and it costs no bytes, because the blob store already
holds the content.
"""

import argparse
import datetime as dt
import json
import os
import sys
import time
import urllib.parse
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path

from mcpwatch.store import (
    Corpus,
    JsonValue,
    Layer,
    ObservationStatus,
    from_iso,
    norm_sha256,
    to_iso,
    utcnow,
)

from .errors import CollectorError, HttpStatusError, ResumeError
from .http import DEFAULT_CONTACT, PoliteClient, PolitenessPolicy
from .locks import exclusive_cycle
from .registry import (
    REGISTRY_BASE,
    primary_endpoint_of,
    registry_meta_of,
    repo_url_of,
)

__all__ = [
    "COLLECTOR",
    "COLLECTOR_VERSION",
    "WITHDRAWN_CLASS",
    "BackfillCollector",
    "BackfillStats",
    "VersionRow",
    "main",
]

COLLECTOR = "backfill"
COLLECTOR_VERSION = "0.1.0"

PAGE_SIZE = 100

WITHDRAWN_CLASS = "withdrawn"
"""``error_class`` marking the observation that records a server's withdrawal."""

_ACTIVE_STATUS = "active"

WITHDRAWN_STATUSES = frozenset({"deleted"})
"""Registry statuses that mean the server is gone, as opposed to merely tagged.

Only ``deleted``. The registry also publishes ``deprecated``, and verified
against production, a deprecated server is still returned by the default listing
and still served by ``/versions`` — it is listed, live, and probeable, just
flagged by its maintainer. Treating it as withdrawn would misreport it as gone
*and* remove it from WP3's target set, costing Layer-2 observations that cannot
be recovered later. Deprecation is a status change, and the report picks it up
from the documents themselves.

An unrecognized future status is therefore treated as still-listed. That is the
safe direction: WP2's full crawl records absence authoritatively, so a server
that really has vanished is caught within a cycle, whereas a probe target
wrongly dropped is a permanent hole.
"""


def _text_or_none(value: JsonValue) -> str | None:
    """Coerce a JSON value to a non-empty string, or None."""
    return value.strip() or None if isinstance(value, str) else None


def _time_or_none(value: JsonValue) -> dt.datetime | None:
    """Parse a registry timestamp, or return None if it is absent or malformed.

    The registry emits ``2026-07-27T10:44:51.359634Z``. A row whose timestamp
    cannot be parsed is still worth storing — it just cannot be placed in
    history, so it is counted rather than dropped.
    """
    text = _text_or_none(value)
    if text is None:
        return None
    try:
        return from_iso(text)
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class VersionRow:
    """One published version of one server, as the registry reports it.

    Attributes:
        entry: The full ``{"server": ..., "_meta": ...}`` record, stored verbatim.
        server_key: The registry name, which is the corpus's primary identity.
        version: The version string the publisher chose. Free-form: it is a label
            here, never something to order by. Chronology comes from
            ``published_at``, because "2.0.0" and "10.0.0" sort the wrong way
            round and nothing stops a publisher from going backwards.
        published_at: When the registry says this version was published.
        status_changed_at: When the registry last changed this record's status —
            the withdrawal date, for a withdrawn server.
        status: Registry status: ``active``, ``deleted``, ``deprecated``, ...
        is_latest: Whether the registry considers this the server's current
            version.
    """

    entry: dict[str, JsonValue]
    server_key: str
    version: str | None
    published_at: dt.datetime | None
    status_changed_at: dt.datetime | None
    status: str | None
    is_latest: bool

    @property
    def active(self) -> bool:
        """Whether the registry reports this record as plain ``active``."""
        return self.status is None or self.status == _ACTIVE_STATUS

    @property
    def withdrawn_at(self) -> dt.datetime | None:
        """When this server left the registry, if it did.

        Withdrawal, not deprecation — see :data:`WITHDRAWN_STATUSES`.
        """
        if self.status not in WITHDRAWN_STATUSES:
            return None
        return self.status_changed_at or self.published_at


def parse_row(entry: JsonValue) -> VersionRow | None:
    """Read one registry entry into a :class:`VersionRow`, or None if malformed."""
    if not isinstance(entry, dict):
        return None
    server = entry.get("server")
    if not isinstance(server, dict):
        return None
    name = _text_or_none(server.get("name"))
    if name is None:
        return None
    meta = registry_meta_of(entry)
    return VersionRow(
        entry=entry,
        server_key=name,
        version=_text_or_none(server.get("version")),
        published_at=_time_or_none(meta.get("publishedAt")),
        status_changed_at=_time_or_none(meta.get("statusChangedAt")),
        status=_text_or_none(meta.get("status")),
        is_latest=meta.get("isLatest") is True,
    )


@dataclass
class BackfillStats:
    """Per-run counters, serialized into ``run.stats_json``.

    Accumulated across resumes: the counters live in the checkpoint, so a job
    that was interrupted at server 18,000 still reports what the whole run did
    rather than only its final leg.
    """

    phases: str = "walk,verify"
    resumed: bool = False
    pages: int = 0
    rows: int = 0
    servers_seen: int = 0
    servers_new: int = 0
    versions_stored: int = 0
    versions_skipped: int = 0
    versions_restated: int = 0
    withdrawals_recorded: int = 0
    non_active_rows: int = 0
    malformed: int = 0
    missing_published_at: int = 0
    verify_targets: int = 0
    servers_verified: int = 0
    versions_recovered: int = 0
    chains_repaired: int = 0
    versions_absent_upstream: int = 0
    verify_not_found: int = 0
    verify_failed: int = 0
    blobs_written: int = 0
    bytes_written: int = 0
    requests: int = 0
    retries: int = 0
    rate_limit_hits: int = 0
    wall_seconds: float = 0.0
    truncated: bool = False
    registry_status_counts: dict[str, int] = field(default_factory=dict)
    errors_by_class: dict[str, int] = field(default_factory=dict)

    def as_json(self) -> dict[str, JsonValue]:
        """Render as a plain JSON-safe mapping."""
        return dict(asdict(self).items())

    @classmethod
    def from_json(cls, payload: Mapping[str, JsonValue]) -> BackfillStats:
        """Rebuild from a checkpointed mapping, ignoring unknown keys."""
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in payload.items() if k in known})  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class _Totals:
    """Counters carried in from earlier legs of a resumed run."""

    seconds: float
    requests: int
    retries: int
    rate_limit_hits: int


@dataclass(frozen=True, slots=True)
class _Checkpoint:
    """Resume state. Fine-grained enough that no leg is ever redone twice.

    ``cursor`` resumes the page walk; ``last_server`` resumes the verify sweep
    after the last server it finished. Both phases are also idempotent, so a
    checkpoint that is slightly behind costs a little duplicated reading and
    never duplicated data.
    """

    run_id: str
    phase: str
    cursor: str | None
    last_server: str | None
    stats: dict[str, JsonValue]

    def to_json(self) -> dict[str, JsonValue]:
        """Render for the checkpoint file."""
        return {
            "run_id": self.run_id,
            "phase": self.phase,
            "cursor": self.cursor,
            "last_server": self.last_server,
            "stats": self.stats,
        }


class BackfillCollector:
    """Reads the registry's version history into the corpus as Layer-1 history."""

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

    # ----------------------------------------------------------- checkpoints ---

    @property
    def _checkpoint_path(self) -> Path:
        return self.state_dir / "backfill.json"

    def _read_checkpoint(self) -> _Checkpoint | None:
        """Load the resume checkpoint, if one is present and still valid."""
        path = self._checkpoint_path
        if not path.is_file():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            msg = f"unreadable backfill checkpoint at {path}: {exc}"
            raise ResumeError(msg) from exc
        run_id = payload.get("run_id")
        run = self.corpus.get_run(run_id) if isinstance(run_id, str) else None
        if run is None or run.finished_at is not None:
            # Stale: the run it names either never existed here or already
            # completed. Drop it rather than resuming into a finished run.
            path.unlink(missing_ok=True)
            return None
        stats = payload.get("stats")
        return _Checkpoint(
            run_id=run_id,
            phase=str(payload.get("phase", "walk")),
            cursor=payload.get("cursor"),
            last_server=payload.get("last_server"),
            stats=stats if isinstance(stats, dict) else {},
        )

    def _write_checkpoint(self, checkpoint: _Checkpoint) -> None:
        """Persist the resume checkpoint atomically."""
        path = self._checkpoint_path
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(checkpoint.to_json()), encoding="utf-8")
        os.replace(tmp, path)  # noqa: PTH105 - Path has no atomic-replace method

    def _clear_checkpoint(self) -> None:
        """Remove the checkpoint once the backfill has completed."""
        self._checkpoint_path.unlink(missing_ok=True)

    # ------------------------------------------------------------------ run ---

    def run(
        self,
        *,
        phases: Sequence[str] = ("walk", "verify"),
        max_pages: int | None = None,
        verify_scope: str = "multi",
        verify_limit: int | None = None,
        resume: bool = True,
    ) -> BackfillStats:
        """Run the backfill and return its statistics.

        Args:
            phases: Which phases to run, in order. ``("walk",)`` collects the
                bulk cheaply; ``("verify",)`` alone re-checks chains without
                re-walking.
            max_pages: Stop the walk after this many pages. Smoke tests only — a
                truncated walk leaves the population half-read, so its version
                counts must not be trusted to select verify targets.
            verify_scope: ``"multi"`` verifies servers whose known version count
                is anything other than exactly one — the multi-version
                population plus anything the walk appears to have missed.
                ``"all"`` verifies every known server, at 20,453 requests.
            verify_limit: Verify at most this many servers.
            resume: Continue an interrupted backfill from its checkpoint.

        Returns:
            The run's :class:`BackfillStats`.

        Raises:
            CollectorError: On an unrecoverable protocol or configuration error.
            RateLimitStop: If the registry's 429 budget for this run runs out.
        """
        unknown = set(phases) - {"walk", "verify"}
        if unknown:
            msg = f"unknown backfill phase(s): {', '.join(sorted(unknown))}"
            raise CollectorError(msg)

        started = time.monotonic()
        checkpoint = self._read_checkpoint() if resume else None
        if checkpoint is not None and checkpoint.phase not in phases:
            # Consuming this checkpoint would close its run and discard the
            # resume point of a phase we are not going to run — turning an
            # interrupted walk into one that has to start over from page one.
            msg = (
                f"an interrupted backfill is checkpointed in phase {checkpoint.phase!r}, "
                f"which is not among the requested phases ({', '.join(phases)}); "
                "finish it first, or pass --no-resume to abandon it"
            )
            raise CollectorError(msg)
        if checkpoint is not None:
            run_id = checkpoint.run_id
            stats = BackfillStats.from_json(checkpoint.stats)
            stats.resumed = True
            cursor = checkpoint.cursor
            last_server = checkpoint.last_server
            done = {"walk"} if checkpoint.phase == "verify" else set[str]()
        else:
            run_id = self.corpus.start_run(COLLECTOR, COLLECTOR_VERSION)
            stats = BackfillStats()
            cursor = last_server = None
            done = set[str]()
        stats.phases = ",".join(phases)
        # Counters carried over from earlier legs. The HTTP client's own totals
        # start at zero in a new process, so a resumed run must add to what the
        # checkpoint remembers rather than overwrite it.
        base = _Totals(
            seconds=stats.wall_seconds,
            requests=stats.requests,
            retries=stats.retries,
            rate_limit_hits=stats.rate_limit_hits,
        )

        try:
            if "walk" in phases and "walk" not in done:
                self._walk(
                    run_id=run_id,
                    stats=stats,
                    cursor=cursor,
                    max_pages=max_pages,
                    started=started,
                    base=base,
                )
            if "verify" in phases and "verify" not in done:
                self._verify(
                    run_id=run_id,
                    stats=stats,
                    after=last_server,
                    scope=verify_scope,
                    limit=verify_limit,
                    started=started,
                    base=base,
                )
        except BaseException:
            # Leave the run open and the checkpoint in place. An unfinished run
            # is WP4's signal that a job died, and the checkpoint is what makes
            # the retry cheap instead of a full restart.
            self._record_client_stats(stats, started, base)
            raise

        self._record_client_stats(stats, started, base)
        self.corpus.finish_run(run_id, stats=stats.as_json())
        self._clear_checkpoint()
        return stats

    def _record_client_stats(self, stats: BackfillStats, started: float, base: _Totals) -> None:
        """Fold HTTP counters and wall-time into the run stats."""
        stats.requests = base.requests + self.client.request_count
        stats.retries = base.retries + self.client.retry_count
        stats.rate_limit_hits = base.rate_limit_hits + self.client.rate_limit_hits
        stats.wall_seconds = round(base.seconds + time.monotonic() - started, 3)

    # ------------------------------------------------------------ phase one ---

    def _pages(
        self, *, cursor: str | None, max_pages: int | None
    ) -> Iterator[tuple[list[JsonValue], str | None]]:
        """Yield ``(rows, next_cursor)`` for each page of the version-row walk.

        Deliberately without ``version=latest``: that parameter is what turns
        this endpoint into WP2's 20,453-server crawl, and what we want here is
        the 67,425-row one underneath it.
        """
        pages_read = 0
        while True:
            params: dict[str, str | int] = {
                "limit": self.page_size,
                # Withdrawn servers are the population this is most interesting
                # about, and they are invisible without this.
                "include_deleted": "true",
            }
            if cursor:
                params["cursor"] = cursor

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

    def _walk(
        self,
        *,
        run_id: str,
        stats: BackfillStats,
        cursor: str | None,
        max_pages: int | None,
        started: float,
        base: _Totals,
    ) -> None:
        """Walk every version row of every server and store what is new.

        Rows arrive grouped by server (the cursor is ``name:version``), so they
        are buffered per server and committed a whole server at a time. That
        gives each group a chronological sort before it is written, which is
        what lets identity history record when a repo or endpoint *first*
        appeared rather than whichever version happened to be read first.
        """
        pending: list[VersionRow] = []
        # A server's rows can straddle a page boundary, so the same key can be
        # flushed twice in a row. Remembering the last one keeps the server count
        # honest without holding a group across a checkpoint.
        last_flushed: str | None = None

        def flush() -> None:
            nonlocal pending, last_flushed
            if not pending:
                return
            key = pending[0].server_key
            self._ingest_group(pending, run_id=run_id, stats=stats)
            if key != last_flushed:
                stats.servers_seen += 1
            last_flushed = key
            pending = []

        for rows, next_cursor in self._pages(cursor=cursor, max_pages=max_pages):
            stats.pages += 1
            for raw in rows:
                stats.rows += 1
                row = parse_row(raw)
                if row is None:
                    stats.malformed += 1
                    _count(stats.errors_by_class, "malformed_row")
                    continue
                if pending and row.server_key != pending[0].server_key:
                    flush()
                pending.append(row)

            # Flush the partial group before checkpointing rather than carrying
            # it across the boundary. Re-reading a server after a resume is free
            # — the content check recognizes every row it already stored — while
            # a checkpoint that promises more than was written is not.
            flush()
            self._record_client_stats(stats, started, base)
            self._write_checkpoint(
                _Checkpoint(
                    run_id=run_id,
                    phase="walk" if next_cursor else "verify",
                    cursor=next_cursor,
                    last_server=None,
                    stats=stats.as_json(),
                )
            )
            stats.truncated = next_cursor is not None

    def _ingest_group(self, rows: list[VersionRow], *, run_id: str, stats: BackfillStats) -> int:
        """Store one server's versions, oldest first. Returns how many were new.

        Everything about the order here is deliberate: versions go in by
        publication date so the ``changed`` flag chains correctly and identity
        tuples are dated from their first appearance, and the server's *current*
        identity is refreshed only from the row the registry marks ``isLatest``
        — letting a 2024 version overwrite today's endpoint would manufacture
        exactly the endpoint-swap signal WP7 is looking for.
        """
        if not rows:
            return 0
        server_key = rows[0].server_key
        # Rows without a usable timestamp sort last: they cannot be placed in
        # history, so they must not displace rows that can.
        ordered = sorted(
            rows, key=lambda r: (r.published_at is None, r.published_at or dt.datetime.max)
        )
        latest = next((r for r in ordered if r.is_latest), ordered[-1])
        stored = 0

        # One transaction for the whole server rather than one per row. With
        # ~67,000 rows to write under `synchronous=FULL`, the difference is
        # ~21,000 fsyncs instead of well over 100,000.
        with self.corpus.index.transaction():
            known = self.corpus.get_server(server_key)
            if known is None:
                stats.servers_new += 1
                # Seed from the *oldest* row, not the newest. A server row has
                # to exist before observations can reference it, and seeding it
                # from the latest version would date that identity tuple to the
                # wrong end of history. The projection below then sets current
                # identity from the row that actually defines it.
                self._project_identity(ordered[0])

            already = self._known_versions(server_key)
            for row in ordered:
                if row.status is not None:
                    _count(stats.registry_status_counts, row.status)
                if not row.active:
                    stats.non_active_rows += 1
                if row.published_at is None:
                    stats.missing_published_at += 1
                    _count(stats.errors_by_class, "missing_published_at")
                if self._store_version(row, run_id=run_id, stats=stats, already=already):
                    stored += 1
                self.corpus.record_identity(
                    server_key=server_key,
                    registry_name=server_key,
                    repo_url=repo_url_of(_server_of(row)),
                    primary_endpoint=primary_endpoint_of(_server_of(row)),
                    observed_at=row.published_at or utcnow(),
                )

            if latest.is_latest:
                # Refresh the projection from the authoritative row. Skipped when
                # the group has no `isLatest` member, which happens only to a
                # group split across a page boundary — the other half carries the
                # real answer.
                self._project_identity(latest)
            self._record_withdrawal(latest, run_id=run_id, stats=stats)
        return stored

    def _project_identity(self, row: VersionRow) -> None:
        """Write a server's current identity from the version that defines it."""
        self.corpus.upsert_server(
            server_key=row.server_key,
            registry_name=row.server_key,
            repo_url=repo_url_of(_server_of(row)),
            primary_endpoint=primary_endpoint_of(_server_of(row)),
            seen_at=row.published_at or utcnow(),
        )

    def _store_version(
        self, row: VersionRow, *, run_id: str, stats: BackfillStats, already: set[str]
    ) -> bool:
        """Append one version as an observation unless it is already stored.

        Args:
            row: The version to store.
            run_id: The run to attribute it to.
            stats: Counters to update.
            already: Publication timestamps already held for this server, used
                only to tell a version we have never seen from one whose record
                has been *edited in place* since we stored it. The latter is a
                republish without a version bump, which is precisely the shape
                of a rug pull that hides from anyone watching version numbers,
                so it is counted separately rather than folded into the total.

        Returns:
            True if an observation was written.
        """
        stamp = None if row.published_at is None else to_iso(row.published_at)
        norm_sha = norm_sha256(row.entry, self.corpus.policy)
        if self.corpus.index.has_content(
            row.server_key, layer=Layer.REGISTRY, norm_sha=norm_sha, published_at=stamp
        ):
            stats.versions_skipped += 1
            return False

        write = self.corpus.record_snapshot(
            run_id=run_id,
            server_key=row.server_key,
            layer=Layer.REGISTRY,
            document=row.entry,
            published_at=row.published_at,
        )
        stats.versions_stored += 1
        if stamp is not None and stamp in already:
            stats.versions_restated += 1
        stats.blobs_written += int(write.raw.created) + int(write.normalized.created)
        stats.bytes_written += write.bytes_written
        return True

    def _record_withdrawal(self, latest: VersionRow, *, run_id: str, stats: BackfillStats) -> None:
        """Record that a server has left the registry, dated to when it did.

        A withdrawal is something the registry asserts rather than a document it
        serves, so it is stored as a marker observation: no blobs, a status that
        is not ``ok``, and a ``published_at`` of the moment the status changed.
        Two things follow from that. WP6 gets the disappearance as a dated event
        instead of having to infer it, and WP3 stops probing the endpoint,
        because a server whose newest Layer-1 observation is not ``ok`` is not a
        live target.
        """
        withdrawn_at = latest.withdrawn_at
        if withdrawn_at is None:
            return
        stamp = to_iso(withdrawn_at)
        if self.corpus.index.has_marker(
            latest.server_key,
            layer=Layer.REGISTRY,
            error_class=WITHDRAWN_CLASS,
            published_at=stamp,
        ):
            return
        self.corpus.record_failure(
            run_id=run_id,
            server_key=latest.server_key,
            layer=Layer.REGISTRY,
            status=ObservationStatus.SKIPPED,
            error_class=WITHDRAWN_CLASS,
            error_detail=f"registry status {latest.status!r} as of {stamp}",
            published_at=withdrawn_at,
        )
        stats.withdrawals_recorded += 1

    # ------------------------------------------------------------ phase two ---

    def verify_targets(
        self, *, scope: str = "multi", limit: int | None = None, after: str | None = None
    ) -> list[str]:
        """Servers whose version chain is worth re-reading authoritatively.

        ``multi`` selects every server whose stored version count is anything
        other than exactly one. That is the 8,294 multi-version servers plus,
        importantly, any server the walk produced no versions for at all — a
        cursor that skipped a server is exactly the failure this phase exists to
        catch, and it would otherwise look like a server with nothing to check.

        The 12,159 servers with a single stored version are left alone. Their
        ``/versions`` response is one row we already have, and spending 12,159
        requests to be told so is not politeness, it is noise.
        """
        if scope not in {"multi", "all"}:
            msg = f"unknown verify scope {scope!r}"
            raise CollectorError(msg)
        sql = """
            SELECT s.server_key AS server_key, count(DISTINCT o.published_at) AS versions
            FROM server s
            LEFT JOIN observation o
              ON o.server_key = s.server_key
             AND o.layer = 'registry'
             AND o.status = 'ok'
             AND o.published_at IS NOT NULL
            WHERE s.server_key > ?
            GROUP BY s.server_key
        """
        if scope == "multi":
            sql += " HAVING versions <> 1"
        sql += " ORDER BY s.server_key"
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        rows = self.corpus.index.connection.execute(sql, (after or "",))
        return [row["server_key"] for row in rows]

    def _verify(
        self,
        *,
        run_id: str,
        stats: BackfillStats,
        after: str | None,
        scope: str,
        limit: int | None,
        started: float,
        base: _Totals,
    ) -> None:
        """Re-read each target's full chain from ``/versions`` and fill the gaps."""
        targets = self.verify_targets(scope=scope, limit=limit, after=after)
        stats.verify_targets += len(targets)
        for server_key in targets:
            self._verify_one(server_key, run_id=run_id, stats=stats)
            self._record_client_stats(stats, started, base)
            self._write_checkpoint(
                _Checkpoint(
                    run_id=run_id,
                    phase="verify",
                    cursor=None,
                    last_server=server_key,
                    stats=stats.as_json(),
                )
            )

    def _verify_one(self, server_key: str, *, run_id: str, stats: BackfillStats) -> None:
        """Verify and repair one server's chain against the authoritative endpoint."""
        try:
            rows = self._fetch_versions(server_key)
        except HttpStatusError as exc:
            if exc.status == 404:
                # Expected for a withdrawn server: the registry drops it from
                # this endpoint while still serving it under include_deleted.
                # The walk is that server's only source, and it already ran.
                stats.verify_not_found += 1
                _count(stats.errors_by_class, "versions_404")
                return
            stats.verify_failed += 1
            _count(stats.errors_by_class, f"versions_http_{exc.status}")
            return
        except CollectorError as exc:
            stats.verify_failed += 1
            _count(stats.errors_by_class, type(exc).__name__)
            return

        before = self._known_versions(server_key)
        recovered = self._ingest_group(rows, run_id=run_id, stats=stats)
        stats.servers_verified += 1
        if recovered:
            stats.versions_recovered += recovered
            stats.chains_repaired += 1

        # Versions we hold that the registry no longer lists. Not an error and
        # not something to delete — the corpus is append-only and a version that
        # was withdrawn after we recorded it is a finding, not a mistake.
        upstream = {to_iso(r.published_at) for r in rows if r.published_at is not None}
        stats.versions_absent_upstream += len(before - upstream)

    def _fetch_versions(self, server_key: str) -> list[VersionRow]:
        """GET one server's complete version list.

        The endpoint returns every version in a single response — 628 of them
        for the busiest server in the population — so there is no pagination to
        follow here.
        """
        quoted = urllib.parse.quote(server_key, safe="")
        payload = self.client.get(f"{self.base_url}/v0/servers/{quoted}/versions").json()
        rows = payload.get("servers") if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            msg = f"versions endpoint returned no 'servers' array for {server_key}"
            raise CollectorError(msg)
        parsed = [parse_row(row) for row in rows]
        return [row for row in parsed if row is not None and row.server_key == server_key]

    def _known_versions(self, server_key: str) -> set[str]:
        """The set of publication timestamps already stored for a server."""
        return {
            row["published_at"]
            for row in self.corpus.index.connection.execute(
                """
                SELECT DISTINCT published_at FROM observation
                WHERE server_key = ? AND layer = 'registry' AND status = 'ok'
                  AND published_at IS NOT NULL
                """,
                (server_key,),
            )
        }


def _server_of(row: VersionRow) -> Mapping[str, JsonValue]:
    """The ``server`` object inside a row, or an empty mapping."""
    server = row.entry.get("server")
    return server if isinstance(server, dict) else {}


def _count(bucket: dict[str, int], key: str) -> None:
    bucket[key] = bucket.get(key, 0) + 1


def _default_corpus_root() -> Path:
    """Corpus location: env override, else the documented production path."""
    override = os.environ.get("MCPWATCH_CORPUS")
    return Path(override) if override else Path.home() / "mcpwatch-corpus"


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns 0 clean, 1 failed, 2 completed with errors."""
    parser = argparse.ArgumentParser(
        prog="python -m mcpwatch.collect.backfill",
        description="Backfill Layer-1 history from the registry's version record.",
    )
    parser.add_argument("--corpus", type=Path, default=_default_corpus_root())
    parser.add_argument(
        "--phase",
        choices=("both", "walk", "verify"),
        default="both",
        help="walk collects the bulk cheaply; verify re-checks chains server by server",
    )
    parser.add_argument(
        "--max-pages", type=int, default=None, help="stop the walk early; for smoke tests only"
    )
    parser.add_argument(
        "--verify-scope",
        choices=("multi", "all"),
        default="multi",
        help="'multi' skips servers with exactly one known version (the point of the walk)",
    )
    parser.add_argument("--verify-limit", type=int, default=None)
    parser.add_argument(
        "--contact",
        default=os.environ.get("MCPWATCH_CONTACT", DEFAULT_CONTACT),
        help="contact address advertised in the User-Agent",
    )
    parser.add_argument("--base-url", default=REGISTRY_BASE)
    parser.add_argument("--page-size", type=int, default=PAGE_SIZE)
    parser.add_argument("--max-rps", type=float, default=None, help="override the request ceiling")
    parser.add_argument("--no-resume", action="store_true", help="ignore any backfill checkpoint")
    args = parser.parse_args(argv)

    phases = ("walk", "verify") if args.phase == "both" else (args.phase,)
    policy = None if args.max_rps is None else PolitenessPolicy(max_rps=args.max_rps)
    client = PoliteClient(contact=args.contact, version=COLLECTOR_VERSION, policy=policy)

    with exclusive_cycle(args.corpus, COLLECTOR) as acquired:
        if not acquired:
            print(
                f"{utcnow().isoformat()} another backfill holds the lock; declining "
                "rather than racing it for the same checkpoint",
                file=sys.stderr,
            )
            return 3

        with Corpus(args.corpus) as corpus:
            collector = BackfillCollector(
                corpus, client, base_url=args.base_url, page_size=args.page_size
            )
            try:
                stats = collector.run(
                    phases=phases,
                    max_pages=args.max_pages,
                    verify_scope=args.verify_scope,
                    verify_limit=args.verify_limit,
                    resume=not args.no_resume,
                )
            except CollectorError as exc:
                print(f"{utcnow().isoformat()} backfill FAILED: {exc}", file=sys.stderr)
                return 1

    print(json.dumps(stats.as_json(), indent=2, sort_keys=True))
    return 2 if (stats.errors_by_class or stats.verify_failed) else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
