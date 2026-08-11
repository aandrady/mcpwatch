"""The SQLite index over the blob store.

The index holds *pointers and metadata*; the documents themselves live in the
blob store. That split is what lets the index be rebuilt from blobs plus run
logs if it is ever lost, while the blobs themselves are irreplaceable.

``observation`` is append-only, enforced by ``BEFORE UPDATE`` / ``BEFORE DELETE``
triggers rather than by convention. A longitudinal corpus whose history can be
edited is not evidence of anything, and the trigger is the difference between a
policy and a guarantee. ``run`` and ``server`` are mutable by design: a run is
closed out after it finishes, and a server's current identity is a projection of
its append-only ``server_identity`` history.

Schema changes are migrations, never rewrites: :meth:`ObservationIndex._migrate`
brings an older corpus up to :data:`SCHEMA_VERSION` by adding what is missing.
The corpus is not reproducible, so a migration that drops or rebuilds
``observation`` is not an option — every step here must be additive.
"""

import json
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .errors import StoreError
from .types import (
    JsonValue,
    Layer,
    Observation,
    ObservationStatus,
    Run,
    ServerIdentity,
    ServerRecord,
)

__all__ = ["SCHEMA_VERSION", "ObservationIndex"]

SCHEMA_VERSION = 2
"""Bump whenever the DDL below changes in a way that needs a migration.

v2 added ``observation.published_at`` and the derived ``observation.effective_at``
for WP5's retrospective backfill.
"""

_LAYERS = ", ".join(f"'{member.value}'" for member in Layer)
_STATUSES = ", ".join(f"'{member.value}'" for member in ObservationStatus)

_SCHEMA_TABLES = f"""
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS run (
    run_id            TEXT PRIMARY KEY,
    collector         TEXT NOT NULL,
    collector_version TEXT NOT NULL,
    started_at        TEXT NOT NULL,
    finished_at       TEXT,
    stats_json        TEXT
);

-- server_key is the primary identity: the registry's reverse-DNS namespaced
-- `name`, e.g. "ac.inference.sh/mcp". repo_url and primary_endpoint are
-- secondary identity keys; WP6 reconciles against them to tell a mutation apart
-- from a replacement (same name, different repo) or a rename (different name,
-- same repo and tool fingerprint).
CREATE TABLE IF NOT EXISTS server (
    server_key       TEXT PRIMARY KEY,
    registry_name    TEXT NOT NULL,
    repo_url         TEXT,
    primary_endpoint TEXT,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL
);

-- Append-only history of every distinct identity tuple a server has presented.
-- Rows are added only when the tuple is new, so this stays small: one row per
-- server plus one per identity change, not one per run.
CREATE TABLE IF NOT EXISTS server_identity (
    identity_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    server_key       TEXT NOT NULL REFERENCES server(server_key),
    observed_at      TEXT NOT NULL,
    registry_name    TEXT NOT NULL,
    repo_url         TEXT,
    primary_endpoint TEXT
);

CREATE TABLE IF NOT EXISTS observation (
    obs_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       TEXT NOT NULL REFERENCES run(run_id),
    server_key   TEXT NOT NULL REFERENCES server(server_key),
    layer        TEXT NOT NULL,
    observed_at  TEXT NOT NULL,
    status       TEXT NOT NULL,
    raw_sha      TEXT,
    norm_sha     TEXT,
    norm_version INTEGER,
    error_class  TEXT,
    error_detail TEXT,

    -- When the *registry* says this state came into being, as opposed to when we
    -- retrieved it. Set by WP5's backfill from `_meta.publishedAt`; NULL for a
    -- live probe, which has no such thing. Keeping the two apart is the whole
    -- point: a version published in 2024 and read today is not an observation
    -- made in 2024, and pretending otherwise would falsify the time series.
    published_at TEXT,

    -- The corpus's chronology key, derived rather than stored so no writer can
    -- forget it and no two callers can disagree about the rule. Every ordering
    -- that means "when was this true" uses this; `observed_at` stays available
    -- for "when did we look". Identical to observed_at for every row that
    -- predates v2, so the ordering of existing data is unchanged.
    effective_at TEXT GENERATED ALWAYS AS (coalesce(published_at, observed_at)) VIRTUAL,

    CHECK (layer IN ({_LAYERS})),
    CHECK (status IN ({_STATUSES})),
    CHECK (norm_version IS NULL OR norm_version >= 0),
    -- A successful observation must point at both blobs and name the
    -- normalization it was hashed under. Catching this here turns a collector
    -- bug into an immediate insert failure instead of an unexplainable gap
    -- discovered months later.
    CHECK (
        status <> 'ok'
        OR (raw_sha IS NOT NULL AND norm_sha IS NOT NULL AND norm_version IS NOT NULL)
    )
);
"""

_SCHEMA_INDEXES = """
CREATE INDEX IF NOT EXISTS run_collector_started
    ON run(collector, started_at);

CREATE INDEX IF NOT EXISTS server_repo_url ON server(repo_url);
CREATE INDEX IF NOT EXISTS server_endpoint ON server(primary_endpoint);

CREATE UNIQUE INDEX IF NOT EXISTS server_identity_tuple
    ON server_identity(
        server_key,
        registry_name,
        ifnull(repo_url, ''),
        ifnull(primary_endpoint, '')
    );

CREATE INDEX IF NOT EXISTS observation_server_time
    ON observation(server_key, observed_at);
CREATE INDEX IF NOT EXISTS observation_server_effective
    ON observation(server_key, effective_at);
-- (server_key, norm_sha) rather than norm_sha alone: every lookup that matters
-- asks "have we already stored this exact content for *this* server", which is
-- how the backfill stays idempotent without re-reading blobs.
CREATE INDEX IF NOT EXISTS observation_server_norm
    ON observation(server_key, norm_sha);
CREATE INDEX IF NOT EXISTS observation_norm_sha
    ON observation(norm_sha);
CREATE INDEX IF NOT EXISTS observation_run
    ON observation(run_id);

CREATE TRIGGER IF NOT EXISTS observation_no_update
BEFORE UPDATE ON observation
BEGIN
    SELECT RAISE(ABORT, 'observation is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS observation_no_delete
BEFORE DELETE ON observation
BEGIN
    SELECT RAISE(ABORT, 'observation is append-only: DELETE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS server_identity_no_update
BEFORE UPDATE ON server_identity
BEGIN
    SELECT RAISE(ABORT, 'server_identity is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS server_identity_no_delete
BEFORE DELETE ON server_identity
BEGIN
    SELECT RAISE(ABORT, 'server_identity is append-only: DELETE is forbidden');
END;
"""


class ObservationIndex:
    """SQLite index of runs, servers, and observations.

    The connection runs in WAL mode with ``synchronous=FULL``: a collector writes
    while analysis reads, and the corpus cannot be re-collected if a power loss
    truncates the tail of a run.
    """

    def __init__(self, path: Path | str) -> None:
        """Open (creating if needed) the index database at ``path``."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # isolation_level=None puts the driver in autocommit mode; transactions
        # are opened explicitly via `transaction()` so a run's inserts commit as
        # one unit rather than one fsync at a time.
        self._conn = sqlite3.connect(str(self.path), isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._configure()
        self._create_schema()

    def _configure(self) -> None:
        """Apply the connection pragmas the corpus depends on."""
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=30000")

    def _create_schema(self) -> None:
        """Create tables, migrate an older corpus, then create indexes and triggers.

        The order is load-bearing. Indexes are created after the migration
        because some of them are over columns the migration adds, and a fresh
        database and a migrated one must end up with exactly the same schema.

        Deliberately not wrapped in an explicit transaction: ``executescript``
        commits any pending one before it runs, so an outer ``BEGIN`` here would
        be closed out from under us.
        """
        self._conn.executescript(_SCHEMA_TABLES)
        self._migrate()
        self._conn.executescript(_SCHEMA_INDEXES)
        self._conn.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(SCHEMA_VERSION),),
        )

    def _migrate(self) -> None:
        """Bring an existing database up to :data:`SCHEMA_VERSION`.

        Additive only, and driven by what the table actually has rather than by
        the recorded version number — a corpus interrupted mid-migration should
        converge on the next open instead of needing a repair. ``ADD COLUMN`` is
        a metadata-only operation in SQLite and does not fire the append-only
        triggers, so no observation row is read, rewritten, or touched.

        Raises:
            StoreError: If the database was written by a newer build than this
                one. Reading a corpus under assumptions that no longer hold is
                worse than refusing to open it.
        """
        recorded = self._conn.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()
        if recorded is not None and int(recorded["value"]) > SCHEMA_VERSION:
            msg = (
                f"corpus at {self.path} is schema v{recorded['value']}, but this build "
                f"understands v{SCHEMA_VERSION}; refusing to open it with a newer schema"
            )
            raise StoreError(msg)

        # table_xinfo, not table_info: the latter omits generated columns, so a
        # freshly created v2 database would look like it still needed migrating
        # and the ALTER would fail on a column that is already there.
        columns = {row["name"] for row in self._conn.execute("PRAGMA table_xinfo(observation)")}
        if "published_at" not in columns:
            self._conn.execute("ALTER TABLE observation ADD COLUMN published_at TEXT")
        if "effective_at" not in columns:
            self._conn.execute(
                "ALTER TABLE observation ADD COLUMN effective_at TEXT"
                " GENERATED ALWAYS AS (coalesce(published_at, observed_at)) VIRTUAL"
            )

    @property
    def connection(self) -> sqlite3.Connection:
        """The underlying connection, for queries this class does not wrap."""
        return self._conn

    @property
    def schema_version(self) -> int:
        """The schema version recorded in the database."""
        row = self._conn.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()
        return int(row["value"])

    def close(self) -> None:
        """Close the connection."""
        self._conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run a block inside one ``BEGIN IMMEDIATE`` transaction.

        ``IMMEDIATE`` takes the write lock up front, so two collectors racing
        fail fast on ``busy_timeout`` instead of halfway through a batch.
        """
        if self._conn.in_transaction:
            yield self._conn
            return
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield self._conn
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")

    # ---------------------------------------------------------------- runs ---

    def insert_run(
        self,
        *,
        run_id: str,
        collector: str,
        collector_version: str,
        started_at: str,
    ) -> None:
        """Insert an open run row. ``finished_at`` stays NULL until it closes."""
        self._conn.execute(
            "INSERT INTO run(run_id, collector, collector_version, started_at) VALUES(?, ?, ?, ?)",
            (run_id, collector, collector_version, started_at),
        )

    def finish_run(
        self,
        run_id: str,
        *,
        finished_at: str,
        stats: Mapping[str, JsonValue] | None = None,
    ) -> None:
        """Close a run, recording its end time and summary statistics.

        A run that never gets a ``finished_at`` is how WP4 detects a collector
        that died mid-cycle, so this must not be called on failure paths.
        """
        stats_json = None if stats is None else json.dumps(stats, sort_keys=True)
        self._conn.execute(
            "UPDATE run SET finished_at = ?, stats_json = ? WHERE run_id = ?",
            (finished_at, stats_json, run_id),
        )

    def get_run(self, run_id: str) -> Run | None:
        """Return a run by id, or None if it does not exist."""
        row = self._conn.execute("SELECT * FROM run WHERE run_id = ?", (run_id,)).fetchone()
        return None if row is None else Run.from_row(row)

    def unfinished_runs(self) -> list[Run]:
        """Return every run that was started but never closed, oldest first."""
        rows = self._conn.execute(
            "SELECT * FROM run WHERE finished_at IS NULL ORDER BY started_at"
        ).fetchall()
        return [Run.from_row(row) for row in rows]

    # ------------------------------------------------------------- servers ---

    def upsert_server(
        self,
        *,
        server_key: str,
        registry_name: str,
        repo_url: str | None,
        primary_endpoint: str | None,
        seen_at: str,
    ) -> None:
        """Insert or refresh a server row and append its identity if it is new.

        ``first_seen`` and ``last_seen`` are folded with ``min``/``max`` rather
        than overwritten, so a backfill that inserts historical sightings out of
        order still produces the correct interval.

        The identity fields are written exactly as given — passing ``None`` for
        ``repo_url`` clears it. Callers holding only a partial view of a server
        should use :meth:`touch_server` instead.
        """
        self._conn.execute(
            """
            INSERT INTO server(
                server_key, registry_name, repo_url, primary_endpoint,
                first_seen, last_seen
            )
            VALUES(?, ?, ?, ?, ?, ?)
            ON CONFLICT(server_key) DO UPDATE SET
                registry_name    = excluded.registry_name,
                repo_url         = excluded.repo_url,
                primary_endpoint = excluded.primary_endpoint,
                first_seen       = min(server.first_seen, excluded.first_seen),
                last_seen        = max(server.last_seen, excluded.last_seen)
            """,
            (server_key, registry_name, repo_url, primary_endpoint, seen_at, seen_at),
        )
        self.record_identity(
            server_key=server_key,
            registry_name=registry_name,
            repo_url=repo_url,
            primary_endpoint=primary_endpoint,
            observed_at=seen_at,
        )

    def record_identity(
        self,
        *,
        server_key: str,
        registry_name: str,
        repo_url: str | None,
        primary_endpoint: str | None,
        observed_at: str,
    ) -> None:
        """Append an identity tuple without touching the ``server`` projection.

        What :meth:`upsert_server` does minus the overwrite, for a caller reading
        historical versions: every repo or endpoint a server has ever presented
        belongs in the history — that is WP7's endpoint-swap signal — but an old
        version must not be allowed to overwrite the server's *current* identity.

        The unique index makes this idempotent, so the ``observed_at`` that
        sticks is the first one written for a given tuple. Feed versions oldest
        first and it reads as "when this identity first appeared".
        """
        self._conn.execute(
            """
            INSERT OR IGNORE INTO server_identity(
                server_key, observed_at, registry_name, repo_url, primary_endpoint
            )
            VALUES(?, ?, ?, ?, ?)
            """,
            (server_key, observed_at, registry_name, repo_url, primary_endpoint),
        )

    def touch_server(self, server_key: str, *, seen_at: str) -> None:
        """Widen the interval a server is known to have existed over.

        Both ends fold, so evidence from any direction in time is absorbed
        without overwriting anything: a daily crawl pushes ``last_seen``
        forward, and a backfill reading a version published in 2024 pulls
        ``first_seen`` back. Identity fields are left alone — an old version
        must never be allowed to restate what a server currently is.
        """
        self._conn.execute(
            """
            UPDATE server
            SET first_seen = min(first_seen, ?), last_seen = max(last_seen, ?)
            WHERE server_key = ?
            """,
            (seen_at, seen_at, server_key),
        )

    def get_server(self, server_key: str) -> ServerRecord | None:
        """Return a server by key, or None if it is not tracked."""
        row = self._conn.execute(
            "SELECT * FROM server WHERE server_key = ?", (server_key,)
        ).fetchone()
        return None if row is None else ServerRecord.from_row(row)

    def identity_history(self, server_key: str) -> list[ServerIdentity]:
        """Return every distinct identity tuple recorded for a server, oldest first."""
        rows = self._conn.execute(
            """
            SELECT * FROM server_identity WHERE server_key = ?
            ORDER BY observed_at, identity_id
            """,
            (server_key,),
        ).fetchall()
        return [ServerIdentity.from_row(row) for row in rows]

    def count_servers(self) -> int:
        """Return the number of tracked servers."""
        row = self._conn.execute("SELECT count(*) AS n FROM server").fetchone()
        return int(row["n"])

    # -------------------------------------------------------- observations ---

    def insert_observation(
        self,
        *,
        run_id: str,
        server_key: str,
        layer: Layer,
        observed_at: str,
        status: ObservationStatus,
        raw_sha: str | None = None,
        norm_sha: str | None = None,
        norm_version: int | None = None,
        error_class: str | None = None,
        error_detail: str | None = None,
        published_at: str | None = None,
    ) -> int:
        """Append one observation and return its ``obs_id``.

        This is the only supported way to write to ``observation``; the table's
        triggers reject every UPDATE and DELETE.

        ``published_at`` is the registry's own timestamp for the state being
        recorded, and must be rendered by :func:`~mcpwatch.store.types.to_iso`
        like every other corpus timestamp — ``effective_at`` orders rows as text,
        so a stray ``Z`` suffix would sort into the wrong place.
        """
        cursor = self._conn.execute(
            """
            INSERT INTO observation(
                run_id, server_key, layer, observed_at, status,
                raw_sha, norm_sha, norm_version, error_class, error_detail,
                published_at
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                server_key,
                str(layer),
                observed_at,
                str(status),
                raw_sha,
                norm_sha,
                norm_version,
                error_class,
                error_detail,
                published_at,
            ),
        )
        rowid = cursor.lastrowid
        if rowid is None:  # pragma: no cover - sqlite always sets this on INSERT
            msg = "sqlite did not report a rowid for the inserted observation"
            raise RuntimeError(msg)
        return rowid

    def get_observation(self, obs_id: int) -> Observation | None:
        """Return an observation by id, or None if it does not exist."""
        row = self._conn.execute("SELECT * FROM observation WHERE obs_id = ?", (obs_id,)).fetchone()
        return None if row is None else Observation.from_row(row)

    def observations(
        self,
        server_key: str,
        *,
        layer: Layer | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> list[Observation]:
        """Return one server's observations in chronological order.

        Chronology is ``effective_at``: a backfilled version published in 2024
        belongs at its publication date, not at the instant the backfill job
        happened to read it. For every observation collected forward in time
        this is identical to ``observed_at``.

        Args:
            server_key: The server to query.
            layer: Restrict to one layer, or None for both.
            since: Inclusive lower bound on ``effective_at``.
            until: Exclusive upper bound on ``effective_at``.
        """
        sql = ["SELECT * FROM observation WHERE server_key = ?"]
        params: list[Any] = [server_key]
        if layer is not None:
            sql.append("AND layer = ?")
            params.append(str(layer))
        if since is not None:
            sql.append("AND effective_at >= ?")
            params.append(since)
        if until is not None:
            sql.append("AND effective_at < ?")
            params.append(until)
        sql.append("ORDER BY effective_at, obs_id")
        rows = self._conn.execute(" ".join(sql), params).fetchall()
        return [Observation.from_row(row) for row in rows]

    def latest_observation(
        self,
        server_key: str,
        *,
        layer: Layer | None = None,
        status: ObservationStatus | None = None,
    ) -> Observation | None:
        """Return a server's most recent observation, optionally filtered.

        Passing ``status=ObservationStatus.OK`` gives the last snapshot that
        actually carries content, which is the baseline a differ compares
        against — a run of failures must not be mistaken for a change.

        "Most recent" is by ``effective_at``. That distinction only bites after a
        backfill: loading a server's whole version history in one job leaves
        dozens of rows sharing today's ``observed_at``, and the last one *read*
        is not necessarily the last one *published*. Ordering by publication
        keeps tomorrow's daily crawl comparing against the newest version rather
        than against whichever historical row happened to be inserted last.
        """
        sql = ["SELECT * FROM observation WHERE server_key = ?"]
        params: list[Any] = [server_key]
        if layer is not None:
            sql.append("AND layer = ?")
            params.append(str(layer))
        if status is not None:
            sql.append("AND status = ?")
            params.append(str(status))
        sql.append("ORDER BY effective_at DESC, obs_id DESC LIMIT 1")
        row = self._conn.execute(" ".join(sql), params).fetchone()
        return None if row is None else Observation.from_row(row)

    def observations_by_norm_sha(self, norm_sha: str) -> list[Observation]:
        """Return every observation sharing a normalized hash, chronologically."""
        rows = self._conn.execute(
            "SELECT * FROM observation WHERE norm_sha = ? ORDER BY effective_at, obs_id",
            (norm_sha,),
        ).fetchall()
        return [Observation.from_row(row) for row in rows]

    def has_content(
        self,
        server_key: str,
        *,
        layer: Layer,
        norm_sha: str,
        published_at: str | None = None,
    ) -> bool:
        """Return whether this content is already stored for this server *as dated*.

        The backfill's idempotency test. The date is part of the key, not an
        afterthought, and leaving it out was a real bug: the daily crawl records
        a server's current version undated, so a content-only check let every
        server's newest version suppress the backfill row that would have
        carried its publication date — costing exactly the most recent
        transition of every server, the one most worth having.

        Two rows with the same bytes and different dates are two different
        facts: "this is how the server looked when we crawled it" and "this
        version was published on this date". Only the second can order history.

        ``IS`` rather than ``=`` so that an undated row matches an undated
        query; ``published_at = NULL`` is never true and would defeat the check
        for records the registry gives no timestamp for.
        """
        row = self._conn.execute(
            """
            SELECT 1 FROM observation
            WHERE server_key = ? AND layer = ? AND norm_sha = ? AND status = 'ok'
              AND published_at IS ?
            LIMIT 1
            """,
            (server_key, str(layer), norm_sha, published_at),
        ).fetchone()
        return row is not None

    def has_marker(
        self, server_key: str, *, layer: Layer, error_class: str, published_at: str
    ) -> bool:
        """Return whether a non-content marker row is already recorded.

        Markers are observations that assert something the registry said rather
        than a document it served — a withdrawal, say. They carry no blobs, so
        :meth:`has_content` cannot recognize them.
        """
        row = self._conn.execute(
            """
            SELECT 1 FROM observation
            WHERE server_key = ? AND layer = ? AND error_class = ? AND published_at = ?
            LIMIT 1
            """,
            (server_key, str(layer), error_class, published_at),
        ).fetchone()
        return row is not None

    def observations_for_run(self, run_id: str) -> list[Observation]:
        """Return every observation recorded by one run, in insertion order."""
        rows = self._conn.execute(
            "SELECT * FROM observation WHERE run_id = ? ORDER BY obs_id", (run_id,)
        ).fetchall()
        return [Observation.from_row(row) for row in rows]

    def count_observations(self) -> int:
        """Return the total number of observations."""
        row = self._conn.execute("SELECT count(*) AS n FROM observation").fetchone()
        return int(row["n"])

    def status_counts(self, run_id: str) -> dict[str, int]:
        """Return a run's observation counts keyed by status."""
        rows = self._conn.execute(
            "SELECT status, count(*) AS n FROM observation WHERE run_id = ? GROUP BY status",
            (run_id,),
        ).fetchall()
        return {row["status"]: int(row["n"]) for row in rows}

    def referenced_digests(self) -> Sequence[str]:
        """Return every blob digest the index refers to.

        Useful for a corpus integrity sweep: every digest here must resolve in
        the blob store.
        """
        rows = self._conn.execute(
            "SELECT DISTINCT raw_sha AS sha FROM observation WHERE raw_sha IS NOT NULL"
            " UNION"
            " SELECT DISTINCT norm_sha AS sha FROM observation WHERE norm_sha IS NOT NULL"
        ).fetchall()
        return [row["sha"] for row in rows]
