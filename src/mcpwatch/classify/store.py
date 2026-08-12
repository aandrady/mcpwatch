"""Durable storage for classifications and human adjudications.

Kept in its own database beside the corpus rather than inside ``index.db``. The
corpus is a record of what the ecosystem did; these are opinions *about* that
record — machine labels that a better classifier will supersede, and human
labels that are the ground truth those classifiers get measured against. Mixing
them would make the append-only observation table something that also holds
revisable judgements.

**Human adjudications are the most expensive rows in the project.** A machine
label can be recomputed for the price of an API call; two hundred adjudicated
diffs are hours of expert attention that cannot be regenerated. They are
therefore append-only by trigger, exactly like observations, and a re-labelling
is a new row rather than an edit — a rater who changes their mind is data about
the taxonomy's clarity, and overwriting it would destroy that.
"""

import json
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from mcpwatch.store import to_iso, utcnow

__all__ = ["Adjudication", "ClassifyStore", "MachineLabel"]

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Machine labels. Replaceable by construction: a newer prompt or model writes
-- new rows, and the (change_id, source, model_id, prompt_sha) tuple is what
-- makes drift measurable rather than invisible.
CREATE TABLE IF NOT EXISTS machine_label (
    label_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    change_id      TEXT NOT NULL,
    source         TEXT NOT NULL,
    label          TEXT NOT NULL,
    confidence     REAL,
    rationale      TEXT,
    model_id       TEXT,
    prompt_version TEXT,
    prompt_sha     TEXT,
    sampling       TEXT,
    hits_json      TEXT,
    created_at     TEXT NOT NULL,
    CHECK (source IN ('rules', 'llm'))
);

CREATE INDEX IF NOT EXISTS machine_label_change ON machine_label(change_id, source);
CREATE UNIQUE INDEX IF NOT EXISTS machine_label_identity
    ON machine_label(change_id, source, ifnull(model_id, ''), ifnull(prompt_sha, ''));

-- Human labels. Append-only, enforced by trigger.
CREATE TABLE IF NOT EXISTS adjudication (
    adjudication_id INTEGER PRIMARY KEY AUTOINCREMENT,
    change_id       TEXT NOT NULL,
    rater           TEXT NOT NULL,
    label           TEXT NOT NULL,
    notes           TEXT,
    seconds_spent   REAL,
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS adjudication_change ON adjudication(change_id);
CREATE INDEX IF NOT EXISTS adjudication_rater ON adjudication(rater, change_id);

CREATE TRIGGER IF NOT EXISTS adjudication_no_update
BEFORE UPDATE ON adjudication
BEGIN
    SELECT RAISE(ABORT, 'adjudication is append-only: relabel by inserting a new row');
END;

CREATE TRIGGER IF NOT EXISTS adjudication_no_delete
BEFORE DELETE ON adjudication
BEGIN
    SELECT RAISE(ABORT, 'adjudication is append-only: DELETE is forbidden');
END;

-- The fixed calibration set. Fixed is the point: reliability measured over a
-- set that drifts is not comparable month to month, and monthly re-adjudication
-- against a moving target would measure the sample rather than the classifier.
CREATE TABLE IF NOT EXISTS calibration_item (
    change_id  TEXT PRIMARY KEY,
    added_at   TEXT NOT NULL,
    stratum    TEXT
);
"""


@dataclass(frozen=True, slots=True)
class MachineLabel:
    """One machine-produced label for one ChangeSet."""

    change_id: str
    source: str
    label: str
    confidence: float | None = None
    rationale: str | None = None
    model_id: str | None = None
    prompt_version: str | None = None
    prompt_sha: str | None = None
    sampling: str | None = None
    hits: tuple[dict[str, object], ...] = ()


@dataclass(frozen=True, slots=True)
class Adjudication:
    """One human label for one ChangeSet."""

    change_id: str
    rater: str
    label: str
    notes: str | None = None
    seconds_spent: float | None = None


class ClassifyStore:
    """SQLite store for classifications, adjudications, and the calibration set."""

    def __init__(self, path: Path | str) -> None:
        """Open (creating if needed) the store at ``path``."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.executescript(_SCHEMA)
        self._conn.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?)"
            " ON CONFLICT(key) DO NOTHING",
            (str(SCHEMA_VERSION),),
        )

    def close(self) -> None:
        """Close the connection."""
        self._conn.close()

    def __enter__(self) -> ClassifyStore:
        """Enter a context manager that closes the store on exit."""
        return self

    def __exit__(self, *exc: object) -> None:
        """Close the store."""
        self.close()

    @property
    def connection(self) -> sqlite3.Connection:
        """The underlying connection, for queries this class does not wrap."""
        return self._conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run a block inside one transaction."""
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

    # -------------------------------------------------------- machine labels ---

    def put_machine_label(self, label: MachineLabel) -> None:
        """Record a machine label, replacing any identical-provenance row.

        Identity is (change_id, source, model_id, prompt_sha): re-running the
        same classifier over the same ChangeSet overwrites, while a new model
        or prompt writes a new row alongside the old one. That is what makes a
        drift comparison possible at all.
        """
        self._conn.execute(
            """
            INSERT INTO machine_label(
                change_id, source, label, confidence, rationale,
                model_id, prompt_version, prompt_sha, sampling, hits_json, created_at
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(change_id, source, ifnull(model_id, ''), ifnull(prompt_sha, ''))
            DO UPDATE SET
                label = excluded.label,
                confidence = excluded.confidence,
                rationale = excluded.rationale,
                prompt_version = excluded.prompt_version,
                sampling = excluded.sampling,
                hits_json = excluded.hits_json,
                created_at = excluded.created_at
            """,
            (
                label.change_id,
                label.source,
                label.label,
                label.confidence,
                label.rationale,
                label.model_id,
                label.prompt_version,
                label.prompt_sha,
                label.sampling,
                json.dumps(list(label.hits), sort_keys=True) if label.hits else None,
                to_iso(utcnow()),
            ),
        )

    def machine_label(
        self,
        change_id: str,
        *,
        source: str,
        model_id: str | None = None,
        prompt_sha: str | None = None,
    ) -> sqlite3.Row | None:
        """Return a stored machine label, or None. The LLM layer's cache read."""
        sql = ["SELECT * FROM machine_label WHERE change_id = ? AND source = ?"]
        params: list[object] = [change_id, source]
        if model_id is not None:
            sql.append("AND model_id = ?")
            params.append(model_id)
        if prompt_sha is not None:
            sql.append("AND prompt_sha = ?")
            params.append(prompt_sha)
        sql.append("ORDER BY label_id DESC LIMIT 1")
        row: sqlite3.Row | None = self._conn.execute(" ".join(sql), params).fetchone()
        return row

    def machine_labels(self, *, source: str) -> dict[str, str]:
        """Every change_id -> label for one source, newest row per change."""
        rows = self._conn.execute(
            """
            SELECT change_id, label FROM machine_label
            WHERE source = ? AND label_id IN (
                SELECT max(label_id) FROM machine_label WHERE source = ? GROUP BY change_id
            )
            """,
            (source, source),
        ).fetchall()
        return {row["change_id"]: row["label"] for row in rows}

    # --------------------------------------------------------- adjudications ---

    def add_adjudication(self, adjudication: Adjudication) -> int:
        """Append a human label and return its id."""
        cursor = self._conn.execute(
            """
            INSERT INTO adjudication(change_id, rater, label, notes, seconds_spent, created_at)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            (
                adjudication.change_id,
                adjudication.rater,
                adjudication.label,
                adjudication.notes,
                adjudication.seconds_spent,
                to_iso(utcnow()),
            ),
        )
        return int(cursor.lastrowid or 0)

    def rater_labels(self, rater: str) -> dict[str, str]:
        """A rater's latest label per ChangeSet.

        Latest, not first: a rater who relabels has changed their mind, and the
        earlier row stays for the audit trail without polluting the score.
        """
        rows = self._conn.execute(
            """
            SELECT change_id, label FROM adjudication
            WHERE rater = ? AND adjudication_id IN (
                SELECT max(adjudication_id) FROM adjudication WHERE rater = ? GROUP BY change_id
            )
            """,
            (rater, rater),
        ).fetchall()
        return {row["change_id"]: row["label"] for row in rows}

    def raters(self) -> list[str]:
        """Every rater who has adjudicated anything."""
        rows = self._conn.execute(
            "SELECT DISTINCT rater FROM adjudication ORDER BY rater"
        ).fetchall()
        return [row["rater"] for row in rows]

    def consensus(self) -> dict[str, str]:
        """Items every rater who touched them agreed on.

        Ground truth for measuring the machine layers. Deliberately excludes
        anything the raters disagreed about: a contested item has no truth to
        measure precision against, and picking a winner would invent one.
        """
        labels: dict[str, set[str]] = {}
        for rater in self.raters():
            for change_id, label in self.rater_labels(rater).items():
                labels.setdefault(change_id, set()).add(label)
        return {key: next(iter(value)) for key, value in labels.items() if len(value) == 1}

    # ------------------------------------------------------- calibration set ---

    def add_calibration_items(self, items: Mapping[str, str | None]) -> int:
        """Add change_ids to the fixed calibration set. Returns how many were new."""
        added = 0
        stamp = to_iso(utcnow())
        for change_id, stratum in items.items():
            cursor = self._conn.execute(
                "INSERT OR IGNORE INTO calibration_item(change_id, added_at, stratum)"
                " VALUES(?, ?, ?)",
                (change_id, stamp, stratum),
            )
            added += cursor.rowcount or 0
        return added

    def calibration_set(self) -> list[sqlite3.Row]:
        """The fixed calibration set, in insertion order."""
        return self._conn.execute(
            "SELECT * FROM calibration_item ORDER BY added_at, change_id"
        ).fetchall()

    def pending_for(self, rater: str) -> list[str]:
        """Calibration items this rater has not yet labelled."""
        rows = self._conn.execute(
            """
            SELECT c.change_id FROM calibration_item c
            WHERE NOT EXISTS (
                SELECT 1 FROM adjudication a
                WHERE a.change_id = c.change_id AND a.rater = ?
            )
            ORDER BY c.added_at, c.change_id
            """,
            (rater,),
        ).fetchall()
        return [row["change_id"] for row in rows]
