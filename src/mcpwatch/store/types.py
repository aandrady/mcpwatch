"""Value types shared across the MCPWatch storage layer.

The enums here are mirrored by ``CHECK`` constraints in the SQLite schema, so a
new member must be added in both places or inserts will be rejected.
"""

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

__all__ = [
    "JsonValue",
    "Layer",
    "Observation",
    "ObservationStatus",
    "Run",
    "ServerIdentity",
    "ServerRecord",
    "from_iso",
    "to_iso",
    "utcnow",
]

type JsonValue = bool | int | float | str | list[JsonValue] | dict[str, JsonValue] | None
"""Any value that survives a ``json.loads`` round trip."""


class Layer(StrEnum):
    """Which of the two MCPWatch data layers an observation belongs to.

    ``REGISTRY`` metadata has retrospective history available from the registry's
    ``/versions`` endpoint. ``MANIFEST`` data does not — it only accrues forward
    from the first successful probe, which is why a missed day is permanent.
    """

    REGISTRY = "registry"
    MANIFEST = "manifest"


class ObservationStatus(StrEnum):
    """Outcome of a single attempt to observe one server on one layer.

    Every value other than ``OK`` is data, not an error to be swallowed: crawl
    reliability and the size of each failure population are reported metrics.
    """

    OK = "ok"
    UNREACHABLE = "unreachable"
    AUTH_REQUIRED = "auth_required"
    PROTOCOL_ERROR = "protocol_error"
    TIMEOUT = "timeout"
    NONDETERMINISTIC = "nondeterministic"
    SKIPPED = "skipped"


def utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


def to_iso(moment: datetime) -> str:
    """Render ``moment`` as a UTC ISO-8601 string with microsecond precision.

    All corpus timestamps use this single representation so that lexicographic
    ordering of the stored text matches chronological ordering.

    Args:
        moment: A timezone-aware datetime.

    Returns:
        An ISO-8601 string such as ``2026-08-07T09:06:00.123456+00:00``.

    Raises:
        ValueError: If ``moment`` is naive. A naive timestamp in a longitudinal
            time series is a silent data bug, so it is rejected outright.
    """
    if moment.tzinfo is None:
        msg = "corpus timestamps must be timezone-aware; got a naive datetime"
        raise ValueError(msg)
    return moment.astimezone(UTC).isoformat(timespec="microseconds")


def from_iso(text: str) -> datetime:
    """Parse a corpus timestamp produced by :func:`to_iso` back into a datetime."""
    return datetime.fromisoformat(text).astimezone(UTC)


@dataclass(frozen=True, slots=True)
class Run:
    """One execution of one collector."""

    run_id: str
    collector: str
    collector_version: str
    started_at: str
    finished_at: str | None
    stats_json: str | None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Run:
        """Build a :class:`Run` from a ``run`` table row."""
        return cls(
            run_id=row["run_id"],
            collector=row["collector"],
            collector_version=row["collector_version"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            stats_json=row["stats_json"],
        )


@dataclass(frozen=True, slots=True)
class ServerRecord:
    """Current identity of one tracked server.

    ``server_key`` is the primary identity (the registry's reverse-DNS namespaced
    ``name``). ``repo_url`` and ``primary_endpoint`` are secondary identity keys:
    WP6 needs them to tell a mutation apart from a replacement or a rename.
    """

    server_key: str
    registry_name: str
    repo_url: str | None
    primary_endpoint: str | None
    first_seen: str
    last_seen: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> ServerRecord:
        """Build a :class:`ServerRecord` from a ``server`` table row."""
        return cls(
            server_key=row["server_key"],
            registry_name=row["registry_name"],
            repo_url=row["repo_url"],
            primary_endpoint=row["primary_endpoint"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
        )


@dataclass(frozen=True, slots=True)
class Observation:
    """One immutable record of one server, on one layer, at one instant.

    Rows of the ``observation`` table are append-only, enforced by SQLite
    triggers. ``raw_sha`` addresses the bytes exactly as received; ``norm_sha``
    addresses the canonicalized bytes under normalization version
    ``norm_version``. Keeping both is what makes a future normalization change
    replayable instead of destructive.
    """

    obs_id: int
    run_id: str
    server_key: str
    layer: Layer
    observed_at: str
    status: ObservationStatus
    raw_sha: str | None
    norm_sha: str | None
    norm_version: int | None
    error_class: str | None
    error_detail: str | None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Observation:
        """Build an :class:`Observation` from an ``observation`` table row."""
        return cls(
            obs_id=row["obs_id"],
            run_id=row["run_id"],
            server_key=row["server_key"],
            layer=Layer(row["layer"]),
            observed_at=row["observed_at"],
            status=ObservationStatus(row["status"]),
            raw_sha=row["raw_sha"],
            norm_sha=row["norm_sha"],
            norm_version=row["norm_version"],
            error_class=row["error_class"],
            error_detail=row["error_detail"],
        )


@dataclass(frozen=True, slots=True)
class ServerIdentity:
    """One distinct (name, repo, endpoint) tuple observed for a server.

    Appended only when the tuple differs from anything seen before, so the table
    is a compact history of identity changes rather than one row per run.
    """

    identity_id: int
    server_key: str
    observed_at: str
    registry_name: str
    repo_url: str | None
    primary_endpoint: str | None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> ServerIdentity:
        """Build a :class:`ServerIdentity` from a ``server_identity`` table row."""
        return cls(
            identity_id=row["identity_id"],
            server_key=row["server_key"],
            observed_at=row["observed_at"],
            registry_name=row["registry_name"],
            repo_url=row["repo_url"],
            primary_endpoint=row["primary_endpoint"],
        )
