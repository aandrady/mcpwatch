"""Value types for the diff engine.

A :class:`ChangeSet` is what WP7 classifies, so everything it needs to make a
judgement has to be *in* it: the before and after values, a token-level view of
text that moved, and the position in history. WP7 re-reading blobs to decide
what a change was would make classification depend on the corpus staying
byte-identical, which is a coupling worth avoiding.

Nothing here scores or judges. ``ChangeKind`` names what moved,
:class:`SeverityFlag` marks what a cheap deterministic rule found worth a second
look, and the verdict says whether we are even looking at the same server. What
any of it *means* is WP7's problem.
"""

import sqlite3
from dataclasses import dataclass, field
from enum import StrEnum

from mcpwatch.store import JsonValue, Layer

__all__ = [
    "Change",
    "ChangeKind",
    "ChangeSet",
    "SeverityFlag",
    "TextDiff",
    "Verdict",
    "change_id",
]


class Verdict(StrEnum):
    """What happened to a server's *identity* between two observations.

    The confound BUILD-PLAN §3 names as the second-order risk: a server that
    changes its registry name looks like a disappearance plus an unrelated new
    server, and the mutation between them vanishes from the statistics. These
    are the five outcomes that have to be told apart before any base rate is
    computed.
    """

    NEW = "new"
    """First time this server has been observed on this layer."""

    MUTATED = "mutated"
    """Same identity, changed content. The ordinary case."""

    REPLACED = "replaced"
    """Same registry name, different repository or endpoint.

    The suspicious one: whoever holds the name is now pointing consumers at code
    or traffic from somewhere else. Pinning a name does not protect against it.
    """

    RENAMED = "renamed"
    """Different registry name, same repository and tool fingerprint.

    Recognized so the mutation across the rename is kept rather than split into
    a disappearance and a creation.
    """

    DISAPPEARED = "disappeared"
    """Present before, absent or withdrawn now."""

    RETURNED = "returned"
    """Absent, then present again under the same name.

    Worth its own verdict rather than folding into MUTATED: the gap is a window
    in which the name could have changed hands entirely.
    """


class ChangeKind(StrEnum):
    """What moved between two observations.

    Deliberately finer-grained than the taxonomy WP7 will apply. A description
    edit and a new filesystem parameter are both "changed" to a text differ and
    entirely different events to a security reviewer, and collapsing them here
    would throw away the distinction before anyone could use it.
    """

    # --- server level, Layer 1 -------------------------------------------
    SERVER_DESCRIPTION_CHANGED = "server_description_changed"
    ENDPOINT_CHANGED = "endpoint_changed"
    REPOSITORY_CHANGED = "repository_changed"
    PACKAGE_CHANGED = "package_changed"
    PACKAGE_IDENTITY_CHANGED = "package_identity_changed"
    VERSION_BUMPED = "version_bumped"
    AUTH_REQUIREMENT_CHANGED = "auth_requirement_changed"
    REGISTRY_STATUS_CHANGED = "registry_status_changed"
    SERVER_FIELD_CHANGED = "server_field_changed"
    """A field of the registry record this engine does not model explicitly.

    Kept rather than dropped: the registry schema has moved before and will
    again, and a field nobody anticipated is exactly the one worth surfacing.
    """

    # --- tool level, Layer 2 ---------------------------------------------
    TOOL_ADDED = "tool_added"
    TOOL_REMOVED = "tool_removed"
    TOOL_RENAMED = "tool_renamed"
    TOOL_DESCRIPTION_CHANGED = "tool_description_changed"
    SCHEMA_PARAM_ADDED = "schema_param_added"
    SCHEMA_PARAM_REMOVED = "schema_param_removed"
    PARAM_TYPE_CHANGED = "param_type_changed"
    PARAM_BECAME_REQUIRED = "param_became_required"
    PARAM_BECAME_OPTIONAL = "param_became_optional"
    PARAM_DESCRIPTION_CHANGED = "param_description_changed"
    ANNOTATION_CHANGED = "annotation_changed"
    EXECUTION_CHANGED = "execution_changed"

    # --- other Layer-2 surfaces ------------------------------------------
    PROMPT_ADDED = "prompt_added"
    PROMPT_REMOVED = "prompt_removed"
    PROMPT_CHANGED = "prompt_changed"
    RESOURCE_ADDED = "resource_added"
    RESOURCE_REMOVED = "resource_removed"
    SERVER_INFO_CHANGED = "server_info_changed"
    CAPABILITIES_CHANGED = "capabilities_changed"
    MANIFEST_FIELD_CHANGED = "manifest_field_changed"


class SeverityFlag(StrEnum):
    """Cheap deterministic triage marks. Not a verdict, and not a score.

    These exist so WP7 can order a queue of tens of thousands of ChangeSets by
    something better than recency. Every one is a *reason to look*, never a
    finding: an imperative sentence in a description is how a prompt injection
    reads and also how half of all honest documentation reads.
    """

    NETWORK_PARAM_ADDED = "network_param_added"
    FILESYSTEM_PARAM_ADDED = "filesystem_param_added"
    CREDENTIAL_PARAM_ADDED = "credential_param_added"
    IMPERATIVE_LANGUAGE_ADDED = "imperative_language_added"
    TOOL_COUNT_GREW = "tool_count_grew"
    DESTRUCTIVE_HINT_CLEARED = "destructive_hint_cleared"
    READONLY_HINT_SET = "readonly_hint_set"
    DESCRIPTION_GREW_SHARPLY = "description_grew_sharply"
    ENDPOINT_OR_REPO_MOVED = "endpoint_or_repo_moved"


@dataclass(frozen=True, slots=True)
class TextDiff:
    """A token-level view of one text change.

    Carried so WP7 can classify without re-reading blobs. ``similarity`` is a
    0..1 ratio over tokens, which is what separates a typo fix from a rewrite
    far more reliably than length does.
    """

    added: tuple[str, ...]
    removed: tuple[str, ...]
    similarity: float

    def as_json(self) -> dict[str, JsonValue]:
        """Render for machine consumption."""
        return {
            "added": list(self.added),
            "removed": list(self.removed),
            "similarity": round(self.similarity, 4),
        }


@dataclass(frozen=True, slots=True)
class Change:
    """One typed difference between two observations of the same server."""

    kind: ChangeKind
    path: str
    """Where it happened, e.g. ``tools/read_file/inputSchema/properties/path``."""

    before: JsonValue = None
    after: JsonValue = None
    tool: str | None = None
    detail: str | None = None
    text: TextDiff | None = None

    def as_json(self) -> dict[str, JsonValue]:
        """Render for machine consumption."""
        payload: dict[str, JsonValue] = {
            "kind": str(self.kind),
            "path": self.path,
            "before": self.before,
            "after": self.after,
        }
        if self.tool is not None:
            payload["tool"] = self.tool
        if self.detail is not None:
            payload["detail"] = self.detail
        if self.text is not None:
            payload["text"] = self.text.as_json()
        return payload


def change_id(server_key: str, from_obs: int | None, to_obs: int) -> str:
    """A stable identifier for one ChangeSet.

    Derived rather than stored. ChangeSets are a *reading* of the corpus, not
    part of it, so the engine writes nothing back — but WP7 still needs to
    attach classifications and human adjudications to something durable. Keying
    on the observation ids makes the identifier reproducible from the corpus
    alone: recompute the diff a year later and the id comes out the same.
    """
    import hashlib

    material = f"{server_key}|{from_obs if from_obs is not None else '-'}|{to_obs}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True, slots=True)
class ChangeSet:
    """Everything that moved for one server between two consecutive observations."""

    change_id: str
    server_key: str
    layer: Layer
    verdict: Verdict
    to_obs_id: int
    to_effective_at: str
    to_norm_sha: str | None
    from_obs_id: int | None = None
    from_effective_at: str | None = None
    from_norm_sha: str | None = None
    changes: tuple[Change, ...] = ()
    flags: tuple[SeverityFlag, ...] = ()
    quarantined: bool = False
    """The server has been recorded nondeterministic at least once.

    Not excluded here — recorded, so that a base rate can exclude it and an
    investigator can still look. A server whose manifest differs between two
    probes minutes apart cannot support a claim that it changed overnight.
    """

    predecessor_key: str | None = None
    """The server this one was renamed from, when the verdict is RENAMED."""

    @property
    def gap_days(self) -> float | None:
        """Days between the two observations, or None for a first sighting."""
        if self.from_effective_at is None:
            return None
        from mcpwatch.store import from_iso

        delta = from_iso(self.to_effective_at) - from_iso(self.from_effective_at)
        return delta.total_seconds() / 86400

    @property
    def kinds(self) -> tuple[ChangeKind, ...]:
        """Distinct change kinds present, in first-seen order."""
        seen: dict[ChangeKind, None] = {}
        for change in self.changes:
            seen.setdefault(change.kind, None)
        return tuple(seen)

    def as_json(self) -> dict[str, JsonValue]:
        """Render one JSONL record."""
        gap = self.gap_days
        return {
            "change_id": self.change_id,
            "server_key": self.server_key,
            "layer": str(self.layer),
            "verdict": str(self.verdict),
            "from_obs_id": self.from_obs_id,
            "to_obs_id": self.to_obs_id,
            "from_effective_at": self.from_effective_at,
            "to_effective_at": self.to_effective_at,
            "from_norm_sha": self.from_norm_sha,
            "to_norm_sha": self.to_norm_sha,
            "gap_days": None if gap is None else round(gap, 4),
            "quarantined": self.quarantined,
            "predecessor_key": self.predecessor_key,
            "kinds": [str(k) for k in self.kinds],
            "flags": [str(f) for f in self.flags],
            "changes": [c.as_json() for c in self.changes],
        }


@dataclass
class DiffStats:
    """Counters for one diff run."""

    servers: int = 0
    observations: int = 0
    changesets: int = 0
    empty_changesets: int = 0
    quarantined_servers: int = 0
    quarantined_changesets: int = 0
    unreadable_blobs: int = 0
    by_verdict: dict[str, int] = field(default_factory=dict)
    by_kind: dict[str, int] = field(default_factory=dict)
    by_flag: dict[str, int] = field(default_factory=dict)

    def as_json(self) -> dict[str, JsonValue]:
        """Render as a plain JSON-safe mapping."""
        return {
            "servers": self.servers,
            "observations": self.observations,
            "changesets": self.changesets,
            "empty_changesets": self.empty_changesets,
            "quarantined_servers": self.quarantined_servers,
            "quarantined_changesets": self.quarantined_changesets,
            "unreadable_blobs": self.unreadable_blobs,
            "by_verdict": dict(sorted(self.by_verdict.items())),
            "by_kind": _by_frequency(self.by_kind),
            "by_flag": _by_frequency(self.by_flag),
        }


def _by_frequency(counts: dict[str, int]) -> dict[str, JsonValue]:
    """Order a tally by descending count, ties broken by name."""
    ordered: dict[str, JsonValue] = {}
    for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        ordered[name] = count
    return ordered


def row_layer(row: sqlite3.Row) -> Layer:
    """Read the layer out of an observation row."""
    return Layer(row["layer"])
