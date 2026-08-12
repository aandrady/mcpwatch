"""The metrics report — plan §4, with its denominators.

Every figure here is paired with what it does not cover. That is not modesty:
this project's headline is a base rate, and a base rate without its denominator
is a number that will be quoted wrong. The auth-required population, the
nondeterministic quarantine, and the servers that never install are all part of
the result.

**Layer 1 and Layer 2 answer different questions and must not be averaged.**
Layer 1 has years of retrospective history from the registry's own ``/versions``
endpoint. Layer 2 begins at the first live probe and cannot be backfilled, so
every Layer-2 figure carries the number of days it actually covers.
:doc:`FRAMING` rule 5 forbids annualising a Layer-2 rate, and
:attr:`Metrics.observation_days` exists so a reader can see why.
"""

from dataclasses import dataclass, field

from mcpwatch.diff import ChangeSet, SeverityFlag
from mcpwatch.store import Corpus, JsonValue, Layer, ObservationStatus, from_iso, utcnow

__all__ = ["Coverage", "Metrics", "collect_coverage", "summarise_changesets"]


@dataclass
class Coverage:
    """What the observatory can and cannot see, counted rather than asserted."""

    servers_tracked: int = 0
    layer2_targets: int = 0
    layer2_ok: int = 0
    layer2_auth_required: int = 0
    layer2_unreachable: int = 0
    layer2_quarantined: int = 0
    stdio_enumerated: int = 0
    stdio_attempted: int = 0

    @property
    def reachable_rate(self) -> float:
        """Fraction of Layer-2 targets that yielded a usable manifest."""
        return self.layer2_ok / self.layer2_targets if self.layer2_targets else 0.0

    def as_json(self) -> dict[str, JsonValue]:
        """Render for the report."""
        return {
            "servers_tracked": self.servers_tracked,
            "layer2_targets": self.layer2_targets,
            "layer2_ok": self.layer2_ok,
            "layer2_auth_required": self.layer2_auth_required,
            "layer2_unreachable": self.layer2_unreachable,
            "layer2_quarantined_nondeterministic": self.layer2_quarantined,
            "stdio_enumerated": self.stdio_enumerated,
            "stdio_attempted": self.stdio_attempted,
            "reachable_rate": round(self.reachable_rate, 4),
            "blind_spots": [
                "Servers requiring credentials are never probed; MCPWatch supplies none.",
                "Servers whose two probes disagree are quarantined from mutation statistics.",
                "Package servers are sampled, not enumerated in full; see the WP8 frame.",
                "Registry churn means the population is not a fixed cohort between runs.",
            ],
        }


@dataclass
class Metrics:
    """Mutation figures for one layer, with the window they cover."""

    layer: str
    observation_days: float
    """Days we have been *collecting* this layer. Never annualise a Layer-2 rate."""

    history_span_days: float = 0.0
    """Days the layer's records actually span.

    Different from :attr:`observation_days` and the difference is the whole
    two-layer design. Layer 1 was collected for days but spans the registry's
    entire published history, because the registry exposes it and WP5 backfilled
    all of it. Layer 2 spans exactly as long as it has been collected, because
    nothing can reconstruct a tool manifest from before the first probe.
    Reporting only the collection window would understate Layer 1 by two orders
    of magnitude.
    """
    servers: int = 0
    transitions: int = 0
    changed: int = 0
    flagged: int = 0
    by_flag: dict[str, int] = field(default_factory=dict)
    by_kind: dict[str, int] = field(default_factory=dict)
    servers_changed: int = 0
    quarantined_transitions: int = 0
    gap_days: list[float] = field(default_factory=list)

    @property
    def mutation_rate(self) -> float:
        """Fraction of tracked servers observed changing at all in the window."""
        return self.servers_changed / self.servers if self.servers else 0.0

    @property
    def flagged_rate(self) -> float:
        """Fraction of changed transitions carrying a severity flag."""
        return self.flagged / self.changed if self.changed else 0.0

    def time_to_first_change(self) -> dict[str, JsonValue]:
        """Quantiles of the gap between consecutive observed states."""
        if not self.gap_days:
            return {}
        ordered = sorted(self.gap_days)

        def at(fraction: float) -> float:
            return round(ordered[min(int(len(ordered) * fraction), len(ordered) - 1)], 3)

        quantiles: dict[str, JsonValue] = {
            "p10": at(0.10),
            "p25": at(0.25),
            "median": at(0.50),
            "p75": at(0.75),
            "p90": at(0.90),
            "max": round(ordered[-1], 3),
        }
        return quantiles

    def as_json(self) -> dict[str, JsonValue]:
        """Render for the report."""
        return {
            "layer": self.layer,
            "observation_days": round(self.observation_days, 2),
            "history_span_days": round(self.history_span_days, 2),
            "servers": self.servers,
            "servers_changed": self.servers_changed,
            "transitions": self.transitions,
            "transitions_with_changes": self.changed,
            "transitions_flagged": self.flagged,
            "transitions_quarantined": self.quarantined_transitions,
            "mutation_rate": round(self.mutation_rate, 4),
            "flagged_rate": round(self.flagged_rate, 4),
            "gap_days": dict(self.time_to_first_change()),
            "by_flag": dict(sorted(self.by_flag.items())),
            "by_kind": dict(sorted(self.by_kind.items(), key=lambda kv: -kv[1])[:15]),
            # Repeated on every Layer-2 block rather than stated once, because a
            # figure gets quoted apart from its report.
            "caveat": (
                "Layer 2 cannot be backfilled; this covers "
                f"{self.observation_days:.1f} days and must not be annualised."
                if self.layer == "manifest"
                else "Layer 1 is retrospective from the registry's own version history."
            ),
        }


def summarise_changesets(
    changesets: list[ChangeSet], *, layer: str, days: float, span: float = 0.0
) -> Metrics:
    """Fold ChangeSets into one layer's metrics."""
    metrics = Metrics(layer=layer, observation_days=days, history_span_days=span)
    servers: set[str] = set()
    changed_servers: set[str] = set()

    for changeset in changesets:
        metrics.transitions += 1
        servers.add(changeset.server_key)
        if changeset.quarantined:
            metrics.quarantined_transitions += 1
            continue
        if not changeset.changes:
            continue
        metrics.changed += 1
        changed_servers.add(changeset.server_key)
        gap = changeset.gap_days
        if gap is not None:
            metrics.gap_days.append(gap)
        if changeset.flags:
            metrics.flagged += 1
            for flag in changeset.flags:
                metrics.by_flag[str(flag)] = metrics.by_flag.get(str(flag), 0) + 1
        for kind in changeset.kinds:
            metrics.by_kind[str(kind)] = metrics.by_kind.get(str(kind), 0) + 1

    metrics.servers = len(servers)
    metrics.servers_changed = len(changed_servers)
    return metrics


def collect_coverage(corpus: Corpus) -> Coverage:
    """Count what the observatory reached, and what it did not."""
    conn = corpus.index.connection
    coverage = Coverage()
    coverage.servers_tracked = conn.execute("SELECT count(*) FROM server").fetchone()[0]

    # The most recent completed manifest cycle, which is what a coverage claim
    # is about — an average over cycles would blur a collector that broke.
    run = conn.execute(
        """
        SELECT run_id FROM run
        WHERE collector = 'manifest' AND finished_at IS NOT NULL
        ORDER BY started_at DESC LIMIT 1
        """
    ).fetchone()
    if run is not None:
        rows = conn.execute(
            "SELECT status, count(*) FROM observation WHERE run_id = ? GROUP BY status",
            (run["run_id"],),
        ).fetchall()
        counts = {row[0]: row[1] for row in rows}
        coverage.layer2_targets = sum(counts.values())
        coverage.layer2_ok = counts.get(str(ObservationStatus.OK), 0)
        coverage.layer2_auth_required = counts.get(str(ObservationStatus.AUTH_REQUIRED), 0)
        coverage.layer2_quarantined = counts.get(str(ObservationStatus.NONDETERMINISTIC), 0)
        coverage.layer2_unreachable = counts.get(
            str(ObservationStatus.UNREACHABLE), 0
        ) + counts.get(str(ObservationStatus.TIMEOUT), 0)

    sandbox = conn.execute(
        """
        SELECT run_id FROM run
        WHERE collector = 'sandbox' AND finished_at IS NOT NULL
        ORDER BY started_at DESC LIMIT 1
        """
    ).fetchone()
    if sandbox is not None:
        rows = conn.execute(
            "SELECT status, count(*) FROM observation WHERE run_id = ? GROUP BY status",
            (sandbox["run_id"],),
        ).fetchall()
        counts = {row[0]: row[1] for row in rows}
        coverage.stdio_attempted = sum(counts.values())
        coverage.stdio_enumerated = counts.get(str(ObservationStatus.OK), 0)
    return coverage


def observation_days(corpus: Corpus, layer: Layer) -> float:
    """How long this layer has actually been collected.

    Measured from the first observation rather than from a hardcoded start date,
    so the figure stays true if collection is ever interrupted and resumed.
    """
    row = corpus.index.connection.execute(
        "SELECT min(observed_at) FROM observation WHERE layer = ?", (str(layer),)
    ).fetchone()
    if row is None or row[0] is None:
        return 0.0
    return (utcnow() - from_iso(row[0])).total_seconds() / 86400


def history_span_days(corpus: Corpus, layer: Layer) -> float:
    """How long this layer's records span, which is not how long we collected.

    Keyed on ``effective_at``: for Layer 1 that is the registry's own
    ``publishedAt``, so the span reaches back years despite days of collection.
    For Layer 2 it falls back to ``observed_at`` and the two figures agree, which
    is itself the point — nothing can reconstruct a manifest from before the
    first probe.
    """
    row = corpus.index.connection.execute(
        "SELECT min(effective_at), max(effective_at) FROM observation WHERE layer = ?",
        (str(layer),),
    ).fetchone()
    if row is None or row[0] is None or row[1] is None:
        return 0.0
    return (from_iso(row[1]) - from_iso(row[0])).total_seconds() / 86400


def flag_glossary() -> dict[str, str]:
    """What each severity flag means, for a reader who has not read WP6."""
    return {
        str(
            SeverityFlag.NETWORK_PARAM_ADDED
        ): "a parameter that can address a network host appeared",
        str(SeverityFlag.FILESYSTEM_PARAM_ADDED): "a parameter naming a path appeared",
        str(SeverityFlag.CREDENTIAL_PARAM_ADDED): "a parameter that looks like a secret appeared",
        str(SeverityFlag.IMPERATIVE_LANGUAGE_ADDED): "text addressed to the model appeared",
        str(SeverityFlag.TOOL_COUNT_GREW): "the server exposes more tools than before",
        str(SeverityFlag.DESTRUCTIVE_HINT_CLEARED): "a destructive-action warning was removed",
        str(SeverityFlag.READONLY_HINT_SET): "a read-only claim appeared",
        str(SeverityFlag.DESCRIPTION_GREW_SHARPLY): "a description grew markedly longer",
        str(SeverityFlag.ENDPOINT_OR_REPO_MOVED): "the endpoint or repository URL changed",
    }
