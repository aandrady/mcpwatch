"""Corpus health checks — proving the collectors ran, not just scheduling them.

The project's entire value is an unbroken daily time series, and the worst
realistic outcome is a collector that fails silently for two weeks. Automation
without detection is how that happens, so this exists to make a broken collector
*loud*.

Run it from a timer. A non-zero exit marks the systemd unit failed, which shows
up in ``systemctl --user list-units --failed`` without needing a mail transport
or an external alerting service configured.

Every check is derived from the corpus itself rather than from a side-channel
log, so it stays true even if the collector died before it could report anything.
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from mcpwatch.store import Corpus, JsonValue, Layer, ObservationStatus, from_iso, utcnow

__all__ = ["Check", "HealthReport", "check_corpus", "main"]

MAX_AGE_HOURS = {"registry": 36.0, "manifest": 36.0}
"""How stale a collector's last success may be before it counts as a gap.

Both run daily, so 36h tolerates one missed run plus clock drift while still
catching a collector that has genuinely stopped.
"""

MIN_COVERAGE_RATIO = 0.90
"""A run seeing under this fraction of the previous run's servers is suspect.

The registry grows; it does not shrink by 10% overnight. A drop that large means
the crawler broke, not that the ecosystem did.
"""

MAX_NONDETERMINISTIC_RATIO = 0.10
"""Above this, suspect our own normalization before blaming the servers."""


@dataclass(frozen=True, slots=True)
class Check:
    """One health check outcome."""

    name: str
    ok: bool
    detail: str

    def render(self) -> str:
        """One-line human-readable form."""
        return f"[{'OK  ' if self.ok else 'FAIL'}] {self.name}: {self.detail}"


@dataclass
class HealthReport:
    """The full set of checks for one corpus."""

    checks: list[Check] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when every check passed."""
        return all(check.ok for check in self.checks)

    @property
    def failures(self) -> list[Check]:
        """Only the failing checks."""
        return [check for check in self.checks if not check.ok]

    def add(self, name: str, ok: bool, detail: str) -> None:
        """Append a check result."""
        self.checks.append(Check(name=name, ok=ok, detail=detail))

    def as_json(self) -> dict[str, JsonValue]:
        """Render for machine consumption."""
        return {
            "ok": self.ok,
            "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in self.checks],
        }


def _last_success(corpus: Corpus, collector: str) -> tuple[str | None, dict[str, JsonValue]]:
    """Return the most recent completed run's start time and its stats."""
    row = corpus.index.connection.execute(
        """
        SELECT started_at, stats_json FROM run
        WHERE collector = ? AND finished_at IS NOT NULL
        ORDER BY started_at DESC LIMIT 1
        """,
        (collector,),
    ).fetchone()
    if row is None:
        return None, {}
    stats = json.loads(row["stats_json"]) if row["stats_json"] else {}
    return row["started_at"], stats


def check_corpus(corpus: Corpus) -> HealthReport:
    """Run every health check against a corpus."""
    report = HealthReport()
    now = utcnow()

    for collector, max_age in MAX_AGE_HOURS.items():
        started, stats = _last_success(corpus, collector)
        if started is None:
            report.add(f"{collector}.freshness", False, "no completed run has ever finished")
            continue
        age = now - from_iso(started)
        report.add(
            f"{collector}.freshness",
            age <= timedelta(hours=max_age),
            f"last success {age.total_seconds() / 3600:.1f}h ago (limit {max_age:.0f}h)",
        )

        seen = stats.get("servers_seen") if collector == "registry" else stats.get("probed")
        if isinstance(seen, int):
            report.add(f"{collector}.volume", seen > 0, f"{seen} servers in the last run")

    # A run left open is how a collector says it died mid-cycle. One that is
    # still running is normal, so only flag runs older than any plausible cycle.
    stale_open = corpus.index.connection.execute(
        "SELECT count(*) AS n FROM run WHERE finished_at IS NULL AND started_at < ?",
        ((now - timedelta(hours=12)).isoformat(timespec="microseconds"),),
    ).fetchone()["n"]
    report.add(
        "runs.no_stale_open",
        stale_open == 0,
        f"{stale_open} run(s) started >12h ago and never finished",
    )

    _check_coverage(corpus, report)
    _check_nondeterminism(corpus, report)

    missing = corpus.missing_blobs()
    report.add(
        "corpus.blobs_present",
        not missing,
        f"{len(missing)} referenced blob(s) missing from the store",
    )
    return report


def _check_coverage(corpus: Corpus, report: HealthReport) -> None:
    """Compare the last two registry runs for a sudden drop in servers seen."""
    rows = corpus.index.connection.execute(
        """
        SELECT stats_json FROM run
        WHERE collector = 'registry' AND finished_at IS NOT NULL
          AND coalesce(json_extract(stats_json, '$.mode'), '') = 'full'
        ORDER BY started_at DESC LIMIT 2
        """
    ).fetchall()
    if len(rows) < 2:
        report.add("registry.coverage", True, "fewer than two full crawls to compare yet")
        return
    latest, previous = (json.loads(r["stats_json"] or "{}") for r in rows)
    now_seen = latest.get("servers_seen") or 0
    was_seen = previous.get("servers_seen") or 0
    if was_seen == 0:
        report.add("registry.coverage", True, "no previous baseline")
        return
    ratio = now_seen / was_seen
    report.add(
        "registry.coverage",
        ratio >= MIN_COVERAGE_RATIO,
        f"{now_seen} vs {was_seen} servers ({ratio:.1%} of previous full crawl)",
    )


def _check_nondeterminism(corpus: Corpus, report: HealthReport) -> None:
    """Track the quarantined population, and flag it if it looks like our bug."""
    row = corpus.index.connection.execute(
        """
        SELECT
          sum(status = ?) AS nd,
          sum(status IN (?, ?)) AS usable
        FROM observation
        WHERE layer = ?
          AND run_id = (
            SELECT run_id FROM run WHERE collector = 'manifest' AND finished_at IS NOT NULL
            ORDER BY started_at DESC LIMIT 1
          )
        """,
        (
            str(ObservationStatus.NONDETERMINISTIC),
            str(ObservationStatus.OK),
            str(ObservationStatus.NONDETERMINISTIC),
            str(Layer.MANIFEST),
        ),
    ).fetchone()
    nondeterministic = row["nd"] or 0
    usable = row["usable"] or 0
    if not usable:
        report.add("manifest.nondeterminism", True, "no manifest observations yet")
        return
    ratio = nondeterministic / usable
    report.add(
        "manifest.nondeterminism",
        ratio <= MAX_NONDETERMINISTIC_RATIO,
        f"{nondeterministic}/{usable} quarantined ({ratio:.1%}); "
        f"above {MAX_NONDETERMINISTIC_RATIO:.0%} suspect our normalization first",
    )


def _default_corpus_root() -> Path:
    override = os.environ.get("MCPWATCH_CORPUS")
    return Path(override) if override else Path.home() / "mcpwatch-corpus"


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns 0 if healthy, 1 if any check failed."""
    parser = argparse.ArgumentParser(
        prog="python -m mcpwatch.health",
        description="Check that MCPWatch's collectors are actually collecting.",
    )
    parser.add_argument("--corpus", type=Path, default=_default_corpus_root())
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    args = parser.parse_args(argv)

    with Corpus(args.corpus) as corpus:
        report = check_corpus(corpus)

    if args.json:
        print(json.dumps(report.as_json(), indent=2, sort_keys=True))
    else:
        for check in report.checks:
            print(check.render())
    if not report.ok:
        names = ", ".join(c.name for c in report.failures)
        print(f"\nUNHEALTHY: {names}", file=sys.stderr)
    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
