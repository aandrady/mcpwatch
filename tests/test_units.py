"""Invariants between the systemd units and the code they run.

Unit files are deployed by copying, not imported, so nothing else notices when
one drifts away from an assumption the code makes about it.
"""

from pathlib import Path

from mcpwatch.collect.manifest import DEFAULT_DEADLINE_SECONDS

UNITS = Path(__file__).resolve().parent.parent / "deploy" / "systemd"

STARTUP_MARGIN_SECONDS = 900
"""Time outside the deadline's clock: uv start-up, loading targets, closing the run."""


def directives(unit: str, key: str) -> list[str]:
    """Every value given for ``key`` in a unit file, comments ignored."""
    values: list[str] = []
    for line in (UNITS / unit).read_text(encoding="utf-8").splitlines():
        name, sep, value = line.partition("=")
        if sep and not line.lstrip().startswith("#") and name.strip() == key:
            values.extend(value.split())
    return values


def test_the_cycle_deadline_fires_before_systemd_kills_the_cycle():
    """Our deadline closes the run and keeps what it collected; SIGTERM does neither."""
    (timeout,) = directives("mcpwatch-manifest.service", "TimeoutStartSec")
    assert int(timeout) - DEFAULT_DEADLINE_SECONDS >= STARTUP_MARGIN_SECONDS


def test_the_health_check_waits_for_the_night_it_is_checking():
    """A cycle still running at 06:00 must be judged when it ends, not a day later."""
    after = directives("mcpwatch-health.service", "After")
    assert "mcpwatch-manifest.service" in after
    assert "mcpwatch-backup.service" in after
