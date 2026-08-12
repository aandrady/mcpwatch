"""What the backfilled Layer-1 history actually says.

The first real measurement this project can make: how often published MCP
servers change, how fast, and which parts of their published identity move. It
runs entirely off the corpus — no network, no state — so it can be re-run at any
time and produce the same numbers from the same data.

Deliberately *not* a classifier. It reports which fields differ between
consecutive published versions and how far apart those versions were; deciding
whether a given change is benign maintenance or a rug pull is WP7's job, and
doing it here with ad-hoc heuristics would quietly become the thing everyone
cites. The one place this report takes a position is in surfacing repository and
endpoint swaps as their own list, because "same name, different code source" is
the change class WP7 should look at first.

Normalized documents are what get compared, so ordering noise and volatile keys
are already gone. Two consecutive versions differing only in ``publishedAt`` are
not counted as changing anything.
"""

import argparse
import datetime as dt
import json
import os
import statistics
import sys
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from mcpwatch.store import Corpus, JsonValue, from_iso, utcnow

__all__ = ["BackfillReport", "Transition", "build_report", "main"]

_META_KEY = "io.modelcontextprotocol.registry/official"

_INTERESTING_FIELDS = (
    "description",
    "title",
    "version",
    "repository",
    "remotes",
    "packages",
    "websiteUrl",
    "$schema",
)
"""Top-level ``server`` fields worth reporting on individually.

Anything else that changes is still counted, under its own name — the registry
schema has moved before and will again, and a field nobody thought to list is
exactly the one worth noticing.
"""

_HISTOGRAM_BUCKETS = ((1, "1"), (2, "2"), (3, "3"), (4, "4"), (9, "5-9"), (10**9, "10+"))

_INTERVAL_BUCKETS = (
    (1 / 24, "under 1h"),
    (1, "1h-1d"),
    (7, "1-7d"),
    (30, "7-30d"),
    (90, "30-90d"),
    (365, "90-365d"),
    (10**6, "over a year"),
)


@dataclass(frozen=True, slots=True)
class Transition:
    """One step from a server's published state to the next."""

    server_key: str
    from_version: str | None
    to_version: str | None
    from_published: str
    to_published: str
    fields: tuple[str, ...]

    @property
    def gap_days(self) -> float:
        """Days between the two publications."""
        delta = from_iso(self.to_published) - from_iso(self.from_published)
        return delta.total_seconds() / 86400

    def as_json(self) -> dict[str, JsonValue]:
        """Render for machine consumption."""
        return {
            "server_key": self.server_key,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "from_published": self.from_published,
            "to_published": self.to_published,
            "gap_days": round(self.gap_days, 3),
            "fields": list(self.fields),
        }


@dataclass
class BackfillReport:
    """Everything the report knows, in a form both humans and WP7 can read."""

    generated_at: str = ""
    servers_total: int = 0
    servers_with_history: int = 0
    servers_multi_version: int = 0
    versions_total: int = 0
    transitions_total: int = 0
    unchanged_transitions: int = 0
    restatements: int = 0
    withdrawn_servers: int = 0
    version_histogram: dict[str, int] = field(default_factory=dict)
    busiest_servers: list[tuple[str, int]] = field(default_factory=list)
    interval_days: dict[str, float] = field(default_factory=dict)
    interval_histogram: dict[str, int] = field(default_factory=dict)
    field_changes: dict[str, int] = field(default_factory=dict)
    endpoint_swaps: list[Transition] = field(default_factory=list)
    repository_swaps: list[Transition] = field(default_factory=list)
    package_identity_swaps: list[Transition] = field(default_factory=list)
    status_changes: dict[str, int] = field(default_factory=dict)

    def as_json(self) -> dict[str, JsonValue]:
        """Render for machine consumption, swap lists included in full."""
        return {
            "generated_at": self.generated_at,
            "population": {
                "servers_total": self.servers_total,
                "servers_with_history": self.servers_with_history,
                "servers_multi_version": self.servers_multi_version,
                "versions_total": self.versions_total,
                "transitions_total": self.transitions_total,
                "unchanged_transitions": self.unchanged_transitions,
                "restatements": self.restatements,
                "withdrawn_servers": self.withdrawn_servers,
            },
            "version_histogram": dict(self.version_histogram),
            "busiest_servers": [{"server_key": k, "versions": n} for k, n in self.busiest_servers],
            "interval_days": dict(self.interval_days),
            "interval_histogram": dict(self.interval_histogram),
            "field_changes": dict(self.field_changes),
            "status_changes": dict(self.status_changes),
            "endpoint_swaps": [t.as_json() for t in self.endpoint_swaps],
            "repository_swaps": [t.as_json() for t in self.repository_swaps],
            "package_identity_swaps": [t.as_json() for t in self.package_identity_swaps],
        }

    def render(self) -> str:
        """Render as Markdown."""
        return "\n".join(_render_sections(self))


def _server_of(document: JsonValue) -> Mapping[str, JsonValue]:
    """The ``server`` object of a stored registry entry."""
    if isinstance(document, dict):
        server = document.get("server")
        if isinstance(server, dict):
            return server
    return {}


def _meta_of(document: JsonValue) -> Mapping[str, JsonValue]:
    """The registry's own metadata block of a stored registry entry."""
    if isinstance(document, dict):
        meta = document.get("_meta")
        if isinstance(meta, dict):
            block = meta.get(_META_KEY)
            if isinstance(block, dict):
                return block
    return {}


def _text(value: JsonValue) -> str | None:
    return value.strip() or None if isinstance(value, str) else None


def _repo_url(server: Mapping[str, JsonValue]) -> str | None:
    repository = server.get("repository")
    if isinstance(repository, str):
        return _text(repository)
    if isinstance(repository, dict):
        return _text(repository.get("url"))
    return None


def _endpoints(server: Mapping[str, JsonValue]) -> frozenset[str]:
    """Every remote URL a version declares."""
    remotes = server.get("remotes")
    if not isinstance(remotes, list):
        return frozenset()
    urls = set()
    for remote in remotes:
        if isinstance(remote, dict):
            url = _text(remote.get("url"))
            if url is not None:
                urls.add(url)
    return frozenset(urls)


def _package_identities(server: Mapping[str, JsonValue]) -> frozenset[str]:
    """Which packages a version ships as, ignoring their version numbers.

    A package bumping its own version is ordinary. A server that starts shipping
    as a *different* package — different registry, different name — is the
    supply-chain equivalent of an endpoint swap.
    """
    packages = server.get("packages")
    if not isinstance(packages, list):
        return frozenset()
    identities = set()
    for package in packages:
        if not isinstance(package, dict):
            continue
        registry_type = _text(package.get("registryType")) or "?"
        identifier = _text(package.get("identifier")) or _text(package.get("name")) or "?"
        identities.add(f"{registry_type}:{identifier}")
    return frozenset(identities)


def changed_fields(before: JsonValue, after: JsonValue) -> tuple[str, ...]:
    """Which ``server`` fields differ between two published versions.

    Compares the full value of every key present in either version, so a field
    added or removed counts as a change. ``_meta`` is excluded: its timestamps
    move on every republish by construction, and treating that as a change would
    make every transition look like one.
    """
    old, new = _server_of(before), _server_of(after)
    names = set(old) | set(new)
    return tuple(sorted(name for name in names if old.get(name) != new.get(name)))


@dataclass(frozen=True, slots=True)
class _Version:
    """One stored version of one server: where it sits in time, and its content.

    The version *string* is deliberately not carried here — it comes out of the
    document when needed. Two rows can share a version string, and one row's
    string can be anything the publisher felt like typing; the publication
    timestamp is the only ordering this report trusts.
    """

    published_at: str
    norm_sha: str


def _version_rows(corpus: Corpus) -> Iterator[tuple[str, list[_Version]]]:
    """Yield each server's published versions, oldest first.

    Streamed one server at a time: the whole population is ~67,000 rows and
    every one of them needs its document loaded, so nothing is held that the
    next server does not need.
    """
    rows = corpus.index.connection.execute(
        """
        SELECT server_key, published_at, norm_sha FROM observation
        WHERE layer = 'registry' AND status = 'ok' AND published_at IS NOT NULL
        ORDER BY server_key, published_at, obs_id
        """
    )
    current: str | None = None
    batch: list[_Version] = []
    for row in rows:
        if row["server_key"] != current:
            if current is not None:
                yield current, batch
            current, batch = row["server_key"], []
        batch.append(_Version(published_at=row["published_at"], norm_sha=row["norm_sha"]))
    if current is not None:
        yield current, batch


def build_report(corpus: Corpus, *, swap_limit: int | None = None) -> BackfillReport:
    """Compute the report from the corpus.

    Args:
        corpus: The corpus to read.
        swap_limit: Keep at most this many entries in each swap list. ``None``
            keeps all of them, which is what WP7 wants.

    Returns:
        The completed :class:`BackfillReport`.
    """
    report = BackfillReport(generated_at=utcnow().isoformat())
    report.servers_total = corpus.index.count_servers()
    report.withdrawn_servers = corpus.index.connection.execute(
        "SELECT count(DISTINCT server_key) AS n FROM observation WHERE error_class = 'withdrawn'"
    ).fetchone()["n"]

    counts: list[int] = []
    intervals: list[float] = []

    for server_key, versions in _version_rows(corpus):
        report.servers_with_history += 1
        distinct = {v.published_at for v in versions}
        counts.append(len(distinct))
        report.versions_total += len(distinct)
        report.busiest_servers.append((server_key, len(distinct)))
        if len(distinct) > 1:
            report.servers_multi_version += 1

        previous: _Version | None = None
        previous_document: JsonValue = None
        for entry in versions:
            document = corpus.load_document(entry.norm_sha)
            if previous is not None:
                _record_transition(
                    report,
                    server_key,
                    previous,
                    previous_document,
                    entry,
                    document,
                    intervals,
                )
            previous, previous_document = entry, document

    report.busiest_servers.sort(key=lambda item: (-item[1], item[0]))
    report.busiest_servers = report.busiest_servers[:10]
    report.version_histogram = _histogram(counts)
    report.interval_days = _percentiles(intervals)
    report.interval_histogram = _bucket(intervals, _INTERVAL_BUCKETS)
    report.field_changes = dict(
        sorted(report.field_changes.items(), key=lambda item: (-item[1], item[0]))
    )
    if swap_limit is not None:
        report.endpoint_swaps = report.endpoint_swaps[:swap_limit]
        report.repository_swaps = report.repository_swaps[:swap_limit]
        report.package_identity_swaps = report.package_identity_swaps[:swap_limit]
    return report


def _record_transition(
    report: BackfillReport,
    server_key: str,
    previous: _Version,
    previous_document: JsonValue,
    entry: _Version,
    document: JsonValue,
    intervals: list[float],
) -> None:
    """Fold one consecutive pair of versions into the report."""
    report.transitions_total += 1
    if previous.published_at == entry.published_at:
        # Same publication timestamp, different content: the record was edited
        # in place rather than republished under a new version.
        report.restatements += 1
    else:
        intervals.append(
            (from_iso(entry.published_at) - from_iso(previous.published_at)).total_seconds() / 86400
        )

    fields = changed_fields(previous_document, document)
    if not fields:
        report.unchanged_transitions += 1
    for name in fields:
        report.field_changes[name] = report.field_changes.get(name, 0) + 1

    old_server, new_server = _server_of(previous_document), _server_of(document)
    old_status = _text(_meta_of(previous_document).get("status"))
    new_status = _text(_meta_of(document).get("status"))
    if old_status != new_status:
        key = f"{old_status or '?'} -> {new_status or '?'}"
        report.status_changes[key] = report.status_changes.get(key, 0) + 1

    transition = Transition(
        server_key=server_key,
        from_version=_text(old_server.get("version")),
        to_version=_text(new_server.get("version")),
        from_published=previous.published_at,
        to_published=entry.published_at,
        fields=fields,
    )
    if _endpoints(old_server) != _endpoints(new_server):
        report.endpoint_swaps.append(transition)
    if _repo_url(old_server) != _repo_url(new_server):
        report.repository_swaps.append(transition)
    if _package_identities(old_server) != _package_identities(new_server):
        report.package_identity_swaps.append(transition)


def _histogram(counts: Sequence[int]) -> dict[str, int]:
    """Bucket version counts the way the census reported them."""
    out = {label: 0 for _, label in _HISTOGRAM_BUCKETS}
    for count in counts:
        for ceiling, label in _HISTOGRAM_BUCKETS:
            if count <= ceiling:
                out[label] += 1
                break
    return out


def _bucket(values: Sequence[float], buckets: Sequence[tuple[float, str]]) -> dict[str, int]:
    """Bucket values by an ordered list of ceilings."""
    out = {label: 0 for _, label in buckets}
    for value in values:
        for ceiling, label in buckets:
            if value <= ceiling:
                out[label] += 1
                break
    return out


def _percentiles(values: Sequence[float]) -> dict[str, float]:
    """Summarize a distribution. Medians, not means: the tail is enormous."""
    if not values:
        return {}
    ordered = sorted(values)
    return {
        "min": round(ordered[0], 3),
        "p10": round(_quantile(ordered, 0.10), 3),
        "p25": round(_quantile(ordered, 0.25), 3),
        "median": round(statistics.median(ordered), 3),
        "p75": round(_quantile(ordered, 0.75), 3),
        "p90": round(_quantile(ordered, 0.90), 3),
        "max": round(ordered[-1], 3),
        "mean": round(statistics.fmean(ordered), 3),
    }


def _quantile(ordered: Sequence[float], fraction: float) -> float:
    """Nearest-rank quantile of an already-sorted sequence."""
    index = min(len(ordered) - 1, int(fraction * len(ordered)))
    return ordered[index]


def _render_sections(report: BackfillReport) -> Iterator[str]:
    """Yield the report's Markdown, section by section."""
    yield "# MCPWatch — Layer-1 retrospective"
    yield ""
    yield f"Generated {report.generated_at} from the corpus. No network access; re-runnable."
    yield ""
    yield "## Population"
    yield ""
    yield "| Measure | Value |"
    yield "|---|---:|"
    yield f"| Servers tracked | {report.servers_total:,} |"
    yield f"| Servers with backfilled history | {report.servers_with_history:,} |"
    yield f"| Servers with more than one version | {report.servers_multi_version:,} |"
    yield f"| Published versions | {report.versions_total:,} |"
    yield f"| Version transitions | {report.transitions_total:,} |"
    yield f"| ...of which changed nothing observable | {report.unchanged_transitions:,} |"
    yield f"| ...of which were in-place restatements | {report.restatements:,} |"
    yield f"| Servers withdrawn from the registry | {report.withdrawn_servers:,} |"
    yield ""
    yield "An in-place restatement is a record edited without a new version number —"
    yield "a change no consumer pinning a version would ever see."
    yield ""
    yield '"Changed nothing observable" means nothing moved in the `server` record —'
    yield "the registry's own `_meta` may still have moved, and a status flip is exactly"
    yield "that. `_meta` is excluded from the field counts below because its timestamps"
    yield "move on every republish by construction; status changes are reported"
    yield "separately. Expect these two rows to track each other closely: a transition"
    yield "that leaves the published record identical is, in practice, a record edited"
    yield "in place rather than a genuinely new version."
    yield ""
    yield "## Versions per server"
    yield ""
    yield "| Versions | Servers |"
    yield "|---|---:|"
    for label, count in report.version_histogram.items():
        yield f"| {label} | {count:,} |"
    yield ""
    if report.busiest_servers:
        yield "Busiest publishers:"
        yield ""
        for server_key, count in report.busiest_servers:
            yield f"- `{server_key}` — {count:,} versions"
        yield ""
    yield "## Time between versions"
    yield ""
    if report.interval_days:
        yield "| Quantile | Days |"
        yield "|---|---:|"
        for label, value in report.interval_days.items():
            yield f"| {label} | {value:,.2f} |"
        yield ""
        yield "| Gap | Transitions |"
        yield "|---|---:|"
        for label, count in report.interval_histogram.items():
            yield f"| {label} | {count:,} |"
    else:
        yield "No multi-version servers in the corpus yet."
    yield ""
    yield "## What changes between versions"
    yield ""
    yield "Fields of the registry record that differ across a transition, counted"
    yield "over normalized documents so key order and volatile fields are already gone."
    yield ""
    yield "| Field | Transitions changing it | Share |"
    yield "|---|---:|---:|"
    total = max(1, report.transitions_total)
    for name, count in report.field_changes.items():
        flag = "" if name in _INTERESTING_FIELDS else " *"
        yield f"| `{name}`{flag} | {count:,} | {count / total:.1%} |"
    yield ""
    yield "`*` marks a field this report did not anticipate — worth a look."
    yield ""
    if report.status_changes:
        yield "Registry status transitions:"
        yield ""
        for label, count in sorted(report.status_changes.items()):
            yield f"- `{label}` — {count:,}"
        yield ""
    yield "## Endpoint and repository swaps"
    yield ""
    yield "The highest-priority subset for WP7. A server keeping its name while"
    yield "changing where its code or its traffic goes is the shape of a rug pull,"
    yield "and it is the one change class visible at Layer 1 without tool-level data."
    yield ""
    yield "| Swap | Transitions | Servers |"
    yield "|---|---:|---:|"
    for label, swaps in (
        ("Remote endpoint set changed", report.endpoint_swaps),
        ("Repository URL changed", report.repository_swaps),
        ("Package identity changed", report.package_identity_swaps),
    ):
        servers = len({t.server_key for t in swaps})
        yield f"| {label} | {len(swaps):,} | {servers:,} |"
    yield ""
    for label, swaps in (
        ("endpoint", report.endpoint_swaps),
        ("repository", report.repository_swaps),
    ):
        if not swaps:
            continue
        yield f"First {min(10, len(swaps))} {label} swaps:"
        yield ""
        for transition in swaps[:10]:
            yield (
                f"- `{transition.server_key}` "
                f"{transition.from_version} → {transition.to_version} "
                f"after {transition.gap_days:.1f}d"
            )
        yield ""


def _default_corpus_root() -> Path:
    override = os.environ.get("MCPWATCH_CORPUS")
    return Path(override) if override else Path.home() / "mcpwatch-corpus"


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns 0 on success."""
    parser = argparse.ArgumentParser(
        prog="python -m mcpwatch.analyze.backfill",
        description="Report on the backfilled Layer-1 history.",
    )
    parser.add_argument("--corpus", type=Path, default=_default_corpus_root())
    parser.add_argument("--json", action="store_true", help="emit the full report as JSON")
    parser.add_argument("--out", type=Path, default=None, help="write to a file instead of stdout")
    parser.add_argument(
        "--swap-limit",
        type=int,
        default=None,
        help="truncate each swap list; the default keeps every entry",
    )
    args = parser.parse_args(argv)

    with Corpus(args.corpus) as corpus:
        report = build_report(corpus, swap_limit=args.swap_limit)

    text = json.dumps(report.as_json(), indent=2, sort_keys=True) if args.json else report.render()
    if args.out is not None:
        args.out.write_text(text + "\n", encoding="utf-8")
        print(f"{dt.datetime.now(dt.UTC).isoformat()} wrote {args.out}")
    else:
        _print_utf8(text)
    return 0


def _print_utf8(text: str) -> None:
    """Print text that may contain anything a server publisher typed.

    The report is Markdown quoting descriptions written by thousands of
    publishers, so it is UTF-8 by nature. Windows consoles still default to a
    legacy code page, and an analysis that dies on an em dash is not one anybody
    runs twice. ``reconfigure`` is looked up rather than called directly because
    stdout is not always a real text stream — under pytest's capture it is not.
    """
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(encoding="utf-8", errors="replace")
    print(text)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
