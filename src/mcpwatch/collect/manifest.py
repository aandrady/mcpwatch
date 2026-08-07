"""Layer-2 collector: live tool manifests from running MCP servers.

This is the irreplaceable one. Registry metadata has a retrospective history at
``/v0/servers/{name}/versions``; live tool definitions have none. A day not
collected is gone permanently, which is why this ships crude-and-running rather
than clean-and-next-week.

**The double probe is the point.** Every server is probed twice per run, in two
separate passes so the two observations are separated by the whole cycle rather
than by milliseconds. If the two normalized hashes disagree, the server is
recorded ``nondeterministic`` and quarantined from mutation statistics. Without
this, a server that randomizes tool order or embeds a session id in a
description registers a mutation *every single day* and silently destroys the
headline base rate — the failure mode BUILD-PLAN §3 identifies as most likely to
ruin the dataset.

Memory matters at 10k servers: pass A keeps only each server's normalized hash
and discards the document. Only pass B's manifest is retained and stored.

Safety properties, by construction rather than by discipline:

* The client in :mod:`mcpwatch.collect.mcp` implements no way to call a tool.
* No credentials are ever sent. A server demanding auth is recorded
  ``auth_required`` and skipped; that population is a reported coverage
  limitation of the dataset.
* Concurrency is globally capped and strictly serialized per host, so a platform
  hosting hundreds of servers sees one connection at a time, not hundreds.
* Failed probes are never retried within a pass. The second pass is the retry.
"""

import argparse
import asyncio
import json
import os
import ssl
import sys
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from mcpwatch.store import Corpus, JsonValue, Layer, ObservationStatus, norm_sha256, utcnow

from .errors import CollectorError
from .http import DEFAULT_CONTACT, user_agent
from .mcp import AuthRequired, McpProtocolError, McpSession

__all__ = ["COLLECTOR", "COLLECTOR_VERSION", "ManifestProber", "ManifestStats", "main"]

COLLECTOR = "manifest"
COLLECTOR_VERSION = "0.1.0"

DEFAULT_CONCURRENCY = 50
DEFAULT_TIMEOUT = 20.0
DEFAULT_PER_HOST_DELAY = 0.5
"""Pause after finishing with a host, while still holding its lock."""


@dataclass
class ManifestStats:
    """Per-run counters, serialized into ``run.stats_json``."""

    targets: int = 0
    probed: int = 0
    ok: int = 0
    nondeterministic: int = 0
    determinism_unverified: int = 0
    changed: int = 0
    unchanged: int = 0
    tools_total: int = 0
    blobs_written: int = 0
    bytes_written: int = 0
    wall_seconds: float = 0.0
    pass_a_seconds: float = 0.0
    pass_b_seconds: float = 0.0
    concurrency: int = DEFAULT_CONCURRENCY
    truncated: bool = False
    status_counts: dict[str, int] = field(default_factory=dict)
    errors_by_class: dict[str, int] = field(default_factory=dict)

    def as_json(self) -> dict[str, JsonValue]:
        """Render as a plain JSON-safe mapping."""
        return dict(asdict(self).items())

    @property
    def reachable_rate(self) -> float:
        """Fraction of targets that yielded a manifest. WP3's headline metric."""
        usable = self.ok + self.nondeterministic
        return usable / self.targets if self.targets else 0.0


class SessionLike(Protocol):
    """The one method the prober needs from an MCP session."""

    async def collect_manifest(self) -> dict[str, Any]:
        """Run the read-only sweep and return the combined manifest."""
        ...


class SessionFactory(Protocol):
    """Constructs a session for one endpoint. Substituted in tests."""

    def __call__(self, *, client: httpx.AsyncClient, url: str, timeout: float) -> SessionLike:
        """Build a session bound to one endpoint."""
        ...


@dataclass(frozen=True, slots=True)
class Target:
    """One server to probe."""

    server_key: str
    endpoint: str

    @property
    def host(self) -> str:
        """Netloc used for per-host serialization."""
        return urlsplit(self.endpoint).netloc.casefold()


@dataclass(frozen=True, slots=True)
class ProbeOutcome:
    """What one probe of one server produced."""

    status: ObservationStatus
    norm_sha: str | None = None
    document: dict[str, JsonValue] | None = None
    error_class: str | None = None
    error_detail: str | None = None

    @property
    def ok(self) -> bool:
        """Whether this probe returned a usable manifest."""
        return self.status is ObservationStatus.OK


def classify(exc: BaseException) -> tuple[ObservationStatus, str, str]:
    """Map an exception to a WP1 status, a precise class, and a detail string.

    The WP1 status enum is deliberately coarse and stable; the precision lives
    in ``error_class``. TLS failures are the clearest case — the enum has no
    ``tls_error`` member, so they land under ``unreachable`` while
    ``error_class`` keeps the distinction that actually matters for analysis.
    """
    detail = str(exc)[:500]
    if isinstance(exc, AuthRequired):
        return ObservationStatus.AUTH_REQUIRED, "auth_required", detail
    if isinstance(exc, McpProtocolError):
        return ObservationStatus.PROTOCOL_ERROR, "mcp_protocol_error", detail
    if isinstance(exc, httpx.TimeoutException):
        return ObservationStatus.TIMEOUT, type(exc).__name__, detail
    if isinstance(exc, ssl.SSLError) or isinstance(exc.__cause__, ssl.SSLError):
        return ObservationStatus.UNREACHABLE, "tls_error", detail
    if isinstance(exc, httpx.ConnectError):
        lowered = detail.casefold()
        if "ssl" in lowered or "certificate" in lowered or "tls" in lowered:
            return ObservationStatus.UNREACHABLE, "tls_error", detail
        return ObservationStatus.UNREACHABLE, "connect_error", detail
    if isinstance(exc, httpx.TooManyRedirects):
        return ObservationStatus.PROTOCOL_ERROR, "too_many_redirects", detail
    if isinstance(exc, httpx.HTTPError):
        return ObservationStatus.UNREACHABLE, type(exc).__name__, detail
    if isinstance(exc, UnicodeDecodeError | ValueError):
        return ObservationStatus.PROTOCOL_ERROR, type(exc).__name__, detail
    return ObservationStatus.PROTOCOL_ERROR, type(exc).__name__, detail


class ManifestProber:
    """Probes live MCP endpoints and appends Layer-2 observations."""

    def __init__(
        self,
        corpus: Corpus,
        *,
        contact: str = DEFAULT_CONTACT,
        concurrency: int = DEFAULT_CONCURRENCY,
        timeout: float = DEFAULT_TIMEOUT,
        per_host_delay: float = DEFAULT_PER_HOST_DELAY,
        session_factory: SessionFactory | None = None,
    ) -> None:
        """Configure a prober.

        Args:
            corpus: Destination corpus.
            contact: Contact address for the User-Agent.
            concurrency: Global cap on simultaneous probes.
            timeout: Per-request timeout in seconds.
            per_host_delay: Pause held against a host after finishing with it.
            session_factory: Override the MCP session class, for tests.
        """
        self.corpus = corpus
        self.user_agent = user_agent(contact, COLLECTOR_VERSION)
        self.concurrency = concurrency
        self.timeout = timeout
        self.per_host_delay = per_host_delay
        self._session_factory = session_factory or McpSession

    # -------------------------------------------------------------- targets ---

    def targets(self, limit: int | None = None) -> list[Target]:
        """Servers to probe: those the registry currently lists with an endpoint.

        A server whose most recent Layer-1 observation is ``absent`` is excluded
        — it is gone from the registry, so probing its old endpoint would be
        both impolite and meaningless.
        """
        sql = """
            SELECT server_key, primary_endpoint FROM server
            WHERE primary_endpoint IS NOT NULL
              AND (
                SELECT status FROM observation o
                WHERE o.server_key = server.server_key AND o.layer = 'registry'
                ORDER BY observed_at DESC, obs_id DESC LIMIT 1
              ) = 'ok'
            ORDER BY server_key
        """
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        rows = self.corpus.index.connection.execute(sql).fetchall()
        return [Target(row["server_key"], row["primary_endpoint"]) for row in rows]

    # --------------------------------------------------------------- probes ---

    async def _probe(
        self, client: httpx.AsyncClient, target: Target, *, keep_document: bool
    ) -> ProbeOutcome:
        """Probe one server once. Never raises; failures become outcomes."""
        try:
            session = self._session_factory(
                client=client, url=target.endpoint, timeout=self.timeout
            )
            manifest = await session.collect_manifest()
        except Exception as exc:
            status, error_class, detail = classify(exc)
            return ProbeOutcome(status=status, error_class=error_class, error_detail=detail)
        return ProbeOutcome(
            status=ObservationStatus.OK,
            norm_sha=norm_sha256(manifest),
            document=manifest if keep_document else None,
        )

    async def _run_pass(
        self,
        targets: list[Target],
        *,
        keep_documents: bool,
        on_complete: Callable[[Target, ProbeOutcome], None] | None = None,
    ) -> dict[str, ProbeOutcome]:
        """Probe every target once, bounded globally and serialized per host.

        ``on_complete`` fires as each probe lands, which is what lets pass B
        commit observations incrementally instead of at the end.
        """
        semaphore = asyncio.Semaphore(self.concurrency)
        host_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        results: dict[str, ProbeOutcome] = {}

        limits = httpx.Limits(
            max_connections=self.concurrency, max_keepalive_connections=self.concurrency
        )
        async with httpx.AsyncClient(
            headers={"User-Agent": self.user_agent},
            limits=limits,
            follow_redirects=True,
            timeout=self.timeout,
        ) as client:

            async def one(target: Target) -> None:
                async with semaphore, host_locks[target.host]:
                    outcome = await self._probe(client, target, keep_document=keep_documents)
                    results[target.server_key] = outcome
                    if self.per_host_delay:
                        # Held inside the host lock on purpose: a platform with
                        # hundreds of listed servers gets paced, not hammered.
                        await asyncio.sleep(self.per_host_delay)
                # Outside the locks: the write is brief and blocking, and there
                # is no reason to hold a host's slot while it happens.
                if on_complete is not None:
                    on_complete(target, outcome)

            await asyncio.gather(*(one(t) for t in targets))
        return results

    # ---------------------------------------------------------------- crawl ---

    def crawl(self, *, limit: int | None = None) -> ManifestStats:
        """Run one full double-probe cycle and return its statistics."""
        return asyncio.run(self.crawl_async(limit=limit))

    async def crawl_async(self, *, limit: int | None = None) -> ManifestStats:
        """Async form of :meth:`crawl`."""
        started = time.monotonic()
        targets = self.targets(limit)
        stats = ManifestStats(targets=len(targets), concurrency=self.concurrency)
        stats.truncated = limit is not None
        if not targets:
            msg = (
                "no probe targets; run the registry collector first so servers "
                "and their endpoints are known"
            )
            raise CollectorError(msg)

        run_id = self.corpus.start_run(COLLECTOR, COLLECTOR_VERSION)

        mark = time.monotonic()
        first = await self._run_pass(targets, keep_documents=False)
        stats.pass_a_seconds = round(time.monotonic() - mark, 3)

        # Commit each observation the moment its second probe lands, rather than
        # batching at the end. A cycle that dies halfway then keeps everything it
        # had already collected; batching would throw the whole day away, and
        # Layer-2 days cannot be re-collected.
        def commit(target: Target, outcome: ProbeOutcome) -> None:
            self._record(target, first[target.server_key], outcome, run_id, stats)

        mark = time.monotonic()
        await self._run_pass(targets, keep_documents=True, on_complete=commit)
        stats.pass_b_seconds = round(time.monotonic() - mark, 3)

        stats.wall_seconds = round(time.monotonic() - started, 3)
        self.corpus.finish_run(run_id, stats=stats.as_json())
        return stats

    def _record(
        self,
        target: Target,
        first: ProbeOutcome,
        second: ProbeOutcome,
        run_id: str,
        stats: ManifestStats,
    ) -> None:
        """Reconcile two probes into exactly one observation."""
        stats.probed += 1

        if not second.ok:
            # Prefer the second probe's verdict; note the first if it differed,
            # so a server that is flaky rather than down is distinguishable.
            detail = second.error_detail
            if first.status is not second.status:
                detail = f"{detail} (first probe: {first.error_class})"
            self.corpus.record_failure(
                run_id=run_id,
                server_key=target.server_key,
                layer=Layer.MANIFEST,
                status=second.status,
                error_class=second.error_class,
                error_detail=detail,
            )
            self._count(stats.status_counts, str(second.status))
            if second.error_class:
                self._count(stats.errors_by_class, second.error_class)
            return

        document = second.document
        if document is None:  # pragma: no cover - pass B always keeps documents
            msg = "second probe reported ok without a document"
            raise CollectorError(msg)

        if not first.ok:
            # One good manifest, but nothing to compare it against. Store it and
            # say so, rather than silently implying the determinism check passed.
            status = ObservationStatus.OK
            error_class: str | None = "determinism_unverified"
            error_detail: str | None = f"first probe: {first.error_class}"
            stats.determinism_unverified += 1
        elif first.norm_sha != second.norm_sha:
            status = ObservationStatus.NONDETERMINISTIC
            error_class = "hash_disagreement"
            error_detail = f"probe A {first.norm_sha} != probe B {second.norm_sha}"
            stats.nondeterministic += 1
        else:
            status = ObservationStatus.OK
            error_class = None
            error_detail = None
            stats.ok += 1

        write = self.corpus.record_snapshot(
            run_id=run_id,
            server_key=target.server_key,
            layer=Layer.MANIFEST,
            document=document,
            status=status,
            error_class=error_class,
            error_detail=error_detail,
        )
        self._count(stats.status_counts, str(status))
        stats.blobs_written += int(write.raw.created) + int(write.normalized.created)
        stats.bytes_written += write.bytes_written
        tools = document.get("tools")
        if isinstance(tools, list):
            stats.tools_total += len(tools)
        if write.changed:
            stats.changed += 1
        else:
            stats.unchanged += 1

    @staticmethod
    def _count(bucket: dict[str, int], key: str) -> None:
        bucket[key] = bucket.get(key, 0) + 1


def _default_corpus_root() -> Path:
    """Corpus location: env override, else the documented production path."""
    override = os.environ.get("MCPWATCH_CORPUS")
    return Path(override) if override else Path.home() / "mcpwatch-corpus"


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns 0 clean, 1 failed, 2 completed below target."""
    parser = argparse.ArgumentParser(
        prog="python -m mcpwatch.collect.manifest",
        description="Probe live MCP servers and append Layer-2 observations.",
    )
    parser.add_argument("--corpus", type=Path, default=_default_corpus_root())
    parser.add_argument(
        "--limit", type=int, default=None, help="probe only the first N targets (staged rollout)"
    )
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--per-host-delay", type=float, default=DEFAULT_PER_HOST_DELAY)
    parser.add_argument("--contact", default=os.environ.get("MCPWATCH_CONTACT", DEFAULT_CONTACT))
    args = parser.parse_args(argv)

    with Corpus(args.corpus) as corpus:
        prober = ManifestProber(
            corpus,
            contact=args.contact,
            concurrency=args.concurrency,
            timeout=args.timeout,
            per_host_delay=args.per_host_delay,
        )
        try:
            stats = prober.crawl(limit=args.limit)
        except CollectorError as exc:
            print(f"{utcnow().isoformat()} manifest probe FAILED: {exc}", file=sys.stderr)
            return 1

    print(json.dumps(stats.as_json(), indent=2, sort_keys=True))
    return 0 if stats.reachable_rate >= 0.90 else 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
