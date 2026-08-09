"""Layer-2 collector: live tool manifests from running MCP servers.

This is the irreplaceable one. Registry metadata has a retrospective history at
``/v0/servers/{name}/versions``; live tool definitions have none. A day not
collected is gone permanently, which is why this ships crude-and-running rather
than clean-and-next-week.

**The double probe is the point.** Every server is probed twice per run, in two
passes over a chunk of targets, so the two observations are separated by the
chunk's duration rather than by milliseconds. If the two normalized hashes
disagree, the server is recorded ``nondeterministic`` and quarantined from
mutation statistics. Without this, a server that randomizes tool order or embeds
a session id in a description registers a mutation *every single day* and
silently destroys the headline base rate — the failure mode BUILD-PLAN §3
identifies as most likely to ruin the dataset.

Work is chunked rather than run as two whole-population passes. The whole-
population version recorded nothing until every server had been probed once,
so a cycle that ran out of time during the first pass discarded everything it
had done — three hours of probing for zero observations, observed in
production. Chunking bounds that loss to the chunk in flight, at the cost of
shorter spacing between a server's two probes.

Memory matters at 10k servers: the first pass keeps only each server's
normalized hash and discards the document. Only the second pass's manifest is
retained and stored.

Safety properties, by construction rather than by discipline:

* The client in :mod:`mcpwatch.collect.mcp` implements no way to call a tool.
* No credentials are ever sent. A server demanding auth is recorded
  ``auth_required`` and skipped; that population is a reported coverage
  limitation of the dataset.
* Concurrency is capped globally and again per host, so a platform hosting
  hundreds of listed servers sees a handful of connections, never a fan-out
  proportional to how many servers it publishes.
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
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import IO, Any, Protocol
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
"""Pause after finishing with a host, while still holding its slot."""

DEFAULT_DEADLINE_SECONDS = 10800.0
"""Hard ceiling on one cycle (3h), below the systemd unit's own timeout.

Our deadline must fire first so the run closes itself and keeps what it
collected, rather than being SIGTERMed mid-write by the service manager.
"""

DEFAULT_RESOLVER_WORKERS = 64
"""Threads available to `getaddrinfo`.

asyncio resolves names on the loop's default executor, sized
`min(32, cpu_count + 4)` — eight threads on the collection host, against ~8,000
distinct hostnames. Widening it is cheap and removes an obvious serialization
point.

It is *not* the explanation for the slow first pass, though it was the first
theory: raising this to 64 made no measurable difference to a full cycle. Kept
because it is still correct, but the real cause is elsewhere — see
`probe_p50_seconds` / `probe_p95_seconds` in the run stats, which exist to find
it with measurements rather than another guess.
"""

DEFAULT_CHUNK_SIZE = 500
"""Targets probed A-then-B before moving on.

Sets both the spacing between a server's two probes and the maximum work a
deadline can discard. Smaller means less lost when a cycle runs out of time and
weaker spacing; larger means the reverse.
"""

DEFAULT_PER_HOST_CONCURRENCY = 4
"""Simultaneous probes allowed against any single host.

Endpoints are not evenly spread across hosts: in the day-zero census one gateway
alone accounted for 1,311 of 10,373 targets (12.6%), and the top six hosts for
1,797 between them. Serializing a host completely — the obvious reading of
"strict per-host serialization" — makes the whole cycle's wall-time hostage to
its most crowded host, and turns a bad day there into a runaway: 1,311 probes
timing out at 20s each is over seven hours for that host alone, per pass.

A small semaphore keeps the politeness property that matters (a host never sees
an unbounded fan-out from us) while bounding the tail. Four concurrent read-only
requests is negligible for a platform that publishes a thousand servers, and any
host with a handful of servers is still effectively serialized.
"""


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
    per_host_concurrency: int = DEFAULT_PER_HOST_CONCURRENCY
    resolver_workers: int = DEFAULT_RESOLVER_WORKERS
    chunk_size: int = DEFAULT_CHUNK_SIZE
    chunks_done: int = 0
    probe_seconds_total: float = 0.0
    probe_p50_seconds: float = 0.0
    probe_p95_seconds: float = 0.0
    probe_max_seconds: float = 0.0
    busiest_host_targets: int = 0
    truncated: bool = False
    deadline_exceeded: bool = False
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
        per_host_concurrency: int = DEFAULT_PER_HOST_CONCURRENCY,
        deadline_seconds: float = DEFAULT_DEADLINE_SECONDS,
        resolver_workers: int = DEFAULT_RESOLVER_WORKERS,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        session_factory: SessionFactory | None = None,
    ) -> None:
        """Configure a prober.

        Args:
            corpus: Destination corpus.
            contact: Contact address for the User-Agent.
            concurrency: Global cap on simultaneous probes.
            timeout: Per-request timeout in seconds.
            per_host_delay: Pause held against a host after finishing with it.
            per_host_concurrency: Simultaneous probes allowed per host.
            deadline_seconds: Hard ceiling on one cycle.
            resolver_workers: Threads available for DNS resolution.
            chunk_size: Targets probed A-then-B before committing and moving on.
            session_factory: Override the MCP session class, for tests.
        """
        self.corpus = corpus
        self.user_agent = user_agent(contact, COLLECTOR_VERSION)
        self.concurrency = concurrency
        self.timeout = timeout
        self.per_host_delay = per_host_delay
        self.per_host_concurrency = max(1, per_host_concurrency)
        self.deadline_seconds = deadline_seconds
        self.resolver_workers = max(1, resolver_workers)
        self.chunk_size = max(1, chunk_size)
        self._durations: list[float] = []
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
        started = time.monotonic()
        try:
            return await self._probe_inner(client, target, keep_document=keep_document)
        finally:
            # Recorded for every probe including failures: knowing that the
            # cycle's time goes into a tail of slow servers, rather than being
            # spread evenly, is the difference between tuning the right knob and
            # the wrong one.
            self._durations.append(time.monotonic() - started)

    async def _probe_inner(
        self, client: httpx.AsyncClient, target: Target, *, keep_document: bool
    ) -> ProbeOutcome:
        """Body of :meth:`_probe`, without the timing wrapper."""
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
        host_slots: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(self.per_host_concurrency)
        )
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
                async with semaphore, host_slots[target.host]:
                    outcome = await self._probe(client, target, keep_document=keep_documents)
                    results[target.server_key] = outcome
                    if self.per_host_delay:
                        # Held inside the host's slot on purpose: a platform with
                        # hundreds of listed servers gets paced, not hammered.
                        await asyncio.sleep(self.per_host_delay)
                # Outside both semaphores: the write is brief and blocking, and
                # there is no reason to hold a host's slot while it happens.
                if on_complete is not None:
                    on_complete(target, outcome)

            await asyncio.gather(*(one(t) for t in targets))
        return results

    # ---------------------------------------------------------------- crawl ---

    def crawl(self, *, limit: int | None = None) -> ManifestStats:
        """Run one full double-probe cycle and return its statistics.

        Installs a wide thread pool for name resolution first. asyncio resolves
        hostnames with ``getaddrinfo`` on the loop's default executor, which
        defaults to ``min(32, cpu_count + 4)`` — eight threads on the collection
        host. With ~8,000 distinct hosts, many of them dead, that one detail
        dominated everything else: a measured cycle spent 175 minutes in pass A
        and 16 minutes in pass B doing identical work, the difference being that
        by pass B the resolver cache (including negative entries) was warm.
        """
        executor = ThreadPoolExecutor(
            max_workers=self.resolver_workers, thread_name_prefix="mcpwatch-resolve"
        )

        async def runner() -> ManifestStats:
            asyncio.get_running_loop().set_default_executor(executor)
            return await self.crawl_async(limit=limit)

        try:
            return asyncio.run(runner())
        finally:
            # Never wait: `getaddrinfo` is not interruptible, so a thread stuck
            # on a pathological domain would otherwise hold the process open
            # indefinitely — which is exactly what happened before this existed.
            # See the note in `__main__` about why that alone is not enough.
            executor.shutdown(wait=False, cancel_futures=True)

    async def crawl_async(self, *, limit: int | None = None) -> ManifestStats:
        """Async form of :meth:`crawl`."""
        started = time.monotonic()
        targets = self.targets(limit)
        stats = ManifestStats(targets=len(targets), concurrency=self.concurrency)
        stats.per_host_concurrency = self.per_host_concurrency
        stats.resolver_workers = self.resolver_workers
        stats.chunk_size = self.chunk_size
        stats.truncated = limit is not None
        host_counts: dict[str, int] = defaultdict(int)
        for target in targets:
            host_counts[target.host] += 1
        # Cycle wall-time is dominated by the busiest host, so track it as a
        # health metric: if it climbs, the cycle is one bad day away from
        # running long, and a Layer-2 cycle that overruns eats the next one.
        stats.busiest_host_targets = max(host_counts.values(), default=0)
        if not targets:
            msg = (
                "no probe targets; run the registry collector first so servers "
                "and their endpoints are known"
            )
            raise CollectorError(msg)

        run_id = self.corpus.start_run(COLLECTOR, COLLECTOR_VERSION)

        async def both_passes() -> None:
            # Chunked rather than two whole-population passes.
            #
            # Two full passes meant nothing at all was recorded until every
            # server had been probed once, so a cycle that ran out of time
            # during pass A threw away every hour it had spent — observed
            # exactly once in production, three hours of probing for zero
            # observations. Chunking bounds that loss to the chunk in flight.
            #
            # The cost is spacing: the two probes of a server are now separated
            # by roughly one chunk instead of one cycle. That is still ample for
            # what the guard is actually for — randomized tool order, session
            # ids embedded in descriptions — and drift over longer horizons is
            # what the day-over-day comparison is for.
            for start in range(0, len(targets), self.chunk_size):
                chunk = targets[start : start + self.chunk_size]

                mark = time.monotonic()
                first = await self._run_pass(chunk, keep_documents=False)
                stats.pass_a_seconds = round(stats.pass_a_seconds + time.monotonic() - mark, 3)

                # Commit each observation the moment its second probe lands.
                def commit(
                    target: Target,
                    outcome: ProbeOutcome,
                    _first: dict[str, ProbeOutcome] = first,
                ) -> None:
                    self._record(target, _first[target.server_key], outcome, run_id, stats)

                mark = time.monotonic()
                await self._run_pass(chunk, keep_documents=True, on_complete=commit)
                stats.pass_b_seconds = round(stats.pass_b_seconds + time.monotonic() - mark, 3)
                stats.chunks_done += 1

        # A cycle must be bounded. Left unbounded it will eventually overrun into
        # the next day's run, and two probers against the same third-party hosts
        # is both impolite and slower than either alone. On expiry we keep the
        # observations already committed and close the run honestly rather than
        # letting systemd SIGTERM us mid-write.
        try:
            await asyncio.wait_for(both_passes(), timeout=self.deadline_seconds)
        except TimeoutError:
            stats.deadline_exceeded = True
            stats.truncated = True

        self._summarize_durations(stats)
        stats.wall_seconds = round(time.monotonic() - started, 3)
        self.corpus.finish_run(run_id, stats=stats.as_json())
        return stats

    def _summarize_durations(self, stats: ManifestStats) -> None:
        """Fold per-probe timings into the run stats."""
        if not self._durations:
            return
        ordered = sorted(self._durations)
        stats.probe_seconds_total = round(sum(ordered), 1)
        stats.probe_p50_seconds = round(ordered[len(ordered) // 2], 3)
        stats.probe_p95_seconds = round(ordered[int(len(ordered) * 0.95)], 3)
        stats.probe_max_seconds = round(ordered[-1], 3)

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


def _try_lock(handle: IO[str]) -> bool:
    """Take an exclusive advisory lock without blocking.

    Kernel-held rather than a PID file: a lock released by the OS on process
    exit cannot be left stale by a ``kill -9``, which matters here because
    killing a wedged cycle is a thing that actually happens.
    """
    if sys.platform == "win32":
        import msvcrt

        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True

    # Reachable on the collection host. mypy narrows `sys.platform` to whichever
    # machine is type-checking, so on the Windows authoring box it decides this
    # branch is dead; it is the only branch that ever runs in production.
    import fcntl  # type: ignore[unreachable]

    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


@contextmanager
def exclusive_cycle(corpus_root: Path) -> Iterator[bool]:
    """Hold an advisory lock so two probe cycles cannot overlap.

    Two probers running at once double the load we place on every third-party
    host and make both slower, so the second must decline rather than compete.
    Yields True if the lock was acquired, False if another cycle holds it. The
    lock is released when the process exits, however it exits.
    """
    lock_dir = corpus_root / "state"
    lock_dir.mkdir(parents=True, exist_ok=True)
    path = lock_dir / "manifest-cycle.lock"
    # Nothing is written to the file: on Windows the locked byte range cannot be
    # truncated, and the holder's identity is available from `ps` anyway. The
    # lock is the whole point of the file.
    handle = path.open("a+")
    try:
        yield _try_lock(handle)
    finally:
        handle.close()


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
    parser.add_argument("--per-host-concurrency", type=int, default=DEFAULT_PER_HOST_CONCURRENCY)
    parser.add_argument("--contact", default=os.environ.get("MCPWATCH_CONTACT", DEFAULT_CONTACT))
    parser.add_argument("--deadline-seconds", type=float, default=DEFAULT_DEADLINE_SECONDS)
    parser.add_argument("--resolver-workers", type=int, default=DEFAULT_RESOLVER_WORKERS)
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    args = parser.parse_args(argv)

    with exclusive_cycle(args.corpus) as acquired:
        if not acquired:
            print(
                f"{utcnow().isoformat()} another manifest cycle holds the lock; "
                "declining rather than competing with it for the same hosts",
                file=sys.stderr,
            )
            return 3

        with Corpus(args.corpus) as corpus:
            prober = ManifestProber(
                corpus,
                contact=args.contact,
                concurrency=args.concurrency,
                timeout=args.timeout,
                per_host_delay=args.per_host_delay,
                per_host_concurrency=args.per_host_concurrency,
                deadline_seconds=args.deadline_seconds,
                resolver_workers=args.resolver_workers,
                chunk_size=args.chunk_size,
            )
            try:
                stats = prober.crawl(limit=args.limit)
            except CollectorError as exc:
                print(f"{utcnow().isoformat()} manifest probe FAILED: {exc}", file=sys.stderr)
                return 1

    print(json.dumps(stats.as_json(), indent=2, sort_keys=True))
    if stats.deadline_exceeded:
        print(
            f"{utcnow().isoformat()} cycle hit its {args.deadline_seconds:.0f}s deadline; "
            f"{stats.probed} of {stats.targets} targets recorded",
            file=sys.stderr,
        )
        return 2
    return 0 if stats.reachable_rate >= 0.90 else 2


if __name__ == "__main__":  # pragma: no cover
    code = main()
    sys.stdout.flush()
    sys.stderr.flush()
    # Hard exit rather than falling off the end of the interpreter.
    #
    # Every observation is already committed to SQLite and the run is closed, so
    # there is nothing left to flush. What remains is `getaddrinfo` threads that
    # may still be blocked on dead domains: `getaddrinfo` cannot be interrupted,
    # and `concurrent.futures` registers an atexit hook that joins its worker
    # threads, so a normal exit can hang forever with all the work done. That is
    # not hypothetical — an earlier cycle finished probing in 3.2 hours and then
    # sat in exactly this state for another 38, blocking the scheduled runs
    # behind it.
    os._exit(code)
