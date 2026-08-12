"""``python -m mcpwatch.sandbox`` — verify, sample, probe.

Three subcommands, in the order WP8 requires them to be run:

``verify``  run the canary and prove containment holds
``sample``  draw the fixed stratified sample
``probe``   install and enumerate every member inside the sandbox

``probe`` re-runs ``verify`` first and refuses to start if any property fails.
That is not belt-and-braces: the Docker daemon, its networks, and the images are
all mutable host state, and a sandbox that was sound last week is not evidence
about tonight. The gate is cheap; running third-party code without it is not.
"""

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from mcpwatch.store import Corpus, JsonValue, Layer, ObservationStatus, norm_sha256

from .containment import ContainmentError, Sandbox, SandboxResult
from .frame import DEFAULT_SAMPLE_SIZE, SampleStore, candidates, draw
from .verify import verify

__all__ = ["main"]

COLLECTOR = "sandbox"
COLLECTOR_VERSION = "0.1.0"

DEFAULT_CONCURRENCY = 2
"""Simultaneous probe containers.

Measured, not guessed. Four was the obvious choice on a 4-vCPU box and it took
the whole machine: two installs pegged a core each, and `docker commit` adds
image-layer compression on top, leaving 8.9% idle and a load average of 6.3 for
an hour. That box is permanent and shared with workloads that matter, so the
sandbox does not get to use all of it.

Two leaves roughly half the machine free. The cycle takes about twice as long,
which is the correct trade for a nightly job with no deadline.
"""


def _default_corpus_root() -> Path:
    override = os.environ.get("MCPWATCH_CORPUS")
    return Path(override) if override else Path.home() / "mcpwatch-corpus"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _sandbox(args: argparse.Namespace) -> Sandbox:
    return Sandbox(repo_root=args.repo_root)


# -------------------------------------------------------------------- verify ---


def _verify(args: argparse.Namespace) -> int:
    """Run the containment gate and report."""
    report = verify(_sandbox(args), keep=args.keep)
    print(report.render())
    if not report.ok:
        names = ", ".join(check.name for check in report.failures)
        print(f"\nCONTAINMENT NOT VERIFIED: {names}", file=sys.stderr)
        return 1
    print("\nContainment verified.")
    return 0


# -------------------------------------------------------------------- sample ---


def _sample(args: argparse.Namespace) -> int:
    """Draw the fixed stratified sample."""
    with Corpus(args.corpus) as corpus:
        pool = list(candidates(corpus))
    if not pool:
        print("no eligible servers; run the registry collector first", file=sys.stderr)
        return 1

    members, sizes = draw(pool, size=args.size, seed=args.seed)
    with SampleStore(args.corpus / "sandbox.db") as store:
        existing = store.members()
        # The sample must not drift: re-probing the same servers over time is
        # what makes a longitudinal claim possible at all.
        if existing and not args.extend:
            print(
                f"sample already holds {len(existing)} member(s); "
                "pass --extend to add to it (this changes what the series measures)",
                file=sys.stderr,
            )
            return 1
        added = store.record_sample(members, sizes, seed=args.seed, size=args.size)
        counts = store.strata_counts()

    print(f"population {sum(sizes.values())} across {len(sizes)} strata, seed {args.seed}")
    print(f"drew {len(members)}, added {added}\n")
    for name in sorted(counts):
        print(f"  {name:28} {counts[name]:4}  of {sizes.get(name, 0)} in population")
    return 0


# --------------------------------------------------------------------- probe ---


def _probe(args: argparse.Namespace) -> int:
    """Probe every sample member inside the sandbox and record observations."""
    sandbox = _sandbox(args)

    report = verify(sandbox)
    if not report.ok:
        print(report.render(), file=sys.stderr)
        names = ", ".join(check.name for check in report.failures)
        print(f"\nrefusing to probe: containment not verified ({names})", file=sys.stderr)
        return 1

    with SampleStore(args.corpus / "sandbox.db") as store:
        specs = store.specs()
    if not specs:
        print("sample is empty; run `sample` first", file=sys.stderr)
        return 1
    if args.limit:
        specs = specs[: args.limit]

    stats: dict[str, int] = {}
    egress_servers: list[str] = []
    with Corpus(args.corpus) as corpus:
        run_id = corpus.start_run(COLLECTOR, COLLECTOR_VERSION)
        try:
            with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
                for result in pool.map(sandbox.probe, specs):
                    _record(corpus, run_id, result, stats)
                    if result.attempted_egress:
                        egress_servers.append(result.server_key)
        finally:
            summary: dict[str, JsonValue] = {
                "members": len(specs),
                "concurrency": args.concurrency,
                "status_counts": dict(stats),
                "attempted_egress": list(egress_servers),
                # The containment report travels with the run, so a reader can
                # tell what was verified at the moment these observations were
                # collected rather than trusting that it was ever checked.
                "containment": report.as_json(),
            }
            corpus.finish_run(run_id, stats=summary)

    print(json.dumps({"members": len(specs), "status_counts": stats}, indent=2, sort_keys=True))
    if egress_servers:
        # Not an error. A server that opens a connection while merely listing
        # its tools is a finding, and the sinkhole is why we can say so.
        print(
            f"\n{len(egress_servers)} server(s) attempted egress during enumeration: "
            f"{', '.join(egress_servers[:10])}",
            file=sys.stderr,
        )
    return 0


def _record(corpus: Corpus, run_id: str, result: SandboxResult, stats: dict[str, int]) -> None:
    """Turn one sandbox result into exactly one Layer-2 observation."""
    stats[result.status] = stats.get(result.status, 0) + 1

    if not result.ok:
        corpus.record_failure(
            run_id=run_id,
            server_key=result.server_key,
            layer=Layer.MANIFEST,
            status=_status_for(result.status),
            error_class=result.status,
            error_detail=result.detail,
        )
        return

    first, second = result.probes
    # `transport` is part of the stored document so a manifest says how it was
    # collected. These servers are never probed over HTTP — dual-transport ones
    # are excluded from the frame — so this cannot alternate with a WP3 record.
    document = dict(second)
    document["transport"] = "stdio"
    document["usedPlaceholderCredentials"] = result.used_placeholders

    if norm_sha256(first) != norm_sha256(second):
        status = ObservationStatus.NONDETERMINISTIC
        error_class: str | None = "hash_disagreement"
        detail: str | None = "the two launches produced different normalized manifests"
    else:
        status = ObservationStatus.OK
        error_class = None
        detail = None

    if result.attempted_egress:
        # Recorded on the observation, not only in the run stats, so the finding
        # travels with the manifest it belongs to.
        destinations = sorted({e.get("sni") or str(e.get("dest_port")) for e in result.egress})
        error_class = error_class or "attempted_egress"
        detail = f"{detail or ''} attempted egress to {destinations}".strip()

    corpus.record_snapshot(
        run_id=run_id,
        server_key=result.server_key,
        layer=Layer.MANIFEST,
        document=document,
        status=status,
        error_class=error_class,
        error_detail=detail,
    )


def _status_for(failure: str) -> ObservationStatus:
    """Map WP8's failure taxonomy onto the corpus's coarse status enum."""
    return {
        "install_failed": ObservationStatus.UNREACHABLE,
        "launch_failed": ObservationStatus.UNREACHABLE,
        "timeout": ObservationStatus.TIMEOUT,
        "requires_credentials": ObservationStatus.AUTH_REQUIRED,
        "protocol_error": ObservationStatus.PROTOCOL_ERROR,
        "crashed": ObservationStatus.PROTOCOL_ERROR,
    }.get(failure, ObservationStatus.PROTOCOL_ERROR)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="python -m mcpwatch.sandbox",
        description="Enumerate package-distributed MCP servers inside a verified sandbox.",
    )
    parser.add_argument("--corpus", type=Path, default=_default_corpus_root())
    parser.add_argument("--repo-root", type=Path, default=_repo_root())
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("verify", help="prove containment with the canary server")
    check.add_argument("--keep", action="store_true", help="leave the canary container running")
    check.set_defaults(func=_verify)

    sample = sub.add_parser("sample", help="draw the fixed stratified sample")
    sample.add_argument("--size", type=int, default=DEFAULT_SAMPLE_SIZE)
    sample.add_argument("--seed", type=int, default=20260812)
    sample.add_argument("--extend", action="store_true")
    sample.set_defaults(func=_sample)

    run = sub.add_parser("probe", help="probe every sample member (verifies containment first)")
    run.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    run.add_argument("--limit", type=int, default=None, help="probe only the first N members")
    run.set_defaults(func=_probe)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ContainmentError as exc:
        print(f"containment error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
