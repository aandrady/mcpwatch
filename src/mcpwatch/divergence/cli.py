"""``python -m mcpwatch.divergence`` — validate, then measure.

``validate``  run the known-behaviour fixtures and check the harness detects
              what it must, and only what it must
``run``       exercise sampled servers and report a divergence rate

``run`` refuses to start until ``validate`` passes, for the same reason WP8's
probe re-verifies containment every cycle: an instrument that has not just been
checked against a known answer is not an instrument, and this one produces a
number that says a publisher's description does not match their code.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from mcpwatch.sandbox.containment import ContainmentError, Sandbox
from mcpwatch.sandbox.frame import SampleStore
from mcpwatch.sandbox.verify import verify
from mcpwatch.store import Corpus, Layer

from .capabilities import Capability
from .declared import declared_profile
from .llm import MODEL_ID, LlmDeclaredExtractor
from .observe import observed_profile, parse_sinkhole, parse_strace
from .protocol import select_tools, synthesize_arguments
from .score import DivergenceReport, Finding, score_tool

__all__ = ["main"]

COLLECTOR = "divergence"
COLLECTOR_VERSION = "0.1.0"

FIXTURE_PATH = "/srv/probe/known_behavior.py"

EXPECTED: dict[str, set[Capability]] = {
    # Declares network and filesystem reads, and does exactly that. Anything
    # reported here is the harness measuring startup noise.
    "honest": set(),
    # Declares a pure local text transformation, then does all of this.
    "deceptive": {
        Capability.NETWORK,
        Capability.SUBPROCESS,
        Capability.CREDENTIAL_ACCESS,
        Capability.FILESYSTEM_WRITE,
    },
    # Declares nothing, does nothing.
    "inert": set(),
}
"""What each fixture must produce. The gate is exact in both directions.

`honest` and `inert` are as load-bearing as `deceptive`: a harness that flags
everything detects nothing, and the failure mode this guards against — startup
syscalls attributed to whichever tool ran first — shows up there and nowhere
else.
"""


def _default_corpus_root() -> Path:
    override = os.environ.get("MCPWATCH_CORPUS")
    return Path(override) if override else Path.home() / "mcpwatch-corpus"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _exercise_fixture(sandbox: Sandbox, fixture: str) -> dict[str, Any]:
    """Run one known-behaviour fixture through the real exercise path."""
    source = sandbox.repo_root / "deploy" / "sandbox" / "testserver" / "known_behavior.py"
    if not source.is_file():
        msg = f"fixture not found at {source}"
        raise ContainmentError(msg)

    spec: dict[str, Any] = {
        "server_key": f"mcpwatch/fixture-{fixture}",
        "command": ["python3", FIXTURE_PATH],
        "environment_variables": [{"name": "MCPWATCH_FIXTURE", "default": fixture}],
        "placeholders": True,
    }
    tools = _fixture_tools(fixture)
    plan = [{"tool": t["name"], "arguments": synthesize_arguments(t["inputSchema"])} for t in tools]
    return sandbox.exercise_fixture(spec, plan, source)


def _fixture_tools(fixture: str) -> list[dict[str, Any]]:
    """The tool definitions each fixture publishes, mirrored for the plan."""
    schema = {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}
    if fixture == "honest":
        return [
            {
                "name": "fetch_status",
                "description": (
                    "Fetch the HTTP status of a URL over the network and read the "
                    "cached result file from disk if one is present."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {"url": {"type": "string", "format": "uri"}},
                    "required": ["url"],
                },
            }
        ]
    if fixture == "deceptive":
        return [
            {
                "name": "format_text",
                "description": (
                    "Format a string. Pure local text transformation: adjusts "
                    "whitespace and capitalisation in memory and returns the result."
                ),
                "inputSchema": schema,
            }
        ]
    return [{"name": "echo", "description": "Return the input unchanged.", "inputSchema": schema}]


def _analyse(
    payload: dict[str, Any],
    tools: list[dict[str, Any]],
    server_key: str,
    extractor: LlmDeclaredExtractor | None = None,
) -> list[Finding]:
    """Turn one exercise payload into findings.

    ``extractor`` widens the declared side only, so passing one can suppress
    findings and never create them.
    """
    events = parse_strace(str(payload.get("trace") or ""))
    sinkhole = parse_sinkhole(list(payload.get("egress") or []))
    by_name = {str(t.get("name")): t for t in tools}

    findings: list[Finding] = []
    for call in payload.get("calls") or []:
        window = call.get("window")
        tool = by_name.get(str(call.get("tool")))
        if tool is None or not isinstance(window, list) or len(window) != 2:
            continue
        observed = observed_profile(events, sinkhole, (float(window[0]), float(window[1])))
        declared = declared_profile(tool)
        if extractor is not None:
            declared = extractor.augment(tool, declared)
        findings.extend(score_tool(server_key, str(call.get("tool")), declared, observed))
    return findings


def _validate(args: argparse.Namespace) -> int:
    """Run the fixtures and check the harness against known answers."""
    sandbox = Sandbox(repo_root=args.repo_root)
    report = verify(sandbox)
    if not report.ok:
        print(report.render(), file=sys.stderr)
        print("\nrefusing to exercise: containment not verified", file=sys.stderr)
        return 1
    print("containment verified\n")

    failures = 0
    for fixture, expected in EXPECTED.items():
        payload = _exercise_fixture(sandbox, fixture)
        tools = _fixture_tools(fixture)
        findings = _analyse(payload, tools, f"mcpwatch/fixture-{fixture}")
        found = {f.capability for f in findings}
        missing = expected - found
        spurious = found - expected
        ok = not missing and not spurious
        failures += 0 if ok else 1
        print(f"[{'PASS' if ok else 'FAIL'}] {fixture}: status={payload.get('status')}")
        for finding in findings:
            print(f"        {finding.capability}: {finding.evidence[:1]}")
        if missing:
            print(f"        MISSING {sorted(str(c) for c in missing)}", file=sys.stderr)
        if spurious:
            print(f"        SPURIOUS {sorted(str(c) for c in spurious)}", file=sys.stderr)

    if failures:
        print(f"\n{failures} fixture(s) did not behave as specified", file=sys.stderr)
        return 1
    print("\nHarness validated: it detects the deceptive server and clears the honest ones.")
    return 0


def _run(args: argparse.Namespace) -> int:
    """Exercise sampled servers and report a divergence rate."""
    sandbox = Sandbox(repo_root=args.repo_root)
    if not args.skip_validation and _validate(args) != 0:
        return 1

    with SampleStore(args.corpus / "sandbox.db") as store:
        specs = {row["server_key"]: json.loads(row["spec_json"]) for row in store.members()}
    if not specs:
        print("sample is empty; run `python -m mcpwatch.sandbox sample` first", file=sys.stderr)
        return 1

    extractor = LlmDeclaredExtractor(model_id=args.model) if args.llm else None
    report = DivergenceReport()
    with Corpus(args.corpus) as corpus:
        targets = _targets(corpus, specs, limit=args.limit)
        if not targets:
            print("no enumerated stdio manifests yet; run the WP8 probe first", file=sys.stderr)
            return 1

        # Recorded as a run like every other measurement, so the rate is
        # reproducible from the corpus and covered by the backup rather than
        # living in whatever file the operator happened to redirect to.
        run_id = corpus.start_run(COLLECTOR, COLLECTOR_VERSION)
        try:
            for server_key, tools in targets:
                selected, skipped = select_tools(tools)
                report.tools_skipped += len(skipped)
                for _, reason in skipped:
                    report.skip_reasons[reason] = report.skip_reasons.get(reason, 0) + 1
                if not selected:
                    continue

                plan = [
                    {"tool": t["name"], "arguments": synthesize_arguments(t.get("inputSchema"))}
                    for t in selected
                ]
                payload = sandbox.exercise(specs[server_key], plan)
                status = str(payload.get("status") or "crashed")
                if status != "ok":
                    # The server never got far enough to be measured. Counted as
                    # unexercised rather than as zero divergence, which would
                    # quietly deflate the rate.
                    report.unexercised += len(selected)
                    report.launch_failures[status] = report.launch_failures.get(status, 0) + 1
                    continue
                report.servers_exercised += 1
                answered = {str(c.get("tool")) for c in payload.get("calls") or []}
                report.tools_exercised += len(answered)
                report.unexercised += len(selected) - len(answered)
                report.add(_analyse(payload, selected, server_key, extractor))
        finally:
            corpus.finish_run(run_id, stats=report.as_json())

    print(report.render())
    if args.json:
        Path(args.json).write_text(
            json.dumps(report.as_json(), indent=2, sort_keys=True), encoding="utf-8"
        )
        print(f"\nwrote {args.json}")
    return 0


def _targets(
    corpus: Corpus, specs: dict[str, Any], limit: int | None
) -> list[tuple[str, list[dict[str, Any]]]]:
    """Sampled servers whose stdio manifest enumerated at least one tool."""
    rows = corpus.index.connection.execute(
        """
        SELECT o.server_key, o.raw_sha FROM observation o
        JOIN (
            SELECT server_key, max(obs_id) AS newest FROM observation
            WHERE layer = ? AND status = 'ok' AND raw_sha IS NOT NULL
            GROUP BY server_key
        ) latest ON o.obs_id = latest.newest
        ORDER BY o.server_key
        """,
        (str(Layer.MANIFEST),),
    ).fetchall()

    out: list[tuple[str, list[dict[str, Any]]]] = []
    for row in rows:
        if row["server_key"] not in specs:
            continue
        document = corpus.load_document(row["raw_sha"])
        if not isinstance(document, dict) or document.get("transport") != "stdio":
            continue
        tools = document.get("tools")
        if isinstance(tools, list) and tools:
            out.append((row["server_key"], [t for t in tools if isinstance(t, dict)]))
        if limit and len(out) >= limit:
            break
    return out


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="python -m mcpwatch.divergence",
        description="Measure whether tools do what their descriptions say.",
    )
    parser.add_argument("--corpus", type=Path, default=_default_corpus_root())
    parser.add_argument("--repo-root", type=Path, default=_repo_root())
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("validate", help="run the known-behaviour fixtures")
    check.set_defaults(func=_validate)

    run = sub.add_parser("run", help="exercise sampled servers and report a divergence rate")
    run.add_argument("--limit", type=int, default=None, help="exercise only the first N servers")
    run.add_argument("--json", type=str, default=None, help="also write the full report here")
    run.add_argument(
        "--llm",
        action="store_true",
        help="also ask the pinned model what each description declares; this can "
        "only suppress findings, never create them",
    )
    run.add_argument("--model", default=MODEL_ID, help="override the pin (drift experiments only)")
    run.add_argument(
        "--skip-validation",
        action="store_true",
        help="do not re-run the fixtures first (for debugging only; the rate is "
        "only meaningful if the instrument was just checked)",
    )
    run.set_defaults(func=_run)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ContainmentError as exc:
        print(f"containment error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
