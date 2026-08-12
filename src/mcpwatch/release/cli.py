"""``python -m mcpwatch.release`` — the project's outputs.

``pinning``   replay the corpus against hypothetical pinning policies
``metrics``   the mutation and coverage report
``build``     everything, plus the datasheet and the static dashboard

All of it reads the corpus and nothing else. No network access, so a reviewer
with a copy of the corpus reproduces every number by running the same command —
which is WP10's stated gate.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from mcpwatch.diff import ChangeSet, DiffEngine
from mcpwatch.store import Corpus, Layer, to_iso, utcnow

from . import pinning
from .datasheet import render_datasheet
from .metrics import (
    collect_coverage,
    history_span_days,
    observation_days,
    summarise_changesets,
)
from .site import render_site

__all__ = ["main"]


def _default_corpus_root() -> Path:
    override = os.environ.get("MCPWATCH_CORPUS")
    return Path(override) if override else Path.home() / "mcpwatch-corpus"


def _changesets(corpus: Corpus, layer: Layer) -> list[ChangeSet]:
    return list(DiffEngine(corpus).changesets(layer=layer))


PUBLISHABLE_DIVERGENCE_KEYS = (
    "servers_exercised",
    "tools_exercised",
    "tools_skipped",
    "tools_unexercised",
    "diverging_tools",
    "divergence_rate",
    "ci95",
    "by_class",
    "skip_reasons",
    "launch_failures",
    "caveats",
)
"""Divergence fields safe to write into the published directory.

`findings` is deliberately absent: it carries a `server_key` per finding, and
naming a server is gated on coordinated disclosure. Everything `build` writes
lands in one directory that a static host serves wholesale, so a file in it is
published whether or not the dashboard links to it — which is exactly how a name
leaks without anyone deciding to publish it.
"""


def _publishable(divergence: dict[str, Any] | None) -> dict[str, Any] | None:
    """Strip per-server detail from a divergence run's stats."""
    if divergence is None:
        return None
    return {k: v for k, v in divergence.items() if k in PUBLISHABLE_DIVERGENCE_KEYS}


def _publishable_pinning(policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop the named publisher from the concentration finding.

    The concentration itself is the methodological point and stays: what share
    of catches came from one operator, and what the ratio becomes without them.
    The operator's identity is not the point, and naming a publisher beside a
    column headed "caught" in a security report reads as an accusation whatever
    the surrounding prose says. It is an ambiguous case, and FRAMING rule 6 says
    ambiguous cases are not named. The console report, which the operator reads
    and does not publish, keeps the name.
    """
    published = []
    for policy in policies:
        row = dict(policy)
        if row.pop("largest_publisher", None) is not None:
            row["largest_publisher"] = "withheld pending disclosure policy"
        published.append(row)
    return published


def _latest_divergence(corpus: Corpus) -> dict[str, Any] | None:
    """The most recent WP9 run's stats, if one has been recorded."""
    row = corpus.index.connection.execute(
        """
        SELECT stats_json FROM run
        WHERE collector = 'divergence' AND finished_at IS NOT NULL
        ORDER BY started_at DESC LIMIT 1
        """
    ).fetchone()
    if row is None or not row["stats_json"]:
        return None
    parsed = json.loads(row["stats_json"])
    return parsed if isinstance(parsed, dict) else None


def _pinning(args: argparse.Namespace) -> int:
    """Replay the corpus against pinning policies."""
    layer = Layer(args.layer)
    with Corpus(args.corpus) as corpus:
        changesets = _changesets(corpus, layer)
    outcomes = pinning.replay(changesets)
    usable = sum(1 for c in changesets if c.changes and not c.quarantined)
    print(pinning.render(outcomes, layer=str(layer), transitions=usable))
    if args.json:
        Path(args.json).write_text(
            json.dumps(
                {
                    "layer": str(layer),
                    "transitions": usable,
                    "policies": [o.as_json() for o in outcomes],
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        print(f"\nwrote {args.json}")
    return 0


def _metrics(args: argparse.Namespace) -> int:
    """Report mutation figures and coverage."""
    with Corpus(args.corpus) as corpus:
        coverage = collect_coverage(corpus)
        layers = [
            summarise_changesets(
                _changesets(corpus, layer),
                layer=str(layer),
                days=observation_days(corpus, layer),
                span=history_span_days(corpus, layer),
            )
            for layer in (Layer.REGISTRY, Layer.MANIFEST)
        ]
    payload = {
        "coverage": coverage.as_json(),
        "layers": [m.as_json() for m in layers],
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _build(args: argparse.Namespace) -> int:
    """Produce every output into one directory."""
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    generated_at = to_iso(utcnow())

    with Corpus(args.corpus) as corpus:
        coverage = collect_coverage(corpus)
        layers = [
            summarise_changesets(
                _changesets(corpus, layer),
                layer=str(layer),
                days=observation_days(corpus, layer),
                span=history_span_days(corpus, layer),
            )
            for layer in (Layer.REGISTRY, Layer.MANIFEST)
        ]
        pin_layer = Layer(args.pinning_layer)
        outcomes = pinning.replay(_changesets(corpus, pin_layer))
        divergence = _latest_divergence(corpus)
        datasheet = render_datasheet(corpus, coverage, layers, generated_at=generated_at)

    (out / "index.html").write_text(
        render_site(
            coverage=coverage,
            layers=layers,
            outcomes=outcomes,
            pinning_layer=str(pin_layer),
            divergence=divergence,
            generated_at=generated_at,
        ),
        encoding="utf-8",
    )
    (out / "DATASHEET.md").write_text(datasheet, encoding="utf-8")
    (out / "metrics.json").write_text(
        json.dumps(
            {
                "generated_at": generated_at,
                "coverage": coverage.as_json(),
                "layers": [m.as_json() for m in layers],
                "pinning": {
                    "layer": str(pin_layer),
                    "policies": _publishable_pinning([o.as_json() for o in outcomes]),
                },
                "divergence": _publishable(divergence),
            },
            indent=2,
            sort_keys=True,
            default=str,
        ),
        encoding="utf-8",
    )

    print(f"wrote {out / 'index.html'}")
    print(f"wrote {out / 'DATASHEET.md'}")
    print(f"wrote {out / 'metrics.json'} (aggregate only — no server is named)")
    print()
    print(
        pinning.render(
            outcomes,
            layer=str(pin_layer),
            transitions=sum(o.blocked + o.passed for o in outcomes[:1]),
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="python -m mcpwatch.release",
        description="Produce MCPWatch's outputs from the corpus. No network access.",
    )
    parser.add_argument("--corpus", type=Path, default=_default_corpus_root())
    sub = parser.add_subparsers(dest="command", required=True)

    pin = sub.add_parser("pinning", help="replay the corpus against pinning policies")
    pin.add_argument("--layer", choices=("registry", "manifest"), default="manifest")
    pin.add_argument("--json", type=str, default=None)
    pin.set_defaults(func=_pinning)

    met = sub.add_parser("metrics", help="mutation figures and coverage, as JSON")
    met.set_defaults(func=_metrics)

    build = sub.add_parser("build", help="dashboard, datasheet and metrics into one directory")
    build.add_argument("--out", type=str, default="site")
    build.add_argument("--pinning-layer", choices=("registry", "manifest"), default="manifest")
    build.set_defaults(func=_build)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, ValueError) as exc:
        print(f"release failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
