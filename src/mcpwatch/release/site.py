"""Static dashboard generation.

One self-contained HTML file with inline CSS and no scripts. That is the whole
design: it can be served from any static host or opened from disk, it has no
build step, no dependencies and no runtime, and it costs nothing to keep online
for the years a longitudinal project runs. A dashboard that needs a server is a
dashboard that will be switched off.

**Aggregate statistics only.** No server is named. The corpus contains
per-server findings and this page deliberately does not surface them: naming is
gated on coordinated disclosure, and a public page rebuilt automatically on
every run is exactly the mechanism that would leak a name before that happened.
"""

import html
from dataclasses import dataclass
from typing import Any

from .metrics import Coverage, Metrics
from .pinning import PolicyOutcome

__all__ = ["render_site"]


@dataclass(frozen=True, slots=True)
class Stat:
    """One headline figure."""

    label: str
    value: str
    note: str = ""


_STYLE = """\
:root {
  color-scheme: light dark;
  --bg: #ffffff; --fg: #16181d; --muted: #5c6370;
  --line: #e3e6ea; --card: #f7f8fa; --accent: #2a5db0;
}
@media (prefers-color-scheme: dark) {
  :root { --bg: #16181d; --fg: #e8eaed; --muted: #9aa2ad;
          --line: #2c3037; --card: #1e2127; --accent: #7aa7f0; }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 2rem 1.25rem 4rem; background: var(--bg); color: var(--fg);
  font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
main { max-width: 60rem; margin: 0 auto; }
h1 { font-size: 1.9rem; margin: 0 0 .25rem; letter-spacing: -.02em; }
h2 { font-size: 1.15rem; margin: 2.5rem 0 .75rem; letter-spacing: -.01em; }
p.sub { color: var(--muted); margin: 0 0 2rem; }
.grid { display: grid; gap: .75rem; grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr)); }
.stat { background: var(--card); border: 1px solid var(--line);
  border-radius: 10px; padding: 1rem; }
.stat .v { font-size: 1.6rem; font-weight: 650; letter-spacing: -.02em; }
.stat .l { color: var(--muted); font-size: .82rem; margin-top: .15rem; }
.stat .n { color: var(--muted); font-size: .72rem; margin-top: .4rem; }
.scroll { overflow-x: auto; -webkit-overflow-scrolling: touch; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; min-width: 34rem; }
th, td { text-align: left; padding: .5rem .7rem; border-bottom: 1px solid var(--line); }
th { color: var(--muted); font-weight: 600; font-size: .78rem; text-transform: uppercase;
  letter-spacing: .04em; }
td.n, th.n { text-align: right; font-variant-numeric: tabular-nums; }
.note { background: var(--card); border-left: 3px solid var(--accent); border-radius: 0 8px 8px 0;
  padding: .85rem 1rem; margin: 1rem 0; font-size: .9rem; }
.note strong { color: var(--fg); }
ul.caveats { color: var(--muted); font-size: .88rem; padding-left: 1.1rem; }
footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--line);
  color: var(--muted); font-size: .8rem; }
code { background: var(--card); padding: .1rem .3rem; border-radius: 4px; font-size: .85em; }
"""


def _esc(value: object) -> str:
    return html.escape(str(value))


def _stats(stats: list[Stat]) -> str:
    cards = "".join(
        f'<div class="stat"><div class="v">{_esc(s.value)}</div>'
        f'<div class="l">{_esc(s.label)}</div>'
        + (f'<div class="n">{_esc(s.note)}</div>' if s.note else "")
        + "</div>"
        for s in stats
    )
    return f'<div class="grid">{cards}</div>'


def _table(headers: list[str], rows: list[list[str]], numeric_from: int = 1) -> str:
    head = "".join(
        f'<th class="n">{_esc(h)}</th>' if i >= numeric_from else f"<th>{_esc(h)}</th>"
        for i, h in enumerate(headers)
    )
    body = "".join(
        "<tr>"
        + "".join(
            f'<td class="n">{_esc(c)}</td>' if i >= numeric_from else f"<td>{_esc(c)}</td>"
            for i, c in enumerate(row)
        )
        + "</tr>"
        for row in rows
    )
    return (
        '<div class="scroll"><table>'
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody>"
        "</table></div>"
    )


def render_site(
    *,
    coverage: Coverage,
    layers: list[Metrics],
    outcomes: list[PolicyOutcome],
    pinning_layer: str,
    divergence: dict[str, Any] | None,
    generated_at: str,
) -> str:
    """Render the whole dashboard as one HTML document."""
    manifest = next((m for m in layers if m.layer == "manifest"), None)
    registry = next((m for m in layers if m.layer == "registry"), None)

    headline = [
        Stat("servers tracked", f"{coverage.servers_tracked:,}"),
        Stat(
            "registry transitions",
            f"{registry.transitions:,}" if registry else "—",
            f"spanning {registry.history_span_days:,.0f} days of published history"
            if registry
            else "",
        ),
        Stat(
            "Layer-2 observation",
            f"{manifest.observation_days:.1f} days" if manifest else "—",
            "cannot be backfilled",
        ),
        Stat(
            "reachable rate",
            f"{coverage.reachable_rate:.0%}",
            "about our access, not the ecosystem",
        ),
    ]

    policy_rows = []
    for outcome in outcomes:
        ratio = outcome.ratio()
        policy_rows.append(
            [
                outcome.policy.name,
                f"{outcome.blocked:,}",
                f"{outcome.passed:,}",
                f"{outcome.caught:,}",
                f"{outcome.missed:,}",
                "n/a" if ratio is None else f"{ratio:,.1f}",
            ]
        )

    layer_rows = [
        [
            m.layer,
            f"{m.observation_days:.1f}",
            f"{m.servers:,}",
            f"{m.transitions:,}",
            f"{m.changed:,}",
            f"{m.flagged:,}",
            f"{m.mutation_rate:.1%}",
        ]
        for m in layers
    ]

    flag_rows: list[list[str]] = []
    for m in layers:
        for flag, count in sorted(m.by_flag.items(), key=lambda kv: -kv[1]):
            flag_rows.append([flag, m.layer, f"{count:,}"])

    divergence_block = ""
    if divergence:
        rate = divergence.get("divergence_rate")
        interval = divergence.get("ci95") or [0.0, 0.0]
        low, high = float(interval[0]), float(interval[1])
        divergence_block = f"""
<h2>Description-behaviour divergence</h2>
{
            _stats(
                [
                    Stat(
                        "tools diverging",
                        f"{float(rate or 0):.1%}",
                        f"95% CI {low:.1%} to {high:.1%}",
                    ),
                    Stat("tools exercised", f"{divergence.get('tools_exercised', 0):,}"),
                    Stat(
                        "tools not exercised",
                        f"{divergence.get('tools_skipped', 0):,}",
                        "destructive-looking or over budget",
                    ),
                ]
            )
        }
<div class="note"><strong>What this measures.</strong> A tool was observed doing
something its description and schema never mentioned — opening a network
connection, touching the filesystem, running another program, or reading where
credentials live. Only observed-and-not-declared counts; a capability that was
not observed is not evidence of its absence.</div>
"""

    caveats = "".join(
        f"<li>{_esc(c)}</li>"
        for c in [
            "Severity flags are heuristics — reasons to look, not adjudicated findings.",
            "No adjudicated labels exist yet: WP7's inter-rater agreement gate is unmet.",
            "Layer-2 figures cover the observation window shown and are never annualised.",
            "Servers requiring credentials are never probed and are absent from every rate.",
            "Nondeterministic servers are quarantined from mutation statistics.",
        ]
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MCPWatch — MCP server mutation observatory</title>
<style>{_STYLE}</style>
</head>
<body>
<main>
<h1>MCPWatch</h1>
<p class="sub">A longitudinal observatory measuring how Model Context Protocol
server definitions change after publication. Aggregate statistics only — no
server is named.</p>

{_stats(headline)}

<h2>Would pinning have helped?</h2>
<p class="sub">Replaying {_esc(pinning_layer)}-layer transitions against
hypothetical content-hash pinning policies. <strong>Friction per catch</strong> is
benign updates blocked for every flagged change caught — the number that decides
the debate.</p>
{
        _table(
            ["policy", "blocked", "passed", "caught", "missed", "friction / catch"],
            policy_rows,
        )
    }
<div class="note"><strong>Read this honestly.</strong> "Caught" counts blocked
transitions carrying any severity flag, treating every flag as security-relevant.
That is an upper bound on the benefit, which makes every friction ratio here a
<em>lower</em> bound on the cost. A version bump counts as a block because not
receiving the new version automatically is precisely what pinning does.</div>

<h2>Mutation by layer</h2>
{
        _table(
            [
                "layer",
                "days observed",
                "servers",
                "transitions",
                "with changes",
                "flagged",
                "servers changed",
            ],
            layer_rows,
        )
    }

<h2>Severity flags observed</h2>
{_table(["flag", "layer", "transitions"], flag_rows, numeric_from=2)}
{divergence_block}
<h2>Coverage, as denominators</h2>
{
        _table(
            ["population", "count"],
            [
                ["Layer-2 targets, last cycle", f"{coverage.layer2_targets:,}"],
                ["yielded a usable manifest", f"{coverage.layer2_ok:,}"],
                ["required credentials we never supply", f"{coverage.layer2_auth_required:,}"],
                ["unreachable or timed out", f"{coverage.layer2_unreachable:,}"],
                ["quarantined as nondeterministic", f"{coverage.layer2_quarantined:,}"],
                ["sampled package servers attempted", f"{coverage.stdio_attempted:,}"],
                ["package servers enumerated", f"{coverage.stdio_enumerated:,}"],
            ],
        )
    }

<h2>Caveats</h2>
<ul class="caveats">{caveats}</ul>

<footer>
Generated {_esc(generated_at)} from the corpus, with no network access.
Reproducible: <code>python -m mcpwatch.release build</code>.
MCPWatch is an observatory, not a scanner. No server here is asserted to be malicious.
</footer>
</main>
</body>
</html>
"""
