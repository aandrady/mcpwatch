"""Divergence per tool, and the rate across a sample.

A finding is one tool holding an observed capability its declaration did not
mention. The comparison is one-directional — see
:mod:`~mcpwatch.divergence.capabilities` — so "declared but not observed" is
recorded as context and never scored.

**The interval is Wilson, not normal.** Divergence classes are rare; a normal
approximation on a proportion near zero produces intervals that include negative
values and understates the upper bound exactly where the interesting classes
live. Wilson is well-behaved at the extremes, needs no extra dependency, and is
the standard choice for this shape of measurement.

**What the interval does and does not cover.** It quantifies sampling error over
the tools actually exercised. It says nothing about the far larger uncertainties
in this measurement: the exercise protocol skips destructive-looking tools, each
tool is invoked once with synthetic arguments on one code path, and the declared
side is extracted from prose by rules tuned to over-declare. Those are stated as
caveats alongside every rate rather than folded into a number that would look
more precise than the method is.
"""

import math
from dataclasses import dataclass, field

from mcpwatch.store import JsonValue

from .capabilities import DIVERGENCE_CLASS, Capability, CapabilityProfile

__all__ = ["CAVEATS", "DivergenceReport", "Finding", "score_tool", "wilson_interval"]

Z_95 = 1.959963984540054
"""Two-sided 95%."""

CAVEATS = (
    "Tools are exercised once each, with synthetic arguments, on one code path; "
    "a capability not observed may still exist.",
    "Tools whose annotations or names indicate a destructive action are never "
    "invoked, so the exercised set is not a random sample of all tools.",
    "Declared capabilities are extracted by rules tuned to over-declare, which "
    "biases the measured divergence rate downward.",
    "Egress is sinkholed, so a tool depending on a real response may abandon a "
    "code path early and appear less capable than it is.",
    "The interval covers sampling error only, not the above.",
)
"""Stated with every reported rate. The brief asks for them plainly, and each
one is a way this number could be wrong that an interval does not capture."""


@dataclass(frozen=True, slots=True)
class Finding:
    """One tool doing something its description did not mention."""

    server_key: str
    tool: str
    capability: Capability
    evidence: tuple[str, ...]

    @property
    def divergence_class(self) -> str:
        """WP9's reported class for this capability."""
        return DIVERGENCE_CLASS[self.capability]

    def as_json(self) -> dict[str, JsonValue]:
        """Render for the corpus."""
        return {
            "server_key": self.server_key,
            "tool": self.tool,
            "capability": str(self.capability),
            "class": self.divergence_class,
            "evidence": list(self.evidence),
        }


def score_tool(
    server_key: str, tool: str, declared: CapabilityProfile, observed: CapabilityProfile
) -> list[Finding]:
    """Every capability observed for one tool that its declaration did not claim."""
    return [
        Finding(
            server_key=server_key,
            tool=tool,
            capability=capability,
            # Bounded: a chatty tool can produce hundreds of identical syscalls,
            # and three examples make the case as well as three hundred.
            evidence=observed.reasons(capability)[:3],
        )
        for capability in sorted(observed.undeclared_against(declared), key=str)
    ]


def wilson_interval(successes: int, trials: int, z: float = Z_95) -> tuple[float, float]:
    """Wilson score interval for a proportion.

    Args:
        successes: Count of the event.
        trials: Total observations.
        z: Standard normal quantile; the default is two-sided 95%.

    Returns:
        ``(low, high)``, both in ``[0, 1]``. ``(0.0, 0.0)`` when there are no
        trials — an empty sample has no proportion, and returning 0 is honest in
        a way that returning ``nan`` or raising would not be for a report.
    """
    if trials <= 0:
        return (0.0, 0.0)
    proportion = successes / trials
    denominator = 1 + z**2 / trials
    centre = proportion + z**2 / (2 * trials)
    spread = z * math.sqrt(proportion * (1 - proportion) / trials + z**2 / (4 * trials**2))
    return (
        max(0.0, (centre - spread) / denominator),
        min(1.0, (centre + spread) / denominator),
    )


@dataclass
class DivergenceReport:
    """Findings across a sample, with rates and the caveats they need."""

    tools_exercised: int = 0
    servers_exercised: int = 0
    tools_skipped: int = 0
    findings: list[Finding] = field(default_factory=list)
    skip_reasons: dict[str, int] = field(default_factory=dict)
    unexercised: int = 0
    """Tools that were selected but produced no result — the server died, the
    call timed out. Excluded from the denominator: a tool that never ran is not
    a tool that diverged, and counting it either way would be a claim."""

    def add(self, findings: list[Finding]) -> None:
        """Record one tool's findings."""
        self.findings.extend(findings)

    @property
    def diverging_tools(self) -> int:
        """Tools with at least one undeclared capability."""
        return len({(f.server_key, f.tool) for f in self.findings})

    def rate(self) -> tuple[float, tuple[float, float]]:
        """Fraction of exercised tools that diverged, with a 95% interval."""
        if not self.tools_exercised:
            return 0.0, (0.0, 0.0)
        return (
            self.diverging_tools / self.tools_exercised,
            wilson_interval(self.diverging_tools, self.tools_exercised),
        )

    def by_class(self) -> dict[str, int]:
        """Distinct tools affected, per divergence class."""
        counts: dict[str, set[tuple[str, str]]] = {}
        for finding in self.findings:
            counts.setdefault(finding.divergence_class, set()).add(
                (finding.server_key, finding.tool)
            )
        return {name: len(tools) for name, tools in sorted(counts.items())}

    def as_json(self) -> dict[str, JsonValue]:
        """Render for the corpus, caveats included.

        The caveats travel with the number rather than living in a README,
        because the number is the thing that gets quoted.
        """
        rate, (low, high) = self.rate()
        return {
            "servers_exercised": self.servers_exercised,
            "tools_exercised": self.tools_exercised,
            "tools_skipped": self.tools_skipped,
            "tools_unexercised": self.unexercised,
            "diverging_tools": self.diverging_tools,
            "divergence_rate": round(rate, 4),
            "ci95": [round(low, 4), round(high, 4)],
            "by_class": dict(self.by_class()),
            "skip_reasons": dict(sorted(self.skip_reasons.items())),
            "findings": [f.as_json() for f in self.findings],
            "caveats": list(CAVEATS),
        }

    def render(self) -> str:
        """Human-readable summary."""
        rate, (low, high) = self.rate()
        lines = [
            f"{self.servers_exercised} servers, {self.tools_exercised} tools exercised "
            f"({self.tools_skipped} skipped, {self.unexercised} did not run)",
            f"diverging tools: {self.diverging_tools}/{self.tools_exercised} = {rate:.1%} "
            f"(95% CI {low:.1%}-{high:.1%})",
        ]
        if self.by_class():
            lines.append("")
            for name, count in self.by_class().items():
                lines.append(f"  {name:34} {count:4} tools")
        if self.skip_reasons:
            lines.append("")
            lines.append("  not exercised:")
            for reason, count in sorted(self.skip_reasons.items(), key=lambda kv: -kv[1])[:8]:
                lines.append(f"    {count:4}  {reason}")
        lines.append("")
        lines.append("Caveats:")
        lines.extend(f"  - {caveat}" for caveat in CAVEATS)
        return "\n".join(lines)
