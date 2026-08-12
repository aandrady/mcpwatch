"""Replaying the corpus against hypothetical pinning policies.

Practitioners are deciding right now whether to pin MCP servers by content hash,
and they are deciding it from first principles because nobody has the data to
price it. This module prices it.

**The scenario being replayed.** A consumer approves server *S* in state *A*.
The publisher later ships state *B*. Under a pinning policy the consumer's agent
refuses *B* until a human re-approves it. Every such refusal is friction; the
ones that stop a security-relevant change are the benefit. The number that
decides the debate is the ratio between them:

    benign updates blocked, per security-relevant change caught

**A version bump counts as a block, and this is not an accounting choice.**
Pinning's whole mechanism is that you do not get the new version automatically.
Exempting version bumps would measure a policy nobody proposes and would flatter
pinning by removing 99.8% of its cost. :data:`FRAMING` rule 2 applies: the ratio
is reported prominently even when — especially when — it is unflattering.

**Security relevance here is a proxy, not ground truth.** WP6's severity flags
are "reasons to look", and WP7's κ gate is unmet, so no adjudicated labels
exist. Every result from this module is therefore an estimate of what pinning
would catch *if every flagged change were security-relevant* — an upper bound on
the benefit, which makes the reported friction ratio a lower bound on the cost.
Both directions favour pinning, and the report says so. :func:`replay` also
computes a stricter variant over high-signal flags alone, because the gap
between the two bounds the proxy's own contribution.
"""

from collections.abc import Iterable
from dataclasses import dataclass, field

from mcpwatch.diff import ChangeKind, ChangeSet, SeverityFlag
from mcpwatch.store import JsonValue

__all__ = [
    "HIGH_SIGNAL_FLAGS",
    "POLICIES",
    "PinPolicy",
    "PolicyOutcome",
    "blocks",
    "replay",
]

HIGH_SIGNAL_FLAGS = frozenset(
    {
        SeverityFlag.CREDENTIAL_PARAM_ADDED,
        SeverityFlag.NETWORK_PARAM_ADDED,
        SeverityFlag.FILESYSTEM_PARAM_ADDED,
        SeverityFlag.IMPERATIVE_LANGUAGE_ADDED,
        SeverityFlag.DESTRUCTIVE_HINT_CLEARED,
        SeverityFlag.ENDPOINT_OR_REPO_MOVED,
    }
)
"""Flags that name a capability or authority change rather than a size change.

``TOOL_COUNT_GREW``, ``DESCRIPTION_GREW_SHARPLY`` and ``READONLY_HINT_SET`` are
excluded: a server growing is ordinary, and a publisher declaring
``readOnlyHint`` for the first time is metadata improving, not a guard dropping
(WP7 learned that one from the corpus). Reporting the ratio under both
definitions bounds how much of the answer comes from the proxy.
"""


@dataclass(frozen=True, slots=True)
class PinPolicy:
    """One hypothetical pinning rule.

    Attributes:
        name: Identifier used in the report.
        description: What a practitioner would understand this policy to be.
        allow_new_tools: A purely additive tool does not require re-approval.
        allow_description_changes: Description edits do not require re-approval.
        allow_additive_params: New parameters do not require re-approval.
    """

    name: str
    description: str
    allow_new_tools: bool = False
    allow_description_changes: bool = False
    allow_additive_params: bool = False


POLICIES: tuple[PinPolicy, ...] = (
    PinPolicy(
        name="whole_manifest",
        description=(
            "Pin the whole normalized manifest; any observable change requires re-approval."
        ),
    ),
    PinPolicy(
        name="per_tool",
        description=(
            "Pin each tool; a purely additive new tool passes, changes to existing tools do not."
        ),
        allow_new_tools=True,
    ),
    PinPolicy(
        name="description_exempt",
        description="As whole_manifest, but description-only edits pass without re-approval.",
        allow_description_changes=True,
    ),
    PinPolicy(
        name="additive_exempt",
        description="New tools and new parameters pass; edits to existing surface do not.",
        allow_new_tools=True,
        allow_additive_params=True,
    ),
    PinPolicy(
        name="permissive",
        description="Every additive or descriptive change passes; only edits and removals block.",
        allow_new_tools=True,
        allow_description_changes=True,
        allow_additive_params=True,
    ),
)
"""The variants the brief asks for, from strictest to most permissive.

``description_exempt`` is the one to read carefully. Exempting descriptions is
intuitively appealing — they are "just documentation" — and it is precisely the
surface tool-poisoning attacks use, because a description is what the model
reads. A policy that waves them through is a policy blind to the attack pinning
is usually proposed to stop.
"""

_DESCRIPTION_KINDS = frozenset(
    {ChangeKind.TOOL_DESCRIPTION_CHANGED, ChangeKind.SERVER_DESCRIPTION_CHANGED}
)
_ADDITIVE_KINDS = frozenset({ChangeKind.SCHEMA_PARAM_ADDED})
_NEW_TOOL_KINDS = frozenset({ChangeKind.TOOL_ADDED})


def _exempt(kind: ChangeKind, policy: PinPolicy) -> bool:
    """Whether one change kind passes without re-approval under ``policy``."""
    if kind in _DESCRIPTION_KINDS:
        return policy.allow_description_changes
    if kind in _ADDITIVE_KINDS:
        return policy.allow_additive_params
    if kind in _NEW_TOOL_KINDS:
        return policy.allow_new_tools
    return False


def blocks(changeset: ChangeSet, policy: PinPolicy) -> bool:
    """Whether ``policy`` would hold this transition for re-approval.

    A transition blocks unless *every* change in it is exempt. One
    non-exempt change is enough: a release bundling a typo fix with a new
    credential parameter is not a typo fix.
    """
    if not changeset.changes:
        return False
    return any(not _exempt(kind, policy) for kind in changeset.kinds)


@dataclass
class PolicyOutcome:
    """What one policy would have done across the replayed corpus."""

    policy: PinPolicy
    blocked: int = 0
    passed: int = 0
    caught: int = 0
    """Blocked transitions carrying at least one severity flag."""

    caught_high_signal: int = 0
    """Blocked transitions carrying a capability or authority flag."""

    missed: int = 0
    """Flagged transitions the policy let through. Pinning's false negatives."""

    caught_by_flag: dict[str, int] = field(default_factory=dict)

    blocked_by_namespace: dict[str, int] = field(default_factory=dict)
    caught_by_namespace: dict[str, int] = field(default_factory=dict)
    """Per publisher, because this population is not one server per publisher.

    One namespace owns 684 servers in the corpus, and a single fleet-wide edit
    there produces 684 transitions that a naive count reads as 684 independent
    catches. See :meth:`concentration`.
    """

    @property
    def friction(self) -> int:
        """Blocked transitions with no flag at all."""
        return self.blocked - self.caught

    def ratio(self, *, high_signal: bool = False) -> float | None:
        """Benign updates blocked per security-relevant change caught.

        ``None`` when nothing was caught: a ratio with a zero denominator is
        undefined, and reporting it as infinity or as the friction count would
        both be claims the data does not make.
        """
        caught = self.caught_high_signal if high_signal else self.caught
        if caught == 0:
            return None
        benign = self.blocked - caught
        return benign / caught

    def concentration(self) -> tuple[str, int, float] | None:
        """The publisher contributing most catches, its count, and its share.

        A monoculture check. Publishers here are not independent samples: one
        operator can own hundreds of servers and push an identical edit to all
        of them in a day, which inflates 'caught' by that fleet's size and makes
        pinning look proportionally better. Reporting the share lets a reader
        see when a headline ratio is one event wearing many hats.
        """
        if not self.caught_by_namespace or self.caught == 0:
            return None
        namespace, count = max(self.caught_by_namespace.items(), key=lambda kv: kv[1])
        return namespace, count, count / self.caught

    def ratio_excluding(self, namespace: str) -> float | None:
        """The friction ratio with one publisher's whole fleet removed.

        Not a correction — the fleet's transitions are real. A sensitivity
        check: if dropping one publisher moves the headline substantially, the
        headline was about that publisher.
        """
        caught = self.caught - self.caught_by_namespace.get(namespace, 0)
        blocked = self.blocked - self.blocked_by_namespace.get(namespace, 0)
        if caught <= 0:
            return None
        return (blocked - caught) / caught

    def as_json(self) -> dict[str, JsonValue]:
        """Render for the report."""
        ratio = self.ratio()
        strict = self.ratio(high_signal=True)
        top = self.concentration()
        payload: dict[str, JsonValue] = {
            "policy": self.policy.name,
            "description": self.policy.description,
            "blocked": self.blocked,
            "passed": self.passed,
            "caught_any_flag": self.caught,
            "caught_high_signal": self.caught_high_signal,
            "missed_flagged": self.missed,
            "friction": self.friction,
            "friction_ratio_any_flag": None if ratio is None else round(ratio, 2),
            "friction_ratio_high_signal": None if strict is None else round(strict, 2),
            "caught_by_flag": dict(sorted(self.caught_by_flag.items())),
        }
        if top is not None:
            namespace, count, share = top
            adjusted = self.ratio_excluding(namespace)
            payload["largest_publisher"] = namespace
            payload["largest_publisher_catches"] = count
            payload["largest_publisher_share"] = round(share, 4)
            payload["friction_ratio_excluding_largest"] = (
                None if adjusted is None else round(adjusted, 2)
            )
        return payload


def replay(
    changesets: Iterable[ChangeSet], policies: Iterable[PinPolicy] = POLICIES
) -> list[PolicyOutcome]:
    """Replay transitions against each policy.

    Quarantined servers are excluded. A server whose manifest differs between
    two probes minutes apart cannot support a claim about what changed
    overnight, and counting its phantom transitions as friction would inflate
    pinning's cost with our own measurement error.
    """
    outcomes = [PolicyOutcome(policy=policy) for policy in policies]
    for changeset in changesets:
        if changeset.quarantined or not changeset.changes:
            continue
        flags = set(changeset.flags)
        high = bool(flags & HIGH_SIGNAL_FLAGS)

        namespace = changeset.server_key.split("/", 1)[0]
        for outcome in outcomes:
            if blocks(changeset, outcome.policy):
                outcome.blocked += 1
                outcome.blocked_by_namespace[namespace] = (
                    outcome.blocked_by_namespace.get(namespace, 0) + 1
                )
                if flags:
                    outcome.caught_by_namespace[namespace] = (
                        outcome.caught_by_namespace.get(namespace, 0) + 1
                    )
                    outcome.caught += 1
                    for flag in flags:
                        outcome.caught_by_flag[str(flag)] = (
                            outcome.caught_by_flag.get(str(flag), 0) + 1
                        )
                if high:
                    outcome.caught_high_signal += 1
            else:
                outcome.passed += 1
                if flags:
                    outcome.missed += 1
    return outcomes


def render(outcomes: list[PolicyOutcome], *, layer: str, transitions: int) -> str:
    """Human-readable retrospective."""
    lines = [
        f"Pinning retrospective over {transitions:,} {layer}-layer transitions",
        "",
        f"{'policy':<20} {'blocked':>8} {'passed':>7} {'caught':>7} {'missed':>7}"
        f" {'friction/catch':>15} {'high-signal':>12}",
        "-" * 82,
    ]
    for outcome in outcomes:
        loose = outcome.ratio()
        strict = outcome.ratio(high_signal=True)
        lines.append(
            f"{outcome.policy.name:<20} {outcome.blocked:>8,} {outcome.passed:>7,} "
            f"{outcome.caught:>7,} {outcome.missed:>7,} "
            f"{('n/a' if loose is None else f'{loose:,.1f}'):>15}"
            f" {('n/a' if strict is None else f'{strict:,.1f}'):>12}"
        )

    lines += [
        "",
        "'caught' counts blocked transitions carrying any WP6 severity flag — a",
        "reason to look, not an adjudicated finding. WP7's kappa gate is unmet, so",
        "no adjudicated labels exist yet. Treating every flag as security-relevant",
        "is an upper bound on what pinning catches, which makes every friction",
        "ratio here a LOWER bound on what pinning costs.",
        "",
        "The 'high-signal' column repeats the ratio counting only flags that name a",
        "capability or authority change — a credential, network or filesystem",
        "parameter appearing, text addressed to the model, a destructive hint",
        "cleared, an endpoint or repository moving. The gap between the two columns",
        "is how much of the answer comes from the proxy rather than from the data.",
    ]

    top = outcomes[0].concentration() if outcomes else None
    if top is not None and top[2] >= 0.2:
        namespace, count, share = top
        adjusted = outcomes[0].ratio_excluding(namespace)
        shown = "undefined" if adjusted is None else f"{adjusted:,.1f}"
        lines += [
            "",
            f"CONCENTRATION WARNING: {share:.0%} of catches ({count:,}) come from a",
            f"single publisher, {namespace}.",
            "",
            "Publishers here are not independent samples. One operator can own",
            "hundreds of servers and push an identical edit to all of them in a day,",
            "which a naive count reads as hundreds of separate catches. Excluding",
            f"that publisher entirely, the friction ratio is {shown} rather than",
            f"{outcomes[0].ratio():,.1f} — a sensitivity check, not a correction, since",
            "those transitions did happen.",
        ]

    distinct = {(o.blocked, o.passed, o.caught) for o in outcomes}
    if len(distinct) == 1 and len(outcomes) > 1:
        lines += [
            "",
            "Every policy variant produced an identical outcome. The variants exempt",
            "tool-level changes — a new tool, a description edit, an added parameter —",
            "and this layer has none: a registry transition is a republication, and",
            "99.8% of them bump the version, which no pinning policy exempts. The",
            "sensitivity analysis only has room to move at the manifest layer.",
        ]
    return "\n".join(lines)
