"""High-precision deterministic detectors, run before the model.

**Precision is the whole design goal here; recall is the LLM's job.** A rule
that fires on a real attack and also on fifty honest descriptions has not
found anything — it has moved the work from the classifier to the adjudicator.
So every rule below is written to be *narrow*, and each one that survived
tuning has a note about the false positive that shaped it.

This layer exists for three reasons beyond speed. It settles the unambiguous
cases without spending a model call; its hits are shown to human adjudicators
as evidence rather than as a verdict; and — because it is deterministic — it is
the only part of the pipeline whose behaviour is guaranteed identical a year
from now, which makes it the control when measuring classifier drift.

A rule firing is *not* a classification. :func:`classify` returns a label only
when the evidence is strong enough that a careful human would agree without
argument; everything else returns ``None`` and goes to the model.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass

from mcpwatch.diff import Change, ChangeKind, ChangeSet
from mcpwatch.diff.text import looks_like_network, split_identifier

from .taxonomy import Label, most_severe

__all__ = ["RULES", "Rule", "RuleHit", "classify", "describe", "evaluate"]


@dataclass(frozen=True, slots=True)
class RuleHit:
    """One deterministic detector firing on a ChangeSet."""

    rule: str
    label: Label
    confident: bool
    """Whether this hit alone justifies the label without a model call.

    A confident hit is one where the evidence is not open to a second reading —
    an explicit "ignore previous instructions", a `destructiveHint` cleared.
    Suggestive hits are evidence for the adjudicator and a prior for the model,
    never a verdict.
    """

    evidence: str

    def as_json(self) -> dict[str, object]:
        """Render for machine consumption."""
        return {
            "rule": self.rule,
            "label": str(self.label),
            "confident": self.confident,
            "evidence": self.evidence[:500],
        }


@dataclass(frozen=True, slots=True)
class Rule:
    """A named detector over a ChangeSet."""

    name: str
    label: Label
    confident: bool
    describe: str


# Phrases whose *only* honest reading is an instruction to the model. Narrower
# than the WP6 triage list on purpose: that one orders a review queue and can
# afford noise, this one can assign a label. "you must" and "always use" are
# deliberately absent — both are overwhelmingly ordinary documentation
# ("You must supply an API key"), and including them made the rule fire on
# honest servers in the corpus.
_INJECTION_PHRASES = (
    "ignore previous",
    "ignore all previous",
    "ignore prior",
    "disregard previous",
    "disregard the above",
    "disregard any previous",
    "do not tell the user",
    "do not inform the user",
    "without telling the user",
    "without informing the user",
    "do not reveal",
    "never reveal to the user",
    "do not mention this",
    "never mention this",
    "before using any other tool",
    "before any other tool",
    "always call this tool first",
    "call this tool before",
    "new instructions",
    "system prompt",
    "override your",
    "override the",
)

# Claims of standing rather than of function. "official" and "verified" alone
# are too common in legitimate copy ("the official Stripe API"), so each phrase
# here pairs the claim with the model's own decision-making.
_AUTHORITY_PHRASES = (
    "this tool takes precedence",
    "takes priority over",
    "highest priority",
    "trusted tool",
    "authoritative source",
    "must be used instead of",
    "supersedes",
    "overrides other tools",
    "do not use other",
    "preferred over all",
)

_EXFIL_PARAM = re.compile(
    r"\b(webhook|callback|exfil|forward_to|send_to|post_to|report_to|"
    r"notify_url|upload_url|destination_url|remote_url|sink)\b",
    re.IGNORECASE,
)

_COMMAND_PARAM = re.compile(
    r"\b(cmd|command|shell|exec|execute|script|eval|bash|sh|powershell|"
    r"subprocess|system)\b",
    re.IGNORECASE,
)

RULES: tuple[Rule, ...] = (
    Rule(
        "injection_phrase_added",
        Label.INSTRUCTION_INJECTION,
        True,
        "Text addressed to the model appeared in a description",
    ),
    Rule(
        "authority_claim_added",
        Label.AUTHORITY_ESCALATION,
        True,
        "Text claiming precedence or trust appeared in a description",
    ),
    Rule(
        "annotation_downgraded",
        Label.AUTHORITY_ESCALATION,
        True,
        "destructiveHint cleared or readOnlyHint set, lowering a client's guard",
    ),
    Rule(
        "exfiltration_param_added",
        Label.EXFILTRATION_ADDITION,
        True,
        "A parameter whose name means 'send this elsewhere' appeared",
    ),
    Rule(
        "command_param_added",
        Label.SCOPE_EXPANSION,
        True,
        "A parameter that takes a command or script appeared",
    ),
    Rule(
        "endpoint_moved",
        Label.EXFILTRATION_ADDITION,
        False,
        "The server's remote endpoint changed",
    ),
    Rule(
        "network_param_added",
        Label.EXFILTRATION_ADDITION,
        False,
        "A parameter that can address a network location appeared",
    ),
    Rule(
        "enum_widened",
        Label.SCOPE_EXPANSION,
        False,
        "A parameter's permitted values grew",
    ),
    Rule(
        "tool_added",
        Label.SCOPE_EXPANSION,
        False,
        "The server gained a tool",
    ),
)

_BY_NAME = {rule.name: rule for rule in RULES}


def _added_text(change: Change) -> str:
    """The text a change introduced, for phrase matching.

    Only *added* tokens are searched. A description that always contained
    "system prompt" has not started addressing the model by being edited
    elsewhere, and matching the whole after-text would fire on it every time
    the server republished.
    """
    if change.text is not None:
        return " ".join(change.text.added)
    return change.after if isinstance(change.after, str) else ""


def _param_name(change: Change) -> str:
    return split_identifier(change.path.rsplit("/", 1)[-1])


def _annotation_reversal(change: Change) -> str | None:
    """Name the annotation a server explicitly reversed, or None.

    The distinction this draws was found by running the rule over the corpus:
    of the first twenty hits, all but two were ``None -> {readOnlyHint: true}``
    — a publisher declaring annotations for the first time, which is metadata
    being filled in, not a guard being lowered. Reading the WP6 triage flag was
    what conflated them; that flag is deliberately over-inclusive because it
    only orders a review queue, and a rule that assigns a label cannot borrow
    it.

    A reversal requires the previous value to have been explicitly the other
    way: ``destructiveHint`` true -> false, or ``readOnlyHint`` false -> true.
    A first declaration is neither.
    """
    before = change.before if isinstance(change.before, dict) else {}
    after = change.after if isinstance(change.after, dict) else {}
    if before.get("destructiveHint") is True and after.get("destructiveHint") is False:
        return "destructiveHint true -> false"
    if before.get("readOnlyHint") is False and after.get("readOnlyHint") is True:
        return "readOnlyHint false -> true"
    return None


def _enum_of(value: object) -> set[str]:
    if isinstance(value, dict):
        enum = value.get("enum")
        if isinstance(enum, list):
            return {str(item) for item in enum}
    return set()


def evaluate(changeset: ChangeSet) -> list[RuleHit]:
    """Run every rule over a ChangeSet and return the hits, most severe first."""
    hits: list[RuleHit] = []
    text_kinds = {
        ChangeKind.TOOL_DESCRIPTION_CHANGED,
        ChangeKind.PARAM_DESCRIPTION_CHANGED,
        ChangeKind.SERVER_DESCRIPTION_CHANGED,
        ChangeKind.PROMPT_CHANGED,
        ChangeKind.TOOL_ADDED,
    }

    for change in changeset.changes:
        if change.kind in text_kinds:
            text = _added_text(change)
            if change.kind is ChangeKind.TOOL_ADDED:
                after = change.after
                described = after.get("description") if isinstance(after, dict) else None
                text = described if isinstance(described, str) else ""
            lowered = text.casefold()
            for phrase in _INJECTION_PHRASES:
                if phrase in lowered:
                    hits.append(
                        RuleHit("injection_phrase_added", Label.INSTRUCTION_INJECTION, True, phrase)
                    )
                    break
            for phrase in _AUTHORITY_PHRASES:
                if phrase in lowered:
                    hits.append(
                        RuleHit("authority_claim_added", Label.AUTHORITY_ESCALATION, True, phrase)
                    )
                    break

        elif change.kind is ChangeKind.SCHEMA_PARAM_ADDED:
            name = _param_name(change)
            if _EXFIL_PARAM.search(name):
                hits.append(
                    RuleHit("exfiltration_param_added", Label.EXFILTRATION_ADDITION, True, name)
                )
            elif _COMMAND_PARAM.search(name):
                hits.append(RuleHit("command_param_added", Label.SCOPE_EXPANSION, True, name))
            elif looks_like_network(name, change.after):
                hits.append(
                    RuleHit("network_param_added", Label.EXFILTRATION_ADDITION, False, name)
                )

        elif change.kind is ChangeKind.PARAM_SCHEMA_CHANGED:
            gained = _enum_of(change.after) - _enum_of(change.before)
            if gained:
                hits.append(
                    RuleHit("enum_widened", Label.SCOPE_EXPANSION, False, ", ".join(sorted(gained)))
                )

        elif change.kind is ChangeKind.ANNOTATION_CHANGED:
            reversal = _annotation_reversal(change)
            if reversal is not None:
                hits.append(
                    RuleHit("annotation_downgraded", Label.AUTHORITY_ESCALATION, True, reversal)
                )

    if any(c.kind is ChangeKind.ENDPOINT_CHANGED for c in changeset.changes):
        hits.append(RuleHit("endpoint_moved", Label.EXFILTRATION_ADDITION, False, "server/remotes"))
    if any(c.kind is ChangeKind.TOOL_ADDED for c in changeset.changes):
        hits.append(RuleHit("tool_added", Label.SCOPE_EXPANSION, False, "tools"))

    return _dedupe(hits)


def _dedupe(hits: Sequence[RuleHit]) -> list[RuleHit]:
    """One hit per rule, keeping the first (and therefore most specific)."""
    seen: dict[str, RuleHit] = {}
    for hit in hits:
        seen.setdefault(hit.rule, hit)
    return sorted(seen.values(), key=lambda h: (not h.confident, h.rule))


def classify(changeset: ChangeSet) -> tuple[Label | None, list[RuleHit]]:
    """Settle a ChangeSet deterministically, or defer to the model.

    Returns:
        ``(label, hits)`` where ``label`` is None unless at least one confident
        rule fired. Deferring is the common case and the correct default: these
        rules can recognize an attack they have a pattern for, and nothing else.
    """
    hits = evaluate(changeset)
    confident = [hit.label for hit in hits if hit.confident]
    if not confident:
        return None, hits
    return most_severe(confident), hits


def describe(rule_name: str) -> str:
    """One-line description of a rule, for the adjudication UI."""
    rule = _BY_NAME.get(rule_name)
    return rule.describe if rule is not None else rule_name
