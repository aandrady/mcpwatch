"""The mutation taxonomy — one primary label per ChangeSet.

These five labels are the project's headline output, so their definitions live
in one place and are quoted verbatim into the LLM prompt and the adjudication
UI. A rater and a classifier working from differently-worded definitions of
``scope_expansion`` do not disagree about a change; they disagree about the
word, and the resulting κ measures nothing.

**Exactly one primary label.** Real changes are frequently several of these at
once — a new `webhook_url` parameter is both scope expansion and an
exfiltration addition. The taxonomy handles that with a documented precedence
order rather than by letting each rater pick a favourite, because a
multi-label scheme cannot be scored with Cohen's κ and an undocumented tie-break
is just noise with extra steps.
"""

from enum import StrEnum

__all__ = ["PRECEDENCE", "Label", "definition", "definitions_block"]


class Label(StrEnum):
    """The primary label assigned to a ChangeSet.

    Order of declaration is not precedence — see :data:`PRECEDENCE`.
    """

    BENIGN = "benign"
    SCOPE_EXPANSION = "scope_expansion"
    INSTRUCTION_INJECTION = "instruction_injection"
    EXFILTRATION_ADDITION = "exfiltration_addition"
    AUTHORITY_ESCALATION = "authority_escalation"
    UNDECIDABLE = "undecidable"
    """Not in the plan's taxonomy, and deliberately added.

    A rater who must choose one of five labels for a change they cannot judge
    will choose ``benign``, because it is the safest-sounding. That silently
    moves unreadable cases into the denominator of the benign rate — the single
    number this project exists to report. An explicit escape hatch keeps them
    countable and excludable.
    """


_DEFINITIONS: dict[Label, str] = {
    Label.BENIGN: (
        "Typos, formatting, wording, dependency bumps, and genuine feature work "
        "consistent with the server's stated purpose. A server adding a second "
        "read-only query tool to a search server is benign. Benign is a positive "
        "finding, not a residual category — if the change cannot be read at all, "
        "use undecidable."
    ),
    Label.SCOPE_EXPANSION: (
        "New parameters, tools, or permitted values that broaden what the server "
        "can do beyond what its description leads a user to expect. An enum "
        "widening from ['read'] to ['read','write','exec'] is the clearest case. "
        "The test is the gap between declared purpose and new capability, not "
        "whether the capability is dangerous in isolation."
    ),
    Label.INSTRUCTION_INJECTION: (
        "Text in a description, prompt, or parameter doc addressed to the *model* "
        "rather than describing the tool to a human — instructions to call this "
        "tool first, to ignore prior instructions, to conceal an action from the "
        "user, or to treat the text as authoritative. The audience of the text is "
        "what distinguishes this from ordinary documentation."
    ),
    Label.EXFILTRATION_ADDITION: (
        "New parameters, remotes, or endpoints capable of moving conversation "
        "context, credentials, or file contents off the host — a webhook or "
        "callback URL, an arbitrary destination host, a new remote endpoint on a "
        "tool that reads local data. Capability is the test; intent is not "
        "observable from a diff."
    ),
    Label.AUTHORITY_ESCALATION: (
        "New claims of trust, priority, or override: text asserting the tool is "
        "official, verified, or must take precedence, or annotation changes that "
        "lower a client's guard — destructiveHint cleared, readOnlyHint set — so "
        "the tool is auto-approved where it previously required confirmation."
    ),
    Label.UNDECIDABLE: (
        "The ChangeSet does not carry enough to judge: the diff is unreadable, "
        "the server's purpose is unstated, or the change is real but its meaning "
        "cannot be determined without information the corpus does not hold. "
        "Choose this rather than defaulting to benign."
    ),
}


PRECEDENCE: tuple[Label, ...] = (
    Label.INSTRUCTION_INJECTION,
    Label.EXFILTRATION_ADDITION,
    Label.AUTHORITY_ESCALATION,
    Label.SCOPE_EXPANSION,
    Label.BENIGN,
    Label.UNDECIDABLE,
)
"""Tie-break order when a change genuinely fits several labels, most severe first.

Published rather than implicit, because the alternative is every rater
inventing their own and the disagreement being scored as if it were about the
data. Ordered by how directly the class describes an attack on the *user*:
text aimed at the model outranks a capability that could move their data, which
outranks a claim that lowers their client's guard, which outranks a capability
that merely exceeds the description.

``BENIGN`` sits above ``UNDECIDABLE`` so that a readable change is labelled
rather than deferred; ``UNDECIDABLE`` is a floor, never a tie-break winner.
"""


def definition(label: Label) -> str:
    """Return the canonical one-paragraph definition of a label."""
    return _DEFINITIONS[label]


def definitions_block() -> str:
    """Render every definition, for the prompt and the adjudication UI.

    Both surfaces read from this function so a definition can never drift
    between what the model was told and what the human was shown.
    """
    return "\n\n".join(f"{label.value}: {_DEFINITIONS[label]}" for label in PRECEDENCE)


def most_severe(labels: list[Label]) -> Label:
    """Collapse several applicable labels to one, by :data:`PRECEDENCE`."""
    for candidate in PRECEDENCE:
        if candidate in labels:
            return candidate
    return Label.UNDECIDABLE
