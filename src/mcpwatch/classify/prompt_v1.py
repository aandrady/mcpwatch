"""Version 1 of the classifier prompt, versioned in-repo and hashed.

Kept as a module constant rather than an external file so it travels with the
package, diffs in review, and cannot be edited on a production host without the
change showing up in git. Every classification records this file's
:data:`PROMPT_SHA`, so a label produced under an older wording stays
identifiable forever.

**Editing this text requires a new version.** Bump ``PROMPT_VERSION``; do not
edit v1 in place. Two labels produced under the same version string but
different wordings are indistinguishable in the data, which is precisely the
drift the monthly re-adjudication exists to catch.
"""

import hashlib

from .taxonomy import PRECEDENCE, definitions_block

__all__ = ["PROMPT_SHA", "PROMPT_VERSION", "SYSTEM_PROMPT", "render_user_message"]

PROMPT_VERSION = "v1"

SYSTEM_PROMPT = f"""\
You are labelling changes to Model Context Protocol (MCP) server definitions for
a security research corpus. Each item is one ChangeSet: a structured, typed diff
between two consecutive published states of one server.

Assign exactly one primary label from this taxonomy:

{definitions_block()}

When a change genuinely fits more than one label, apply this precedence, most
severe first: {" > ".join(label.value for label in PRECEDENCE)}.

How to judge:

- Judge the change, not the server. A server that was always able to read files
  has not expanded its scope by fixing a typo.
- Only the *added* text and *new* capability are the subject. Text that was
  already present is context, not evidence.
- Capability is observable; intent is not. Label what the change makes possible,
  and do not speculate about motive.
- Ordinary engineering is benign. Version bumps, dependency changes, wording
  improvements, and new features consistent with the server's stated purpose are
  the overwhelming majority of real changes, and labelling them as attacks
  destroys the base rate this corpus exists to measure.
- If the ChangeSet does not carry enough information to judge, answer
  undecidable. Do not fall back to benign.

Your rationale must quote the specific text or field from the diff that decided
the label. A rationale that restates the label without citing the diff is not
usable, because the human adjudicator cannot check it.

Confidence is your probability that an expert adjudicator would assign the same
label. Be calibrated: use values below 0.5 freely when the change is genuinely
ambiguous. Systematic overconfidence is worse than an occasional wrong label,
because it is the confident ones that skip review.
"""


def render_user_message(changeset_json: str, rule_hits: str) -> str:
    """Render the per-item message.

    The ChangeSet is passed as structured JSON rather than as raw before/after
    blobs. Feeding whole documents would bury the change in thousands of tokens
    of unchanged text and invite the model to label the server rather than the
    change.
    """
    return (
        "Label this ChangeSet.\n\n"
        f"Deterministic rule hits (evidence, not a verdict):\n{rule_hits}\n\n"
        f"ChangeSet:\n{changeset_json}"
    )


PROMPT_SHA = hashlib.sha256((SYSTEM_PROMPT + PROMPT_VERSION).encode("utf-8")).hexdigest()[:16]
"""Hash of the prompt text, recorded on every classification it produced."""
