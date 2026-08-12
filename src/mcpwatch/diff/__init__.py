"""Semantic diffs over the corpus — WP6.

Turns consecutive observations into typed, classifiable change records. The
engine reads and never writes: ChangeSets are a reading of the corpus, not part
of it, so a better differ next year produces better answers from the same
evidence.

Three things this package is careful about, each because getting it wrong moves
a number silently rather than leaving a visible gap:

* **Semantic, not textual.** "A required parameter named `path` appeared on the
  tool `summarize`" is classifiable; "40 lines differ" is not.
* **Identity before content.** A server that changes its registry name looks
  like a disappearance plus an unrelated creation, and the mutation between them
  disappears with it. See :mod:`~mcpwatch.diff.identity`.
* **Description, not judgement.** Nothing here decides whether a change is
  benign. :class:`~mcpwatch.diff.types.SeverityFlag` orders a review queue;
  WP7 owns the verdict.
"""

from .engine import DiffEngine, main
from .identity import IdentityIndex, ServerIdentity, classify_transition
from .semantic import diff_manifest, diff_registry, tool_fingerprint
from .severity import flags_for
from .text import diff_text, imperative_markers, tokenize
from .types import (
    Change,
    ChangeKind,
    ChangeSet,
    DiffStats,
    SeverityFlag,
    TextDiff,
    Verdict,
    change_id,
)

__all__ = [
    "Change",
    "ChangeKind",
    "ChangeSet",
    "DiffEngine",
    "DiffStats",
    "IdentityIndex",
    "ServerIdentity",
    "SeverityFlag",
    "TextDiff",
    "Verdict",
    "change_id",
    "classify_transition",
    "diff_manifest",
    "diff_registry",
    "diff_text",
    "flags_for",
    "imperative_markers",
    "main",
    "tokenize",
    "tool_fingerprint",
]
