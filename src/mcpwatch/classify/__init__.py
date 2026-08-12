"""Mutation classification and adjudication — WP7.

Produces the paper's headline numbers, so the package is built for
trustworthiness rather than throughput. Three layers, in order of how much they
should be trusted:

* :mod:`~mcpwatch.classify.rules` — deterministic, precision-tuned, and the only
  part guaranteed to behave identically a year from now. Its hits are evidence
  shown to adjudicators, not verdicts.
* :mod:`~mcpwatch.classify.llm` — a pinned model with a versioned, hashed prompt.
  Every label records the model id and prompt hash that produced it, because
  classifier drift is a named confound and an unlabelled label cannot be
  re-checked.
* :mod:`~mcpwatch.classify.cli` — human adjudication. The ground truth the other
  two are measured against.

:mod:`~mcpwatch.classify.reliability` computes Cohen's κ per class as well as
overall, because the taxonomy is dominated by ``benign`` and an overall figure
hides poor performance on exactly the rare classes the project exists to find.
"""

from .llm import MODEL_ID, LlmClassifier, LlmVerdict
from .prompt_v1 import PROMPT_SHA, PROMPT_VERSION
from .reliability import Agreement, cohens_kappa, per_class_kappa, score
from .rules import RULES, Rule, RuleHit, classify, evaluate
from .store import Adjudication, CalibrationFrame, ClassifyStore, MachineLabel
from .taxonomy import PRECEDENCE, Label, definition, definitions_block, most_severe

__all__ = [
    "MODEL_ID",
    "PRECEDENCE",
    "PROMPT_SHA",
    "PROMPT_VERSION",
    "RULES",
    "Adjudication",
    "Agreement",
    "CalibrationFrame",
    "ClassifyStore",
    "Label",
    "LlmClassifier",
    "LlmVerdict",
    "MachineLabel",
    "Rule",
    "RuleHit",
    "classify",
    "cohens_kappa",
    "definition",
    "definitions_block",
    "evaluate",
    "most_severe",
    "per_class_kappa",
    "score",
]
