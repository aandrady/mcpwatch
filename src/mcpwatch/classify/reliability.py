"""Inter-rater reliability — Cohen's κ, reported per class as well as overall.

The project's Phase 2 gate is κ > 0.75, so this module computes the number the
gate is judged on. Two properties of κ make the details matter more than the
formula:

**Overall κ hides exactly the classes worth measuring.** The taxonomy is
dominated by ``benign`` — most published changes really are typo fixes and
version bumps. Two raters who agree on every benign case and disagree on every
injection can still post a high overall κ, because agreement on the common
class swamps everything. So per-class κ is computed too, one-vs-rest, and it is
the per-class figure on the rare classes that says whether the pipeline works.

**κ is undefined when both raters use one label.** Perfect agreement on a
single class gives expected agreement of 1 and a 0/0 in the formula. That is
not κ = 1 and not κ = 0; it is *no information*, and this module returns None
rather than a number that would flatter the gate. A per-class κ of None on
``instruction_injection`` means the calibration set contains no examples of it,
which is a fact about the sample, not a result.
"""

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .taxonomy import Label

__all__ = ["Agreement", "cohens_kappa", "per_class_kappa", "score"]


@dataclass(frozen=True, slots=True)
class Agreement:
    """Agreement between two raters over the same items."""

    items: int
    observed: float
    expected: float
    kappa: float | None
    per_class: dict[str, float | None]
    confusion: dict[str, dict[str, int]]

    @property
    def passes_gate(self) -> bool:
        """Whether overall κ clears the project's 0.75 Phase-2 gate."""
        return self.kappa is not None and self.kappa > 0.75

    def as_json(self) -> dict[str, object]:
        """Render for machine consumption."""
        return {
            "items": self.items,
            "observed_agreement": round(self.observed, 4),
            "expected_agreement": round(self.expected, 4),
            "kappa": None if self.kappa is None else round(self.kappa, 4),
            "passes_gate": self.passes_gate,
            "per_class_kappa": {
                name: (None if value is None else round(value, 4))
                for name, value in sorted(self.per_class.items())
            },
            "confusion": self.confusion,
        }

    def render(self) -> str:
        """Human-readable summary for the CLI."""
        lines = [
            f"items adjudicated by both raters: {self.items}",
            f"observed agreement: {self.observed:.1%}",
            f"expected by chance:  {self.expected:.1%}",
            f"Cohen's kappa: {'undefined' if self.kappa is None else f'{self.kappa:.3f}'}"
            f"  (gate: > 0.75 -> {'PASS' if self.passes_gate else 'FAIL'})",
            "",
            "per-class kappa (one-vs-rest) — the rare classes are the ones that matter:",
        ]
        for name, value in sorted(self.per_class.items()):
            shown = "undefined (no examples from either rater)" if value is None else f"{value:.3f}"
            lines.append(f"  {name:24} {shown}")
        return "\n".join(lines)


def _kappa(a: Sequence[str], b: Sequence[str]) -> tuple[float, float, float | None]:
    """Return (observed, expected, kappa) for two aligned label sequences."""
    total = len(a)
    if total == 0:
        return 0.0, 0.0, None

    observed = sum(1 for x, y in zip(a, b, strict=True) if x == y) / total
    count_a, count_b = Counter(a), Counter(b)
    expected = sum(
        (count_a[label] / total) * (count_b[label] / total) for label in set(count_a) | set(count_b)
    )
    if expected >= 1.0:
        # Both raters used exactly one label. Agreement is perfect and chance
        # agreement is also perfect, so kappa is 0/0 — no information, not 1.0.
        return observed, expected, None
    return observed, expected, (observed - expected) / (1 - expected)


def cohens_kappa(a: Sequence[str], b: Sequence[str]) -> float | None:
    """Cohen's κ for two aligned sequences of labels, or None if undefined."""
    return _kappa(a, b)[2]


def per_class_kappa(a: Sequence[str], b: Sequence[str]) -> dict[str, float | None]:
    """One-vs-rest κ for every label either rater used.

    Every label in the taxonomy is reported, including ones neither rater
    assigned — an absent class returns None, which is the honest statement that
    the calibration set could not measure it.
    """
    out: dict[str, float | None] = {}
    for label in Label:
        name = str(label)
        binary_a = [name if x == name else "other" for x in a]
        binary_b = [name if y == name else "other" for y in b]
        out[name] = _kappa(binary_a, binary_b)[2]
    return out


def score(labels_a: Mapping[str, str], labels_b: Mapping[str, str]) -> Agreement:
    """Compare two raters over the items they both labelled.

    Args:
        labels_a: change_id -> label from the first rater.
        labels_b: change_id -> label from the second rater.

    Returns:
        The :class:`Agreement`, computed over the intersection of the two
        keysets. Items only one rater reached are excluded rather than imputed
        — a missing label is not a disagreement.
    """
    shared = sorted(set(labels_a) & set(labels_b))
    a = [labels_a[key] for key in shared]
    b = [labels_b[key] for key in shared]
    observed, expected, kappa = _kappa(a, b)

    confusion: dict[str, dict[str, int]] = {}
    for x, y in zip(a, b, strict=True):
        confusion.setdefault(x, {})
        confusion[x][y] = confusion[x].get(y, 0) + 1

    return Agreement(
        items=len(shared),
        observed=observed,
        expected=expected,
        kappa=kappa,
        per_class=per_class_kappa(a, b),
        confusion=confusion,
    )


def precision_against(
    predicted: Mapping[str, str], truth: Mapping[str, str], label: str
) -> tuple[float | None, int, int]:
    """Precision of one label against adjudicated ground truth.

    WP7 asks for the rule layer's precision to be measured and reported, which
    is a different question from κ: κ asks whether two raters agree, precision
    asks how often a rule that fired was right.

    Returns:
        ``(precision, hits, correct)``; precision is None when the label was
        never predicted on an adjudicated item.
    """
    shared = set(predicted) & set(truth)
    hits = [key for key in shared if predicted[key] == label]
    if not hits:
        return None, 0, 0
    correct = sum(1 for key in hits if truth[key] == label)
    return correct / len(hits), len(hits), correct
