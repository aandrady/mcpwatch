"""Outputs — WP10: pinning retrospective, metrics, dashboard, datasheet.

Everything here reads the corpus and nothing else. No network access, so a
reviewer holding a copy of the corpus reproduces every published number by
running the same command — which is WP10's stated gate and the reason the
analysis lives in the package rather than in a notebook.

* :mod:`~mcpwatch.release.pinning` — the most actionable output. Replays the
  corpus against hypothetical content-hash pinning policies and reports how many
  benign updates each would block per security-relevant change caught.
* :mod:`~mcpwatch.release.metrics` — mutation rates and coverage, every figure
  paired with the population it does not cover.
* :mod:`~mcpwatch.release.datasheet` — collection methodology, normalization
  history, exclusion criteria and known biases, generated from the corpus so the
  numbers cannot drift from the data they describe.
* :mod:`~mcpwatch.release.site` — one self-contained HTML file, aggregate
  statistics only. No server is ever named here: naming is gated on coordinated
  disclosure, and a page rebuilt automatically every run is exactly what would
  leak a name before that happened.

``FRAMING.md`` states how results are to be reported and was committed before
this package existed, so a finding cannot bend the framing retroactively.
"""

from .datasheet import render_datasheet
from .metrics import Coverage, Metrics, collect_coverage, observation_days, summarise_changesets
from .pinning import HIGH_SIGNAL_FLAGS, POLICIES, PinPolicy, PolicyOutcome, blocks, replay
from .site import render_site

__all__ = [
    "HIGH_SIGNAL_FLAGS",
    "POLICIES",
    "Coverage",
    "Metrics",
    "PinPolicy",
    "PolicyOutcome",
    "blocks",
    "collect_coverage",
    "observation_days",
    "render_datasheet",
    "render_site",
    "replay",
    "summarise_changesets",
]
