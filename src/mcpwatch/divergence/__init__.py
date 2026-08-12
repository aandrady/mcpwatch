"""Description-behaviour divergence — WP9, the project's method contribution.

Every existing MCP scanner reads the tool *description*. None systematically
checks whether the tool does what it says. That gap is both a poisoning
indicator and a rug-pull indicator, because it survives description-level
review: a description edited to look harmless is exactly what a reviewer
approves and exactly what this measures against.

Four modules, mirroring the two halves of the comparison and what joins them:

* :mod:`~mcpwatch.divergence.declared` — what a tool's description, schema and
  annotations claim. Rules-based and deliberately generous, so an ambiguous
  description resolves toward "declared" and a divergence goes unreported.
  :mod:`~mcpwatch.divergence.llm` adds a pinned-model pass for prose the rules
  cannot read; it may only *add* declarations, so the worst a drifting model can
  do is make this harness less accusatory.
* :mod:`~mcpwatch.divergence.protocol` — which tools may be invoked at all, and
  with what. The ethics of this package live here.
* :mod:`~mcpwatch.divergence.observe` — what a tool actually did, from syscalls
  and the sinkhole, windowed per call so startup noise is excluded.
* :mod:`~mcpwatch.divergence.score` — findings, a rate, and the caveats a
  first-of-its-kind number needs stated beside it.

**This is the only part of MCPWatch that invokes a third party's tool.** The
collectors have no code path to ``tools/call`` by construction, and nothing here
is imported by them or run by a scheduled unit.
"""

from .capabilities import DIVERGENCE_CLASS, Capability, CapabilityProfile
from .declared import declared_from_schema, declared_from_text, declared_profile
from .llm import MODEL_ID, PROMPT_SHA, PROMPT_VERSION, LlmDeclaredExtractor
from .observe import TraceEvent, observed_profile, parse_sinkhole, parse_strace
from .protocol import Decision, Unfillable, may_exercise, select_tools, synthesize_arguments
from .score import CAVEATS, DivergenceReport, Finding, score_tool, wilson_interval

__all__ = [
    "CAVEATS",
    "DIVERGENCE_CLASS",
    "MODEL_ID",
    "PROMPT_SHA",
    "PROMPT_VERSION",
    "Capability",
    "CapabilityProfile",
    "Decision",
    "DivergenceReport",
    "Finding",
    "LlmDeclaredExtractor",
    "TraceEvent",
    "Unfillable",
    "declared_from_schema",
    "declared_from_text",
    "declared_profile",
    "may_exercise",
    "observed_profile",
    "parse_sinkhole",
    "parse_strace",
    "score_tool",
    "select_tools",
    "synthesize_arguments",
    "wilson_interval",
]
