"""The exercise protocol — which tools may be invoked, and with what.

This is the module the ethics section of any writeup rests on, so it states its
rules rather than implying them. Everything else in MCPWatch is read-only by
construction: :mod:`mcpwatch.collect.mcp` and WP8's driver have no code path
that calls a tool, deliberately. WP9 needs one, because behaviour only appears
on invocation. That capability lives here and *only* here, in a package the
nightly collectors do not import.

**The containment does the safety work, not the policy.** A tool invoked under
this protocol runs with no route off the host — every name resolves to a
sinkhole that absorbs and records — no mounts, no capabilities, a fixed non-root
uid, and hard CPU, memory and PID caps. A tool that tries to email someone
cannot. A tool that tries to delete a bucket cannot reach it. The rules below
are defence in depth on top of that, not the only thing standing between a
synthetic argument and somebody's production data.

**Four exclusions, in the order they are applied:**

1. *Declared destructive.* ``annotations.destructiveHint`` true, or
   ``readOnlyHint`` false, is the publisher telling us this tool changes things.
   Believe them and skip it.
2. *Named destructive.* A verb family in the tool's name or description —
   delete, send, pay, publish, deploy. Prose is weaker evidence than an
   annotation, so this is matched on the name first and the description second,
   and both are logged.
3. *Unfillable.* A required parameter this module cannot synthesise a value for
   is a tool we would have to guess at. Guessing is how you invoke
   ``transfer(amount, destination)`` with something that looks plausible.
4. *Budgeted.* At most :data:`MAX_TOOLS_PER_SERVER`. A server exposing 121 tools
   would otherwise dominate both the runtime and the divergence rate.

**Arguments are obviously synthetic and inert.** Strings are a fixed marker
string; hosts and URLs use the reserved ``.invalid`` TLD, which cannot resolve
anywhere even if every other control failed; numbers are 1; nothing resembles a
credential, an email address, a real path, or a real identifier. The goal is to
reach the tool's code, not to make it succeed — a tool that rejects the argument
as malformed has usually already opened its socket, and that is the observation.
"""

import re
from typing import Any

__all__ = [
    "MAX_TOOLS_PER_SERVER",
    "SYNTHETIC_MARKER",
    "Decision",
    "may_exercise",
    "select_tools",
    "synthesize_arguments",
]

SYNTHETIC_MARKER = "mcpwatch-synthetic"
"""Every generated string contains this, so a value can be traced back here.

If it turns up in someone's logs, it is identifiable as a research probe rather
than a user, and the contact address in the crawler's User-Agent applies.
"""

SYNTHETIC_HOST = "mcpwatch-synthetic.invalid"
"""``.invalid`` is reserved by RFC 2606 and can never resolve to a real host."""

MAX_TOOLS_PER_SERVER = 10
"""Tools exercised per server.

A cap, not a sample of convenience: one server in the WP8 run exposes 121 tools,
and letting it contribute 121 observations to a 400-server divergence rate would
make the rate a statement about that server. Selection is by name order so the
same tools are exercised on every cycle.
"""

MAX_ARGUMENT_DEPTH = 4
"""How deep to synthesise nested objects before giving up as unfillable."""

MAX_STRING_LENGTH = 64

# Annotation-level refusals. The publisher said so; no further analysis needed.
_DESTRUCTIVE_ANNOTATIONS = ("destructiveHint",)

_DESTRUCTIVE_VERBS = (
    r"delete|destroy|drop|purge|remove|erase|wipe|truncate|revoke|reset|"
    r"send|email|mail|sms|notify|publish|post|tweet|share|invite|"
    r"pay|charge|refund|transfer|withdraw|buy|sell|order|checkout|subscribe|"
    r"deploy|release|merge|push|revert|rollback|restart|shutdown|kill|terminate|"
    r"create|update|write|upload|insert|modify|patch|rename|move|copy|"
    r"execute|exec|run|shell|eval|spawn|install|uninstall"
)

_DESTRUCTIVE_NAME = re.compile(rf"\b(?:{_DESTRUCTIVE_VERBS})(?:e?s|e?d|ing)?\b")
"""Verb families excluded from invocation, with their common inflections.

Broad on purpose, and it excludes plenty of harmless tools. Coverage is
recoverable — the divergence rate is reported against the tools actually
exercised, with that stated — whereas invoking someone's ``delete_project``
because the sandbox was assumed to hold is not.

The inflections are load-bearing rather than tidiness. Tool *names* use the bare
stem (``delete_project``), but *descriptions* are written in the third person,
so "Deletes the named bucket." slipped past a stem-only pattern — the exclusion
read as passing while doing nothing on every description in the corpus.
"""


# Named for the parameter's state rather than a fault on our side (cf. N818),
# matching `AuthRequired` in mcpwatch.collect.mcp: declining to invent a value
# is this protocol working as specified, not failing.
class Unfillable(ValueError):  # noqa: N818
    """A required parameter this module will not invent a value for."""


class Decision:
    """Whether a tool may be exercised, and why not if it may not."""

    __slots__ = ("allowed", "reason")

    def __init__(self, allowed: bool, reason: str) -> None:
        """Record a decision and its justification."""
        self.allowed = allowed
        self.reason = reason

    def __bool__(self) -> bool:
        """Whether the tool may be exercised."""
        return self.allowed

    def __repr__(self) -> str:
        """Readable form for logs and test failures."""
        return f"Decision({self.allowed}, {self.reason!r})"


def may_exercise(tool: dict[str, Any]) -> Decision:
    """Decide whether one tool may be invoked, and record why."""
    name = str(tool.get("name") or "")
    if not name:
        return Decision(False, "tool has no name")

    annotations = tool.get("annotations")
    if isinstance(annotations, dict):
        for hint in _DESTRUCTIVE_ANNOTATIONS:
            if annotations.get(hint) is True:
                return Decision(False, f"annotations.{hint} is true")
        if annotations.get("readOnlyHint") is False:
            return Decision(False, "annotations.readOnlyHint is false")

    match = _DESTRUCTIVE_NAME.search(name.casefold().replace("_", " ").replace("-", " "))
    if match:
        return Decision(False, f"name contains {match.group(0)!r}")

    description = str(tool.get("description") or "").casefold()
    # Only the first sentence: a description's opening states what the tool does,
    # while later prose often enumerates what it will not do ("this does not
    # delete anything"), and matching that would exclude the honest ones.
    opening = re.split(r"[.!?\n]", description, maxsplit=1)[0]
    match = _DESTRUCTIVE_NAME.search(opening)
    if match:
        return Decision(False, f"description opens with {match.group(0)!r}")

    schema = tool.get("inputSchema") or tool.get("input_schema")
    try:
        synthesize_arguments(schema)
    except Unfillable as exc:
        return Decision(False, str(exc))
    return Decision(True, "no exclusion applies")


def select_tools(tools: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[tuple[str, str]]]:
    """Split a server's tools into those to exercise and those skipped.

    Returns the selected tools and ``(name, reason)`` for every exclusion. The
    skipped list is reported, not discarded: the denominator of a divergence
    rate is only meaningful alongside what never entered it.
    """
    selected: list[dict[str, Any]] = []
    skipped: list[tuple[str, str]] = []
    for tool in sorted(tools, key=lambda t: str(t.get("name") or "")):
        decision = may_exercise(tool)
        if not decision:
            skipped.append((str(tool.get("name") or "?"), decision.reason))
        elif len(selected) < MAX_TOOLS_PER_SERVER:
            selected.append(tool)
        else:
            skipped.append((str(tool.get("name") or "?"), "over the per-server budget"))
    return selected, skipped


def synthesize_arguments(schema: Any, depth: int = 0) -> dict[str, Any]:  # noqa: ANN401 - third-party JSON
    """Build inert arguments for a tool's required parameters.

    Only required parameters are filled. An optional parameter left out is a
    code path not taken, which costs coverage; an optional parameter filled in
    is a code path taken *because we chose to*, which is a decision to invoke
    more of someone's tool than it needs. The cheaper mistake is the first.

    Raises:
        Unfillable: If a required parameter has no synthesisable type.
    """
    if not isinstance(schema, dict):
        return {}
    required = schema.get("required")
    if not isinstance(required, list):
        return {}
    properties = schema.get("properties")
    properties = properties if isinstance(properties, dict) else {}

    arguments: dict[str, Any] = {}
    for name in required:
        if not isinstance(name, str):
            continue
        definition = properties.get(name)
        arguments[name] = _synthesize_value(name, definition, depth)
    return arguments


def _synthesize_value(name: str, definition: Any, depth: int) -> Any:  # noqa: ANN401 - third-party JSON
    """One inert value for one parameter."""
    if depth > MAX_ARGUMENT_DEPTH:
        raise Unfillable(f"parameter {name!r} nests deeper than {MAX_ARGUMENT_DEPTH}")
    if not isinstance(definition, dict):
        # Untyped, so a marker string is as good a guess as any and cannot be
        # mistaken for a real identifier.
        return f"{SYNTHETIC_MARKER}-value"

    # An enum names its own legal values; picking one is not inventing anything.
    enum = definition.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    if "const" in definition:
        return definition["const"]
    if isinstance(definition.get("default"), (str, int, float, bool)):
        return definition["default"]

    declared = definition.get("type")
    if isinstance(declared, list):
        declared = next((t for t in declared if t != "null"), None)

    if declared == "string" or declared is None:
        return _synthetic_string(name, definition)
    if declared == "integer":
        return int(definition.get("minimum", 1) or 1)
    if declared == "number":
        return float(definition.get("minimum", 1) or 1)
    if declared == "boolean":
        return False
    if declared == "array":
        items = definition.get("items")
        if definition.get("minItems"):
            return [_synthesize_value(f"{name}[0]", items, depth + 1)]
        return []
    if declared == "object":
        return synthesize_arguments(definition, depth + 1)
    if declared == "null":
        return None
    raise Unfillable(f"parameter {name!r} has unsupported type {declared!r}")


def _synthetic_string(name: str, definition: dict[str, Any]) -> str:
    """A string that reaches the code without resembling anything real."""
    fmt = str(definition.get("format") or "").casefold()
    lowered = name.casefold()

    if fmt in ("uri", "url", "iri") or re.search(r"(url|uri|endpoint|link)", lowered):
        return f"https://{SYNTHETIC_HOST}/{SYNTHETIC_MARKER}"
    if fmt in ("hostname", "idn-hostname") or re.search(r"(host|domain|server)", lowered):
        return SYNTHETIC_HOST
    if fmt == "email" or "email" in lowered:
        return f"{SYNTHETIC_MARKER}@{SYNTHETIC_HOST}"
    if fmt in ("date", "date-time"):
        return "2026-01-01T00:00:00Z" if fmt == "date-time" else "2026-01-01"
    if fmt == "uuid":
        return "00000000-0000-4000-8000-000000000000"
    if re.search(r"(path|file|dir|folder)", lowered):
        # Inside the container's own scratch space, never a host path and never
        # anything the server shipped.
        return f"/tmp/{SYNTHETIC_MARKER}.txt"
    if re.search(r"(token|key|secret|password|credential|auth)", lowered):
        # Obviously fake. A tool that validates it and refuses has still told us
        # what it does with a credential before rejecting this one.
        return f"{SYNTHETIC_MARKER}-not-a-real-credential"

    minimum = definition.get("minLength")
    value = f"{SYNTHETIC_MARKER}-value"
    if isinstance(minimum, int) and minimum > len(value):
        value = value.ljust(min(minimum, MAX_STRING_LENGTH), "x")
    return value
