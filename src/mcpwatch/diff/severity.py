"""Cheap deterministic triage flags.

WP7 will have tens of thousands of ChangeSets and a human adjudication budget
measured in hundreds. Something has to decide what a reviewer looks at first,
and it must not be recency — the interesting change is as likely to be from
March as from yesterday.

These flags are that ordering. Each is a **reason to look**, not a finding. They
are computed from the ChangeSet alone, cost nothing, and are deliberately
over-inclusive: the price of a false positive is one glance, and the price of a
false negative is a rug pull that never reaches a human.

Nothing here scores or ranks. WP7 owns judgement; this owns attention.
"""

from collections.abc import Sequence

from mcpwatch.store import JsonValue

from .text import (
    imperative_markers,
    looks_like_credential,
    looks_like_filesystem,
    looks_like_network,
)
from .types import Change, ChangeKind, SeverityFlag

__all__ = ["DESCRIPTION_GROWTH_RATIO", "flags_for"]

DESCRIPTION_GROWTH_RATIO = 2.0
"""How much a description must grow to be worth flagging.

A tool description that doubles has usually had something *inserted* rather than
edited. That is the shape of an injected instruction appended to honest text,
and it is cheap to notice.
"""


def _param_name(change: Change) -> str:
    return change.path.rsplit("/", 1)[-1]


def _schema_of(change: Change) -> JsonValue:
    return change.after if change.after is not None else change.before


def flags_for(changes: Sequence[Change]) -> tuple[SeverityFlag, ...]:
    """Return the triage flags a set of changes earns, in enum order.

    Args:
        changes: The typed changes of one ChangeSet.

    Returns:
        Distinct flags, ordered by :class:`SeverityFlag` declaration order so
        the output is stable across runs.
    """
    found: set[SeverityFlag] = set()

    for change in changes:
        if change.kind is ChangeKind.SCHEMA_PARAM_ADDED:
            name, schema = _param_name(change), _schema_of(change)
            if looks_like_network(name, schema):
                found.add(SeverityFlag.NETWORK_PARAM_ADDED)
            if looks_like_filesystem(name, schema):
                found.add(SeverityFlag.FILESYSTEM_PARAM_ADDED)
            if looks_like_credential(name, schema):
                found.add(SeverityFlag.CREDENTIAL_PARAM_ADDED)

        elif change.kind is ChangeKind.TOOL_ADDED:
            # A new tool arrives with its whole surface at once, so its
            # parameters deserve the same reading a newly added parameter gets.
            found.update(_flags_for_new_tool(change.after))
            found.add(SeverityFlag.TOOL_COUNT_GREW)

        elif change.kind in {
            ChangeKind.TOOL_DESCRIPTION_CHANGED,
            ChangeKind.PARAM_DESCRIPTION_CHANGED,
            ChangeKind.SERVER_DESCRIPTION_CHANGED,
            ChangeKind.PROMPT_CHANGED,
        }:
            found.update(_flags_for_text(change))

        elif change.kind is ChangeKind.ANNOTATION_CHANGED:
            found.update(_flags_for_annotations(change))

        elif change.kind in {
            ChangeKind.ENDPOINT_CHANGED,
            ChangeKind.REPOSITORY_CHANGED,
            ChangeKind.PACKAGE_IDENTITY_CHANGED,
        }:
            found.add(SeverityFlag.ENDPOINT_OR_REPO_MOVED)

    return tuple(flag for flag in SeverityFlag if flag in found)


def _flags_for_new_tool(tool: JsonValue) -> set[SeverityFlag]:
    """Read a newly added tool's parameters and description."""
    found: set[SeverityFlag] = set()
    if not isinstance(tool, dict):
        return found

    schema = tool.get("inputSchema")
    properties = schema.get("properties") if isinstance(schema, dict) else None
    if isinstance(properties, dict):
        for name, param in properties.items():
            if looks_like_network(name, param):
                found.add(SeverityFlag.NETWORK_PARAM_ADDED)
            if looks_like_filesystem(name, param):
                found.add(SeverityFlag.FILESYSTEM_PARAM_ADDED)
            if looks_like_credential(name, param):
                found.add(SeverityFlag.CREDENTIAL_PARAM_ADDED)

    description = tool.get("description")
    if isinstance(description, str) and imperative_markers(description):
        found.add(SeverityFlag.IMPERATIVE_LANGUAGE_ADDED)
    return found


def _flags_for_text(change: Change) -> set[SeverityFlag]:
    """Read a text change for injected instructions and sudden growth."""
    found: set[SeverityFlag] = set()
    before = change.before if isinstance(change.before, str) else ""
    after = change.after if isinstance(change.after, str) else ""

    # Only markers that are *new* count. A description that always said
    # "you must supply a key" has not changed its character by being edited
    # elsewhere, and flagging it every time would make the flag meaningless.
    if set(imperative_markers(after)) - set(imperative_markers(before)):
        found.add(SeverityFlag.IMPERATIVE_LANGUAGE_ADDED)

    if before and len(after) >= len(before) * DESCRIPTION_GROWTH_RATIO:
        found.add(SeverityFlag.DESCRIPTION_GREW_SHARPLY)
    return found


def _flags_for_annotations(change: Change) -> set[SeverityFlag]:
    """Read annotation changes that lower a client's guard.

    ``destructiveHint`` going false and ``readOnlyHint`` going true both tell a
    client this tool is safer than it previously claimed. That may be a
    correction; it may also be how a tool gets itself auto-approved. Either way
    a human should decide, because the client already stopped asking.
    """
    found: set[SeverityFlag] = set()
    before = change.before if isinstance(change.before, dict) else {}
    after = change.after if isinstance(change.after, dict) else {}

    if before.get("destructiveHint") is True and after.get("destructiveHint") is False:
        found.add(SeverityFlag.DESTRUCTIVE_HINT_CLEARED)
    if before.get("readOnlyHint") is not True and after.get("readOnlyHint") is True:
        found.add(SeverityFlag.READONLY_HINT_SET)
    return found
