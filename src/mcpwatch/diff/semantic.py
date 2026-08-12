"""Semantic diffs: what actually changed, not which bytes moved.

A text diff of two manifests tells you 40 lines differ. That is useless to a
classifier and worse than useless to a human: it cannot tell a reordered key
from a new filesystem parameter. These differs walk the documents structurally
and emit typed :class:`~mcpwatch.diff.types.Change` records, so "a required
parameter named `path` appeared on the tool `summarize`" arrives as that
statement rather than as a hunk.

Both layers are handled here because they share the hard parts — matching
collections by identity, diffing text, deciding what counts as unchanged.

**The `_meta` rule.** Layer-1 records carry the registry's own `publishedAt`,
`updatedAt` and `statusChangedAt`, and those move on *every* republish by
construction. Reporting them as changes would put a change on every transition
in the corpus and drown everything that matters, so only `status` is read out of
`_meta`. This is the same decision the WP5 report made, for the same reason.
"""

import json
from collections.abc import Sequence
from typing import cast

from mcpwatch.store import JsonValue

from .text import diff_text
from .types import Change, ChangeKind

__all__ = ["diff_manifest", "diff_registry", "tool_fingerprint"]

_REGISTRY_META_KEY = "io.modelcontextprotocol.registry/official"

_MODELLED_SERVER_FIELDS = frozenset(
    {"description", "remotes", "repository", "packages", "version", "name", "$schema"}
)

_MODELLED_MANIFEST_FIELDS = frozenset(
    {"tools", "prompts", "resources", "serverInfo", "capabilities"}
)

_MODELLED_TOOL_FIELDS = frozenset(
    {"name", "description", "annotations", "execution", "inputSchema"}
)

_SCHEMA_BODY = frozenset({"properties", "required"})
"""Parts of an input schema diffed parameter by parameter, not as a blob."""

_RENAME_SIMILARITY = 0.6
"""How alike two descriptions must be to support a rename claim.

Only consulted when the schema evidence is weak. Set low on purpose: a rename
accompanied by a rewritten description is still a rename, and the alternative —
reporting it as an unrelated removal plus addition — hides the very mutation
this package exists to catch.
"""


def _obj(value: JsonValue) -> dict[str, JsonValue]:
    return value if isinstance(value, dict) else {}


def _seq(value: JsonValue) -> list[JsonValue]:
    return value if isinstance(value, list) else []


def _strings(values: Sequence[str]) -> JsonValue:
    """Widen a list of strings to a JSON value.

    ``JsonValue`` is invariant in its list parameter, so ``list[str]`` is not a
    ``list[JsonValue]`` as far as the type checker is concerned even though
    every element is one. This is the one place that gap is bridged.
    """
    return cast(JsonValue, list(values))


def _text(value: JsonValue) -> str | None:
    return value.strip() or None if isinstance(value, str) else None


def _canon(value: JsonValue) -> str:
    """A comparable rendering of any JSON value."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _text_change(
    kind: ChangeKind,
    path: str,
    before: JsonValue,
    after: JsonValue,
    *,
    tool: str | None = None,
) -> Change:
    """Build a change, attaching a token diff when both sides are text."""
    text = None
    if isinstance(before, str) and isinstance(after, str):
        text = diff_text(before, after)
    return Change(kind=kind, path=path, before=before, after=after, tool=tool, text=text)


# ---------------------------------------------------------------- Layer 1 ---


def _endpoints(server: dict[str, JsonValue]) -> list[str]:
    urls = [_text(_obj(r).get("url")) for r in _seq(server.get("remotes"))]
    return sorted(u for u in urls if u is not None)


def _repo_url(server: dict[str, JsonValue]) -> str | None:
    repository = server.get("repository")
    if isinstance(repository, str):
        return _text(repository)
    return _text(_obj(repository).get("url"))


def _package_identities(server: dict[str, JsonValue]) -> list[str]:
    out = []
    for package in _seq(server.get("packages")):
        entry = _obj(package)
        registry_type = _text(entry.get("registryType")) or "?"
        identifier = _text(entry.get("identifier")) or _text(entry.get("name")) or "?"
        out.append(f"{registry_type}:{identifier}")
    return sorted(out)


def _secret_inputs(server: dict[str, JsonValue]) -> list[str]:
    """Every named input the server declares as a secret.

    Both places one can hide: headers on a remote, and environment variables on
    a package. A server that begins demanding a credential it never wanted
    before has changed what it asks of its users, which is a fact about trust
    rather than about code.
    """
    out = []
    for remote in _seq(server.get("remotes")):
        for header in _seq(_obj(remote).get("headers")):
            entry = _obj(header)
            if entry.get("isSecret") is True and (name := _text(entry.get("name"))):
                out.append(f"header:{name}")
    for package in _seq(server.get("packages")):
        for variable in _seq(_obj(package).get("environmentVariables")):
            entry = _obj(variable)
            if entry.get("isSecret") is True and (name := _text(entry.get("name"))):
                out.append(f"env:{name}")
    return sorted(set(out))


def diff_registry(before: JsonValue, after: JsonValue) -> list[Change]:
    """Diff two Layer-1 registry records.

    Args:
        before: The earlier ``{"server": ..., "_meta": ...}`` entry.
        after: The later one.

    Returns:
        Typed changes, in a stable order.
    """
    old, new = _obj(_obj(before).get("server")), _obj(_obj(after).get("server"))
    changes: list[Change] = []

    if old.get("description") != new.get("description"):
        changes.append(
            _text_change(
                ChangeKind.SERVER_DESCRIPTION_CHANGED,
                "server/description",
                old.get("description"),
                new.get("description"),
            )
        )

    if (a := _endpoints(old)) != (b := _endpoints(new)):
        changes.append(
            Change(
                kind=ChangeKind.ENDPOINT_CHANGED,
                path="server/remotes",
                before=_strings(a),
                after=_strings(b),
                detail=_set_detail(a, b),
            )
        )

    if (a_repo := _repo_url(old)) != (b_repo := _repo_url(new)):
        changes.append(
            Change(
                kind=ChangeKind.REPOSITORY_CHANGED,
                path="server/repository/url",
                before=a_repo,
                after=b_repo,
            )
        )

    if (a_pkg := _package_identities(old)) != (b_pkg := _package_identities(new)):
        changes.append(
            Change(
                kind=ChangeKind.PACKAGE_IDENTITY_CHANGED,
                path="server/packages",
                before=_strings(a_pkg),
                after=_strings(b_pkg),
                detail=_set_detail(a_pkg, b_pkg),
            )
        )
    elif _canon(old.get("packages")) != _canon(new.get("packages")):
        # Same packages, different contents — a version bump inside the package
        # list, or changed environment variables. Ordinary maintenance, kept
        # distinct from the supply-chain-relevant identity swap above.
        changes.append(
            Change(
                kind=ChangeKind.PACKAGE_CHANGED,
                path="server/packages",
                before=old.get("packages"),
                after=new.get("packages"),
            )
        )

    if (a_sec := _secret_inputs(old)) != (b_sec := _secret_inputs(new)):
        changes.append(
            Change(
                kind=ChangeKind.AUTH_REQUIREMENT_CHANGED,
                path="server/auth",
                before=_strings(a_sec),
                after=_strings(b_sec),
                detail=_set_detail(a_sec, b_sec),
            )
        )

    if old.get("version") != new.get("version"):
        changes.append(
            Change(
                kind=ChangeKind.VERSION_BUMPED,
                path="server/version",
                before=old.get("version"),
                after=new.get("version"),
            )
        )

    old_status = _text(_registry_meta(before).get("status"))
    new_status = _text(_registry_meta(after).get("status"))
    if old_status != new_status:
        changes.append(
            Change(
                kind=ChangeKind.REGISTRY_STATUS_CHANGED,
                path="_meta/status",
                before=old_status,
                after=new_status,
            )
        )

    for name in sorted((set(old) | set(new)) - _MODELLED_SERVER_FIELDS):
        if _canon(old.get(name)) != _canon(new.get(name)):
            changes.append(
                _text_change(
                    ChangeKind.SERVER_FIELD_CHANGED,
                    f"server/{name}",
                    old.get(name),
                    new.get(name),
                )
            )
    return changes


def _registry_meta(entry: JsonValue) -> dict[str, JsonValue]:
    return _obj(_obj(_obj(entry).get("_meta")).get(_REGISTRY_META_KEY))


def _set_detail(before: Sequence[str], after: Sequence[str]) -> str:
    """Summarize what entered and left a set-valued field."""
    gained = sorted(set(after) - set(before))
    lost = sorted(set(before) - set(after))
    parts = []
    if gained:
        parts.append("+" + ", ".join(gained))
    if lost:
        parts.append("-" + ", ".join(lost))
    return "; ".join(parts) or "reordered"


# ---------------------------------------------------------------- Layer 2 ---


def tool_fingerprint(document: JsonValue) -> str:
    """A server's tool-set identity: the sorted names of the tools it offers.

    Used by identity resolution to recognize a renamed server. Names only, not
    schemas — a rename usually travels with edits, and a fingerprint that
    changed whenever a description did would recognize nothing.
    """
    names = sorted(
        name for t in _seq(_obj(document).get("tools")) if (name := _text(_obj(t).get("name")))
    )
    return "|".join(names)


def _by_name(items: Sequence[JsonValue], key: str = "name") -> dict[str, dict[str, JsonValue]]:
    out: dict[str, dict[str, JsonValue]] = {}
    for item in items:
        entry = _obj(item)
        name = _text(entry.get(key))
        if name is not None:
            out[name] = entry
    return out


def _match_renames(
    removed: dict[str, dict[str, JsonValue]],
    added: dict[str, dict[str, JsonValue]],
) -> list[tuple[str, str]]:
    """Pair disappeared tools with appeared ones that are plausibly the same.

    A rename reported as a removal plus an addition loses the connection between
    them, and with it any chance of seeing that the *renamed* tool also gained a
    parameter. So it is worth some effort to recognize.

    Evidence, strongest first: an identical non-trivial input schema, then a
    similar description. An identical *trivial* schema proves nothing — a great
    many tools take no arguments at all, and pairing them by that would invent
    renames wholesale.
    """
    pairs: list[tuple[str, str]] = []
    available = dict(added)

    for old_name, old_tool in removed.items():
        old_schema = _obj(old_tool.get("inputSchema"))
        old_props = _obj(old_schema.get("properties"))
        old_desc = _text(old_tool.get("description")) or ""

        best: tuple[float, str] | None = None
        for new_name, new_tool in available.items():
            new_schema = _obj(new_tool.get("inputSchema"))
            score = 0.0
            if old_props and _canon(old_schema) == _canon(new_schema):
                score = 1.0
            else:
                new_desc = _text(new_tool.get("description")) or ""
                if old_desc and new_desc:
                    similarity = diff_text(old_desc, new_desc).similarity
                    if similarity >= _RENAME_SIMILARITY:
                        score = similarity
            if score and (best is None or score > best[0]):
                best = (score, new_name)

        if best is not None:
            pairs.append((old_name, best[1]))
            available.pop(best[1], None)
    return pairs


def _diff_schema(
    tool: str, before: dict[str, JsonValue], after: dict[str, JsonValue]
) -> list[Change]:
    """Diff one tool's input schema at the parameter level."""
    old_schema, new_schema = _obj(before.get("inputSchema")), _obj(after.get("inputSchema"))
    old_props, new_props = _obj(old_schema.get("properties")), _obj(new_schema.get("properties"))
    old_required = {r for r in _seq(old_schema.get("required")) if isinstance(r, str)}
    new_required = {r for r in _seq(new_schema.get("required")) if isinstance(r, str)}
    changes: list[Change] = []
    base = f"tools/{tool}/inputSchema/properties"

    for name in sorted(set(new_props) - set(old_props)):
        changes.append(
            Change(
                kind=ChangeKind.SCHEMA_PARAM_ADDED,
                path=f"{base}/{name}",
                after=new_props[name],
                tool=tool,
                detail="required" if name in new_required else "optional",
            )
        )
    for name in sorted(set(old_props) - set(new_props)):
        changes.append(
            Change(
                kind=ChangeKind.SCHEMA_PARAM_REMOVED,
                path=f"{base}/{name}",
                before=old_props[name],
                tool=tool,
            )
        )

    for name in sorted(set(old_props) & set(new_props)):
        old_param, new_param = _obj(old_props[name]), _obj(new_props[name])
        explained = False
        if old_param.get("type") != new_param.get("type"):
            explained = True
            changes.append(
                Change(
                    kind=ChangeKind.PARAM_TYPE_CHANGED,
                    path=f"{base}/{name}/type",
                    before=old_param.get("type"),
                    after=new_param.get("type"),
                    tool=tool,
                )
            )
        if old_param.get("description") != new_param.get("description"):
            explained = True
            changes.append(
                _text_change(
                    ChangeKind.PARAM_DESCRIPTION_CHANGED,
                    f"{base}/{name}/description",
                    old_param.get("description"),
                    new_param.get("description"),
                    tool=tool,
                )
            )
        # Anything type and description do not account for: an `enum` gaining a
        # value, a `pattern` loosening, a `default` moving. Without this the
        # change is invisible and the transition looks like a hash that moved
        # for no reason.
        if not explained and _canon(old_props[name]) != _canon(new_props[name]):
            changes.append(
                Change(
                    kind=ChangeKind.PARAM_SCHEMA_CHANGED,
                    path=f"{base}/{name}",
                    before=old_props[name],
                    after=new_props[name],
                    tool=tool,
                )
            )

    for name in sorted((new_required - old_required) & set(new_props)):
        changes.append(
            Change(
                kind=ChangeKind.PARAM_BECAME_REQUIRED,
                path=f"tools/{tool}/inputSchema/required/{name}",
                before=False,
                after=True,
                tool=tool,
            )
        )
    for name in sorted((old_required - new_required) & set(old_props) & set(new_props)):
        changes.append(
            Change(
                kind=ChangeKind.PARAM_BECAME_OPTIONAL,
                path=f"tools/{tool}/inputSchema/required/{name}",
                before=True,
                after=False,
                tool=tool,
            )
        )
    return changes


def _diff_tool(
    tool: str, before: dict[str, JsonValue], after: dict[str, JsonValue]
) -> list[Change]:
    """Diff one tool that exists on both sides."""
    changes: list[Change] = []
    if before.get("description") != after.get("description"):
        changes.append(
            _text_change(
                ChangeKind.TOOL_DESCRIPTION_CHANGED,
                f"tools/{tool}/description",
                before.get("description"),
                after.get("description"),
                tool=tool,
            )
        )
    if _canon(before.get("annotations")) != _canon(after.get("annotations")):
        changes.append(
            Change(
                kind=ChangeKind.ANNOTATION_CHANGED,
                path=f"tools/{tool}/annotations",
                before=before.get("annotations"),
                after=after.get("annotations"),
                tool=tool,
            )
        )
    if _canon(before.get("execution")) != _canon(after.get("execution")):
        changes.append(
            Change(
                kind=ChangeKind.EXECUTION_CHANGED,
                path=f"tools/{tool}/execution",
                before=before.get("execution"),
                after=after.get("execution"),
                tool=tool,
            )
        )
    changes.extend(_diff_schema(tool, before, after))

    # The schema outside `properties` and `required` — `additionalProperties`,
    # `$schema`, nested `$defs` — plus any tool-level field the protocol has
    # that this engine does not model, such as `title` or `outputSchema`.
    old_frame = {k: v for k, v in _obj(before.get("inputSchema")).items() if k not in _SCHEMA_BODY}
    new_frame = {k: v for k, v in _obj(after.get("inputSchema")).items() if k not in _SCHEMA_BODY}
    if _canon(old_frame) != _canon(new_frame):
        changes.append(
            Change(
                kind=ChangeKind.TOOL_FIELD_CHANGED,
                path=f"tools/{tool}/inputSchema",
                before=old_frame,
                after=new_frame,
                tool=tool,
            )
        )
    for name in sorted((set(before) | set(after)) - _MODELLED_TOOL_FIELDS):
        if _canon(before.get(name)) != _canon(after.get(name)):
            changes.append(
                _text_change(
                    ChangeKind.TOOL_FIELD_CHANGED,
                    f"tools/{tool}/{name}",
                    before.get(name),
                    after.get(name),
                    tool=tool,
                )
            )
    return changes


def diff_manifest(before: JsonValue, after: JsonValue) -> list[Change]:
    """Diff two Layer-2 tool manifests.

    Args:
        before: The earlier manifest.
        after: The later one.

    Returns:
        Typed changes, in a stable order.
    """
    old, new = _obj(before), _obj(after)
    old_tools = _by_name(_seq(old.get("tools")))
    new_tools = _by_name(_seq(new.get("tools")))
    changes: list[Change] = []

    removed = {k: v for k, v in old_tools.items() if k not in new_tools}
    added = {k: v for k, v in new_tools.items() if k not in old_tools}
    renames = _match_renames(removed, added)

    for old_name, new_name in renames:
        changes.append(
            Change(
                kind=ChangeKind.TOOL_RENAMED,
                path=f"tools/{old_name}",
                before=old_name,
                after=new_name,
                tool=new_name,
            )
        )
        changes.extend(_diff_tool(new_name, removed[old_name], added[new_name]))

    renamed_old = {a for a, _ in renames}
    renamed_new = {b for _, b in renames}

    for name in sorted(set(added) - renamed_new):
        changes.append(
            Change(
                kind=ChangeKind.TOOL_ADDED,
                path=f"tools/{name}",
                after=added[name],
                tool=name,
                detail=_text(added[name].get("description")),
            )
        )
    for name in sorted(set(removed) - renamed_old):
        changes.append(
            Change(
                kind=ChangeKind.TOOL_REMOVED, path=f"tools/{name}", before=removed[name], tool=name
            )
        )

    for name in sorted(set(old_tools) & set(new_tools)):
        changes.extend(_diff_tool(name, old_tools[name], new_tools[name]))

    changes.extend(
        _diff_named(
            old,
            new,
            "prompts",
            ChangeKind.PROMPT_ADDED,
            ChangeKind.PROMPT_REMOVED,
            ChangeKind.PROMPT_CHANGED,
        )
    )
    changes.extend(
        _diff_named(
            old,
            new,
            "resources",
            ChangeKind.RESOURCE_ADDED,
            ChangeKind.RESOURCE_REMOVED,
            None,
            key="uri",
        )
    )

    for name, kind in (
        ("serverInfo", ChangeKind.SERVER_INFO_CHANGED),
        ("capabilities", ChangeKind.CAPABILITIES_CHANGED),
    ):
        if _canon(old.get(name)) != _canon(new.get(name)):
            changes.append(Change(kind=kind, path=name, before=old.get(name), after=new.get(name)))

    for name in sorted((set(old) | set(new)) - _MODELLED_MANIFEST_FIELDS):
        if _canon(old.get(name)) != _canon(new.get(name)):
            changes.append(
                Change(
                    kind=ChangeKind.MANIFEST_FIELD_CHANGED,
                    path=name,
                    before=old.get(name),
                    after=new.get(name),
                )
            )
    return changes


def _diff_named(
    old: dict[str, JsonValue],
    new: dict[str, JsonValue],
    field: str,
    added_kind: ChangeKind,
    removed_kind: ChangeKind,
    changed_kind: ChangeKind | None,
    *,
    key: str = "name",
) -> list[Change]:
    """Diff a named collection — prompts by name, resources by uri."""
    old_items, new_items = _by_name(_seq(old.get(field)), key), _by_name(_seq(new.get(field)), key)
    changes: list[Change] = []
    for name in sorted(set(new_items) - set(old_items)):
        changes.append(Change(kind=added_kind, path=f"{field}/{name}", after=new_items[name]))
    for name in sorted(set(old_items) - set(new_items)):
        changes.append(Change(kind=removed_kind, path=f"{field}/{name}", before=old_items[name]))
    if changed_kind is not None:
        for name in sorted(set(old_items) & set(new_items)):
            if _canon(old_items[name]) != _canon(new_items[name]):
                changes.append(
                    _text_change(
                        changed_kind,
                        f"{field}/{name}",
                        old_items[name].get("description"),
                        new_items[name].get("description"),
                    )
                )
    return changes
