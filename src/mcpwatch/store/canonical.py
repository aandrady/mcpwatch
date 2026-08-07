"""Canonical JSON normalization — the hash-stability layer.

Every mutation MCPWatch reports is ultimately "``norm_sha`` changed between two
observations". That makes this module the single point where the headline result
can be silently corrupted:

* Normalize too little and a server that shuffles its tool order, or embeds a
  session id in a description, registers a phantom mutation every single day.
* Normalize too much and a real change gets erased before it is ever recorded.

Two structural defences make the trade-off recoverable rather than permanent:

1. **The raw blob is always stored.** Nothing here is destructive to the corpus;
   normalization only decides what gets hashed.
2. **Normalization is versioned.** :data:`NORM_VERSION` is stamped onto every
   observation, so a v2 policy can be replayed retroactively over v1 raw blobs
   and the two populations stay distinguishable.

Any change to the behaviour of :data:`DEFAULT_POLICY` — a new volatile key, a new
sort rule, a different Unicode form — **must** come with a bumped
:data:`NORM_VERSION`. Silently changing normalization under a fixed version
number invents mutations that never happened.
"""

import hashlib
import json
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from .errors import CanonicalizationError
from .types import JsonValue

__all__ = [
    "DEFAULT_POLICY",
    "NORM_VERSION",
    "NormalizationPolicy",
    "canonical_bytes",
    "norm_sha256",
    "normalize",
    "sha256_hex",
]

NORM_VERSION = 1
"""Version of :data:`DEFAULT_POLICY`. Bump on *any* behavioural change."""

_VOLATILE_KEYS = frozenset(
    {
        # Session / correlation identifiers that change on every connection.
        "sessionid",
        "mcpsessionid",
        "connectionid",
        "clientid",
        "requestid",
        "xrequestid",
        "correlationid",
        "traceid",
        "spanid",
        "progresstoken",
        # One-shot values.
        "nonce",
        "cachebuster",
        # Wall-clock stamps emitted by the responding server, not by the registry.
        "timestamp",
        "servertime",
        "currenttime",
        "generatedat",
        "retrievedat",
        "fetchedat",
        "observedat",
        "expiresat",
        "expiresin",
        "issuedat",
        # Counters that drift without the definition changing.
        "uptime",
        "uptimeseconds",
        "requestcount",
    }
)
# Deliberately NOT stripped: the registry's own `publishedAt` / `updatedAt`.
# Those move only when a server is republished, which is exactly the Layer-1
# signal we are trying to measure. A collector that wants them gone should
# declare them in `volatile_paths` under a new norm_version rather than widen
# this key list, because key matching is global and would also catch a live
# server that legitimately reports its own publish date.

_PROTECTED_KEY_PARENTS = frozenset(
    {
        # Objects whose *keys* are author-chosen names, not protocol fields.
        # Applying the volatile-key denylist inside these would delete a real
        # tool parameter that merely happens to be called `timestamp`.
        "properties",
        "patternProperties",
        "definitions",
        "$defs",
        "dependentSchemas",
        "dependentRequired",
    }
)

_OPAQUE_KEYS = frozenset(
    {
        # Author-supplied payloads. Their contents are data, so neither the
        # denylist nor array sorting may touch them. Object keys inside are still
        # sorted, which is always safe: JSON objects are unordered by definition.
        "const",
        "default",
        "enum",
        "example",
        "examples",
    }
)

_OBJECT_ARRAY_SORT_KEYS: Mapping[str, str] = MappingProxyType(
    {
        "tools": "name",
        "resources": "uri",
        "resourceTemplates": "uriTemplate",
        "prompts": "name",
    }
)

_STRING_ARRAY_SORT_KEYS = frozenset({"required"})

_LIST_SEGMENT = "[]"
"""Path segment standing in for any list index, so patterns are index-free."""


@dataclass(frozen=True, slots=True)
class NormalizationPolicy:
    """A versioned, declarative description of how documents are canonicalized.

    Every field is part of the contract that :attr:`version` names. Construct a
    variant only together with a new version number; two policies that differ in
    behaviour must never share a version.

    Attributes:
        version: Integer stamped onto observations as ``norm_version``.
        volatile_keys: Match-normalized key names (case-folded, ``-``/``_``
            removed) stripped wherever they appear, except inside
            :attr:`protected_key_parents` and :attr:`opaque_keys` subtrees.
        volatile_paths: Exact paths to strip, as tuples of segments. ``"*"``
            matches any single segment and ``"[]"`` stands for a list index —
            e.g. ``("tools", "[]", "_meta", "issuedAt")``. Applied everywhere,
            including inside protected and opaque subtrees, because a path is an
            explicit statement about one location rather than a global guess.
        object_array_sort_keys: Array key name to the element field it sorts on.
            Applied only when every element is an object carrying that field as
            a string, so a differently shaped array is left alone.
        string_array_sort_keys: Array key names sorted as plain strings.
        protected_key_parents: Keys whose direct children are author-chosen
            names, exempt from :attr:`volatile_keys`.
        opaque_keys: Keys whose entire subtree is author data: no stripping and
            no array reordering below them.
        unicode_form: Unicode normal form applied to every string and key, or
            ``None`` to leave text untouched. ``NFC`` keeps visually identical
            descriptions from hashing differently.
    """

    version: int
    volatile_keys: frozenset[str] = _VOLATILE_KEYS
    volatile_paths: frozenset[tuple[str, ...]] = field(default=frozenset())
    object_array_sort_keys: Mapping[str, str] = _OBJECT_ARRAY_SORT_KEYS
    string_array_sort_keys: frozenset[str] = _STRING_ARRAY_SORT_KEYS
    protected_key_parents: frozenset[str] = _PROTECTED_KEY_PARENTS
    opaque_keys: frozenset[str] = _OPAQUE_KEYS
    unicode_form: str | None = "NFC"


DEFAULT_POLICY = NormalizationPolicy(version=NORM_VERSION)
"""The policy every collector uses unless it has a documented reason not to."""


def _match_key(key: str) -> str:
    """Fold a key for denylist comparison: ``Mcp-Session-Id`` -> ``mcpsessionid``."""
    return key.casefold().replace("-", "").replace("_", "")


def _path_matches(path: tuple[str, ...], patterns: frozenset[tuple[str, ...]]) -> bool:
    """Return whether ``path`` matches any pattern, honouring ``"*"`` wildcards."""
    for pattern in patterns:
        if len(pattern) != len(path):
            continue
        if all(seg == "*" or seg == actual for seg, actual in zip(pattern, path, strict=True)):
            return True
    return False


def _fold_text(text: str, policy: NormalizationPolicy) -> str:
    """Apply the policy's Unicode normal form to a string."""
    if policy.unicode_form is None:
        return text
    return unicodedata.normalize(policy.unicode_form, text)  # type: ignore[arg-type]


def _sort_array(
    key: str,
    items: list[JsonValue],
    policy: NormalizationPolicy,
) -> list[JsonValue]:
    """Reorder an array whose order carries no meaning.

    The sort is total: ties on the primary field fall back to the element's own
    canonical bytes, so two tools sharing a name still order deterministically.
    Arrays that do not match a rule's shape are returned untouched — order is
    assumed meaningful until proven otherwise.
    """
    sort_field = policy.object_array_sort_keys.get(key)
    if sort_field is not None and items:
        decorated: list[tuple[str, bytes, JsonValue]] = []
        for item in items:
            if not isinstance(item, dict):
                return items
            field_value = item.get(sort_field)
            if not isinstance(field_value, str):
                return items
            decorated.append((field_value, _dumps(item), item))
        decorated.sort(key=lambda entry: (entry[0], entry[1]))
        return [entry[2] for entry in decorated]

    if key in policy.string_array_sort_keys:
        strings: list[JsonValue] = []
        for item in items:
            if not isinstance(item, str):
                return items
            strings.append(item)
        strings.sort(key=str)
        return strings

    return items


def _normalize_node(
    node: JsonValue,
    path: tuple[str, ...],
    policy: NormalizationPolicy,
    *,
    structural: bool,
    keys_are_names: bool,
) -> JsonValue:
    """Recursively normalize one node.

    Args:
        node: The value to normalize.
        path: Segments from the document root, with ``"[]"`` for list indices.
        policy: The active normalization policy.
        structural: Whether protocol-level rules (volatile-key stripping, array
            reordering) apply here. False inside an opaque subtree.
        keys_are_names: Whether this mapping's keys are author-chosen names and
            therefore exempt from the volatile-key denylist.
    """
    if isinstance(node, dict):
        return _normalize_mapping(
            node, path, policy, structural=structural, keys_are_names=keys_are_names
        )
    if isinstance(node, list):
        child_path = (*path, _LIST_SEGMENT)
        return [
            _normalize_node(item, child_path, policy, structural=structural, keys_are_names=False)
            for item in node
        ]
    if isinstance(node, str):
        return _fold_text(node, policy)
    if isinstance(node, bool) or node is None or isinstance(node, int | float):
        return node

    # Unreachable per the annotation, reachable in practice: documents arrive
    # from the wire as `Any`, so a datetime or a set can and does turn up here.
    msg = f"value of type {type(node).__name__!r} at path {path} is not JSON"  # type: ignore[unreachable]
    raise CanonicalizationError(msg)


def _normalize_mapping(
    node: dict[str, JsonValue],
    path: tuple[str, ...],
    policy: NormalizationPolicy,
    *,
    structural: bool,
    keys_are_names: bool,
) -> dict[str, JsonValue]:
    """Normalize an object: strip, recurse, sort arrays, emit keys in order."""
    out: dict[str, JsonValue] = {}
    for raw_key, value in node.items():
        if not isinstance(raw_key, str):
            # Same as above: `json.loads` only ever yields string keys, but a
            # caller handing us a hand-built dict is not bound by the annotation.
            msg = f"object key {raw_key!r} at path {path} is not a string"  # type: ignore[unreachable]
            raise CanonicalizationError(msg)
        key = _fold_text(raw_key, policy)
        child_path = (*path, key)

        if _path_matches(child_path, policy.volatile_paths):
            continue
        if structural and not keys_are_names and _match_key(key) in policy.volatile_keys:
            continue
        if key in out:
            msg = f"Unicode normalization collapsed two distinct keys at path {path}: {key!r}"
            raise CanonicalizationError(msg)

        child_structural = structural and key not in policy.opaque_keys
        child = _normalize_node(
            value,
            child_path,
            policy,
            structural=child_structural,
            keys_are_names=key in policy.protected_key_parents,
        )
        if child_structural and isinstance(child, list):
            child = _sort_array(key, child, policy)
        out[key] = child

    return {key: out[key] for key in sorted(out)}


def normalize(document: JsonValue, policy: NormalizationPolicy = DEFAULT_POLICY) -> JsonValue:
    """Return ``document`` rewritten into its canonical form.

    Object keys are sorted recursively, semantically unordered arrays are sorted,
    volatile fields are stripped, and text is Unicode-normalized. The input is
    not modified.

    Args:
        document: Any value produced by ``json.loads``.
        policy: The normalization policy to apply.

    Returns:
        A new value equal to ``document`` modulo the policy's rewrites.

    Raises:
        CanonicalizationError: If the document contains non-string object keys,
            non-JSON values, or keys that collide under Unicode normalization.
    """
    return _normalize_node(document, (), policy, structural=True, keys_are_names=False)


def _dumps(document: JsonValue) -> bytes:
    """Serialize an already-normalized value to canonical UTF-8 bytes."""
    try:
        text = json.dumps(
            document,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
            check_circular=True,
        )
    except (TypeError, ValueError) as exc:
        msg = f"document is not representable as canonical JSON: {exc}"
        raise CanonicalizationError(msg) from exc
    return text.encode("utf-8")


def canonical_bytes(
    document: JsonValue,
    policy: NormalizationPolicy = DEFAULT_POLICY,
) -> bytes:
    """Normalize ``document`` and serialize it to canonical UTF-8 bytes.

    The serialization is compact (no whitespace), key-sorted, and
    ``ensure_ascii=False`` so non-ASCII text is stored as itself rather than as
    escape sequences.

    Raises:
        CanonicalizationError: If the document cannot be canonicalized, which
            includes ``NaN`` and ``Infinity`` — both are accepted by
            ``json.loads`` but are not valid JSON to emit.
    """
    return _dumps(normalize(document, policy))


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex sha256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def norm_sha256(
    document: JsonValue,
    policy: NormalizationPolicy = DEFAULT_POLICY,
) -> str:
    """Return the sha256 of ``document``'s canonical bytes under ``policy``."""
    return sha256_hex(canonical_bytes(document, policy))
