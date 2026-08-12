"""What a tool's description and schema *claim* it does.

The declared side of the divergence comparison. Rules first, for the same reason
WP7's classifier is rules-first: this half of the measurement decides whether a
publisher gets accused of shipping a dishonest description, and a deterministic
extractor can be audited, replayed, and argued with a year from now.

**The extraction is deliberately generous.** Every rule here widens what counts
as declared, never narrows it, because a false positive on this side produces a
false *accusation* on the other: a capability the description did in fact hint
at, scored as undeclared. When a description is ambiguous, this resolves toward
"declared" and the divergence goes unreported. That biases the measured rate
downward, which is the direction a first-of-its-kind number should be wrong in,
and it is stated in the reported caveats rather than left for a reader to infer.

Schema parameters count as declaration. A tool taking a ``url`` parameter has
told you it makes requests whether or not its prose says so — the signature is
part of the contract a consumer reads.

:mod:`~mcpwatch.divergence.llm` adds a pinned-model pass for descriptions the
rules cannot read. It is additive by construction: the model may add a declared
capability, never remove one, so a model that drifts can only ever make this
harness *less* accusatory.
"""

import re
from typing import Any

from .capabilities import Capability, CapabilityProfile

__all__ = ["declared_from_schema", "declared_from_text", "declared_profile"]

# Word-boundary matched, so "apiary" does not read as "api" and "path" does not
# fire on "pathology". Cheap, and it removed a third of the early false hits.
_TEXT_RULES: tuple[tuple[Capability, str, str], ...] = (
    (
        Capability.NETWORK,
        r"\b(http|https|url|uri|endpoint|api|apis|web|website|internet|online|fetch|"
        r"download|upload|request|requests|query|queries|search|searches|remote|server|"
        r"webhook|callback|rest|graphql|scrape|crawl|proxy|dns|host|domain)\b",
        "text mentions network access",
    ),
    (
        Capability.FILESYSTEM_READ,
        r"\b(file|files|filesystem|directory|directories|folder|folders|path|paths|"
        r"read|reads|load|loads|open|opens|parse|parses|import|imports|scan|scans|"
        r"disk|local)\b",
        "text mentions reading from disk",
    ),
    (
        Capability.FILESYSTEM_WRITE,
        r"\b(write|writes|save|saves|store|stores|persist|persists|create|creates|"
        r"export|exports|output|outputs|generate|generates|delete|deletes|remove|"
        r"removes|modify|modifies|update|updates)\b",
        "text mentions writing to disk",
    ),
    (
        Capability.SUBPROCESS,
        r"\b(command|commands|shell|bash|sh|exec|execute|executes|run|runs|spawn|"
        r"spawns|process|processes|subprocess|cli|binary|script|scripts|invoke|"
        r"invokes|compile|compiles|build|builds|install|installs)\b",
        "text mentions running a program",
    ),
    (
        Capability.CREDENTIAL_ACCESS,
        r"\b(credential|credentials|token|tokens|api[_ -]?key|apikey|secret|secrets|"
        r"password|passwords|auth|authenticate|authentication|authorization|oauth|"
        r"login|signin|bearer|session)\b",
        "text mentions credentials",
    ),
)

_PARAM_RULES: tuple[tuple[Capability, str, str], ...] = (
    (
        Capability.NETWORK,
        r"(url|uri|endpoint|host|hostname|domain|webhook|callback|address|link|"
        r"server|proxy|port|api_base|base_url)",
        "parameter implies a network destination",
    ),
    (
        Capability.FILESYSTEM_READ,
        r"(path|file|filename|filepath|dir|directory|folder|source|input_file|"
        r"location|document)",
        "parameter implies a filesystem path",
    ),
    (
        Capability.FILESYSTEM_WRITE,
        r"(output|output_path|destination|dest|target|save_to|write_to|out_file)",
        "parameter implies a write destination",
    ),
    (
        Capability.SUBPROCESS,
        r"(command|cmd|shell|exec|script|args|argv|program|binary|executable)",
        "parameter implies running a program",
    ),
    (
        Capability.CREDENTIAL_ACCESS,
        r"(token|api_?key|apikey|secret|password|passwd|credential|auth|bearer|"
        r"access_token|client_secret)",
        "parameter implies a credential",
    ),
)

_STRING_FORMAT_CAPABILITY = {
    "uri": Capability.NETWORK,
    "url": Capability.NETWORK,
    "iri": Capability.NETWORK,
    "hostname": Capability.NETWORK,
    "idn-hostname": Capability.NETWORK,
    "ipv4": Capability.NETWORK,
    "ipv6": Capability.NETWORK,
}
"""JSON Schema ``format`` values that name a capability outright."""

MAX_SCHEMA_DEPTH = 6
"""How deep to walk a schema. Third-party schemas can be cyclic or absurd."""


def declared_from_text(text: str) -> CapabilityProfile:
    """Read declared capabilities out of a description."""
    if not text:
        return CapabilityProfile()
    lowered = text.casefold()
    found: list[tuple[Capability, str]] = []
    for capability, pattern, why in _TEXT_RULES:
        match = re.search(pattern, lowered)
        if match:
            found.append((capability, f"{why}: {match.group(0)!r}"))
    return CapabilityProfile.of(*found)


def declared_from_schema(schema: Any, depth: int = 0) -> CapabilityProfile:  # noqa: ANN401 - third-party JSON
    """Read declared capabilities out of a tool's input schema.

    A parameter is a declaration. A tool accepting ``webhook_url`` has told a
    consumer it will make a request, whatever its prose says, so this counts
    toward *declared* and suppresses a divergence finding rather than creating
    one.
    """
    if not isinstance(schema, dict) or depth > MAX_SCHEMA_DEPTH:
        return CapabilityProfile()

    found: list[tuple[Capability, str]] = []
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, definition in properties.items():
            if not isinstance(name, str):
                continue
            lowered = name.casefold()
            for capability, pattern, why in _PARAM_RULES:
                if re.search(pattern, lowered):
                    found.append((capability, f"{why}: {name!r}"))
            if isinstance(definition, dict):
                fmt = definition.get("format")
                if isinstance(fmt, str) and fmt.casefold() in _STRING_FORMAT_CAPABILITY:
                    found.append(
                        (
                            _STRING_FORMAT_CAPABILITY[fmt.casefold()],
                            f"parameter {name!r} declares format {fmt!r}",
                        )
                    )
                # A parameter's own description is part of the contract too.
                description = definition.get("description")
                if isinstance(description, str):
                    nested = declared_from_text(description)
                    found.extend(
                        (capability, f"parameter {name!r} description: {why}")
                        for capability, why in nested.evidence
                    )
                found.extend(declared_from_schema(definition, depth + 1).evidence)

    for key in ("items", "additionalProperties"):
        found.extend(declared_from_schema(schema.get(key), depth + 1).evidence)
    for key in ("anyOf", "oneOf", "allOf"):
        branches = schema.get(key)
        if isinstance(branches, list):
            for branch in branches:
                found.extend(declared_from_schema(branch, depth + 1).evidence)

    return CapabilityProfile.of(*found)


def declared_profile(tool: dict[str, Any]) -> CapabilityProfile:
    """The full declared profile of one tool: name, description, and schema.

    The name counts. A tool called ``fetch_url`` has declared network access
    even with an empty description, and treating that as undeclared would
    manufacture a divergence out of terseness.
    """
    name = str(tool.get("name") or "")
    description = str(tool.get("description") or "")
    profile = declared_from_text(f"{name.replace('_', ' ').replace('-', ' ')} {description}")

    schema = tool.get("inputSchema")
    if schema is None:
        schema = tool.get("input_schema")
    profile = profile.merge(declared_from_schema(schema))

    # Annotations are a declaration in the protocol's own vocabulary, and the
    # strongest one available: a tool that says it is not read-only has said it
    # changes something, which covers a write we would otherwise call undeclared.
    annotations = tool.get("annotations")
    if isinstance(annotations, dict) and annotations.get("readOnlyHint") is False:
        profile = profile.merge(
            CapabilityProfile.of(
                (Capability.FILESYSTEM_WRITE, "annotations.readOnlyHint is false"),
            )
        )
    return profile
