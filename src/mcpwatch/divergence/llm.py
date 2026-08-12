"""A pinned-model pass over descriptions the rules cannot read.

The rules in :mod:`~mcpwatch.divergence.declared` match vocabulary. They miss a
description that conveys a capability without using any of its words — "returns
the current weather for a city" declares network access to a reader and nothing
to a regex. Recall is what this layer is for, exactly as in WP7.

**Additive by construction, and this is the load-bearing property.** The model
may only *add* declared capabilities. It is never consulted about the observed
side, and it can never remove a declaration the rules found. A capability the
model adds suppresses a finding; one it fails to add leaves the rules' answer
standing. So the worst a drifting or badly-prompted model can do to this harness
is make it *less* accusatory — never more. That asymmetry is why a model is
acceptable in a measurement that names publishers at all.

The pin, the versioned prompt and the recorded provenance follow WP7's
reasoning: ``claude-opus-5`` is written here as a constant, the prompt is hashed,
and both travel with every capability the model contributes so a declaration can
always be traced to the exact wording that produced it.
"""

import hashlib
import json
from typing import Any, Protocol, cast

from .capabilities import Capability, CapabilityProfile

__all__ = ["MODEL_ID", "PROMPT_SHA", "PROMPT_VERSION", "LlmDeclaredExtractor"]

MODEL_ID = "claude-opus-5"
"""Pinned. An alias would silently re-extract the corpus when it moved."""

PROMPT_VERSION = "v1"

SYSTEM_PROMPT = """\
You are reading Model Context Protocol (MCP) tool definitions for a security
research corpus. For each tool, decide what its description and input schema
tell a *reader* the tool will do — not what it could conceivably do.

Report only capabilities a competent reader would take as declared or clearly
implied by the text and parameters shown. The five capabilities:

- network: contacts anything over a network, including calling an API a
  description names or implies (e.g. "returns the current weather" implies it,
  because that data cannot come from nowhere).
- filesystem_read: reads files or directories from the machine it runs on.
- filesystem_write: creates, modifies or deletes files on that machine.
- subprocess: runs another program, shell command or script.
- credential_access: reads stored credentials, tokens or keys.

Judge generously toward "declared". This output is used to *suppress* findings
that a description already accounted for, so a capability you include can only
ever prevent an accusation, never cause one. When a description plausibly
conveys a capability, include it.

Cite the exact substring that conveys each capability. Do not infer from the
tool's name alone — the caller already handles names.
"""

PROMPT_SHA = hashlib.sha256((SYSTEM_PROMPT + PROMPT_VERSION).encode("utf-8")).hexdigest()[:16]

MAX_TOKENS = 1000
EFFORT = "low"
"""The judgement is a short reading comprehension task, not an analysis."""

RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "declared": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "capability": {
                        "type": "string",
                        "enum": [str(capability) for capability in Capability],
                    },
                    "cited_text": {"type": "string"},
                },
                "required": ["capability", "cited_text"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["declared"],
    "additionalProperties": False,
}


class MessagesClient(Protocol):
    """The one call this module makes. Substituted in tests."""

    def create(self, **kwargs: Any) -> Any:  # noqa: ANN401 - SDK response is dynamic
        """Create a message."""
        ...


class AnthropicLike(Protocol):
    """The shape of ``anthropic.Anthropic`` this module depends on."""

    @property
    def messages(self) -> MessagesClient:
        """The messages resource."""
        ...


def render_user_message(tool: dict[str, Any]) -> str:
    """What the model is shown: the tool, trimmed of what it does not need."""
    payload = {
        "name": tool.get("name"),
        "description": tool.get("description"),
        "inputSchema": tool.get("inputSchema") or tool.get("input_schema"),
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)
    if len(rendered) > 6000:
        rendered = rendered[:6000] + "\n…[truncated]"
    return f"Tool definition:\n\n{rendered}"


class LlmDeclaredExtractor:
    """Adds declared capabilities a rules pass could not read out of prose."""

    def __init__(self, client: AnthropicLike | None = None, *, model_id: str = MODEL_ID) -> None:
        """Bind an extractor to an API client.

        Args:
            client: An ``anthropic.Anthropic`` or anything with the same
                ``messages.create``. Constructed lazily, so importing this
                module never requires credentials.
            model_id: Override the pin. For drift experiments only.
        """
        self.model_id = model_id
        self._client = client
        self._cache: dict[str, CapabilityProfile] = {}

    @property
    def client(self) -> AnthropicLike:
        """The API client, constructed on first use."""
        if self._client is None:
            try:
                import anthropic
            except ImportError as exc:  # pragma: no cover - dependency is declared
                msg = "the anthropic SDK is required for the model layer; run `uv sync`"
                raise RuntimeError(msg) from exc
            # No api_key argument: the SDK resolves ANTHROPIC_API_KEY, then
            # ANTHROPIC_AUTH_TOKEN, then an `ant auth login` profile.
            client: AnthropicLike = cast("AnthropicLike", anthropic.Anthropic())
            self._client = client
            return client
        return self._client

    def augment(self, tool: dict[str, Any], rules: CapabilityProfile) -> CapabilityProfile:
        """Return ``rules`` plus anything the model reads as declared.

        Never subtracts. A failure to reach the model returns ``rules``
        unchanged rather than raising: the rules answer is a complete, if
        narrower, declaration, and a measurement that stops because an API call
        failed is worse than one that stays slightly more accusatory and says so.
        """
        try:
            return rules.merge(self.extract(tool))
        except RuntimeError, ValueError, KeyError:
            return rules

    def extract(self, tool: dict[str, Any]) -> CapabilityProfile:
        """Ask the model what one tool's text declares.

        Raises:
            ValueError: If the response falls outside the pinned schema.
        """
        message = render_user_message(tool)
        key = hashlib.sha256(f"{self.model_id}{PROMPT_SHA}{message}".encode()).hexdigest()
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        response = self.client.messages.create(
            model=self.model_id,
            max_tokens=MAX_TOKENS,
            system=[
                {"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}
            ],
            output_config={
                "format": {"type": "json_schema", "schema": RESPONSE_SCHEMA},
                "effort": EFFORT,
            },
            messages=[{"role": "user", "content": message}],
        )
        if getattr(response, "stop_reason", None) == "refusal":
            msg = f"model declined to read {tool.get('name')!r}"
            raise ValueError(msg)

        text = _first_text(response)
        try:
            parsed = json.loads(text)
            declared = parsed["declared"]
        except (ValueError, KeyError, TypeError) as exc:
            msg = f"model returned a response outside the pinned schema: {text[:300]}"
            raise ValueError(msg) from exc

        pairs: list[tuple[Capability, str]] = []
        for item in declared:
            if not isinstance(item, dict):
                continue
            try:
                capability = Capability(item["capability"])
            except ValueError, KeyError:
                continue
            cited = str(item.get("cited_text", ""))[:200]
            pairs.append(
                (capability, f"{self.model_id}/{PROMPT_VERSION} read it as declared: {cited!r}")
            )
        profile = CapabilityProfile.of(*pairs)
        self._cache[key] = profile
        return profile


def _first_text(response: Any) -> str:  # noqa: ANN401 - SDK response is dynamic
    """Pull the text block out of a Messages response."""
    for block in getattr(response, "content", []) or []:
        if getattr(block, "type", None) == "text":
            return str(getattr(block, "text", ""))
    return ""
