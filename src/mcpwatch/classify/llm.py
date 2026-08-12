"""The model layer: everything the rules could not settle.

Rules recognize attacks they have a pattern for. This is where recall comes
from — and where the project's headline numbers become dependent on a model
whose behaviour can change under it. Four decisions follow from that:

**The model id is pinned, never an alias.** ``claude-opus-5`` is written here as
a constant and recorded on every row. A floating alias would silently re-label
the corpus when the alias moves, and the change would be invisible in the data.

**The prompt is versioned in-repo and hashed.** :mod:`~mcpwatch.classify.prompt_v1`
carries the text; its SHA is stored with every classification. A label always
names the exact wording that produced it.

**Sampling is recorded as what it is.** WP7 asks for the temperature to be
logged, and on this model there is none to log — ``temperature`` was removed
from Claude Opus 5 and sending it returns a 400. That is better than a
temperature of zero for this purpose, and the row says so explicitly rather
than leaving a null that reads like an omission.

**The cache is keyed on the ChangeSet id, model, and prompt hash together.**
WP6 derives ``change_id`` from the corpus itself, so it is stable across
recomputation. Keying on it alone would serve a stale label after a prompt
edit; keying on all three makes a re-run under new conditions a new row and
leaves the old one intact for the drift comparison.
"""

import json
from dataclasses import dataclass
from typing import Any, Protocol, cast

from mcpwatch.diff import ChangeSet

from .prompt_v1 import PROMPT_SHA, PROMPT_VERSION, SYSTEM_PROMPT, render_user_message
from .rules import RuleHit
from .store import ClassifyStore, MachineLabel
from .taxonomy import Label

__all__ = ["MODEL_ID", "SAMPLING", "LlmClassifier", "LlmVerdict"]

MODEL_ID = "claude-opus-5"
"""Pinned. Classifier drift is a named confound; an alias would hide it."""

SAMPLING = "model-default (temperature/top_p/top_k are not accepted by claude-opus-5)"
"""Recorded on every classification in place of a temperature.

Not an omission: these parameters were removed from the model and sending one
is a 400. Writing the reason into the row means a future reader does not have
to reconstruct why the field is empty.
"""

MAX_TOKENS = 2000
EFFORT = "high"

RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "label": {"type": "string", "enum": [str(label) for label in Label]},
        "confidence": {"type": "number"},
        "rationale": {"type": "string"},
        "cited_text": {"type": "string"},
    },
    "required": ["label", "confidence", "rationale", "cited_text"],
    "additionalProperties": False,
}


@dataclass(frozen=True, slots=True)
class LlmVerdict:
    """One model-produced label."""

    change_id: str
    label: Label
    confidence: float
    rationale: str
    cited_text: str
    model_id: str = MODEL_ID
    prompt_version: str = PROMPT_VERSION
    prompt_sha: str = PROMPT_SHA
    cached: bool = False

    def as_machine_label(self) -> MachineLabel:
        """Render for :class:`~mcpwatch.classify.store.ClassifyStore`."""
        return MachineLabel(
            change_id=self.change_id,
            source="llm",
            label=str(self.label),
            confidence=self.confidence,
            rationale=f"{self.rationale}\n\ncited: {self.cited_text}",
            model_id=self.model_id,
            prompt_version=self.prompt_version,
            prompt_sha=self.prompt_sha,
            sampling=SAMPLING,
        )


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


def changeset_payload(changeset: ChangeSet) -> dict[str, Any]:
    """What the model is shown.

    The typed ChangeSet, trimmed of bookkeeping the judgement does not need
    (blob digests, observation ids) and with long values truncated. A model
    reading a 40KB embedded document is reading the server, not the change.
    """
    payload = changeset.as_json()
    for key in ("from_norm_sha", "to_norm_sha", "from_obs_id", "to_obs_id", "change_id"):
        payload.pop(key, None)
    changes = payload.get("changes")
    if isinstance(changes, list):
        payload["changes"] = [_trim(change) for change in changes[:40]]
    return payload


def _trim(change: Any, limit: int = 1500) -> Any:  # noqa: ANN401 - JSON is dynamic
    """Truncate long before/after values so one field cannot fill the window."""
    if not isinstance(change, dict):
        return change
    out = dict(change)
    for field in ("before", "after"):
        rendered = json.dumps(out.get(field), ensure_ascii=False)
        if len(rendered) > limit:
            out[field] = rendered[:limit] + "…[truncated]"
    return out


class LlmClassifier:
    """Labels ChangeSets with a pinned Claude model, caching by content."""

    def __init__(
        self,
        store: ClassifyStore,
        client: AnthropicLike | None = None,
        *,
        model_id: str = MODEL_ID,
    ) -> None:
        """Bind a classifier to a store and an API client.

        Args:
            store: Where labels are cached and recorded.
            client: An ``anthropic.Anthropic`` (or anything with the same
                ``messages.create``). Constructed lazily when omitted, so
                importing this module never requires credentials.
            model_id: Override the pinned model. For drift experiments only —
                the default is the pin, and changing it changes what the
                corpus's labels mean.
        """
        self.store = store
        self.model_id = model_id
        self._client = client

    @property
    def client(self) -> AnthropicLike:
        """The API client, constructed on first use."""
        if self._client is None:
            try:
                import anthropic
            except ImportError as exc:  # pragma: no cover - dependency is declared
                msg = "the anthropic SDK is required for the LLM layer; run `uv sync`"
                raise RuntimeError(msg) from exc
            # No api_key argument: the SDK resolves ANTHROPIC_API_KEY, then
            # ANTHROPIC_AUTH_TOKEN, then an `ant auth login` profile. Passing a
            # key here would mean this process had to hold one.
            client: AnthropicLike = cast("AnthropicLike", anthropic.Anthropic())
            self._client = client
            return client
        return self._client

    def classify(
        self, changeset: ChangeSet, hits: list[RuleHit] | None = None, *, refresh: bool = False
    ) -> LlmVerdict:
        """Label one ChangeSet, using the cache unless ``refresh`` is set.

        Raises:
            ValueError: If the model returns something outside the schema. The
                request pins a JSON schema, so this means the contract broke —
                worth failing loudly rather than storing a guess.
        """
        if not refresh:
            cached = self.store.machine_label(
                changeset.change_id, source="llm", model_id=self.model_id, prompt_sha=PROMPT_SHA
            )
            if cached is not None:
                rationale = cached["rationale"] or ""
                body, _, cited = rationale.partition("\n\ncited: ")
                return LlmVerdict(
                    change_id=changeset.change_id,
                    label=Label(cached["label"]),
                    confidence=cached["confidence"] or 0.0,
                    rationale=body,
                    cited_text=cited,
                    model_id=cached["model_id"] or self.model_id,
                    cached=True,
                )

        verdict = self._ask(changeset, hits or [])
        self.store.put_machine_label(verdict.as_machine_label())
        return verdict

    def _ask(self, changeset: ChangeSet, hits: list[RuleHit]) -> LlmVerdict:
        """One API call."""
        rule_text = (
            "\n".join(f"- {hit.rule} ({hit.label}): {hit.evidence}" for hit in hits) or "- none"
        )
        message = render_user_message(
            json.dumps(changeset_payload(changeset), indent=2, sort_keys=True), rule_text
        )

        response = self.client.messages.create(
            model=self.model_id,
            max_tokens=MAX_TOKENS,
            # The taxonomy and instructions are identical on every request and
            # are the whole system prompt, so caching them makes the per-item
            # cost the ChangeSet alone.
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
            msg = f"model declined to classify {changeset.change_id}"
            raise ValueError(msg)

        text = _first_text(response)
        try:
            parsed = json.loads(text)
            label = Label(parsed["label"])
            confidence = float(parsed["confidence"])
        except (ValueError, KeyError, TypeError) as exc:
            msg = f"model returned a response outside the pinned schema: {text[:300]}"
            raise ValueError(msg) from exc

        return LlmVerdict(
            change_id=changeset.change_id,
            label=label,
            confidence=confidence,
            rationale=str(parsed.get("rationale", "")),
            cited_text=str(parsed.get("cited_text", "")),
            model_id=self.model_id,
        )


def _first_text(response: Any) -> str:  # noqa: ANN401 - SDK response is dynamic
    """Pull the text block out of a Messages response."""
    for block in getattr(response, "content", []) or []:
        if getattr(block, "type", None) == "text":
            return str(getattr(block, "text", ""))
    return ""
