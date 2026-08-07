"""Minimal read-only MCP client over streamable HTTP.

Deliberately not a general MCP implementation. It performs exactly the four
read-only methods the observatory needs and has no code path that can call a
tool, because the safest way to guarantee we never invoke ``tools/call`` against
a live third-party server is to not implement it.

Two framings must both be handled: a streamable-HTTP endpoint may answer a POST
with a plain ``application/json`` body or with ``text/event-stream`` frames, and
which one you get varies by server and sometimes by method. Both were observed
in the wild during the feasibility probe.

Session handling follows the 2025-06-18 revision: the ``Mcp-Session-Id`` header
returned by ``initialize`` is echoed on every subsequent request, as is
``MCP-Protocol-Version``.
"""

import json
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx

from .errors import CollectorError

__all__ = [
    "PROTOCOL_VERSION",
    "READ_ONLY_METHODS",
    "AuthRequired",
    "McpProtocolError",
    "McpSession",
    "parse_jsonrpc",
]

PROTOCOL_VERSION = "2025-06-18"
"""Negotiated protocol revision. Confirmed working against live servers."""

CLIENT_NAME = "mcpwatch"

READ_ONLY_METHODS = ("tools/list", "resources/list", "prompts/list")
"""The only methods this client will ever issue after `initialize`.

`tools/call` is absent by construction, not by discipline.
"""

_AUTH_STATUSES = frozenset({401, 402, 403, 407})
# JSON-RPC error codes servers use to demand credentials. -32001/-32002 are
# unofficial but observed; the string check below catches the rest.
_AUTH_ERROR_CODES = frozenset({-32001, -32002})
_AUTH_HINTS = ("unauthor", "unauthent", "auth required", "authentication", "forbidden", "api key")


class McpProtocolError(CollectorError):
    """The endpoint answered, but not with usable MCP."""


# Named for the server's state, not for a malfunction on our side (cf. N818):
# a server requiring credentials is a documented population, not an error.
class AuthRequired(CollectorError):  # noqa: N818
    """The endpoint demands credentials.

    Recorded as its own population and skipped. We never supply credentials, so
    this is a documented coverage limitation of the dataset rather than an
    obstacle to work around.
    """


def _decode_sse(body: str) -> list[Any]:
    """Extract JSON payloads from ``text/event-stream`` frames.

    Frames are separated by blank lines; ``data:`` lines within one frame
    concatenate with newlines. Non-JSON frames (comments, keep-alives) are
    skipped rather than raising — a heartbeat is not a protocol error.
    """
    messages: list[Any] = []
    for frame in body.replace("\r\n", "\n").split("\n\n"):
        data_lines = [
            line[5:].lstrip() if line.startswith("data:") else None for line in frame.split("\n")
        ]
        payload = "\n".join(line for line in data_lines if line is not None)
        if not payload.strip():
            continue
        try:
            messages.append(json.loads(payload))
        except ValueError:
            continue
    return messages


def parse_jsonrpc(content_type: str, body: str, request_id: str) -> dict[str, Any]:
    """Pull the JSON-RPC response matching ``request_id`` out of a body.

    Args:
        content_type: The response's Content-Type header.
        body: The decoded response body.
        request_id: The id sent with the request.

    Returns:
        The matching JSON-RPC message.

    Raises:
        McpProtocolError: If the body is not JSON, or contains no message with
            the expected id.
    """
    if "text/event-stream" in content_type.lower():
        candidates = _decode_sse(body)
    else:
        try:
            decoded = json.loads(body)
        except ValueError as exc:
            msg = f"response was not JSON ({content_type}): {body[:200]!r}"
            raise McpProtocolError(msg) from exc
        candidates = decoded if isinstance(decoded, list) else [decoded]

    for message in candidates:
        if isinstance(message, dict) and str(message.get("id")) == request_id:
            return message
    # Some servers answer with a single unlabelled response object.
    if len(candidates) == 1 and isinstance(candidates[0], dict) and "id" not in candidates[0]:
        return candidates[0]
    msg = f"no JSON-RPC message with id {request_id!r} in response ({content_type})"
    raise McpProtocolError(msg)


def _looks_like_auth(error: dict[str, Any]) -> bool:
    """Decide whether a JSON-RPC error is really a demand for credentials."""
    if error.get("code") in _AUTH_ERROR_CODES:
        return True
    message = str(error.get("message", "")).casefold()
    return any(hint in message for hint in _AUTH_HINTS)


@dataclass
class McpSession:
    """One read-only conversation with one MCP endpoint.

    Attributes:
        client: An ``httpx.AsyncClient`` carrying the collector's User-Agent.
        url: The endpoint to POST to.
        timeout: Per-request timeout in seconds.
    """

    client: httpx.AsyncClient
    url: str
    timeout: float = 20.0
    session_id: str | None = field(default=None, init=False)
    server_info: dict[str, Any] = field(default_factory=dict, init=False)
    negotiated_version: str | None = field(default=None, init=False)
    capabilities: dict[str, Any] = field(default_factory=dict, init=False)

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": self.negotiated_version or PROTOCOL_VERSION,
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        return headers

    async def _post(self, payload: dict[str, Any]) -> httpx.Response:
        """POST one JSON-RPC message, translating auth rejections."""
        response = await self.client.post(
            self.url, json=payload, headers=self._headers(), timeout=self.timeout
        )
        if response.status_code in _AUTH_STATUSES:
            msg = f"HTTP {response.status_code} from {self.url}"
            raise AuthRequired(msg)
        if response.status_code >= 400:
            msg = f"HTTP {response.status_code} from {self.url}: {response.text[:200]!r}"
            raise McpProtocolError(msg)
        return response

    async def _request(self, method: str, params: dict[str, Any] | None = None) -> Any:  # noqa: ANN401 - a JSON-RPC result is genuinely dynamic
        """Issue one JSON-RPC request and return its ``result``.

        Raises:
            AuthRequired: The server demands credentials.
            McpProtocolError: The server returned a JSON-RPC error or unusable
                framing.
        """
        request_id = uuid.uuid4().hex[:12]
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            payload["params"] = params

        response = await self._post(payload)
        message = parse_jsonrpc(response.headers.get("content-type", ""), response.text, request_id)
        if "error" in message:
            error = message["error"] if isinstance(message["error"], dict) else {}
            if _looks_like_auth(error):
                raise AuthRequired(f"{method}: {error.get('message')}")
            msg = f"{method} returned JSON-RPC error {error.get('code')}: {error.get('message')}"
            raise McpProtocolError(msg)
        return message.get("result")

    async def _notify(self, method: str) -> None:
        """Send a notification, tolerating servers that dislike them.

        ``notifications/initialized`` is required by the spec and some servers
        refuse to answer `tools/list` without it, but others reject it. A failure
        here must not fail the probe.
        """
        payload = {"jsonrpc": "2.0", "method": method}
        try:
            await self.client.post(
                self.url, json=payload, headers=self._headers(), timeout=self.timeout
            )
        except httpx.HTTPError, McpProtocolError:
            return

    async def initialize(self) -> dict[str, Any]:
        """Perform the MCP handshake and capture the session identity.

        Returns:
            The ``initialize`` result.
        """
        request_id = uuid.uuid4().hex[:12]
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": CLIENT_NAME, "version": "0.1.0"},
            },
        }
        response = await self._post(payload)
        # Capture the session id before parsing: a server may answer the body
        # with an error yet still have issued one.
        self.session_id = response.headers.get("mcp-session-id") or None
        message = parse_jsonrpc(response.headers.get("content-type", ""), response.text, request_id)
        if "error" in message:
            error = message["error"] if isinstance(message["error"], dict) else {}
            if _looks_like_auth(error):
                raise AuthRequired(f"initialize: {error.get('message')}")
            msg = f"initialize returned JSON-RPC error {error.get('code')}"
            raise McpProtocolError(msg)

        result = message.get("result")
        if not isinstance(result, dict):
            msg = f"initialize returned no result object: {str(message)[:200]}"
            raise McpProtocolError(msg)

        self.server_info = result.get("serverInfo", {}) or {}
        self.capabilities = result.get("capabilities", {}) or {}
        version = result.get("protocolVersion")
        self.negotiated_version = version if isinstance(version, str) else None
        await self._notify("notifications/initialized")
        return result

    async def collect_manifest(self) -> dict[str, Any]:
        """Run the full read-only sweep and return the combined manifest.

        ``resources/list`` and ``prompts/list`` are optional capabilities; a
        server that does not implement them returns an error, which is recorded
        as an absent section rather than failing the probe. ``tools/list`` is
        not optional — a server with no tool list has nothing this project
        measures.

        Returns:
            The document stored as one Layer-2 observation.
        """
        await self.initialize()

        manifest: dict[str, Any] = {
            "serverInfo": self.server_info,
            "protocolVersion": self.negotiated_version,
            "capabilities": self.capabilities,
        }
        tools = await self._request("tools/list")
        manifest["tools"] = tools.get("tools", []) if isinstance(tools, dict) else []

        for method, key in (("resources/list", "resources"), ("prompts/list", "prompts")):
            try:
                result = await self._request(method)
            except McpProtocolError:
                # Unsupported capability, not a failed probe.
                manifest[key] = None
                continue
            manifest[key] = result.get(key, []) if isinstance(result, dict) else []

        return manifest
