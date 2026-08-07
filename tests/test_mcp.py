"""MCP client tests: response framing, session handling, and read-only safety."""

import asyncio
import json

import httpx
import pytest

from mcpwatch.collect.mcp import (
    PROTOCOL_VERSION,
    AuthRequired,
    McpProtocolError,
    McpSession,
    parse_jsonrpc,
)

TOOLS = [{"name": "read_file", "description": "Read a file.", "inputSchema": {"type": "object"}}]


def sse(*messages: dict) -> str:
    """Frame messages the way a streamable-http server does."""
    return "".join(f"event: message\ndata: {json.dumps(m)}\n\n" for m in messages)


class TestFraming:
    def test_plain_json(self):
        body = json.dumps({"jsonrpc": "2.0", "id": "abc", "result": {"tools": TOOLS}})
        assert parse_jsonrpc("application/json", body, "abc")["result"]["tools"] == TOOLS

    def test_sse_single_frame(self):
        body = sse({"jsonrpc": "2.0", "id": "abc", "result": {"ok": True}})
        assert parse_jsonrpc("text/event-stream", body, "abc")["result"] == {"ok": True}

    def test_sse_picks_the_matching_id_out_of_several_frames(self):
        body = sse(
            {"jsonrpc": "2.0", "method": "notifications/progress"},
            {"jsonrpc": "2.0", "id": "other", "result": {"no": True}},
            {"jsonrpc": "2.0", "id": "abc", "result": {"yes": True}},
        )
        assert parse_jsonrpc("text/event-stream", body, "abc")["result"] == {"yes": True}

    def test_sse_tolerates_comments_and_keepalives(self):
        body = ": keep-alive\n\n" + sse({"jsonrpc": "2.0", "id": "abc", "result": {}})
        assert parse_jsonrpc("text/event-stream", body, "abc")["id"] == "abc"

    def test_sse_with_crlf_and_no_space_after_colon(self):
        body = 'event: message\r\ndata:{"jsonrpc":"2.0","id":"abc","result":{}}\r\n\r\n'
        assert parse_jsonrpc("text/event-stream", body, "abc")["id"] == "abc"

    def test_sse_multiline_data_is_concatenated(self):
        body = 'event: message\ndata: {"jsonrpc":"2.0",\ndata: "id":"abc","result":{}}\n\n'
        assert parse_jsonrpc("text/event-stream", body, "abc")["id"] == "abc"

    def test_json_array_batch(self):
        body = json.dumps(
            [
                {"jsonrpc": "2.0", "id": "zzz", "result": {}},
                {"jsonrpc": "2.0", "id": "abc", "result": {"found": True}},
            ]
        )
        assert parse_jsonrpc("application/json", body, "abc")["result"] == {"found": True}

    def test_unlabelled_single_response_is_accepted(self):
        """Some servers omit the id entirely; one response is unambiguous."""
        body = json.dumps({"jsonrpc": "2.0", "result": {"lenient": True}})
        assert parse_jsonrpc("application/json", body, "abc")["result"] == {"lenient": True}

    def test_a_single_response_with_the_wrong_id_is_still_accepted(self):
        """Observed live: several servers echo `"id": 0` instead of ours.

        Non-compliant, but the manifest is perfectly good and we sent exactly
        one request, so the lone reply is unambiguously its answer.
        """
        body = json.dumps({"jsonrpc": "2.0", "id": 0, "result": {"tools": TOOLS}})
        assert parse_jsonrpc("application/json", body, "abc")["result"]["tools"] == TOOLS

    def test_the_fallback_does_not_apply_when_several_replies_came_back(self):
        """With more than one reply, guessing would be a real risk."""
        body = sse(
            {"jsonrpc": "2.0", "id": 0, "result": {"first": True}},
            {"jsonrpc": "2.0", "id": 1, "result": {"second": True}},
        )
        with pytest.raises(McpProtocolError, match="no JSON-RPC message"):
            parse_jsonrpc("text/event-stream", body, "abc")

    def test_notifications_do_not_count_as_replies(self):
        """A progress notification alongside one reply must not block it."""
        body = sse(
            {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}},
            {"jsonrpc": "2.0", "id": 0, "result": {"ok": True}},
        )
        assert parse_jsonrpc("text/event-stream", body, "abc")["result"] == {"ok": True}

    def test_non_json_body_raises(self):
        with pytest.raises(McpProtocolError, match="not JSON"):
            parse_jsonrpc("text/html", "<html>nope</html>", "abc")

    def test_a_stream_carrying_no_reply_at_all_raises(self):
        """Notifications only, and nothing that answers the request."""
        body = sse(
            {"jsonrpc": "2.0", "method": "notifications/message", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}},
        )
        with pytest.raises(McpProtocolError, match="no JSON-RPC message"):
            parse_jsonrpc("text/event-stream", body, "abc")


class FakeServer:
    """An MCP server built on httpx's MockTransport, recording every call."""

    def __init__(self, *, session_id="sess-1", framing="json", tools=None, unsupported=()):
        self.session_id = session_id
        self.framing = framing
        self.tools = TOOLS if tools is None else tools
        self.unsupported = set(unsupported)
        self.methods: list[str] = []
        self.headers: list[httpx.Headers] = []

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handle))

    def _wrap(self, message: dict) -> httpx.Response:
        headers = {"Mcp-Session-Id": self.session_id} if self.session_id else {}
        if self.framing == "sse":
            return httpx.Response(
                200,
                text=sse(message),
                headers={**headers, "Content-Type": "text/event-stream"},
            )
        return httpx.Response(200, json=message, headers=headers)

    def handle(self, request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        method = payload["method"]
        self.methods.append(method)
        self.headers.append(request.headers)

        if method.startswith("notifications/"):
            return httpx.Response(202)
        rid = payload["id"]
        if method in self.unsupported:
            return self._wrap(
                {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "not found"}}
            )
        if method == "initialize":
            return self._wrap(
                {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "result": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "serverInfo": {"name": "fake", "version": "0.1.0"},
                        "capabilities": {"tools": {}},
                    },
                }
            )
        key = method.split("/")[0]
        body = {"tools": self.tools, "resources": [], "prompts": []}[key]
        return self._wrap({"jsonrpc": "2.0", "id": rid, "result": {key: body}})


async def _collect(server: FakeServer) -> dict:
    async with server.client() as client:
        return await McpSession(client=client, url="https://fake.example/mcp").collect_manifest()


class TestHandshake:
    def test_full_sweep_over_plain_json(self):
        server = FakeServer(framing="json")
        manifest = asyncio.run(_collect(server))

        assert manifest["tools"] == TOOLS
        assert manifest["serverInfo"] == {"name": "fake", "version": "0.1.0"}
        assert manifest["protocolVersion"] == PROTOCOL_VERSION

    def test_full_sweep_over_sse(self):
        manifest = asyncio.run(_collect(FakeServer(framing="sse")))
        assert manifest["tools"] == TOOLS

    def test_only_read_only_methods_are_ever_called(self):
        """The safety property, asserted rather than assumed."""
        server = FakeServer()
        asyncio.run(_collect(server))

        assert set(server.methods) == {
            "initialize",
            "notifications/initialized",
            "tools/list",
            "resources/list",
            "prompts/list",
        }
        assert not any("call" in m for m in server.methods)

    def test_session_id_is_captured_and_echoed(self):
        server = FakeServer(session_id="sess-xyz")
        asyncio.run(_collect(server))

        assert "Mcp-Session-Id" not in server.headers[0]  # initialize cannot know it yet
        assert all(h.get("mcp-session-id") == "sess-xyz" for h in server.headers[1:])

    def test_protocol_version_header_is_sent(self):
        server = FakeServer()
        asyncio.run(_collect(server))
        assert server.headers[0]["mcp-protocol-version"] == PROTOCOL_VERSION

    def test_a_server_without_a_session_id_still_works(self):
        manifest = asyncio.run(_collect(FakeServer(session_id=None)))
        assert manifest["tools"] == TOOLS

    def test_unsupported_optional_capabilities_become_null_not_failure(self):
        server = FakeServer(unsupported={"resources/list", "prompts/list"})
        manifest = asyncio.run(_collect(server))

        assert manifest["tools"] == TOOLS
        assert manifest["resources"] is None
        assert manifest["prompts"] is None

    def test_a_failing_tools_list_is_a_protocol_error(self):
        server = FakeServer(unsupported={"tools/list"})
        with pytest.raises(McpProtocolError):
            asyncio.run(_collect(server))


class TestAuth:
    def test_http_401_is_auth_required(self):
        def handler(_request):
            return httpx.Response(401, text="nope")

        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                await McpSession(client=client, url="https://x.example/mcp").collect_manifest()

        with pytest.raises(AuthRequired):
            asyncio.run(go())

    def test_jsonrpc_error_mentioning_auth_is_auth_required(self):
        def handler(request):
            rid = json.loads(request.content).get("id")
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": rid,
                    "error": {"code": -32000, "message": "Unauthorized: API key required"},
                },
            )

        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                await McpSession(client=client, url="https://x.example/mcp").collect_manifest()

        with pytest.raises(AuthRequired):
            asyncio.run(go())

    def test_no_credentials_are_ever_sent(self):
        server = FakeServer()
        asyncio.run(_collect(server))
        for headers in server.headers:
            assert "authorization" not in headers
            assert "cookie" not in headers
            assert "x-api-key" not in headers
