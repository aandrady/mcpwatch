"""An in-process stand-in for the MCP registry, shaped like the real responses.

Field shapes here were copied from a live probe on 2026-08-07, not invented:
``repository`` is ``{url, source}``, ``packages[]`` carry ``registryType`` and a
``transport`` object, and the registry's own metadata sits under
``_meta["io.modelcontextprotocol.registry/official"]``.
"""

import json
from typing import Any

from mcpwatch.collect.http import HttpResponse
from mcpwatch.collect.registry import REGISTRY_META_KEY


def entry(
    name: str,
    *,
    version: str = "1.0.0",
    description: str = "A test server.",
    repo: str | None = "https://github.com/example/mcp",
    endpoint: str | None = "https://example.com/mcp",
    remote_type: str = "streamable-http",
    is_latest: bool = True,
    status: str = "active",
    updated_at: str = "2026-08-07T00:00:00.000000Z",
    extra_remotes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build one registry row."""
    server: dict[str, Any] = {
        "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
        "name": name,
        "description": description,
        "version": version,
    }
    if repo is not None:
        server["repository"] = {"url": repo, "source": "github"}
    remotes = []
    if endpoint is not None:
        remotes.append({"type": remote_type, "url": endpoint})
    remotes.extend(extra_remotes or [])
    if remotes:
        server["remotes"] = remotes
    return {
        "server": server,
        "_meta": {
            REGISTRY_META_KEY: {
                "status": status,
                "statusChangedAt": updated_at,
                "publishedAt": updated_at,
                "updatedAt": updated_at,
                "isLatest": is_latest,
            }
        },
    }


class FakeRegistry:
    """Serves canned pages with real cursor pagination.

    Also records every request so tests can assert on the query parameters the
    collector actually sent — ``version=latest`` and ``updated_since`` are load
    bearing, and a test that never checks them would not notice them going away.
    """

    def __init__(self, entries: list[dict[str, Any]], *, page_size: int = 2) -> None:
        self.entries = entries
        self.page_size = page_size
        self.requests: list[dict[str, str]] = []
        self.request_count = 0
        self.retry_count = 0
        self.rate_limit_hits = 0
        self.fail_on_page: int | None = None

    def get(self, url: str, params: dict[str, Any] | None = None) -> HttpResponse:
        """Serve one page, honouring cursor and updated_since."""
        params = {str(k): str(v) for k, v in (params or {}).items()}
        self.requests.append(params)
        self.request_count += 1

        rows = self.entries
        since = params.get("updated_since")
        if since is not None:
            rows = [
                e
                for e in rows
                if e["_meta"][REGISTRY_META_KEY]["updatedAt"] >= since.replace("+00:00", "Z")
            ]

        start = 0
        cursor = params.get("cursor")
        if cursor:
            keys = [f"{e['server']['name']}:{e['server']['version']}" for e in rows]
            start = keys.index(cursor) + 1

        page_size = int(params.get("limit", self.page_size))
        page = rows[start : start + page_size]

        page_number = len(self.requests)
        if self.fail_on_page is not None and page_number == self.fail_on_page:
            msg = f"simulated network failure on page {page_number}"
            raise ConnectionError(msg)

        next_cursor = None
        if start + page_size < len(rows) and page:
            last = page[-1]["server"]
            next_cursor = f"{last['name']}:{last['version']}"

        body = json.dumps(
            {"servers": page, "metadata": {"nextCursor": next_cursor, "count": len(page)}}
        ).encode()
        return HttpResponse(status=200, url=url, headers={}, body=body)
