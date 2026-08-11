"""An in-process stand-in for the MCP registry, shaped like the real responses.

Field shapes here were copied from a live probe on 2026-08-07, not invented:
``repository`` is ``{url, source}``, ``packages[]`` carry ``registryType`` and a
``transport`` object, and the registry's own metadata sits under
``_meta["io.modelcontextprotocol.registry/official"]``.
"""

import json
import urllib.parse
from typing import Any

from mcpwatch.collect.errors import HttpStatusError
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
    published_at: str | None = None,
    status_changed_at: str | None = None,
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
                "statusChangedAt": status_changed_at or updated_at,
                "publishedAt": published_at or updated_at,
                "updatedAt": updated_at,
                "isLatest": is_latest,
            }
        },
    }


def _meta_of(row: dict[str, Any]) -> dict[str, Any]:
    """The registry's own metadata block, or an empty one for a malformed row."""
    meta = row.get("_meta")
    block = meta.get(REGISTRY_META_KEY) if isinstance(meta, dict) else None
    return block if isinstance(block, dict) else {}


def _name_of(row: dict[str, Any]) -> str | None:
    server = row.get("server")
    return server.get("name") if isinstance(server, dict) else None


class FakeRegistry:
    """Serves canned pages with real cursor pagination.

    Also records every request so tests can assert on the query parameters the
    collector actually sent — ``version=latest``, ``updated_since`` and
    ``include_deleted`` are load bearing, and a test that never checks them
    would not notice them going away.

    Both endpoints the collectors use are served: the ``/v0/servers`` listing
    and the per-server ``/v0/servers/{name}/versions`` chain, including its 404
    for a server the registry has withdrawn.
    """

    def __init__(
        self,
        entries: list[dict[str, Any]],
        *,
        page_size: int = 2,
        filtering: bool = False,
    ) -> None:
        """Serve ``entries``.

        Args:
            entries: Rows to serve, in registry order.
            page_size: Default rows per page.
            filtering: Whether to honour ``version=latest`` and hide withdrawn
                servers unless ``include_deleted=true`` is sent, as the live
                registry does. Off by default so that WP2's tests can hand the
                collector rows it asked not to receive — its defence against the
                registry silently dropping a query parameter is a real behaviour
                that only an unfaithful server can exercise.
        """
        self.entries = entries
        self.page_size = page_size
        self.filtering = filtering
        self.requests: list[dict[str, str]] = []
        self.urls: list[str] = []
        self.request_count = 0
        self.retry_count = 0
        self.rate_limit_hits = 0
        self.fail_on_page: int | None = None
        self.fail_on_versions: str | None = None
        self.pages_served = 0

    def get(self, url: str, params: dict[str, Any] | None = None) -> HttpResponse:
        """Serve one listing page or one server's version chain."""
        params = {str(k): str(v) for k, v in (params or {}).items()}
        self.requests.append(params)
        self.urls.append(url)
        self.request_count += 1
        if url.endswith("/versions"):
            return self._versions(url)
        return self._page(url, params)

    # ------------------------------------------------------------- listing ---

    def _page(self, url: str, params: dict[str, str]) -> HttpResponse:
        rows = self._visible(include_deleted=params.get("include_deleted") == "true")
        if self.filtering and params.get("version") == "latest":
            rows = [e for e in rows if _meta_of(e).get("isLatest")]
        since = params.get("updated_since")
        if since is not None:
            rows = [e for e in rows if _meta_of(e)["updatedAt"] >= since.replace("+00:00", "Z")]

        start = 0
        cursor = params.get("cursor")
        if cursor:
            keys = [f"{e['server']['name']}:{e['server']['version']}" for e in rows]
            start = keys.index(cursor) + 1

        page_size = int(params.get("limit", self.page_size))
        page = rows[start : start + page_size]

        self.pages_served += 1
        if self.fail_on_page is not None and self.pages_served == self.fail_on_page:
            msg = f"simulated network failure on page {self.pages_served}"
            raise ConnectionError(msg)

        next_cursor = None
        if start + page_size < len(rows) and page:
            last = page[-1]["server"]
            next_cursor = f"{last['name']}:{last['version']}"

        body = json.dumps(
            {"servers": page, "metadata": {"nextCursor": next_cursor, "count": len(page)}}
        ).encode()
        return HttpResponse(status=200, url=url, headers={}, body=body)

    # ------------------------------------------------------------ versions ---

    def _versions(self, url: str) -> HttpResponse:
        name = urllib.parse.unquote(url.rsplit("/", 2)[-2])
        if self.fail_on_versions == name:
            msg = f"simulated network failure on /versions for {name}"
            raise ConnectionError(msg)
        rows = [e for e in self.entries if _name_of(e) == name]
        # The live registry drops withdrawn servers from this endpoint entirely
        # — verified against production, and the reason the walk is the only
        # source of their history.
        if not rows or all(_meta_of(e).get("status") != "active" for e in rows):
            raise HttpStatusError(404, url)
        body = json.dumps({"servers": rows, "metadata": {"count": len(rows)}}).encode()
        return HttpResponse(status=200, url=url, headers={}, body=body)

    def _visible(self, *, include_deleted: bool) -> list[dict[str, Any]]:
        if include_deleted or not self.filtering:
            return list(self.entries)
        return [e for e in self.entries if _meta_of(e).get("status", "active") == "active"]
