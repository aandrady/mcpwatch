"""Shared fixtures and manifest builders for the storage tests."""

import copy
from pathlib import Path
from typing import Any

import pytest

from mcpwatch.store import Corpus, Layer


@pytest.fixture
def corpus(tmp_path: Path):
    """A fresh corpus rooted in a temporary directory."""
    with Corpus(tmp_path / "corpus") as store:
        yield store


def manifest(description: str = "Read a file from disk.") -> dict[str, Any]:
    """A representative Layer-2 manifest, shaped like a real tools/list result."""
    return {
        "serverInfo": {"name": "example-server", "version": "0.1.0"},
        "protocolVersion": "2025-06-18",
        "tools": [
            {
                "name": "read_file",
                "description": description,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Absolute path."},
                        "encoding": {"type": "string", "default": "utf-8"},
                    },
                    "required": ["path"],
                },
                "annotations": {"readOnlyHint": True, "destructiveHint": False},
            },
            {
                "name": "write_file",
                "description": "Write a file to disk.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "contents": {"type": "string"},
                    },
                    "required": ["contents", "path"],
                },
                "annotations": {"readOnlyHint": False, "destructiveHint": True},
            },
        ],
        "resources": [
            {"uri": "file:///a", "name": "a"},
            {"uri": "file:///b", "name": "b"},
        ],
        "prompts": [
            {"name": "summarize", "description": "Summarize a file."},
            {"name": "explain", "description": "Explain a file."},
        ],
    }


def reordered_manifest(description: str = "Read a file from disk.") -> dict[str, Any]:
    """The same manifest with every semantically unordered thing shuffled."""
    doc = copy.deepcopy(manifest(description))
    doc["tools"] = list(reversed(doc["tools"]))
    doc["resources"] = list(reversed(doc["resources"]))
    doc["prompts"] = list(reversed(doc["prompts"]))
    doc["tools"][0]["inputSchema"]["required"] = list(
        reversed(doc["tools"][0]["inputSchema"]["required"])
    )
    reversed_top = {key: doc[key] for key in reversed(list(doc))}
    return reversed_top


def register(store: Corpus, server_key: str = "example.com/mcp") -> str:
    """Register a server so observations can reference it, and return its key."""
    store.upsert_server(
        server_key=server_key,
        registry_name=server_key,
        repo_url="https://github.com/example/mcp",
        primary_endpoint="https://example.com/mcp",
    )
    return server_key


REGISTRY = Layer.REGISTRY
MANIFEST = Layer.MANIFEST
