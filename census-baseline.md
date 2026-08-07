# Registry census — day-zero baseline

Measured **2026-08-07** by full pagination of `https://registry.modelcontextprotocol.io/v0/servers?limit=100`
(675 pages, 0.2s inter-request spacing, 356s wall-time).

This is the reference point every later coverage claim is measured against. If a WP2 bootstrap
crawl returns materially fewer servers, suspect the crawler before suspecting the registry.

## Population

| Measure | Value |
|---|---|
| Unique servers | 20,453 |
| Total version rows | 67,425 |
| Mean versions per server | 3.30 |
| Servers with >1 version | 8,294 (40.6%) |
| Version transitions already available | ~46,970 |
| Latest-version servers with `remotes` | 10,345 (50.6%) |
| Latest-version servers with `packages` | 10,826 (52.9%) |
| Non-active (withdrawn/deleted) | 233 |

## Versions-per-server distribution

| Versions | Servers |
|---|---|
| 1 | 12,159 |
| 2 | 3,400 |
| 3 | 1,468 |
| 4 | 800 |
| 5 | 490 |
| 6 | 363 |
| 7 | 268 |
| 8 | 203 |
| 9 | 167 |
| 10 | 130 |
| 11+ | (tail) |

## Context

Published MCP censuses this project positions against covered **1,899 servers** (academic tool-poisoning
study, ~5.5% finding rate) and **1,808 servers** (AgentSeal scan, 66% with some security finding).
This population is roughly **11x larger** than either.

## Transport split

`remotes` and `packages` are not mutually exclusive — 50.6% + 52.9% exceeds 100% because some
servers declare both. Remote transports observed: `streamable-http` (dominant) and `sse`.
Package registry types observed: `npm` (dominant), `pypi`, `oci`.

## Verified API behaviour

- `GET /v0/servers?limit=100&cursor=<c>` — cursor pagination, `metadata.nextCursor`
- `GET /v0/servers?updated_since=<ISO8601>` — incremental delta; implies `include_deleted=true`
- `GET /v0/servers/{urlencoded-name}/versions` — full per-server version history
- Registry metadata under `_meta["io.modelcontextprotocol.registry/official"]`:
  `status`, `publishedAt`, `updatedAt`, `isLatest`
- No `robots.txt` at root; no rate-limit headers exposed. `X-Registry-Cache` header present.
- Unauthenticated MCP `initialize` + `tools/list` over `streamable-http` returns complete tool
  manifests (names, descriptions, full JSON Schemas). Confirmed against `mcp.goji.agency` (9 tools)
  and `api.inference.sh` (25 tools) with `protocolVersion: 2025-06-18`.
- Registry `version` and live `serverInfo.version` diverge in practice — `mcp.goji.agency` is
  published at registry version `1.0.0` while its live server reports `0.1.0`.

## Reproduction

Probe scripts used for this measurement are in the session scratchpad (`count.py`, `probe.py`).
Re-derive rather than trusting these numbers indefinitely — the registry grows continuously, and
this snapshot ages.
