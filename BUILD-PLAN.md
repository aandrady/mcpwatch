# MCPWatch — Build Plan

Decomposition of `plan-09-mcp-mutation-observatory.md` into buildable work packages.
Companion file: `PROMPTS.md` (copy-pasteable prompt per package).

---

## 0. Feasibility findings that change the plan

I probed the live ecosystem before decomposing. Five findings materially affect sequencing:

**F1 — Unauthenticated `tools/list` works.** I ran a full MCP handshake (`initialize` → `tools/list`) against two registry-listed remote servers. Both returned complete tool manifests — names, descriptions, full JSON Schemas — with no credentials. Component A's core data is directly collectable today.

**F2 — The registry is already versioned, and the history is retrospective.** `GET /v0/servers/{name}/versions` returns every published version with `publishedAt` timestamps. Example (`ac.inference.sh/mcp`): 4 versions spanning 2026-04-13 → 2026-07-27. **A large mutation history already exists and can be backfilled on day one** — see F3 for the scale, which is the single most consequential number in this document.

**F3 — The population is an order of magnitude larger than any published census.** I completed a full pagination of the registry (675 pages, 356 seconds):

| Measure | Value |
|---|---|
| Unique servers | **20,453** |
| Total version rows | **67,425** |
| Mean versions per server | 3.30 |
| Servers with >1 version | **8,294** (40.6%) |
| **Already-existing version transitions** | **~46,970** |
| Latest-version servers with remote endpoints | 10,345 (50.6%) |
| Latest-version servers shipping as packages | 10,826 (52.9%) |
| Non-active (withdrawn/deleted) | 233 |

Versions-per-server distribution: 12,159 servers have exactly 1 version, 3,400 have 2, 1,468 have 3, 800 have 4, tailing to 130 servers with 10+.

> **Correction (2026-08-11, from the WP5 backfill).** The head of that distribution held up; the tail figure did not. Measured over the full backfilled corpus (21,666 servers, 71,706 versions): 12,794 have 1 version, 3,596 have 2, 1,650 have 3, 856 have 4, 1,553 have 5–9, and **1,217 have 10 or more** — nearly ten times the "130" above. The census's own totals already implied this and the tail statement contradicted them: 67,425 versions minus the ~26,563 held by servers with 1–4 versions leaves ~40,862 versions spread over ~2,626 servers, which cannot happen with only 130 servers above 10. The mean (3.30 then, 3.31 now) was never wrong. Population growth accounts for the rest: ~600 new servers/day since the day-zero census.

Two consequences worth stating plainly:

1. **The published censuses this plan positions against covered 1,899 and 1,808 servers.** This observatory's population is ~11x larger. Coverage alone is a defensible contribution.
2. **~46,970 version transitions already exist and are backfillable in week 1.** The plan's stated minimum publishable result — "three months of mutation data with classification" — is exceeded on day one for Layer 1, before the observation window even starts.

**F4 — Registry version ≠ server-reported version.** `mcp.goji.agency` is published at registry version `1.0.0` but its live `serverInfo` reports `0.1.0`. The plan lists this divergence as a confound to control for; it is observable immediately and is itself a publishable finding.

**F5 — The API supports polite incremental crawling.** `updated_since` lets daily runs fetch only deltas instead of re-paginating thousands of rows. No `robots.txt` at the root and no rate-limit headers exposed — so set conservative self-imposed limits.

### The consequence: a two-layer data model

| | Layer 1 — Registry metadata | Layer 2 — Live tool manifests |
|---|---|---|
| Content | name, description, repo, remotes, packages, version | tool names, descriptions, JSON schemas, annotations |
| Retrospective? | **Yes** — full history via `/versions` | **No** — only forward from first crawl |
| Detects | server-level mutation, repo/endpoint swaps, republish patterns | **tool poisoning, instruction injection, scope expansion** |
| Available | **~46,970 transitions, backfillable week 1** | Accrues from day one onward |

This is the single biggest improvement over the plan as written. The plan assumes a 4–6 month wait before any result exists. In fact **Layer 1 yields ~47,000 real mutation transitions in week 1**, which means:

1. You get a publishable retrospective result in weeks, not months — de-risking the whole project. If the observation window produces nothing, you still have a paper.
2. **The diff engine and classifier can be built and calibrated against tens of thousands of real historical mutations** rather than synthetic ones. By the time Layer 2 matures, the pipeline is already validated on ground truth. This replaces the plan's Phase 1 gate ("diffs reliably detected on *synthetic* mutations") with something far stronger.
3. Layer 2 remains the irreplaceable moat — tool-level poisoning is invisible at Layer 1, and every day not crawling is lost permanently.

Both layers still start on day one. Layer 1 just pays off immediately as well.

### The corollary: scale now constrains the design

At 20,453 servers the naive "crawl everything daily" framing does not survive contact:

| Operation | Volume | Verdict |
|---|---|---|
| Registry full crawl (WP2) | 675 pages, ~6 min | Fine daily; use `updated_since` for deltas |
| Backfill `/versions` (WP5) | 20,453 requests | Hours, one-time. Must checkpoint and resume |
| Live manifest probe (WP3) | 10,345 servers × 2 probes = **20,690 handshakes/day** | Feasible but needs real concurrency engineering |
| Package sandbox (WP8) | 10,826 servers × container build+run | **Infeasible at full coverage. Must be sampled** |

WP3's double-probe nondeterminism guard doubles the daily third-party request load — that is a deliberate trade of volume for data integrity, and it is worth it (see §3), but it must be budgeted for rather than discovered late. WP8 requires a documented stratified sampling frame, not best-effort coverage.

---

## 1. Infrastructure — RESOLVED (2026-08-07)

Both blocking decisions are settled. The production host is provisioned and verified.

**Host:** a dedicated Linux VPS, reachable from a dev session as `ssh mcpwatch` via the local
`~/.ssh/config` alias (ed25519 key, no passphrase, non-interactive).

| Property | Value |
|---|---|
| OS / kernel | Ubuntu 24.04.4 LTS, 6.8.0-137 |
| Resources | 4 vCPU · 7.6 GB RAM · 53 GB free of 75 GB |
| Clock | UTC, NTP-synchronized (matters for a daily time series) |
| Registry latency | HTTP 200 in ~0.42s from the VPS |
| Durability | Confirmed permanent box; ~2.5 months uptime between reboots |
| Project root | `~/code/mcpwatch/` (`corpus/blobs/`, `logs/`) |

**Key constraint: `sudo` requires a password, so no `apt install` from an agent session.** This turns out not to matter — everything needed is already present or installs to userspace:

- **Docker 29.4.3** installed and usable without sudo → WP8/WP9 unblocked
- **systemd *user* units** running with `Linger=yes` → daily timers survive logout and reboot, no sudo
- **uv 0.12.2** installed to `~/.local/bin` (already on PATH)
- **Python 3.12.3** with built-in `sqlite3` 3.45.1 → the missing `sqlite3` CLI is irrelevant
- git 2.43, node 18.19.1, tmux present

**Verified end-to-end from the VPS** (`~/code/mcpwatch/smoke_test.py`): registry pagination (100 servers / 0.73s), the `/versions` history endpoint, and a live MCP `initialize` + `tools/list` handshake enumerating 9 tools. Both data layers are collectable from this host today.

**Note for WP4:** the box is shared with other workloads. Isolate MCPWatch under its own directory and user-level systemd units, and keep resource caps modest so a runaway crawl cannot disrupt co-tenants. Backup remains in scope for WP4 as planned rather than as an emergency.

**Operational note:** SSH has brute-force protection. Rapid repeated auth failures will ban the connecting IP. Do not loop over candidate usernames — connect once, read the error.

---

## 2. Work packages

Ten packages in four waves. Wave 1 is the critical path — nothing else matters until data is flowing.

### Wave 1 — Get data flowing (week 1; do not defer any of this)

| # | Package | Deliverable | Gate |
|---|---|---|---|
| **1** | **Storage core & schema** | Content-addressed blob store + SQLite index; canonical JSON normalization | Same input → same hash; unchanged snapshot costs 0 new bytes |
| **2** | **Registry collector (Layer 1)** | Daily incremental crawl of `/v0/servers` | 3 consecutive clean daily runs; >95% of registry captured |
| **3** | **Live manifest prober (Layer 2)** | MCP `initialize`+`tools/list` against 10,345 remote servers | >90% reachable; **double-probe yields identical hash**; full cycle completes inside 24h |
| **4** | **Scheduling & health monitoring** | systemd timers, run-health table, alert on gap/coverage drop | Missed run alerts within 24h |

Package 3's gate is the one people get wrong — see §3.

### Wave 2 — Analysis pipeline, built on backfilled data (weeks 2–4)

| # | Package | Deliverable | Gate |
|---|---|---|---|
| **5** | **Retrospective backfill** — **[DONE 2026-08-11]** | 71,706 versions across 21,666 servers → **50,040 transitions** | Met: 8,872 multi-version servers, all chains verified against `/versions` |
| **6** | **Diff engine & identity model** | Semantic diffs; mutated vs. replaced vs. disappeared | Correct on hand-built fixture set + real backfilled diffs |
| **7** | **Mutation classifier & adjudication** | Rules + LLM + human adjudication UI; taxonomy from plan §B | **κ > 0.75 on 200 adjudicated diffs** |

### Wave 3 — The technical novelty (weeks 4–12, runs *during* the observation window)

| # | Package | Deliverable | Gate |
|---|---|---|---|
| **8** | **Package-server sandbox enumeration** | Docker harness + **stratified sample** of the 10,826 package servers | Documented sampling frame; no egress escapes sinkhole |
| **9** | **Description-behavior divergence** | Instrumented execution; declared vs. observed capability diff | Instrumentation validated on known-behavior servers |

### Wave 4 — Outputs (after ≥3 months of observation)

| # | Package | Deliverable | Gate |
|---|---|---|---|
| **10** | **Pinning retrospective, dashboard, dataset release** | Caught/friction ratio; public dashboard; versioned dataset | Reproducible from corpus |

---

## 3. The failure mode most likely to ruin the dataset

**Nondeterministic manifests producing phantom mutations.** If a server returns tools in random order, embeds a session ID or timestamp in a description, or load-balances across slightly divergent instances, a naive hash flags a mutation every single day. That poisons the base-rate number — the headline result of the entire project — and it poisons it *silently*.

Mitigations, all in Package 1/3:
- Canonical normalization before hashing: sort tools by name, sort schema keys recursively, strip known-volatile fields.
- **Double-probe validation**: probe every server twice in the same run; any server whose two hashes differ is flagged nondeterministic and quarantined from mutation statistics. Track that population as its own reported metric.
- Always store the raw blob alongside the normalized hash, so normalization decisions can be revised retroactively without losing data.

Second-order risk: **false-negative on identity.** A server that changes its registry `name` looks like a disappearance plus a new server, hiding a mutation. Track repo URL and endpoint URL as secondary identity keys and reconcile.

---

## 4. Sequencing summary

```
Week 1    ├─ [DONE] VPS provisioned & verified — ssh mcpwatch
          ├─ WP1 storage → WP2 registry collector → WP4 scheduling   [LIVE]
          └─ WP3 live prober                                         [LIVE]
Week 2    ├─ WP5 backfill (instant historical corpus)                [DONE 2026-08-11]
Weeks 2-4 ├─ WP6 diff engine   ─┐ built and calibrated against
          └─ WP7 classifier    ─┘ real backfilled mutations
Weeks 4-12├─ WP8 sandbox → WP9 divergence harness
          └─ (observation window running continuously)
Month 4+  └─ WP10 pinning retrospective, dashboard, release
```

**Minimum publishable result** shifts earlier than the plan assumed: Layer 1 retrospective analysis is a genuine first-of-its-kind measurement available in weeks. Layer 2 tool-level data remains the headline contribution at month 4+.

---

## 5. Ethics guardrails (bake into WP2/WP3 from the first commit, not later)

- Identifying User-Agent with a contact address on every request.
- Conservative rate limits and backoff; treat 429/5xx as stop signals.
- Read-only protocol methods only — `initialize`, `tools/list`, `resources/list`, `prompts/list`. **Never call a tool.**
- Never supply credentials; skip servers requiring auth and record them as a separate population.
- WP8/WP9 execute only in a sandbox with sinkholed egress, no real credentials, no third-party data.
- Confirmed-malicious findings: registry operator and maintainer first, 90-day window, no name-and-shame on ambiguous cases.
