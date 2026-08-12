# MCPWatch — Layer-1 retrospective

Generated 2026-08-12T02:03:07.532699+00:00 from the corpus. No network access; re-runnable.

## Population

| Measure | Value |
|---|---:|
| Servers tracked | 21,701 |
| Servers with backfilled history | 21,701 |
| Servers with more than one version | 8,888 |
| Published versions | 71,850 |
| Version transitions | 50,256 |
| ...of which changed nothing observable | 107 |
| ...of which were in-place restatements | 107 |
| Servers withdrawn from the registry | 495 |

An in-place restatement is a record edited without a new version number —
a change no consumer pinning a version would ever see.

"Changed nothing observable" means nothing moved in the `server` record —
the registry's own `_meta` may still have moved, and a status flip is exactly
that. `_meta` is excluded from the field counts below because its timestamps
move on every republish by construction; status changes are reported
separately. Expect these two rows to track each other closely: a transition
that leaves the published record identical is, in practice, a record edited
in place rather than a genuinely new version.

## Versions per server

| Versions | Servers |
|---|---:|
| 1 | 12,813 |
| 2 | 3,597 |
| 3 | 1,658 |
| 4 | 856 |
| 5-9 | 1,555 |
| 10+ | 1,222 |

Busiest publishers:

- `io.github.brilliantdirectories/brilliant-directories-mcp` — 1,156 versions
- `ai.bowmark/bowmark` — 631 versions
- `com.linkbreakers/mcp` — 387 versions
- `io.github.devantler-tech/ksail` — 360 versions
- `io.github.kivanccakmak/yaver` — 288 versions
- `io.github.KevinRabun/judges` — 258 versions
- `io.github.avabuildsdata/mcp-us-business-data` — 252 versions
- `com.local-mcp/local-mcp` — 235 versions
- `io.github.havilandsoftware/mcp-server-innoday` — 234 versions
- `io.github.appium/appium-mcp` — 229 versions

## Time between versions

| Quantile | Days |
|---|---:|
| min | 0.00 |
| p10 | 0.01 |
| p25 | 0.04 |
| median | 0.55 |
| p75 | 3.52 |
| p90 | 14.32 |
| max | 319.76 |
| mean | 5.73 |

| Gap | Transitions |
|---|---:|
| under 1h | 12,338 |
| 1h-1d | 17,282 |
| 1-7d | 12,044 |
| 7-30d | 6,149 |
| 30-90d | 1,901 |
| 90-365d | 435 |
| over a year | 0 |

## What changes between versions

Fields of the registry record that differ across a transition, counted
over normalized documents so key order and volatile fields are already gone.

| Field | Transitions changing it | Share |
|---|---:|---:|
| `version` | 50,149 | 99.8% |
| `packages` | 39,840 | 79.3% |
| `description` | 5,843 | 11.6% |
| `remotes` | 1,820 | 3.6% |
| `repository` | 1,490 | 3.0% |
| `title` | 1,302 | 2.6% |
| `websiteUrl` | 1,067 | 2.1% |
| `_meta` * | 574 | 1.1% |
| `icons` * | 563 | 1.1% |
| `$schema` | 471 | 0.9% |

`*` marks a field this report did not anticipate — worth a look.

Registry status transitions:

- `active -> deleted` — 45
- `active -> deprecated` — 5
- `deleted -> active` — 129
- `deleted -> deprecated` — 5
- `deprecated -> active` — 88
- `deprecated -> deleted` — 4

## Endpoint and repository swaps

The highest-priority subset for WP7. A server keeping its name while
changing where its code or its traffic goes is the shape of a rug pull,
and it is the one change class visible at Layer 1 without tool-level data.

| Swap | Transitions | Servers |
|---|---:|---:|
| Remote endpoint set changed | 1,467 | 993 |
| Repository URL changed | 1,238 | 1,096 |
| Package identity changed | 6,411 | 1,034 |

First 10 endpoint swaps:

- `ac.inference.sh/mcp` 2.0.0 → 2.0.1 after 6.7d
- `ai.adramp/google-ads` 1.0.0 → 1.0.1 after 0.0d
- `ai.agentdm/agentdm` 1.0.0 → 2.0.0 after 49.9d
- `ai.backengine/backengine-mcp` 8.0.3 → 8.0.4 after 0.0d
- `ai.backengine/backengine-mcp` 8.0.4 → 8.1.1 after 9.7d
- `ai.biddeed/biddeed-mcp` 1.0.0 → 1.0.1 after 0.0d
- `ai.bowmark/bowmark` 1.1.0 → 1.2.0 after 1.3d
- `ai.bowmark/bowmark` 5.2.1 → 5.3.1 after 0.1d
- `ai.ccapi/mcp` 1.0.0 → 1.0.1 after 0.0d
- `ai.complyhat/compliance` 1.5.0 → 2.0.0 after 52.1d

First 10 repository swaps:

- `ai.adramp/google-ads` 1.0.1 → 1.0.2 after 0.0d
- `ai.agentdm/agentdm` 1.0.0 → 2.0.0 after 49.9d
- `ai.analyticslegends/sap-analytics` 1.0.2 → 1.0.3 after 0.4d
- `ai.auteng/mcp` 1.0.0 → 1.0.1 after 0.0d
- `ai.auxen/auxen` 1.0.0 → 1.0.1 after 2.4d
- `ai.bloopo/bloopo` 0.1.0 → 0.1.1 after 14.3d
- `ai.borealhost/mcp` 0.1.1 → 0.1.2 after 0.1d
- `ai.bourdon/bourdon` 0.12.4 → 0.12.5 after 12.8d
- `ai.bowmark/bowmark` 3.22.1 → 3.22.2 after 3.1d
- `ai.canaryusers/canaryusers` 1.2.0 → 1.2.1 after 0.4d

