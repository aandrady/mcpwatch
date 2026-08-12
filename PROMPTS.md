# MCPWatch — Work Package Prompts

Each prompt is self-contained: paste into a fresh Claude Code session in `C:\Users\andra\Claude\Projects\MCPWatch`.
Read `BUILD-PLAN.md` first for context. Packages 1–4 are the critical path; run them this week.

Shared context to keep in mind across all packages:

> **Project:** MCPWatch, a longitudinal observatory measuring how MCP server tool definitions mutate after publication — the "rug pull" threat, which has a named taxonomy slot but zero published field data. We are **not** building a scanner (MCP-Scan, MCP-Scanner already exist) and not running a one-shot census. The contribution is *time*: an append-only corpus nobody else is collecting.
>
> **Two data layers:** Layer 1 = registry metadata (retrospective history available via `/v0/servers/{name}/versions`). Layer 2 = live tool manifests via MCP `tools/list` (only obtainable going forward — this is the irreplaceable asset).
>
> **Verified scale (full pagination, 675 pages):** 20,453 unique servers · 67,425 version rows · 8,294 servers with >1 version · ~46,970 already-existing version transitions · 10,345 servers with remote endpoints · 10,826 shipping as packages · 233 withdrawn. This is ~11x larger than any published MCP census.
>
> **Environment — authoring is local, production is the VPS.** Write code in this directory with normal file tools; deploy and run on the VPS. `ssh mcpwatch` (alias in the local `~/.ssh/config`), key auth, non-interactive, remote root `~/code/mcpwatch/`. VPS has Ubuntu 24.04.4, 4 vCPU / 7.6 GB / 53 GB free, Python 3.12.3, uv 0.12.2, Docker 29.4.3 (usable without sudo), systemd **user** units with `Linger=yes`. **`sudo` needs a password, so no `apt install`.** SSH has brute-force protection — connect once and read the error, never loop usernames. See `CLAUDE.md` and `BUILD-PLAN.md` §1.

---

## WP1 — Storage core & schema

```
Build the storage foundation for MCPWatch, a longitudinal observatory that snapshots MCP server
definitions daily and detects mutations over time. Read BUILD-PLAN.md for full context.

This package is pure foundation — every other component appends to it, so correctness here
matters more than features.

BUILD:
A Python package `mcpwatch.store` providing a content-addressed blob store plus a SQLite index.

1. Blob store (content-addressed):
   - sha256 of the canonicalized bytes, stored gzipped at blobs/<aa>/<bb>/<full-sha>.json.gz
   - Writing an identical blob is a no-op. This is the critical property: on a typical day most
     servers will not have changed, and unchanged snapshots must cost zero additional bytes.

2. Canonical JSON normalization (`mcpwatch.store.canonical`) — get this exactly right, the entire
   mutation-detection result depends on hash stability:
   - Recursively sort object keys; compact separators; UTF-8; ensure_ascii=False
   - Sort arrays whose order is semantically meaningless: `tools` by name, `resources` by uri,
     `prompts` by name, JSON Schema `required` arrays
   - Strip a configurable volatile-field denylist (session ids, timestamps, nonces, request ids)
   - Normalization must be VERSIONED (`norm_version` int). Store raw blobs always, so a later
     normalization change can be replayed retroactively without data loss.

3. SQLite index (WAL mode) with tables:
   - `run`      (run_id, collector, collector_version, started_at, finished_at, stats_json)
   - `server`   (server_key PK, registry_name, repo_url, primary_endpoint, first_seen, last_seen)
   - `observation` (obs_id, run_id, server_key, layer, observed_at, status, raw_sha,
                    norm_sha, norm_version, error_class, error_detail)
     where layer ∈ {registry, manifest} and status ∈ {ok, unreachable, auth_required,
     protocol_error, timeout, nondeterministic, skipped}
   - Index observation on (server_key, observed_at) and (norm_sha).
   - APPEND-ONLY: no UPDATE or DELETE on `observation`. Enforce with a SQLite trigger.

4. `server_key` identity: primary = registry `name` (reverse-DNS namespaced, e.g.
   "ac.inference.sh/mcp"). Also persist repo_url and endpoint as secondary identity keys —
   WP6 needs them to distinguish "mutated" from "replaced" from "renamed".

REQUIREMENTS:
- uv-managed project, pyproject.toml, Python 3.14, ruff + pytest configured
- Zero heavy dependencies in the storage layer (stdlib sqlite3, hashlib, gzip, json)
- Typed (mypy-clean), with docstrings on public API

ACCEPTANCE:
- pytest suite proving: identical input → identical norm_sha; key reordering → identical norm_sha;
  tool-array reordering → identical norm_sha; a real description change → different norm_sha;
  writing the same blob twice adds zero bytes; the append-only trigger rejects UPDATE and DELETE
- A property test: random key/array shuffles of the same document always hash identically

NON-GOALS: no crawling, no HTTP, no diffing, no analysis. Storage only.
```

---

## WP2 — Registry collector (Layer 1)

```
Build the MCPWatch registry collector. Read BUILD-PLAN.md; WP1 (mcpwatch.store) is complete.

GOAL: a daily incremental crawl of the official MCP registry, appending one observation per
server per run. This must be running in production before anything else is built — every day of
delay is unrecoverable data.

API FACTS (verified by probe, do not re-derive):
- Base: https://registry.modelcontextprotocol.io
- GET /v0/servers?limit=100&cursor=<c>  → {"servers":[{server:{...},_meta:{...}}],
                                           "metadata":{"nextCursor":...,"count":N}}
- GET /v0/servers?updated_since=<ISO8601>  → incremental delta (implies deleted servers included)
- Registry _meta lives under _meta["io.modelcontextprotocol.registry/official"] and carries
  status, publishedAt, updatedAt, isLatest
- Server records contain: name, description, version, title?, repository?, websiteUrl?,
  remotes? (type ∈ streamable-http|sse, url), packages? (registryType ∈ npm|pypi|oci), icons?
- VERIFIED SCALE: 20,453 unique servers, 67,425 version rows. A full pagination is 675 pages and
  takes ~356s at 0.2s spacing. 10,345 latest-version servers have remotes, 10,826 have packages,
  233 are non-active.
- No robots.txt at root, no rate-limit headers exposed — impose your own conservative limits

BUILD `mcpwatch.collect.registry`:
1. Full crawl mode (bootstrap + weekly reconciliation) and incremental mode (`updated_since`,
   watermarked from the last successful run) — default daily path is incremental.
2. Store the complete raw record per server as a Layer-1 observation via mcpwatch.store.
3. Upsert `server` rows; maintain first_seen/last_seen; record disappearance explicitly
   (a server absent from a full crawl gets a `skipped`/absent observation, never a silent gap).
4. Record run stats: servers seen, new, changed-hash, absent, errors by class.

POLITENESS AND ETHICS — non-negotiable, in the first commit:
- User-Agent: "MCPWatch/0.1 (+<contact-url-or-email>) longitudinal MCP security research"
- Max ~2 req/sec, 250ms inter-request sleep, exponential backoff on 429/5xx, hard stop after
  repeated 429s
- Full crawl resumable from cursor; never restart a multi-thousand-page crawl from scratch on
  transient failure

ACCEPTANCE:
- Bootstrap full crawl completes and captures >95% of the registry — the day-zero baseline is
  20,453 unique servers / 67,425 version rows (see census-baseline.md); a materially lower count
  means the crawl is broken, not that the registry shrank
- Three consecutive incremental runs complete cleanly with no unhandled exceptions
- Second run on unchanged data creates observations but zero new blobs (proves WP1 dedup)
- Crawl is interruptible and resumes correctly from cursor

NON-GOALS: no live server probing (that is WP3), no diffing, no classification.
```

---

## WP3 — Live tool-manifest prober (Layer 2)

```
Build the MCPWatch live manifest prober. Read BUILD-PLAN.md; WP1 and WP2 are complete.

This collects the irreplaceable data: actual tool manifests from running MCP servers. Layer 1
(registry metadata) has retrospective history; Layer 2 does NOT — it only accrues forward from
the first successful probe. Ship it this week.

VERIFIED FEASIBILITY (probe already done, do not re-derive):
- Unauthenticated `initialize` + `tools/list` over streamable-http returns full manifests:
  tool names, descriptions, complete JSON Schemas. Confirmed against mcp.goji.agency (9 tools)
  and api.inference.sh (25 tools).
- Handshake: POST JSON-RPC 2.0, headers Content-Type: application/json and
  Accept: application/json, text/event-stream. Response may be plain JSON or SSE (`data:` lines) —
  handle both. Capture Mcp-Session-Id from the initialize response and echo it on subsequent calls.
- protocolVersion "2025-06-18" works.
- Registry `version` and live `serverInfo.version` DIVERGE in practice (goji: registry 1.0.0 vs
  serverInfo 0.1.0). Record both; the divergence is itself a finding.

SCALE — this drives the architecture, do not treat it as an afterthought:
10,345 registry servers expose remote endpoints. With the mandatory double-probe below that is
~20,690 MCP handshakes per day against third-party hosts, each 2+ HTTP round trips. A naive
sequential loop at 20s timeout cannot finish in 24h. You need bounded concurrency (asyncio,
global cap ~50, strict per-host serialization), and the full cycle must complete well inside a
24h window with headroom. Measure and report cycle wall-time as a health metric — if it creeps
toward 24h the time series will start eating itself.

BUILD `mcpwatch.collect.manifest`:
1. Target set: all latest-version servers with a `remotes` entry (streamable-http or sse) — 10,345
   servers as of the initial census.
2. Per server: initialize → tools/list → resources/list → prompts/list. Store the combined
   manifest as one Layer-2 observation. Record serverInfo and negotiated protocolVersion.
3. READ-ONLY PROTOCOL METHODS ONLY. Never call `tools/call`. Never supply credentials. A server
   demanding auth is recorded status=auth_required and skipped — it becomes a reported
   population-coverage limitation, not an obstacle to work around.
4. Failure taxonomy mapped to the WP1 status enum: unreachable, timeout, auth_required,
   protocol_error, tls_error. Errors are DATA — crawl reliability is a reported metric.
5. Concurrency with a global cap and strict per-host serialization; 20s timeout; no retry storms.

CRITICAL — nondeterminism guard (this is the failure mode most likely to silently ruin the
dataset; see BUILD-PLAN.md §3):
- Probe every server TWICE per run, spaced apart.
- If the two normalized hashes differ, mark status=nondeterministic and quarantine that server
  from mutation statistics. Track the nondeterministic population as its own reported metric.
- Without this, servers that randomize tool order or embed session ids in descriptions will
  register a phantom mutation every single day and destroy the headline base-rate number.

Same politeness/UA/backoff rules as WP2.

ACCEPTANCE:
- >90% of remote-endpoint servers reachable on a run, with the remainder classified by error type
- A full 10,345-server cycle completes in well under 24h; wall-time recorded per run
- Double-probe agreement: report the nondeterministic rate; investigate and fix any case caused by
  our own normalization rather than the server
- Re-running against an unchanged server produces zero new blobs
- Unit tests parse both plain-JSON and SSE response framing

NON-GOALS: no package/stdio servers (that is WP8), no tool execution ever, no diffing.
```

---

## WP4 — Scheduling & health monitoring

```
Make MCPWatch's collectors run unattended and prove they ran. Read BUILD-PLAN.md.
WP1–WP3 are complete.

The project's entire value is an unbroken daily time series. A silent collector failure that goes
unnoticed for two weeks is the worst realistic outcome, so detection matters more than automation.

BUILD:
1. A single CLI entrypoint: `mcpwatch run --collector registry|manifest|all`
   Exit codes distinguishing clean / partial / failed runs.
2. Deployment for a Linux VPS: systemd service + timer units, staggered so registry runs before
   manifest. Include a README with exact provisioning steps from a bare Ubuntu box (uv install,
   clone, systemd enable, log rotation, backup).
3. Health monitoring:
   - `mcpwatch health` reporting: last successful run per collector, hours since, coverage %
     (servers observed / servers known), error-class breakdown, nondeterministic-server count,
     blob-store size and growth rate
   - Alert conditions: no successful run in 36h; coverage drop >10% run-over-run; error rate
     >20%; blob growth anomaly (a sudden spike usually means normalization broke, not that the
     ecosystem changed)
   - Alerting via a pluggable sink; start with a simple webhook plus non-zero exit for cron mail
4. Backup: nightly SQLite `.backup` plus offsite sync of blobs. The corpus is the deliverable and
   it is not reconstructible — treat backup as part of this package, not a later chore.

ACCEPTANCE:
- Timers fire on schedule on the VPS; three consecutive unattended daily cycles complete
- Killing a run mid-flight is detected by `mcpwatch health` and alerts within one cycle
- Restore-from-backup rehearsal succeeds into a clean directory

NON-GOALS: no dashboard (WP10), no analysis.
```

---

## WP5 — Retrospective backfill

```
Backfill MCPWatch's historical corpus from the registry's own version history.
Read BUILD-PLAN.md. WP1–WP4 are complete and collecting daily.

WHY THIS IS THE HIGHEST-VALUE PACKAGE IN THE PROJECT: the registry retains every published
version with timestamps, so a large mutation corpus ALREADY EXISTS for Layer 1 — no waiting.
Verified by full census:
  - 20,453 unique servers, 67,425 version rows, mean 3.30 versions/server
  - 8,294 servers (40.6%) have more than one version
  - ~46,970 version transitions are sitting there right now, backfillable this week
  - Distribution: 12,159 servers at 1 version, 3,400 at 2, 1,468 at 3, 800 at 4, tail to 130 at 10+
  - GET /v0/servers/{name}/versions returns all versions with publishedAt/isLatest
This exceeds the plan's stated minimum publishable result ("three months of mutation data with
classification") on day one, and gives WP6/WP7 tens of thousands of real historical mutations to
calibrate against instead of synthetic fixtures.

BUILD `mcpwatch.collect.backfill`:
1. For every known server, fetch /v0/servers/{urlencoded-name}/versions and store each historical
   version as a Layer-1 observation stamped with its true publishedAt (NOT the crawl time).
   The observation schema must clearly distinguish observation time from publication time.
2. Reconcile with already-collected data — backfill must be idempotent and must not duplicate
   observations already captured by WP2.
3. Handle deleted/inactive servers (`?include_deleted=true` semantics) — a server that was
   published and then withdrawn is a signal worth keeping, not noise to drop.
4. Same politeness rules as WP2. This is 20,453 individual requests — at polite spacing expect
   1–3 hours minimum. Make it checkpointed and resumable at the per-server level; a failure at
   server 18,000 must not restart from zero. Run it as a background job, not interactively.
   Optimization: 12,159 servers have exactly one version and their `/versions` response is
   already implied by the WP2 crawl — deprioritize or skip them and spend the request budget on
   the 8,294 multi-version servers that actually carry mutation signal.

ANALYSIS OUTPUT (a short report, this is a real interim result):
- Distribution of versions per server; servers with >1 version
- Time-between-versions distribution
- Which registry fields change across versions (description? remotes? repository? packages?)
- Servers whose repository URL or remote endpoint changed between versions — endpoint swaps are
  a direct rug-pull-adjacent signal and the highest-priority subset for WP7

ACCEPTANCE:
- All 8,294 multi-version servers have complete, gap-free version chains
- Total stored transitions is within a few percent of the expected ~46,970
- Re-running the backfill produces zero new observations (idempotent)
- The interim report runs off the corpus reproducibly

NON-GOALS: no classification yet (WP7); no Layer-2 history (it does not exist and cannot be
manufactured — do not attempt to infer it).
```

---

## WP6 — Diff engine & identity model

```
Build MCPWatch's diff engine. Read BUILD-PLAN.md. WP1–WP5 complete; a backfilled Layer-1
corpus with real historical mutations exists.

GOAL: turn consecutive observations into structured, classifiable change records.

BUILD `mcpwatch.diff`:
1. Change detection: for each server, walk observations in time order; a norm_sha change is a
   candidate mutation. Exclude servers quarantined as nondeterministic by WP3.
2. Semantic diff producing a typed ChangeSet, NOT a text diff. At minimum:
   - Tool level: tool_added, tool_removed, tool_renamed, description_changed,
     schema_param_added, schema_param_removed, param_type_changed, param_became_required,
     annotation_changed (readOnlyHint/destructiveHint/openWorldHint especially)
   - Server level: description_changed, endpoint_changed, repository_changed, package_changed,
     version_bumped, auth_requirement_changed
   - For text changes, carry both before/after plus a token-level diff so WP7 can classify
     without re-reading blobs.
3. IDENTITY RESOLUTION — the confound that produces wrong numbers:
   - Distinguish MUTATED (same identity, changed content) from REPLACED (same name, different
     repo/endpoint — highly suspicious) from RENAMED (different name, same repo+tool fingerprint)
     from DISAPPEARED from NEW.
   - Primary key is registry name; reconcile against repo_url and endpoint. A rename that looks
     like disappearance+creation hides a real mutation, so match on tool-set fingerprint too.
4. Severity prefilter: cheap deterministic flags for WP7 triage — new network-capable parameter,
   new filesystem path parameter, imperative language appearing in a description, tool count
   growth, destructiveHint flipping to false.
5. `mcpwatch diff` CLI: emit ChangeSets over a date range as JSONL.

ACCEPTANCE:
- Fixture suite of hand-built before/after manifest pairs covering every change type
- Runs over the real backfilled corpus and produces a coherent ChangeSet stream; manually verify
  20 real diffs by eye against the raw blobs
- Identity resolution correctly handles a synthetic rename, a synthetic endpoint swap, and a
  synthetic disappearance-then-return

NON-GOALS: no benign/malicious judgement (WP7). This package describes changes; it does not
score them.
```

---

## WP7 — Mutation classifier & adjudication protocol

```
Build MCPWatch's mutation classifier. Read BUILD-PLAN.md. WP1–WP6 complete; ChangeSets over a
real backfilled corpus are available.

This produces the paper's headline numbers, so trustworthiness beats throughput. Every
security-relevant classification gets human adjudication.

TAXONOMY (from the plan; every ChangeSet gets exactly one primary label):
- benign — typos, formatting, genuine feature work consistent with stated purpose
- scope_expansion — new params/tools broadening capability beyond the original description
- instruction_injection — imperative text addressed to the model appearing in a description
- exfiltration_addition — new params or endpoints capable of moving context off-host
- authority_escalation — new claims of trust, priority, or override

BUILD:
1. Rule layer (`mcpwatch.classify.rules`) — high-precision deterministic detectors run first:
   imperative-to-model phrasing patterns, URL/webhook/callback parameters appearing, path or
   command parameters appearing, "ignore previous"/"do not tell"/"always call first" families,
   annotation downgrades. Rules must be precision-tuned; recall is the LLM's job.
2. LLM layer (`mcpwatch.classify.llm`) for everything rules do not settle:
   - **Load the `claude-api` skill before writing this.** Use a PINNED model id — classifier
     drift is an explicit confound and monthly re-adjudication of a fixed calibration set is
     required. Log the model id, prompt hash, and temperature on every classification.
   - Structured output with a confidence score and a required rationale citing specific diff
     text. Never let it classify from the whole blob — feed the ChangeSet.
   - Batch, cache by ChangeSet hash, and keep prompts versioned in-repo.
3. Adjudication tooling (`mcpwatch adjudicate`) — a minimal local review UI/CLI showing the diff,
   rule hits, LLM label and rationale; the human records an independent label. Design so two
   raters can work blind to each other's labels.
4. Reliability measurement: Cohen's κ between raters and between LLM and human consensus, over a
   fixed 200-item calibration set. Report per-class κ, not just overall — the interesting classes
   are rare and overall κ will hide poor performance on them.

ACCEPTANCE:
- κ > 0.75 on 200 adjudicated diffs (the plan's Phase 2 gate)
- Rule layer precision measured against adjudicated ground truth and reported
- Classifications are reproducible: same ChangeSet + same pinned model + same prompt version →
  same label, or the discrepancy is logged as drift
- A monthly re-adjudication job over the calibration set exists and is scheduled

NON-GOALS: no public accusations. Confirmed-malicious findings enter the WP10 disclosure
workflow — registry operator and maintainer first, 90-day window.
```

---

## WP8 — Package-server sandbox enumeration

```
Extend MCPWatch's Layer-2 coverage to package-distributed servers. Read BUILD-PLAN.md.
WP1–WP7 complete. Requires Docker — already installed on the VPS (29.4.3) and usable without
sudo. Run there, not on the Windows box.

WHY: 10,345 registry servers expose remote HTTP endpoints and are covered by WP3. A further
10,826 ship as npm / PyPI / OCI packages over stdio and are currently invisible to the
observatory — roughly half the ecosystem, and precisely the half where malicious code is easiest
to hide, since the code actually runs on the victim's machine.

SAMPLING IS MANDATORY — READ THIS BEFORE DESIGNING ANYTHING:
Building and running containers for 10,826 servers daily is not feasible on any budget this
project has. Do NOT attempt full coverage and do NOT let coverage degrade into "whatever
finished." Define an explicit, documented, reproducible stratified sampling frame FIRST, and
treat it as a research-design artifact that goes in the paper. Stratify on at least: registry
type (npm/pypi/oci), publication age, version count (multi-version servers carry the mutation
signal WP5/WP6 care about), and declared capability surface. Fix the sample, re-probe THE SAME
sample over time — a sample that drifts between runs cannot support longitudinal claims, which
is the entire point of the project. Record the sampling seed and frame in the corpus.

BUILD `mcpwatch.sandbox`:
1. Per-server ephemeral container: no host mounts, non-root, read-only rootfs where possible,
   dropped capabilities, memory/CPU/PID limits, hard wall-clock timeout.
2. NETWORK: default-deny egress routed to a sinkhole. The container may resolve and connect only
   to the package registry during install, then egress is cut before the server is launched.
   Record every attempted connection — attempted egress during mere tool enumeration is itself
   a finding.
3. Install the pinned package version (npm/pip/oci as declared in the registry record), launch
   over stdio, run initialize + tools/list + resources/list + prompts/list, capture the manifest,
   tear down. NEVER call a tool. NEVER inject credentials — supply obviously-fake placeholder env
   values only where a server refuses to start without them, and record that fact.
4. Store as Layer-2 observations, tagged transport=stdio, with the same double-probe
   nondeterminism guard as WP3.
5. Failure taxonomy: install_failed, launch_failed, timeout, requires_credentials, crashed.
   Report coverage honestly — this population will have materially lower success rates than
   remote servers, and that gap is a reportable result.

SAFETY — this package executes untrusted third-party code, so treat the sandbox as the deliverable:
- Verify egress containment with a deliberately-exfiltrating test server before running any real one
- Verify the container cannot reach host filesystem or Docker socket
- CRITICAL: the VPS is NOT disposable. It is a permanent box shared with other workloads that
  matter, and it holds the MCPWatch corpus, which is irreplaceable. You are executing
  untrusted third-party code on a machine that matters. Escalate containment accordingly: verify
  isolation before the first real package, never mount the host filesystem or Docker socket, cap
  CPU/memory/PIDs, and keep the corpus directory unreachable from any container. If stronger
  isolation is wanted, run a disposable throwaway VM for this package and ship only the resulting
  manifests back to the corpus.
- Only servers whose license and terms permit analysis

ACCEPTANCE:
- Containment tests pass FIRST, before any real package is run: a deliberately-exfiltrating test
  server's egress is captured and blocked, and it cannot escape the container or reach the host
  filesystem or Docker socket
- Tools enumerated for a hand-picked validation set of ~20 known-good package servers
- Sampling frame documented, seeded, and reproducible; the same sample is re-probed across runs
- Coverage and failure-class breakdown reported against the SAMPLE, with the sampling frame
  stated — never against the full 10,826 population

NON-GOALS: no behavioral analysis yet (WP9) — this package only enumerates manifests.
```

---

## WP9 — Description-behavior divergence harness

```
Build MCPWatch's description-behavior divergence harness — the project's method novelty.
Read BUILD-PLAN.md. WP8's sandbox is complete and containment-verified.

THESIS: every existing scanner reads the tool DESCRIPTION. Nobody systematically checks whether
the tool DOES what it says. That divergence is both a poisoning indicator and a rug-pull
indicator that survives description-level review — and it is publishable independently as a
method paper.

BUILD:
1. Declared-capability extraction: from each tool's description + JSON Schema, derive an expected
   capability profile — network egress (and to which hosts)? filesystem reads/writes (which
   paths)? subprocess execution? credential access? Use the pinned-model LLM approach from WP7,
   with a rules fallback and a human-validated sample.
2. Observed-capability instrumentation, extending the WP8 sandbox:
   - Network: mitmproxy sinkhole capturing every connection attempt, destination, TLS SNI, and
     payload shape
   - Syscalls: strace or falco capturing file opens, execve, socket calls
   - Filesystem: overlay diff of what was written
3. Exercise protocol — the hard design problem, think carefully before coding:
   Enumeration alone reveals little; behavior appears on invocation. Invoking tools means
   executing untrusted code with synthetic input. Constrain hard: synthetic non-sensitive
   arguments only, egress sinkholed, no real credentials, no third-party data, destructive-hint
   tools excluded, per-tool timeout. Document the protocol precisely — reviewers will scrutinize
   this, and the ethics section depends on it.
4. Divergence scoring: diff observed against declared, per tool. Classify as
   undeclared_network / undeclared_filesystem / undeclared_subprocess / undeclared_credential_access.
   Report a divergence RATE across the sample, with confidence intervals.

ACCEPTANCE:
- Instrumentation validated against purpose-built servers with KNOWN behavior — including a
  server that declares one thing and does another (proving the harness detects real divergence,
  which is the whole point)
- No egress escapes the sinkhole under any test
- Divergence rate reported with sample-size and selection-bias caveats stated plainly

NON-GOALS: do not scale to the full population — this is a sampled method contribution.
Scope to servers whose license and terms permit analysis.
```

---

## WP10 — Pinning retrospective, dashboard & dataset release

```
Produce MCPWatch's outputs. Read BUILD-PLAN.md. WP1–WP9 complete with >=3 months of Layer-2
observation and a backfilled Layer-1 corpus.

A. PINNING RETROSPECTIVE (the most actionable output — practitioners are making this design
   decision right now on the basis of a hypothetical):
   Replay the mutation corpus against a hypothetical content-hash pinning policy applied at
   approval time. Report:
   - Caught: how many security-relevant mutations pinning would have blocked
   - False friction: how many benign updates blocked per malicious one caught
   - Sensitivity: how the ratio shifts under variants (pin whole manifest vs. per-tool; allow
     description-only changes; allow additive-only schema changes)
   The friction ratio is the number that decides the debate. Report it prominently even if — 
   especially if — it is unflattering to pinning.

B. METRICS REPORT (plan §4):
   - Mutation rate: fraction of servers changing tool definitions per month
   - Security-relevant mutation rate by taxonomy class
   - Time-to-first-mutation distribution; dormancy analysis
   - Description-behavior divergence rate
   - Population coverage and crawl reliability, reported honestly including registry churn,
     nondeterministic-server exclusions, and the auth-required blind spot

C. PUBLIC DASHBOARD: static-site generation from the corpus, rebuilt on each run. Cheap to host,
   zero ongoing effort. Aggregate statistics only.

D. DATASET RELEASE: versioned, documented, with a datasheet covering collection methodology,
   normalization version history, known biases, and the exclusion criteria.

DISCLOSURE — gate everything else on this:
   - Publish aggregate statistics freely; name specific servers ONLY for confirmed-malicious cases
     AFTER coordinated disclosure
   - Registry operator and affected maintainers first; 90-day window
   - No name-and-shame on ambiguous cases
   - Consider co-publishing via the OWASP MCP Top 10 working group

NEGATIVE RESULT PLAN — write this section BEFORE looking at the final numbers:
If malicious mutation turns out to be essentially absent, that is a real and publishable finding:
"rug pulls are a theorized threat with no measurable field base rate over N months and M servers;
here is the observatory, and here is what pinning would cost you in friction for the risk it
removes." Do NOT let a null result push toward over-claiming from a handful of anecdotes. Fix the
framing now so the result cannot bend it later.
```

---

## Suggested order

**This week:** WP1 → WP2 → WP3 → WP4. Data starts accruing. (VPS is provisioned and verified —
see `CLAUDE.md`.)
**Weeks 2–4:** WP5 → WP6 → WP7, calibrated against real backfilled mutations.
**Weeks 4–12:** WP8 → WP9, running alongside the observation window.
**Month 4+:** WP10.
