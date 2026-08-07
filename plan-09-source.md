# Plan 09 — The MCP Mutation Observatory: Longitudinal Rug-Pull Measurement

**Thesis:** static scanning of agent tool servers is solved. What nobody has done is *watch them over time*. The rug pull — a server that behaves during review and changes its tool definitions after approval — is a named, catalogued threat with **zero published field data on how often it actually happens**. That measurement requires only a cron job and patience, and it is unowned.

---

## 1. Status of the field — the census and the scanner both exist

This changed since the original idea was drafted:

- [MCP-Scanner (ICSE/EnCyCriS 2026)](https://conf.researchr.org/details/icse-2026/encycris-2026/6/MCP-Scanner-Detecting-Security-Risks-in-Model-Context-Protocol-Systems) — keyword + semantic + LLM-based detection of tool poisoning, prompt injection, rug pulls, server impersonation.
- **MCP-Scan** (Invariant Labs) — tool poisoning, cross-origin escalation, rug pull detection via hashing of tool definitions.
- [MCP-38: A Comprehensive Threat Taxonomy](https://arxiv.org/pdf/2603.18063) and [MCP-DPT defense-placement taxonomy](https://arxiv.org/pdf/2604.07551) — the taxonomy slot is filled.
- Censuses already published: tool poisoning at ~5.5% of 1,899 servers in an academic study; an AgentSeal scan of 1,808 servers found 66% with some security finding ([stats roundup](https://www.practical-devsecops.com/mcp-security-statistics-2026-report/)).
- OWASP codified tool poisoning as MCP03; rug pulls and tool shadowing sit alongside it.

**Do not build a scanner or run a one-shot census.** Both exist, better resourced.

## 2. The actual gap

Every existing result is a **snapshot**. The rug pull is definitionally a *temporal* attack — "behaves legitimately at installation, then silently changes after permissions are granted." Snapshot scanning is structurally incapable of measuring it. Open questions with no published answers:

1. **Base rate.** What fraction of MCP servers mutate their tool definitions after publication, and what fraction of those mutations are security-relevant?
2. **Mutation taxonomy in the wild.** Of observed changes, how many are benign feature work vs. scope expansion vs. injected instructions vs. exfiltration additions? Nobody has a labeled corpus of *real* mutations.
3. **Time-to-mutation.** If malicious mutation happens, how long after publication? Is there a dormancy pattern consistent with waiting for install base?
4. **Description-behavior divergence.** Static scanners read the *description*. Nobody systematically checks whether the tool *does what it says* — and that divergence is both a poisoning indicator and a rug-pull indicator that survives description-level review.
5. **Pinning efficacy.** Would content-hash pinning at approval time have caught the mutations that actually occurred? A retrospective answer would settle a live design debate.

**Reframed contribution: a longitudinal observatory, not a scanner.** The moat is time — a dataset that takes six months to collect can't be scooped in two weeks, which is unusual in this field and worth a lot.

## 3. Design

### Component A — the observatory (start this first, on day one)

A daily crawler that snapshots, for every reachable server in public registries:

- Full tool manifest: names, descriptions, JSON schemas, annotations.
- Server metadata: repo, version, maintainer, auth requirements.
- Content hash per tool and per manifest.
- Registry-level metadata: publish date, install/star counts.

Store as an append-only versioned corpus. **Start collecting on day one, before any analysis code is written** — every day of delay is a day of data you can't recover, and this is the single most important sequencing decision in the plan.

### Component B — mutation classification

When a hash changes, diff and classify:

- **Benign** — typos, formatting, genuine feature additions consistent with stated purpose.
- **Scope expansion** — new params or tools broadening capability beyond original description.
- **Instruction injection** — imperative text addressed to the model appearing in a description.
- **Exfiltration addition** — new parameters or endpoints capable of moving context off-host.
- **Authority escalation** — new claims of trust, priority, or override.

Hybrid pipeline: rules for obvious cases, LLM classification for the rest, **human adjudication of every security-relevant classification**. Report inter-rater reliability. At realistic volumes the security-relevant subset will be small enough to review by hand, and hand-review is what makes the numbers trustworthy.

### Component C — description-behavior divergence (the technical novelty)

For a sample of servers safe to execute in a sandbox:

1. Derive expected behavior from the description (network egress? filesystem writes? which endpoints?).
2. Execute in an instrumented sandbox — network egress captured, syscalls traced, filesystem monitored.
3. Diff observed against declared. Report a divergence rate.

This is the part no existing scanner does, and it's what upgrades the project from measurement to method. Scope carefully: containerized, no credentials, egress to a sinkhole, and only servers whose license and terms permit analysis.

### Component D — retrospective pinning analysis

Replay the mutation corpus against a hypothetical pinning policy. Report: how many security-relevant mutations pinning would have caught, and the false-friction rate (benign updates blocked per malicious one caught). **This is the practitioner-facing recommendation and the most actionable output.**

## 4. Metrics

- Mutation rate: fraction of servers changing tool definitions per month.
- Security-relevant mutation rate, by class.
- Time-to-first-mutation distribution; dormancy analysis.
- Description-behavior divergence rate.
- Pinning: caught-attacks vs. false-friction ratio.
- Population coverage and crawl reliability (report honestly — registry churn will break things).

## 5. Stack and compute

No GPU needed beyond optional LLM classification calls. Python crawler, versioned object store (git-based works and gives free diffs), Docker sandbox with network capture (mitmproxy sinkhole) and syscall tracing (falco/strace). A small VPS suffices.

**Cost: the lowest of all ten plans. Elapsed time: the longest.** That trade is exactly why it's the right background project.

## 6. Phased plan

| Phase | Weeks | Work | Gate |
|---|---|---|---|
| 0 | 1 | **Crawler live and collecting daily.** Nothing else matters until this runs | Stable daily snapshots, >90% of registry reachable |
| 1 | 2 | Storage/versioning, diff tooling, dashboards | Diffs reliably detected on synthetic mutations |
| 2 | 3 | Mutation classifier + hand-adjudication protocol | κ > 0.75 on 200 adjudicated diffs |
| 3 | 4 | Sandbox harness for description-behavior divergence | Instrumentation validated on known-behavior servers |
| 4 | *continuous* | **Observation window — 4–6 months minimum** | Enough mutations for stable rates |
| 5 | 2 | Pinning retrospective | Caught/friction ratio |
| 6 | 3 | Write-up; disclosure; public dashboard | — |

Run Phases 1–3 and Component C *during* the observation window. In parallel, ship something else — this plan's dead time is precisely why it pairs well with a compute-heavy flagship like Plan 03.

**Minimum publishable result:** three months of mutation data with classification is already a first-of-its-kind measurement. Component C is publishable independently as a method paper.

## 7. Confounds and controls

- **Registry churn** — servers appear and vanish; distinguish "mutated" from "replaced" from "disappeared." Track identity by repo+name, not URL.
- **Version-tag vs. live-endpoint divergence** — a repo tag may not match what the live server serves. Snapshot both; the divergence between them is itself a finding.
- **Selection bias** — public registries are not the whole ecosystem; enterprise-internal servers are invisible. State the population limitation clearly.
- **Observer effect** — if the project becomes known, adversaries may adapt. Keep detailed detection heuristics private until publication.
- **LLM classifier drift** — pin versions; re-adjudicate a fixed calibration set monthly.

## 8. Negative-result plan

If malicious mutation is essentially absent — plausible, and worth knowing — the paper is: *"Rug pulls are a theorized threat with no measurable field base rate over N months and M servers; here is the observatory, and here is what pinning would cost you in friction for the risk it removes."* That is a real service to a community currently making design decisions on the basis of a hypothetical. Do not let a null result push you into over-claiming from a handful of anecdotes.

## 9. Ethics and disclosure

- **Crawl politely**: robots.txt, rate limits, identifying user agent with a contact address.
- **Never execute a server against real credentials or third-party data.** Sandbox with sinkholed egress only.
- If you find an actively malicious server: report to the registry operator and any affected maintainers first; 90-day disclosure window; do not name-and-shame individual maintainers for ambiguous cases.
- Publish aggregate statistics; publish specific server names only for confirmed-malicious cases after coordinated disclosure.
- Consider co-publishing findings through the OWASP MCP Top 10 working group — an institutional home makes disclosure cleaner and puts you in the room.

## 10. Deliverables

1. **The mutation corpus** — a versioned, longitudinal dataset of MCP server definitions. The durable artifact; useful to others long after your paper.
2. First published rug-pull base rates with a mutation taxonomy grounded in real diffs.
3. Description-behavior divergence method and measured rates.
4. Pinning-policy retrospective with a concrete recommendation.
5. A public dashboard (cheap to run, generates ongoing visibility).

## 11. Career leverage

The dashboard and dataset generate continuous visibility for near-zero ongoing effort — the best passive-attention artifact in the set. The work is unmistakably security engineering. Its weakness is the long elapsed time before results, which is exactly why it should run in the background rather than as your primary. **Start Phase 0 this week regardless of what else you choose**; the crawler costs a weekend and buys you an option on a dataset nobody else will have.

## Key references

- [MCP-Scanner: Detecting Security Risks in MCP Systems](https://dl.acm.org/doi/10.1145/3786160.3788471)
- [MCP-38: A Comprehensive Threat Taxonomy for Model Context Protocol Systems](https://arxiv.org/pdf/2603.18063)
- [MCP-DPT: Defense-Placement Taxonomy and Coverage Analysis](https://arxiv.org/pdf/2604.07551)
- [MCP-Guard: Multi-Stage Defense-in-Depth](https://arxiv.org/pdf/2508.10991)
- [CSA: MCP Tool Poisoning](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-ai-agent-exfiltration-2/)
- [MCP Security Statistics 2026](https://www.practical-devsecops.com/mcp-security-statistics-2026-report/)
- [MCP Threat Modeling and Tool Poisoning (MDPI)](https://www.mdpi.com/2624-800X/6/3/84)
