# MCPWatch

Longitudinal observatory measuring how MCP server tool definitions mutate after publication —
the "rug pull" threat, which has a taxonomy slot but no published field data. Not a scanner
(MCP-Scan and MCP-Scanner already exist); the contribution is *time*.

Docs: `BUILD-PLAN.md` (decomposition, sequencing) · `PROMPTS.md` (per-package prompts) ·
`census-baseline.md` (day-zero registry measurement) · `plan-09-source.md` (original plan).

## Where things run

**This directory is for authoring. Production runs on the VPS.**

Write and edit code here with the normal file tools — they operate on the local filesystem, and
editing over SSH through Bash heredocs is slow and error-prone. Then deploy and run on the VPS.

```
ssh mcpwatch        # → [redacted-user]@[redacted-ip] ([redacted-host]), key auth, non-interactive
```

Remote project root: `~/code/mcpwatch/` (`corpus/blobs/`, `logs/`).
No `rsync` locally; deploy with tar over ssh or git.

| | Local (this dir) | VPS |
|---|---|---|
| Role | authoring, docs, analysis | collection, scheduled runs, the corpus |
| OS | Windows 11 | Ubuntu 24.04.4 (4 vCPU, 7.6 GB RAM, 53 GB free) |
| Toolchain | Python 3.14.4, uv 0.11.28, git, node 22, gh | Python 3.12.3, uv 0.12.2, Docker 29.4.3, git, node 18, tmux |

The corpus lives on the VPS and must never be treated as reproducible — Layer 2 (live tool
manifests) cannot be backfilled. A missed day is gone permanently.

## Hard constraints on the VPS

- **`sudo` requires a password.** No `apt install` from an agent session. Not a blocker —
  Docker is installed with `[redacted-user]` in the `docker` group, systemd **user** units run with
  `Linger=yes` (timers survive logout and reboot), and uv installs to `~/.local/bin`.
- **fail2ban is active.** Repeated SSH auth failures ban the connecting IP, and recovery needs
  console access. Connect once and read the error — never loop over candidate usernames.
- **The box is shared** with other agent workloads (`[redacted-workload]` process; `.claude`, `.codex`,
  `.gemini` in `$HOME`; `[redacted-workload]`, `[redacted-workload]`, `[redacted-workload]` in `~/code`). It is a
  permanent machine that matters, not a disposable sandbox. Keep MCPWatch in its own directory,
  use user-level systemd units, cap resources, and be conservative when running untrusted code.

## Working rules

- **Collection start date is the only thing that can't be recovered.** When in doubt, ship a
  crude collector today over a clean one next week.
- **Crawl politely.** Identifying User-Agent with contact address, conservative rate limits,
  backoff on 429/5xx. Read-only MCP methods only (`initialize`, `tools/list`, `resources/list`,
  `prompts/list`) — never `tools/call` against a live third-party server. Never supply real
  credentials.
- **Storage is append-only.** Never rewrite history in the corpus; normalization is versioned so
  decisions can be replayed instead of destroying data.
- **Hash stability is load-bearing.** Servers that randomize tool order or embed session IDs will
  otherwise register a phantom mutation daily and silently corrupt the headline base rate. Keep
  the double-probe nondeterminism guard.
