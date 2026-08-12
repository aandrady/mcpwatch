"""The dataset datasheet — how the corpus was made, and what is wrong with it.

Following the "Datasheets for Datasets" convention: a dataset released without
its collection methodology, its biases and its exclusion criteria will be used
for questions it cannot answer. This one is a longitudinal security corpus, so
the ways it is incomplete are load-bearing — a reader who does not know that
credential-requiring servers were never probed will read the reachable rate as
a statement about the ecosystem rather than about our access to it.

Generated from the corpus rather than written by hand, so the numbers in it
cannot drift from the data they describe. The prose is versioned here; the
figures are read at generation time.
"""

from mcpwatch.store import Corpus

from .metrics import Coverage, Metrics, flag_glossary

__all__ = ["render_datasheet"]

NORMALIZATION_HISTORY = (
    (
        1,
        "Initial. Canonical JSON: keys sorted recursively, tools sorted by name, "
        "volatile fields stripped before hashing. Raw bytes always stored "
        "alongside the normalized hash so a later revision can be replayed "
        "rather than requiring re-collection.",
    ),
)
"""Every normalization version and what changed.

One entry so far. The list exists because the corpus is append-only and a
normalization change must be replayable: the raw blob is always kept, so a
future version can re-derive every hash without losing data.
"""

EXCLUSIONS = (
    (
        "Credential-requiring servers",
        "Never probed. MCPWatch supplies no credentials to any third party, so a "
        "server demanding them is recorded as `auth_required` and skipped. This is "
        "the largest single blind spot and it is not random: servers behind auth "
        "are plausibly different from servers without it.",
    ),
    (
        "Nondeterministic servers",
        "Quarantined from mutation statistics. A server whose two probes minutes "
        "apart produce different normalized manifests cannot support a claim that "
        "it changed overnight. Tracked and reported as its own population rather "
        "than dropped.",
    ),
    (
        "Dual-transport servers (WP8/WP9)",
        "Excluded from the package sample. A server reachable both over HTTP and "
        "as a package would produce two different Layer-2 manifests under one "
        "identity, and the diff engine would read the alternation as a mutation "
        "every cycle.",
    ),
    (
        "Non-npm/PyPI package types",
        "mcpb, OCI, NuGet and Cargo servers are outside the WP8 sampling frame. "
        "Each needs its own install toolchain, and OCI in particular means running "
        "a publisher's own image rather than a hardened one.",
    ),
    (
        "Destructive-looking tools (WP9)",
        "Never invoked. Tools whose annotations or names indicate a destructive "
        "action are excluded from the divergence exercise, so the exercised set is "
        "not a random sample of all tools.",
    ),
)

BIASES = (
    "Registry-listed servers only. Servers distributed privately or outside the "
    "official registry are invisible to this corpus entirely.",
    "The population is not a fixed cohort. The registry grows by roughly 600 "
    "servers a day, so a rate computed across runs spans a moving denominator.",
    "Layer 2 begins at first probe and cannot be backfilled. Any tool-level "
    "change before 2026-08-07 is permanently unobservable.",
    "Severity flags are precision-tuned heuristics, not adjudicated labels. Until "
    "WP7's kappa gate is met, any 'security-relevant' count is a proxy.",
    "The divergence harness biases toward silence in both halves: declared "
    "capabilities are extracted generously and only observed-not-declared is "
    "scored, so the measured divergence rate is a lower bound.",
    "Probes originate from a single host in one network location. A server that "
    "geofences or rate-limits by origin appears differently to us than to a user "
    "elsewhere.",
)


def render_datasheet(
    corpus: Corpus,
    coverage: Coverage,
    layers: list[Metrics],
    *,
    generated_at: str,
) -> str:
    """Produce the datasheet as Markdown."""
    conn = corpus.index.connection
    observations = conn.execute("SELECT count(*) FROM observation").fetchone()[0]
    runs = conn.execute("SELECT count(*) FROM run WHERE finished_at IS NOT NULL").fetchone()[0]
    first = conn.execute("SELECT min(observed_at) FROM observation").fetchone()[0]

    lines = [
        "# MCPWatch corpus — datasheet",
        "",
        f"Generated {generated_at} from the corpus. Re-runnable; no network access.",
        "",
        "## What this is",
        "",
        "A longitudinal record of Model Context Protocol server definitions: what",
        "the registry published about each server, and what each server reported",
        "about its own tools, sampled repeatedly over time. It exists to measure",
        "how those definitions *change after publication* — the 'rug pull' threat,",
        "which has a taxonomy slot and, before this, no published field data.",
        "",
        "It is not a scanner and not a blocklist. No server in it is asserted to be",
        "malicious.",
        "",
        "## Composition",
        "",
        "| Measure | Value |",
        "|---|---:|",
        f"| Servers tracked | {coverage.servers_tracked:,} |",
        f"| Observations | {observations:,} |",
        f"| Completed collection runs | {runs:,} |",
        f"| First observation | {first or 'n/a'} |",
        "",
        "### Layers",
        "",
        "| Layer | Source | Retrospective? | Collected for | Records span |",
        "|---|---|---|---|---|",
    ]
    for metrics in layers:
        is_registry = metrics.layer == "registry"
        retrospective = "yes — registry `/versions`" if is_registry else "**no**"
        source = "registry metadata" if is_registry else "live tool manifests"
        lines.append(
            f"| {metrics.layer} | {source} | {retrospective} "
            f"| {metrics.observation_days:.1f} days "
            f"| {metrics.history_span_days:,.0f} days |"
        )

    lines += [
        "",
        "The two columns differ for a reason that is the whole two-layer design.",
        "Layer 1 has been collected for days and covers the registry's entire",
        "published history, because the registry exposes its own version history",
        "and WP5 backfilled all of it. Layer 2's two",
        "figures are equal and always will be: nothing can reconstruct a tool",
        "manifest from before the first probe, so a day not collected is gone",
        "permanently. That is why the collector shipped crude and running rather",
        "than clean and later.",
        "",
        "## Collection methodology",
        "",
        "- Registry metadata is crawled daily via the official API, incrementally",
        "  using `updated_since`, with a full crawl weekly.",
        "- Live manifests are collected by an MCP `initialize` + `tools/list` /",
        "  `resources/list` / `prompts/list` handshake. **No tool is ever called by",
        "  the collectors** — `tools/call` is absent from the client by",
        "  construction, not by policy.",
        "- Every server is probed **twice** per cycle. If the two normalized hashes",
        "  disagree the server is recorded nondeterministic and quarantined, because",
        "  a server that randomizes tool order would otherwise register a mutation",
        "  every single day and silently corrupt the headline base rate.",
        "- Package servers are enumerated inside a sandbox with no route off the",
        "  host, every capability dropped, and no mounts. Containment is verified",
        "  against a deliberately-exfiltrating canary before each cycle.",
        "- Requests carry an identifying User-Agent with a contact address.",
        "  Rate limits are conservative and self-imposed; 429 and 5xx are stop",
        "  signals.",
        "",
        "## Storage and normalization",
        "",
        "Content-addressed blobs plus a SQLite index. Observations are append-only,",
        "enforced by database triggers: a correction is a new row, never an edit.",
        "Both the raw bytes and a normalized form are stored for every observation,",
        "so a normalization change can be replayed over history instead of",
        "destroying it.",
        "",
        "| Version | Change |",
        "|---:|---|",
    ]
    lines += [f"| {version} | {description} |" for version, description in NORMALIZATION_HISTORY]

    lines += ["", "## Exclusion criteria", ""]
    for title, body in EXCLUSIONS:
        lines += [f"**{title}.** {body}", ""]

    lines += ["## Known biases", ""]
    lines += [f"- {bias}" for bias in BIASES]

    lines += [
        "",
        "## Coverage, stated as denominators",
        "",
        "| Population | Count |",
        "|---|---:|",
        f"| Layer-2 targets in the last cycle | {coverage.layer2_targets:,} |",
        f"| ...yielded a usable manifest | {coverage.layer2_ok:,} |",
        f"| ...required credentials we never supply | {coverage.layer2_auth_required:,} |",
        f"| ...unreachable or timed out | {coverage.layer2_unreachable:,} |",
        f"| ...quarantined as nondeterministic | {coverage.layer2_quarantined:,} |",
        f"| Sampled package servers attempted | {coverage.stdio_attempted:,} |",
        f"| ...enumerated successfully | {coverage.stdio_enumerated:,} |",
        "",
        f"Reachable rate is **{coverage.reachable_rate:.1%}**, and that figure is about",
        "our access rather than about the ecosystem's health.",
        "",
        "## Severity flag glossary",
        "",
        "Flags are *reasons to look*, never findings. An imperative sentence in a",
        "description is how a prompt injection reads and also how half of all honest",
        "documentation reads.",
        "",
        "| Flag | Meaning |",
        "|---|---|",
    ]
    lines += [f"| `{name}` | {meaning} |" for name, meaning in sorted(flag_glossary().items())]

    lines += [
        "",
        "## Ethics and disclosure",
        "",
        "- Read-only protocol methods against live third-party servers. Never a tool",
        "  call, never a credential.",
        "- Behavioural analysis (WP9) invokes tools only inside a sandbox with",
        "  sinkholed egress, synthetic arguments, and destructive-looking tools",
        "  excluded.",
        "- Aggregate statistics are published freely. A specific server is named only",
        "  for a confirmed-malicious case, after coordinated disclosure to the",
        "  registry operator and maintainer with a 90-day window, and never for an",
        "  ambiguous one.",
        "",
        "See `FRAMING.md` for the result-framing rules, written before the analysis",
        "that produces the numbers.",
        "",
    ]
    return "\n".join(lines)
