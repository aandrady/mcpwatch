"""The stratified sampling frame — a research-design artifact, not a work queue.

Building containers for every package server daily is not affordable, so WP8 is
a sample. That makes *how* the sample was chosen part of the result, and it has
to be fixed: a sample that drifts between runs cannot support a longitudinal
claim, which is the entire point of the observatory. The same servers are
re-probed every cycle, and the seed and frame live in the corpus so the draw is
reproducible from the data rather than from anyone's shell history.

**The population.** Servers whose current registry record ships at least one
``stdio`` package from npm or PyPI, and which expose **no remote endpoint**.
Measured 2026-08-12: 9,197 servers, from 11,311 that ship packages at all.

Two exclusions, both deliberate and both reported rather than quietly applied:

*Dual-transport servers* (1,072) are excluded because WP3 already probes them
over HTTP. Probing the same ``server_key`` both ways would write two different
Layer-2 manifests for one server, and the diff engine would read the alternation
as a mutation every cycle — precisely the phantom-mutation failure BUILD-PLAN §3
names as most likely to ruin the dataset. What remains is the half of the
ecosystem genuinely invisible to WP3, which is the population WP8 exists for.

*Other registry types* — mcpb (810), oci (706), nuget (100), cargo (28) — are
excluded from this frame because each needs its own install toolchain, and OCI
in particular means running a publisher's own image rather than our hardened
one. That is a materially different containment posture and deserves its own
verification rather than being folded in silently.

**The strata**, crossed: registry type (npm, pypi), by version count (1, 2-4,
5+), by whether the package declares a secret environment variable. Version
count is the mutation signal WP5/WP6 care about; the secret declaration is the
cheapest available proxy for capability surface, and predicts the
``requires_credentials`` failure class.

**Allocation** is proportional with a floor, so the rare cells (18 single-version
PyPI servers against 2,462 npm servers with 2-4 versions) are still represented.
That over-samples them, so each member records its stratum and the frame records
each stratum's size — base rates reported from this sample must be reweighted by
the inverse inclusion probability, and the data needed to do that is stored.
"""

import json
import random
import sqlite3
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TypeGuard

from mcpwatch.store import Corpus, JsonValue, to_iso, utcnow

__all__ = [
    "ELIGIBLE_REGISTRIES",
    "Candidate",
    "SampleStore",
    "candidates",
    "draw",
]

ELIGIBLE_REGISTRIES = ("npm", "pypi")
"""Install toolchains this sandbox's single image can handle and has verified."""

DEFAULT_SAMPLE_SIZE = 400
"""Servers re-probed each cycle.

Sized against the host, not against ambition. Each member costs an install plus
two launches; at four concurrent containers on a 4-vCPU box shared with other
workloads, 400 members fits comfortably inside a nightly window with room for
the tail. Raising it is a decision about the host's spare capacity, so it is a
flag rather than a constant to edit.
"""

MINIMUM_PER_STRATUM = 5
"""Floor per non-empty cell, so a rare stratum is not rounded out of existence."""

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- The fixed sample. `spec_json` is the pinned install instruction captured at
-- draw time: the sample re-probes the same package identifier every cycle, and
-- letting the identifier float would mean measuring a moving target.
CREATE TABLE IF NOT EXISTS sample_member (
    server_key TEXT PRIMARY KEY,
    stratum    TEXT NOT NULL,
    added_at   TEXT NOT NULL,
    spec_json  TEXT NOT NULL
);

-- How the draw was made, and how big each stratum was in the population. Both
-- are needed: the seed to reproduce the sample, the stratum sizes to reweight
-- anything reported from it back to population base rates.
CREATE TABLE IF NOT EXISTS sample_frame (
    frame_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    seed        INTEGER NOT NULL,
    size        INTEGER NOT NULL,
    population  INTEGER NOT NULL,
    strata_json TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
"""


@dataclass(frozen=True, slots=True)
class Candidate:
    """One server eligible for the sample, with its pinned install spec."""

    server_key: str
    registry_type: str
    identifier: str
    version: str | None
    version_count: int
    declares_secret: bool
    environment_variables: tuple[dict[str, JsonValue], ...] = ()

    @property
    def version_bucket(self) -> str:
        """Version-count stratum. Multi-version servers carry the mutation signal."""
        if self.version_count <= 1:
            return "1"
        return "2-4" if self.version_count <= 4 else "5+"

    @property
    def stratum(self) -> str:
        """The crossed stratum this candidate belongs to."""
        secret = "secret" if self.declares_secret else "nosecret"
        return f"{self.registry_type}/{self.version_bucket}/{secret}"

    def as_spec(self) -> dict[str, JsonValue]:
        """The instruction handed to the sandbox driver."""
        return {
            "server_key": self.server_key,
            "registry_type": self.registry_type,
            "identifier": self.identifier,
            "version": self.version,
            "environment_variables": list(self.environment_variables),
        }


def _is_eligible(package: JsonValue) -> TypeGuard[dict[str, JsonValue]]:
    """Whether one declared package is one this sandbox can install and launch."""
    if not isinstance(package, dict):
        return False
    transport = package.get("transport")
    return (
        package.get("registryType") in ELIGIBLE_REGISTRIES
        and isinstance(transport, dict)
        and transport.get("type") == "stdio"
        and bool(package.get("identifier"))
    )


def candidates(corpus: Corpus) -> Iterator[Candidate]:
    """Every server in the population, read from its latest registry record."""
    conn = corpus.index.connection
    version_counts = dict(
        conn.execute(
            """
            SELECT server_key, count(*) FROM observation
            WHERE layer = 'registry' AND status = 'ok'
            GROUP BY server_key
            """
        ).fetchall()
    )
    rows = conn.execute(
        """
        SELECT o.server_key, o.raw_sha FROM observation o
        JOIN (
            SELECT server_key, max(obs_id) AS newest FROM observation
            WHERE layer = 'registry' AND status = 'ok' AND raw_sha IS NOT NULL
            GROUP BY server_key
        ) latest ON o.obs_id = latest.newest
        ORDER BY o.server_key
        """
    ).fetchall()

    for row in rows:
        document = corpus.load_document(row["raw_sha"])
        if not isinstance(document, dict):
            continue
        server = document.get("server")
        if not isinstance(server, dict):
            continue
        # Dual-transport servers belong to WP3, not here. See the module
        # docstring: probing one server_key both ways manufactures mutations.
        if server.get("remotes"):
            continue

        declared = server.get("packages")
        packages = [
            package
            for package in (declared if isinstance(declared, list) else [])
            if _is_eligible(package)
        ]
        if not packages:
            continue

        # The first eligible package, deterministically. A server shipping
        # several is rare (732 of 11,311) and picking one keeps a member's
        # identity stable across cycles.
        package = packages[0]
        variables = package.get("environmentVariables")
        env = tuple(
            item
            for item in (variables if isinstance(variables, list) else [])
            if isinstance(item, dict)
        )
        yield Candidate(
            server_key=row["server_key"],
            registry_type=str(package["registryType"]),
            identifier=str(package["identifier"]),
            version=str(package["version"]) if package.get("version") else None,
            version_count=int(version_counts.get(row["server_key"], 1)),
            declares_secret=any(item.get("isSecret") for item in env),
            environment_variables=env,
        )


def allocate(sizes: dict[str, int], total: int) -> dict[str, int]:
    """Split ``total`` across strata, proportionally but with a floor.

    The floor is what keeps a stratum holding 18 of 9,197 servers from
    disappearing into a rounding error. It costs proportionality, which is why
    each stratum's population size is stored alongside the draw: reweighting is
    possible only if the inclusion probability is recoverable.
    """
    population = sum(sizes.values())
    if not population:
        return {}

    quotas = {
        name: min(size, max(MINIMUM_PER_STRATUM, round(total * size / population)))
        for name, size in sizes.items()
    }

    # Proportional rounding plus a floor overshoots or undershoots; settle the
    # difference on the largest strata, where one member changes least.
    order = sorted(sizes, key=lambda name: sizes[name], reverse=True)
    while (drift := sum(quotas.values()) - total) != 0:
        moved = False
        for name in order if drift > 0 else reversed(order):
            step = -1 if drift > 0 else 1
            candidate = quotas[name] + step
            if MINIMUM_PER_STRATUM <= candidate <= sizes[name]:
                quotas[name] = candidate
                moved = True
                break
        if not moved:
            break
    return quotas


def draw(pool: list[Candidate], *, size: int, seed: int) -> tuple[list[Candidate], dict[str, int]]:
    """Draw a stratified sample. Returns the members and the stratum sizes."""
    rng = random.Random(seed)
    by_stratum: dict[str, list[Candidate]] = {}
    for candidate in pool:
        by_stratum.setdefault(candidate.stratum, []).append(candidate)

    sizes = {name: len(members) for name, members in by_stratum.items()}
    quotas = allocate(sizes, size)

    chosen: list[Candidate] = []
    for name in sorted(by_stratum):
        members = sorted(by_stratum[name], key=lambda c: c.server_key)
        rng.shuffle(members)
        chosen.extend(members[: quotas.get(name, 0)])
    return chosen, sizes


class SampleStore:
    """SQLite store for the fixed sample and the frame it was drawn under."""

    def __init__(self, path: Path | str) -> None:
        """Open (creating if needed) the store at ``path``."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.executescript(_SCHEMA)
        self._conn.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(SCHEMA_VERSION),),
        )

    def close(self) -> None:
        """Close the connection."""
        self._conn.close()

    def __enter__(self) -> SampleStore:
        """Enter a context manager that closes the store on exit."""
        return self

    def __exit__(self, *exc: object) -> None:
        """Close the store."""
        self.close()

    @property
    def connection(self) -> sqlite3.Connection:
        """The underlying connection."""
        return self._conn

    def record_sample(
        self, members: list[Candidate], sizes: dict[str, int], *, seed: int, size: int
    ) -> int:
        """Store the drawn sample and its frame. Returns members added."""
        stamp = to_iso(utcnow())
        added = 0
        for member in members:
            cursor = self._conn.execute(
                "INSERT OR IGNORE INTO sample_member(server_key, stratum, added_at, spec_json)"
                " VALUES(?, ?, ?, ?)",
                (member.server_key, member.stratum, stamp, json.dumps(member.as_spec())),
            )
            added += cursor.rowcount or 0
        self._conn.execute(
            "INSERT INTO sample_frame(seed, size, population, strata_json, created_at)"
            " VALUES(?, ?, ?, ?, ?)",
            (seed, size, sum(sizes.values()), json.dumps(sizes, sort_keys=True), stamp),
        )
        return added

    def members(self) -> list[sqlite3.Row]:
        """The fixed sample, in draw order."""
        return self._conn.execute(
            "SELECT * FROM sample_member ORDER BY added_at, server_key"
        ).fetchall()

    def specs(self) -> list[dict[str, JsonValue]]:
        """Install specs for every member, ready for the sandbox."""
        return [dict(json.loads(row["spec_json"])) for row in self.members()]

    def frames(self) -> list[sqlite3.Row]:
        """Every draw that has contributed to the sample."""
        return self._conn.execute("SELECT * FROM sample_frame ORDER BY frame_id").fetchall()

    def strata_counts(self) -> Counter[str]:
        """How many members each stratum contributed."""
        return Counter(row["stratum"] for row in self.members())
