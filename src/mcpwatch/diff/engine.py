"""Walking the corpus and emitting ChangeSets.

The engine reads and never writes. ChangeSets are a *reading* of the corpus, not
part of it: recompute them next year against a better differ and you get better
answers from the same evidence, which is only possible while the evidence stays
untouched.

Chronology is ``effective_at``, so a backfilled version published in 2024 sits
where it belongs rather than where the backfill job happened to read it. That
matters most on Layer 1, where a server's history is a mix of versions
backfilled from the registry and daily snapshots taken since.

**What is skipped, and why it is skipped rather than dropped.** Observations
recorded ``nondeterministic`` never enter a chain: a server whose manifest
differs between two probes minutes apart cannot support a claim that it changed
overnight, and letting one in would manufacture a mutation. But every ChangeSet
for such a server is *marked* rather than withheld, because "this server is
unstable" is itself a finding, and an investigator should still be able to look.
"""

import argparse
import json
import os
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from mcpwatch.store import Corpus, JsonValue, Layer, ObservationStatus

from .identity import IdentityIndex, ServerIdentity, classify_transition
from .semantic import diff_manifest, diff_registry, tool_fingerprint
from .severity import flags_for
from .types import Change, ChangeSet, DiffStats, Verdict, change_id

__all__ = ["ABSENCE_CLASSES", "DiffEngine", "main"]

ABSENCE_CLASSES = ("absent", "withdrawn")
"""``error_class`` values that mean the server was gone, not that we failed.

WP2 records ``absent`` when a complete crawl did not return a server; WP5
records ``withdrawn`` when the registry reports it deleted. Everything else with
a non-OK status is a *collection* failure — a timeout, a TLS error — and says
nothing about the server having changed, so it is passed over rather than read
as a disappearance.
"""


@dataclass(frozen=True, slots=True)
class _Step:
    """One point in a server's chain: a snapshot, or a recorded absence."""

    obs_id: int
    effective_at: str
    status: str
    norm_sha: str | None
    error_class: str | None

    @property
    def present(self) -> bool:
        """Whether this step carries a document."""
        return self.status == str(ObservationStatus.OK)

    @property
    def absence(self) -> bool:
        """Whether this step records the server being gone."""
        return self.error_class in ABSENCE_CLASSES


class DiffEngine:
    """Turns a corpus into a stream of ChangeSets."""

    def __init__(self, corpus: Corpus) -> None:
        """Bind an engine to a corpus and index its identities."""
        self.corpus = corpus
        self.identities = IdentityIndex(corpus)
        self._quarantined = self._load_quarantined()

    def _load_quarantined(self) -> frozenset[str]:
        """Servers WP3 has ever recorded as nondeterministic."""
        rows = self.corpus.index.connection.execute(
            "SELECT DISTINCT server_key FROM observation WHERE status = ?",
            (str(ObservationStatus.NONDETERMINISTIC),),
        ).fetchall()
        return frozenset(row["server_key"] for row in rows)

    # ----------------------------------------------------------- selection ---

    def _steps(
        self,
        *,
        layer: Layer,
        since: str | None,
        until: str | None,
        server_key: str | None,
    ) -> Iterator[tuple[str, list[_Step]]]:
        """Yield ``(server_key, chain)`` for each server, chronologically.

        The window is applied to the *output*, not to the walk: a ChangeSet
        needs the observation immediately before the window to have anything to
        compare against, so the chain is built whole and filtered at emit time.
        """
        sql = [
            """
            SELECT server_key, obs_id, effective_at, status, norm_sha, error_class
            FROM observation
            WHERE layer = ?
              AND (status = 'ok' OR error_class IN (?, ?))
            """
        ]
        params: list[JsonValue] = [str(layer), *ABSENCE_CLASSES]
        if server_key is not None:
            sql.append("AND server_key = ?")
            params.append(server_key)
        if until is not None:
            sql.append("AND effective_at < ?")
            params.append(until)
        sql.append("ORDER BY server_key, effective_at, obs_id")
        del since  # applied at emit time; see the docstring

        current: str | None = None
        chain: list[_Step] = []
        for row in self.corpus.index.connection.execute(" ".join(sql), params):
            if row["server_key"] != current:
                if current is not None:
                    yield current, chain
                current, chain = row["server_key"], []
            chain.append(
                _Step(
                    obs_id=row["obs_id"],
                    effective_at=row["effective_at"],
                    status=row["status"],
                    norm_sha=row["norm_sha"],
                    error_class=row["error_class"],
                )
            )
        if current is not None:
            yield current, chain

    # --------------------------------------------------------------- walk ---

    def changesets(
        self,
        *,
        layer: Layer = Layer.REGISTRY,
        since: str | None = None,
        until: str | None = None,
        server_key: str | None = None,
        include_unchanged: bool = False,
        stats: DiffStats | None = None,
    ) -> Iterator[ChangeSet]:
        """Emit ChangeSets for one layer.

        Args:
            layer: Which layer to walk.
            since: Only emit ChangeSets whose later observation is at or after
                this timestamp. Earlier history is still *read*, because a diff
                needs a predecessor.
            until: Ignore observations at or after this timestamp entirely.
            server_key: Restrict to one server.
            include_unchanged: Emit a ChangeSet even when the semantic differ
                found nothing. Useful for auditing: a hash that moved with no
                describable change means the differ is blind to something.
            stats: Optional counters to populate.

        Yields:
            One :class:`ChangeSet` per transition, oldest first.
        """
        tally = stats if stats is not None else DiffStats()
        for key, chain in self._steps(layer=layer, since=since, until=until, server_key=server_key):
            tally.servers += 1
            tally.observations += len(chain)
            if key in self._quarantined:
                tally.quarantined_servers += 1
            for changeset in self._walk_server(key, chain, layer, tally):
                if since is not None and changeset.to_effective_at < since:
                    continue
                # A transition whose hash moved but whose differ found nothing
                # is worth counting: it means the differ is blind to something
                # the normalizer considers significant. NEW and DISAPPEARED are
                # events in themselves and carry no changes by definition.
                describable = changeset.verdict not in {Verdict.MUTATED, Verdict.REPLACED}
                if not changeset.changes and not include_unchanged and not describable:
                    tally.empty_changesets += 1
                    continue
                self._count(changeset, tally)
                yield changeset

    def _walk_server(
        self, key: str, chain: Sequence[_Step], layer: Layer, tally: DiffStats
    ) -> Iterator[ChangeSet]:
        """Walk one server's chain, emitting a ChangeSet per transition."""
        quarantined = key in self._quarantined
        previous: _Step | None = None
        gone = False

        for step in chain:
            if step.absence:
                if previous is not None and not gone:
                    yield self._build(
                        key, layer, previous, step, Verdict.DISAPPEARED, (), quarantined
                    )
                gone = True
                continue

            if not step.present:  # pragma: no cover - filtered in SQL
                continue

            if previous is None:
                verdict = Verdict.NEW
                predecessor = self.identities.predecessor_of(key, self._identity_of(key))
                if predecessor is not None:
                    verdict = Verdict.RENAMED
                yield self._build(
                    key, layer, None, step, verdict, (), quarantined, predecessor=predecessor
                )
            elif gone:
                yield self._build(
                    key,
                    layer,
                    previous,
                    step,
                    Verdict.RETURNED,
                    self._diff(layer, previous, step, tally),
                    quarantined,
                )
            elif step.norm_sha != previous.norm_sha:
                changes = self._diff(layer, previous, step, tally)
                verdict = self._verdict(key, layer, previous, step, changes)
                yield self._build(key, layer, previous, step, verdict, changes, quarantined)

            previous = step
            gone = False

    def _identity_of(self, key: str) -> ServerIdentity:
        record = self.corpus.get_server(key)
        if record is None:  # pragma: no cover - chains come from real servers
            return ServerIdentity(repo_url=None, endpoint=None)
        return ServerIdentity(repo_url=record.repo_url, endpoint=record.primary_endpoint)

    def _verdict(
        self, key: str, layer: Layer, before: _Step, after: _Step, changes: Sequence[Change]
    ) -> Verdict:
        """Decide MUTATED vs REPLACED for a same-name transition."""
        if layer is Layer.REGISTRY:
            return classify_transition(*self._identities_from(changes))
        # A manifest declares no repository and no endpoint, so the swap has to
        # be read from the identity history the collectors maintain.
        moved = self.identities.identity_moved_between(key, before.effective_at, after.effective_at)
        return Verdict.REPLACED if moved else Verdict.MUTATED

    @staticmethod
    def _identities_from(changes: Sequence[Change]) -> tuple[ServerIdentity, ServerIdentity]:
        """Read before/after identity out of the Layer-1 changes themselves.

        More precise than consulting the server table, which holds only the
        server's *current* identity: this reflects what the two documents
        actually declared at their own moments in time.
        """
        before_repo = after_repo = before_end = after_end = None
        for change in changes:
            if change.kind.value == "repository_changed":
                before_repo = change.before if isinstance(change.before, str) else None
                after_repo = change.after if isinstance(change.after, str) else None
            elif change.kind.value == "endpoint_changed":
                before_list = change.before if isinstance(change.before, list) else []
                after_list = change.after if isinstance(change.after, list) else []
                before_end = str(before_list[0]) if before_list else None
                after_end = str(after_list[0]) if after_list else None
        return (
            ServerIdentity(repo_url=before_repo, endpoint=before_end),
            ServerIdentity(repo_url=after_repo, endpoint=after_end),
        )

    def _diff(
        self, layer: Layer, before: _Step, after: _Step, tally: DiffStats
    ) -> tuple[Change, ...]:
        """Load both documents and run the layer's differ."""
        old = self._document(before.norm_sha, tally)
        new = self._document(after.norm_sha, tally)
        if old is None or new is None:
            return ()
        differ = diff_registry if layer is Layer.REGISTRY else diff_manifest
        return tuple(differ(old, new))

    def _document(self, digest: str | None, tally: DiffStats) -> JsonValue:
        """Load a normalized document, counting anything unreadable."""
        if digest is None:
            return None
        try:
            return self.corpus.load_document(digest)
        except OSError, ValueError:
            # An unreadable blob is a corpus-integrity incident, not a diff
            # result. Counted loudly and skipped; `mcpwatch health` is what
            # notices the store and the index have diverged.
            tally.unreadable_blobs += 1
            return None

    @staticmethod
    def _build(
        key: str,
        layer: Layer,
        before: _Step | None,
        after: _Step,
        verdict: Verdict,
        changes: Sequence[Change],
        quarantined: bool,
        *,
        predecessor: str | None = None,
    ) -> ChangeSet:
        return ChangeSet(
            change_id=change_id(key, before.obs_id if before else None, after.obs_id),
            server_key=key,
            layer=layer,
            verdict=verdict,
            from_obs_id=before.obs_id if before else None,
            from_effective_at=before.effective_at if before else None,
            from_norm_sha=before.norm_sha if before else None,
            to_obs_id=after.obs_id,
            to_effective_at=after.effective_at,
            to_norm_sha=after.norm_sha,
            changes=tuple(changes),
            flags=flags_for(changes),
            quarantined=quarantined,
            predecessor_key=predecessor,
        )

    @staticmethod
    def _count(changeset: ChangeSet, tally: DiffStats) -> None:
        tally.changesets += 1
        if changeset.quarantined:
            tally.quarantined_changesets += 1
        tally.by_verdict[str(changeset.verdict)] = (
            tally.by_verdict.get(str(changeset.verdict), 0) + 1
        )
        for kind in changeset.kinds:
            tally.by_kind[str(kind)] = tally.by_kind.get(str(kind), 0) + 1
        for flag in changeset.flags:
            tally.by_flag[str(flag)] = tally.by_flag.get(str(flag), 0) + 1


def fingerprint_of(corpus: Corpus, digest: str) -> str:
    """Tool-set fingerprint of a stored manifest, for identity work."""
    return tool_fingerprint(corpus.load_document(digest))


def _default_corpus_root() -> Path:
    override = os.environ.get("MCPWATCH_CORPUS")
    return Path(override) if override else Path.home() / "mcpwatch-corpus"


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Emits ChangeSets as JSONL; returns 0 on success."""
    parser = argparse.ArgumentParser(
        prog="python -m mcpwatch.diff",
        description="Emit semantic ChangeSets over the corpus as JSONL.",
    )
    parser.add_argument("--corpus", type=Path, default=_default_corpus_root())
    parser.add_argument("--layer", choices=("registry", "manifest"), default="registry")
    parser.add_argument(
        "--since", default=None, help="ISO timestamp; earlier history is still read"
    )
    parser.add_argument("--until", default=None, help="ISO timestamp, exclusive")
    parser.add_argument("--server", default=None, help="restrict to one server key")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--flagged-only", action="store_true", help="emit only ChangeSets carrying a severity flag"
    )
    parser.add_argument(
        "--include-quarantined",
        action="store_true",
        help="include servers WP3 recorded as nondeterministic (excluded from base rates)",
    )
    parser.add_argument(
        "--include-unchanged",
        action="store_true",
        help="emit transitions the differ found nothing in; an audit aid, not a normal mode",
    )
    parser.add_argument("--out", type=Path, default=None, help="write JSONL here instead of stdout")
    parser.add_argument("--stats", action="store_true", help="write a summary to stderr")
    args = parser.parse_args(argv)

    stats = DiffStats()
    emitted = 0
    handle = args.out.open("w", encoding="utf-8") if args.out else None
    try:
        with Corpus(args.corpus) as corpus:
            engine = DiffEngine(corpus)
            stream = engine.changesets(
                layer=Layer(args.layer),
                since=args.since,
                until=args.until,
                server_key=args.server,
                include_unchanged=args.include_unchanged,
                stats=stats,
            )
            for changeset in stream:
                if changeset.quarantined and not args.include_quarantined:
                    continue
                if args.flagged_only and not changeset.flags:
                    continue
                line = json.dumps(changeset.as_json(), ensure_ascii=False, sort_keys=True)
                if handle is not None:
                    handle.write(line + "\n")
                else:
                    sys.stdout.write(line + "\n")
                emitted += 1
                if args.limit is not None and emitted >= args.limit:
                    break
    finally:
        if handle is not None:
            handle.close()

    if args.stats:
        print(json.dumps(stats.as_json(), indent=2, sort_keys=True), file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
