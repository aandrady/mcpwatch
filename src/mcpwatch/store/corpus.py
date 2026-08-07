"""The corpus: blob store plus index, with the append-only write path.

:class:`Corpus` is the object every collector talks to. It owns the invariant
that matters most — a snapshot is written as *both* its raw bytes and its
canonical bytes, and the observation row that points at them names the
normalization version used. Nothing else in MCPWatch is allowed to write to the
corpus directly.

On-disk layout::

    <root>/
      blobs/          content-addressed gzipped JSON
      index.db        the SQLite index (plus -wal and -shm)

On the production host this root is ``~/mcpwatch-corpus``, deliberately outside
the deploy work tree so no ``git clean`` or ``checkout -f`` can reach it.
"""

import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import TracebackType
from uuid import uuid4

from .blobs import BlobStore, BlobWrite
from .canonical import DEFAULT_POLICY, NormalizationPolicy, canonical_bytes
from .index import ObservationIndex
from .types import (
    JsonValue,
    Layer,
    Observation,
    ObservationStatus,
    Run,
    ServerRecord,
    to_iso,
    utcnow,
)

__all__ = ["Corpus", "SnapshotWrite"]

BLOBS_DIRNAME = "blobs"
INDEX_FILENAME = "index.db"


@dataclass(frozen=True, slots=True)
class SnapshotWrite:
    """Result of recording one successful snapshot.

    Attributes:
        observation: The appended observation row.
        raw: Blob write result for the bytes as received.
        normalized: Blob write result for the canonical bytes.
        bytes_written: Compressed bytes newly committed for this snapshot. Zero
            when nothing changed, which is the property the whole storage design
            exists to provide.
        changed: True when this snapshot's ``norm_sha`` differs from the
            server's previous successful observation on the same layer, or when
            there is no previous one. A candidate mutation, not a verdict — WP6
            decides what actually changed.
    """

    observation: Observation
    raw: BlobWrite
    normalized: BlobWrite
    changed: bool

    @property
    def bytes_written(self) -> int:
        """Compressed bytes newly written to disk for this snapshot."""
        return self.raw.bytes_written + self.normalized.bytes_written


def _new_run_id(collector: str) -> str:
    """Mint a run id that sorts chronologically and reads well in logs."""
    stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
    return f"{collector}-{stamp}-{uuid4().hex[:8]}"


class Corpus:
    """An append-only MCPWatch corpus rooted at a directory.

    Example:
        >>> with Corpus(root) as corpus:  # doctest: +SKIP
        ...     with corpus.run("registry", "0.1.0") as run_id:
        ...         corpus.upsert_server(
        ...             server_key="ac.inference.sh/mcp",
        ...             registry_name="ac.inference.sh/mcp",
        ...             repo_url="https://github.com/example/mcp",
        ...             primary_endpoint="https://api.inference.sh/mcp",
        ...         )
        ...         corpus.record_snapshot(
        ...             run_id=run_id,
        ...             server_key="ac.inference.sh/mcp",
        ...             layer=Layer.REGISTRY,
        ...             document=record,
        ...             raw_bytes=response_body,
        ...         )
    """

    def __init__(
        self,
        root: Path | str,
        *,
        policy: NormalizationPolicy = DEFAULT_POLICY,
    ) -> None:
        """Open (creating if needed) a corpus at ``root``.

        Args:
            root: Directory holding ``blobs/`` and ``index.db``.
            policy: Normalization policy. Overriding this changes what
                ``norm_sha`` means, so a custom policy must carry its own
                ``version``; see :mod:`mcpwatch.store.canonical`.
        """
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.policy = policy
        self.blobs = BlobStore(self.root / BLOBS_DIRNAME)
        self.index = ObservationIndex(self.root / INDEX_FILENAME)

    def close(self) -> None:
        """Close the underlying database connection."""
        self.index.close()

    def __enter__(self) -> Corpus:
        """Enter a context manager that closes the corpus on exit."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close the corpus."""
        self.close()

    # ---------------------------------------------------------------- runs ---

    def start_run(
        self,
        collector: str,
        collector_version: str,
        *,
        run_id: str | None = None,
        started_at: datetime | None = None,
    ) -> str:
        """Open a run and return its id."""
        rid = run_id or _new_run_id(collector)
        self.index.insert_run(
            run_id=rid,
            collector=collector,
            collector_version=collector_version,
            started_at=to_iso(started_at or utcnow()),
        )
        return rid

    def finish_run(
        self,
        run_id: str,
        *,
        stats: Mapping[str, JsonValue] | None = None,
        finished_at: datetime | None = None,
    ) -> None:
        """Close a run, recording its end time and summary statistics."""
        self.index.finish_run(
            run_id,
            finished_at=to_iso(finished_at or utcnow()),
            stats=stats,
        )

    @contextmanager
    def run(self, collector: str, collector_version: str) -> Iterator[str]:
        """Open a run for the duration of a block, yielding its id.

        A run that raises is left open on purpose. An unfinished run is the
        signal WP4's health check looks for; auto-closing a crashed cycle would
        make a broken collector look like a healthy one.
        """
        run_id = self.start_run(collector, collector_version)
        yield run_id
        self.finish_run(run_id)

    def get_run(self, run_id: str) -> Run | None:
        """Return a run by id, or None if it does not exist."""
        return self.index.get_run(run_id)

    # ------------------------------------------------------------- servers ---

    def upsert_server(
        self,
        *,
        server_key: str,
        registry_name: str,
        repo_url: str | None = None,
        primary_endpoint: str | None = None,
        seen_at: datetime | None = None,
    ) -> None:
        """Register or refresh a server's identity.

        A server row must exist before observations can reference it; the
        foreign key enforces that.
        """
        self.index.upsert_server(
            server_key=server_key,
            registry_name=registry_name,
            repo_url=repo_url,
            primary_endpoint=primary_endpoint,
            seen_at=to_iso(seen_at or utcnow()),
        )

    def get_server(self, server_key: str) -> ServerRecord | None:
        """Return a server by key, or None if it is not tracked."""
        return self.index.get_server(server_key)

    # -------------------------------------------------------- observations ---

    def record_snapshot(
        self,
        *,
        run_id: str,
        server_key: str,
        layer: Layer,
        document: JsonValue,
        raw_bytes: bytes | None = None,
        observed_at: datetime | None = None,
        status: ObservationStatus = ObservationStatus.OK,
    ) -> SnapshotWrite:
        """Store a snapshot's raw and canonical blobs and append an observation.

        Args:
            run_id: The run this observation belongs to.
            server_key: The server observed.
            layer: Which data layer the document came from.
            document: The parsed document to canonicalize and hash.
            raw_bytes: The bytes exactly as received. Strongly preferred over
                letting this be re-serialized from ``document``: the raw blob is
                what makes a future normalization change replayable, and a
                round-tripped copy has already lost whatever the parser dropped.
            observed_at: When the observation was made. Defaults to now.
            status: Normally ``OK``. ``NONDETERMINISTIC`` is the other legitimate
                value — WP3's double probe still stores the manifest it got, it
                just quarantines it from mutation statistics.

        Returns:
            A :class:`SnapshotWrite` reporting the bytes actually written and
            whether the normalized hash moved.

        Raises:
            CanonicalizationError: If the document cannot be canonicalized.
        """
        norm = canonical_bytes(document, self.policy)
        raw = raw_bytes if raw_bytes is not None else self._fallback_raw_bytes(document)
        moment = to_iso(observed_at or utcnow())

        with self.index.transaction():
            # Read the baseline under the write lock, so `changed` cannot be
            # computed against an observation another probe appended meanwhile.
            previous = self.index.latest_observation(
                server_key, layer=layer, status=ObservationStatus.OK
            )
            raw_write = self.blobs.put(raw)
            norm_write = self.blobs.put(norm)
            obs_id = self.index.insert_observation(
                run_id=run_id,
                server_key=server_key,
                layer=layer,
                observed_at=moment,
                status=status,
                raw_sha=raw_write.digest,
                norm_sha=norm_write.digest,
                norm_version=self.policy.version,
            )
            self.index.touch_server(server_key, seen_at=moment)
            observation = self.index.get_observation(obs_id)

        if observation is None:  # pragma: no cover - the insert just succeeded
            msg = f"observation {obs_id} vanished immediately after insert"
            raise RuntimeError(msg)

        return SnapshotWrite(
            observation=observation,
            raw=raw_write,
            normalized=norm_write,
            changed=previous is None or previous.norm_sha != norm_write.digest,
        )

    def record_failure(
        self,
        *,
        run_id: str,
        server_key: str,
        layer: Layer,
        status: ObservationStatus,
        error_class: str | None = None,
        error_detail: str | None = None,
        observed_at: datetime | None = None,
    ) -> Observation:
        """Append an observation for an attempt that produced no document.

        Failures are recorded, never skipped. A silent gap is indistinguishable
        from a server that was fine, and crawl reliability is itself a reported
        metric.

        Raises:
            ValueError: If ``status`` is ``OK``; a successful observation must
                go through :meth:`record_snapshot` so it carries its blobs.
        """
        if status is ObservationStatus.OK:
            msg = "record_failure cannot record status 'ok'; use record_snapshot"
            raise ValueError(msg)

        moment = to_iso(observed_at or utcnow())
        with self.index.transaction():
            obs_id = self.index.insert_observation(
                run_id=run_id,
                server_key=server_key,
                layer=layer,
                observed_at=moment,
                status=status,
                error_class=error_class,
                error_detail=error_detail,
            )
            self.index.touch_server(server_key, seen_at=moment)
            observation = self.index.get_observation(obs_id)

        if observation is None:  # pragma: no cover - the insert just succeeded
            msg = f"observation {obs_id} vanished immediately after insert"
            raise RuntimeError(msg)
        return observation

    def latest_observation(
        self,
        server_key: str,
        *,
        layer: Layer | None = None,
        status: ObservationStatus | None = None,
    ) -> Observation | None:
        """Return a server's most recent observation, optionally filtered."""
        return self.index.latest_observation(server_key, layer=layer, status=status)

    def observations(
        self,
        server_key: str,
        *,
        layer: Layer | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> list[Observation]:
        """Return one server's observations in chronological order."""
        return self.index.observations(server_key, layer=layer, since=since, until=until)

    # --------------------------------------------------------------- blobs ---

    def load_bytes(self, digest: str) -> bytes:
        """Return the raw bytes stored under ``digest``, verifying its hash."""
        return self.blobs.get(digest)

    def load_document(self, digest: str) -> JsonValue:
        """Return the JSON document stored under ``digest``."""
        return json.loads(self.blobs.get(digest))  # type: ignore[no-any-return]

    def missing_blobs(self) -> list[str]:
        """Return every digest the index references that the blob store lacks.

        Should always be empty. A non-empty result means the index and the blob
        store have diverged, which is a corpus-integrity incident.
        """
        return [
            digest for digest in self.index.referenced_digests() if not self.blobs.exists(digest)
        ]

    @staticmethod
    def _fallback_raw_bytes(document: JsonValue) -> bytes:
        """Serialize a document when the caller did not supply the wire bytes.

        Insertion order is preserved and keys are left unsorted, so this stays as
        close to "what the parser saw" as a re-serialization can get.
        """
        return json.dumps(
            document,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=False,
            allow_nan=False,
        ).encode("utf-8")
