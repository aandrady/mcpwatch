"""Append-only storage for the MCPWatch corpus.

Two pieces, one contract:

* :class:`~mcpwatch.store.blobs.BlobStore` — content-addressed gzipped JSON.
  Writing content that is already present costs zero bytes, so an unchanged
  daily snapshot is free.
* :class:`~mcpwatch.store.index.ObservationIndex` — a SQLite index of runs,
  servers, and observations, with ``observation`` held append-only by trigger.

:class:`~mcpwatch.store.corpus.Corpus` composes them and is the only supported
write path. Every observation stores both the raw bytes as received and the
canonical bytes hashed under a versioned normalization policy, which is what
makes a later normalization change replayable rather than destructive.
"""

from .blobs import BlobStore, BlobWrite
from .canonical import (
    DEFAULT_POLICY,
    NORM_VERSION,
    NormalizationPolicy,
    canonical_bytes,
    norm_sha256,
    normalize,
    sha256_hex,
)
from .corpus import BLOBS_DIRNAME, INDEX_FILENAME, Corpus, SnapshotWrite
from .errors import (
    BlobIntegrityError,
    BlobNotFoundError,
    CanonicalizationError,
    StoreError,
)
from .index import SCHEMA_VERSION, ObservationIndex
from .types import (
    JsonValue,
    Layer,
    Observation,
    ObservationStatus,
    Run,
    ServerIdentity,
    ServerRecord,
    from_iso,
    to_iso,
    utcnow,
)

__all__ = [
    "BLOBS_DIRNAME",
    "DEFAULT_POLICY",
    "INDEX_FILENAME",
    "NORM_VERSION",
    "SCHEMA_VERSION",
    "BlobIntegrityError",
    "BlobNotFoundError",
    "BlobStore",
    "BlobWrite",
    "CanonicalizationError",
    "Corpus",
    "JsonValue",
    "Layer",
    "NormalizationPolicy",
    "Observation",
    "ObservationIndex",
    "ObservationStatus",
    "Run",
    "ServerIdentity",
    "ServerRecord",
    "SnapshotWrite",
    "StoreError",
    "canonical_bytes",
    "from_iso",
    "norm_sha256",
    "normalize",
    "sha256_hex",
    "to_iso",
    "utcnow",
]
