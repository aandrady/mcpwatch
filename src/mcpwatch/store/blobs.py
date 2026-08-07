"""Content-addressed, gzip-compressed blob storage.

The defining property is that writing a blob whose content is already present is
a no-op costing zero additional bytes. On a typical day the overwhelming
majority of servers will not have changed, so an unchanged snapshot must be free
— otherwise a multi-year daily corpus grows linearly in servers x days instead
of in actual mutations.

Layout is ``blobs/<aa>/<bb>/<full-sha256>.json.gz``: two levels of 256-way
fan-out keeps any single directory small enough for the filesystem to stay fast
at corpus scale, and the full digest in the filename makes the store verifiable
with nothing but ``sha256sum`` and ``gunzip``.

Blobs are never modified or deleted through this API. The corpus is append-only.
"""

import gzip
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .canonical import sha256_hex
from .errors import BlobIntegrityError, BlobNotFoundError

__all__ = ["BlobStore", "BlobWrite"]

_DIGEST_LENGTH = 64
_DIGEST_ALPHABET = frozenset("0123456789abcdef")
_SUFFIX = ".json.gz"
_COMPRESS_LEVEL = 9


@dataclass(frozen=True, slots=True)
class BlobWrite:
    """Outcome of a :meth:`BlobStore.put`.

    Attributes:
        digest: sha256 hex digest of the uncompressed content.
        created: True if this call materialized the blob, False if it was
            already present and nothing was written.
        bytes_written: Compressed bytes newly committed to disk. Zero on a
            deduplicated write — this is the number run stats should sum.
    """

    digest: str
    created: bool
    bytes_written: int


def _validate_digest(digest: str) -> str:
    """Reject anything that is not a lowercase sha256 hex digest.

    Digests become path components, so this is also the guard that keeps a
    caller-supplied string from escaping the store root.
    """
    if len(digest) != _DIGEST_LENGTH or not _DIGEST_ALPHABET.issuperset(digest):
        msg = f"not a lowercase sha256 hex digest: {digest!r}"
        raise ValueError(msg)
    return digest


class BlobStore:
    """A content-addressed store of gzipped JSON blobs rooted at a directory."""

    def __init__(self, root: Path | str) -> None:
        """Open (creating if needed) a blob store rooted at ``root``."""
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def path_for(self, digest: str) -> Path:
        """Return the on-disk path a blob with ``digest`` occupies.

        The blob need not exist; this is pure path arithmetic.
        """
        checked = _validate_digest(digest)
        return self.root / checked[:2] / checked[2:4] / f"{checked}{_SUFFIX}"

    def exists(self, digest: str) -> bool:
        """Return whether a blob with ``digest`` is present."""
        return self.path_for(digest).is_file()

    def __contains__(self, digest: str) -> bool:
        """Support ``digest in store``."""
        return self.exists(digest)

    def put(self, data: bytes) -> BlobWrite:
        """Store ``data``, returning its digest and whether anything was written.

        Storing content already present is a no-op: the existing file is not
        touched, rewritten, or restamped.

        The write itself goes to a temporary file in the destination directory
        and is committed with an atomic rename, so an interrupted run can never
        leave a truncated blob filed under a valid digest.
        """
        digest = sha256_hex(data)
        path = self.path_for(digest)
        if path.is_file():
            return BlobWrite(digest=digest, created=False, bytes_written=0)

        path.parent.mkdir(parents=True, exist_ok=True)
        # mtime=0 makes the gzip container byte-for-byte reproducible, so two
        # stores built from the same corpus compare equal file by file.
        payload = gzip.compress(data, compresslevel=_COMPRESS_LEVEL, mtime=0)
        tmp = path.parent / f".{digest}.{os.getpid()}.tmp"
        try:
            tmp.write_bytes(payload)
            os.replace(tmp, path)  # noqa: PTH105 - Path has no atomic-replace method
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        return BlobWrite(digest=digest, created=True, bytes_written=len(payload))

    def get(self, digest: str, *, verify: bool = True) -> bytes:
        """Return the uncompressed bytes stored under ``digest``.

        Args:
            digest: The blob's sha256 hex digest.
            verify: Re-hash the decompressed bytes and confirm they match.
                Defaults to True: the corpus is not reproducible, so silent
                corruption is worse than the cost of a hash.

        Raises:
            BlobNotFoundError: If no blob is filed under ``digest``.
            BlobIntegrityError: If ``verify`` is set and the content does not
                hash to ``digest``.
        """
        path = self.path_for(digest)
        try:
            payload = path.read_bytes()
        except FileNotFoundError as exc:
            raise BlobNotFoundError(digest) from exc

        data = gzip.decompress(payload)
        if verify:
            actual = sha256_hex(data)
            if actual != digest:
                msg = f"blob at {path} hashes to {actual}, not {digest}"
                raise BlobIntegrityError(msg)
        return data

    def iter_digests(self) -> Iterator[str]:
        """Yield the digest of every blob in the store, in filesystem order."""
        for path in self.root.glob(f"*/*/*{_SUFFIX}"):
            yield path.name[: -len(_SUFFIX)]

    def disk_usage(self) -> int:
        """Return the total size in bytes of every blob file in the store."""
        return sum(path.stat().st_size for path in self.root.glob(f"*/*/*{_SUFFIX}"))

    def count(self) -> int:
        """Return the number of blobs in the store."""
        return sum(1 for _ in self.iter_digests())
