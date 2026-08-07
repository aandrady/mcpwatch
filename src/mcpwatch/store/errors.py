"""Exception hierarchy for the MCPWatch storage layer."""

__all__ = [
    "BlobIntegrityError",
    "BlobNotFoundError",
    "CanonicalizationError",
    "StoreError",
]


class StoreError(Exception):
    """Base class for every error raised by :mod:`mcpwatch.store`."""


class CanonicalizationError(StoreError):
    """A document could not be canonicalized.

    Raised for input that is not representable as canonical JSON: non-string
    object keys, ``NaN``/``Infinity`` floats, non-JSON Python objects, or key
    collisions introduced by Unicode normalization.
    """


class BlobNotFoundError(StoreError, KeyError):
    """A blob digest was requested that is not present in the store."""


class BlobIntegrityError(StoreError):
    """A blob's stored bytes do not hash to the digest they are filed under.

    This means corpus corruption. The corpus is not reproducible, so treat this
    as a hard failure rather than something to route around.
    """
