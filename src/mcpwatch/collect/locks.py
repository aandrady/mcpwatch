"""Advisory locks that keep two collectors of the same kind from overlapping.

Kernel-held rather than PID files: a lock released by the OS on process exit
cannot be left stale by a ``kill -9``, which matters here because killing a
wedged cycle is a thing that actually happens.
"""

import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import IO

__all__ = ["exclusive_cycle"]


def _try_lock(handle: IO[str]) -> bool:
    """Take an exclusive advisory lock without blocking."""
    if sys.platform == "win32":
        import msvcrt

        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True

    # Reachable on the collection host. mypy narrows `sys.platform` to whichever
    # machine is type-checking, so on the Windows authoring box it decides this
    # branch is dead; it is the only branch that ever runs in production.
    import fcntl  # type: ignore[unreachable]

    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


@contextmanager
def exclusive_cycle(corpus_root: Path, name: str = "manifest") -> Iterator[bool]:
    """Hold an advisory lock so two cycles of the same collector cannot overlap.

    Two probers running at once double the load we place on every third-party
    host and make both slower, so the second must decline rather than compete.
    The same applies to two backfills, which would additionally race each other's
    checkpoints.

    Args:
        corpus_root: Corpus directory; the lock lives under its ``state/``.
        name: Collector name, so different collectors take different locks.

    Yields:
        True if the lock was acquired, False if another cycle holds it. The lock
        is released when the process exits, however it exits.
    """
    lock_dir = corpus_root / "state"
    lock_dir.mkdir(parents=True, exist_ok=True)
    path = lock_dir / f"{name}-cycle.lock"
    # Nothing is written to the file: on Windows the locked byte range cannot be
    # truncated, and the holder's identity is available from `ps` anyway. The
    # lock is the whole point of the file.
    handle = path.open("a+")
    try:
        yield _try_lock(handle)
    finally:
        handle.close()
