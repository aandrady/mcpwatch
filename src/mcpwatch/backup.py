"""Backup and restore for the MCPWatch corpus.

The corpus is the deliverable, and Layer-2 cannot be re-collected — a lost day is
lost permanently, and a lost corpus is the project. So backup is part of the
collection system rather than an operational afterthought.

The design falls out of two properties the store already guarantees:

* **Blobs are content-addressed and append-only.** A blob that exists never
  changes, so mirroring is a pure "copy what is missing" — no diffing, no
  deletion, and every snapshot can share one mirrored blob directory.
* **The index is a single SQLite file.** ``Connection.backup()`` is the online
  backup API: it yields a consistent copy while a collector is mid-write, which
  matters because the manifest cycle runs for 40 minutes.

Only the index is snapshotted per run; blobs accumulate in a shared mirror. That
makes a snapshot cost roughly the size of the index (~50 MB) rather than the
whole corpus, so keeping a fortnight of them is cheap.

Nothing here deletes a blob. Retention prunes old *index* snapshots only.
"""

import argparse
import json
import os
import shutil
import sqlite3
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from mcpwatch.store import BLOBS_DIRNAME, INDEX_FILENAME, BlobStore, Corpus, JsonValue, utcnow

__all__ = [
    "BackupResult",
    "backup_corpus",
    "list_snapshots",
    "main",
    "restore",
    "verify_backup",
]

SNAPSHOT_PREFIX = "index-"
SNAPSHOT_SUFFIX = ".db"
MANIFEST_NAME = "manifest.json"
DEFAULT_KEEP = 14


@dataclass(frozen=True, slots=True)
class BackupResult:
    """Outcome of one backup run."""

    snapshot: str
    index_bytes: int
    blobs_copied: int
    blob_bytes_copied: int
    blobs_total: int
    snapshots_kept: int
    snapshots_pruned: int
    verified: bool
    seconds: float

    def as_json(self) -> dict[str, JsonValue]:
        """Render for logs and the on-disk manifest."""
        return dict(asdict(self).items())


def _snapshot_name(moment: str) -> str:
    return f"{SNAPSHOT_PREFIX}{moment}{SNAPSHOT_SUFFIX}"


def _unique_snapshot(backup_root: Path, moment: str) -> Path:
    """Pick a snapshot path that does not already exist.

    Timestamps are second-resolution for readability, so two backups within the
    same second would otherwise land on one filename and the second would
    silently overwrite the first. Rare on a nightly timer, entirely normal when
    someone takes a manual backup right after one.
    """
    candidate = backup_root / _snapshot_name(moment)
    suffix = 2
    while candidate.exists():
        candidate = backup_root / f"{SNAPSHOT_PREFIX}{moment}-{suffix}{SNAPSHOT_SUFFIX}"
        suffix += 1
    return candidate


def list_snapshots(backup_root: Path) -> list[Path]:
    """Return index snapshots in the backup, oldest first."""
    return sorted(backup_root.glob(f"{SNAPSHOT_PREFIX}*{SNAPSHOT_SUFFIX}"))


def _copy_index(source_db: Path, target: Path) -> int:
    """Take a consistent online copy of the index while writers may be active.

    ``Connection.backup()`` rather than a file copy: the index runs in WAL mode
    and a plain copy taken mid-write can land torn, with the ``-wal`` sidecar
    holding committed data the ``.db`` file does not yet have.
    """
    source = sqlite3.connect(f"file:{source_db}?mode=ro", uri=True)
    try:
        destination = sqlite3.connect(str(target))
        try:
            source.backup(destination)
        finally:
            destination.close()
    finally:
        source.close()
    return target.stat().st_size


def _copy_sidecars(corpus_root: Path, backup_root: Path, moment: str) -> int:
    """Snapshot every other SQLite database sitting beside the corpus.

    ``classify.db`` is the one that matters: WP7's human adjudications are the
    most expensive rows in the project — hours of expert attention that, unlike
    a machine label, cannot be regenerated at any price. They were outside the
    backup until this existed, which made the backup's promise narrower than it
    looked.

    Discovered by glob rather than named, so a later package that puts its own
    database here is covered without anyone having to remember to add it.
    """
    total = 0
    for source in sorted(corpus_root.glob("*.db")):
        if source.name == INDEX_FILENAME:
            continue
        target = backup_root / f"{source.stem}-{moment}.db"
        total += _copy_index(source, target)
    return total


def _mirror_blobs(source: BlobStore, mirror: BlobStore, *, link: bool) -> tuple[int, int]:
    """Copy blobs missing from the mirror. Returns (count, bytes).

    Content addressing makes this trivially incremental and safe to interrupt:
    a blob either exists at its digest or it does not, and one that exists is
    never stale. The temp-file-then-rename keeps a partial copy from ever being
    visible under a valid digest.
    """
    copied = 0
    total_bytes = 0
    for digest in source.iter_digests():
        target = mirror.path_for(digest)
        if target.exists():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        origin = source.path_for(digest)
        tmp = target.with_suffix(f".{os.getpid()}.tmp")
        try:
            if link:
                os.link(origin, tmp)
            else:
                shutil.copy2(origin, tmp)
            os.replace(tmp, target)  # noqa: PTH105 - Path has no atomic-replace
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        copied += 1
        total_bytes += target.stat().st_size
    return copied, total_bytes


def verify_backup(backup_root: Path, snapshot: Path | None = None) -> tuple[bool, str]:
    """Check that a snapshot's index and the blob mirror actually agree.

    A backup nobody has opened is a hope, not a backup. This opens the snapshot
    as a real corpus and confirms every blob digest it references resolves in
    the mirror.
    """
    snapshots = list_snapshots(backup_root)
    if not snapshots:
        return False, "no snapshots present"
    chosen = snapshot or snapshots[-1]
    if not chosen.is_file():
        return False, f"snapshot {chosen.name} is missing"

    staging = backup_root / ".verify"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    try:
        shutil.copy2(chosen, staging / INDEX_FILENAME)
        # Point the staged corpus at the real mirror rather than copying it:
        # verification is about whether the references resolve, and duplicating
        # hundreds of megabytes to find that out would make nobody run it.
        with Corpus(staging) as staged:
            mirror = BlobStore(backup_root / BLOBS_DIRNAME)
            referenced = staged.index.referenced_digests()
            missing = [d for d in referenced if not mirror.exists(d)]
            observations = staged.index.count_observations()
        if missing:
            return False, f"{len(missing)} of {len(referenced)} referenced blobs missing"
        return True, f"{observations} observations, {len(referenced)} blob references all resolve"
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def backup_corpus(
    corpus_root: Path,
    backup_root: Path,
    *,
    keep: int = DEFAULT_KEEP,
    link: bool = False,
    verify: bool = True,
) -> BackupResult:
    """Back a corpus up into ``backup_root``.

    Args:
        corpus_root: The live corpus.
        backup_root: Destination. Created if absent.
        keep: Index snapshots to retain. Blobs are never pruned.
        link: Hard-link blobs instead of copying. Only valid on the same
            filesystem, where it makes an on-box snapshot nearly free — but it
            shares storage with the original, so it is not protection against
            a failing disk.
        verify: Open the finished snapshot and confirm its blob references
            resolve.

    Returns:
        A :class:`BackupResult`.
    """
    started = time.monotonic()
    backup_root.mkdir(parents=True, exist_ok=True)

    moment = utcnow().strftime("%Y%m%dT%H%M%SZ")
    snapshot = _unique_snapshot(backup_root, moment)

    # Blobs first, index second. The index is what names blobs, so mirroring
    # blobs before snapshotting the index guarantees the snapshot never
    # references something the mirror lacks. The reverse order has a window
    # where it does.
    source_blobs = BlobStore(corpus_root / BLOBS_DIRNAME)
    mirror_blobs = BlobStore(backup_root / BLOBS_DIRNAME)
    copied, copied_bytes = _mirror_blobs(source_blobs, mirror_blobs, link=link)

    index_bytes = _copy_index(corpus_root / INDEX_FILENAME, snapshot)
    sidecar_bytes = _copy_sidecars(corpus_root, backup_root, moment)

    existing = list_snapshots(backup_root)
    pruned = 0
    for stale in existing[: max(0, len(existing) - keep)]:
        stale.unlink(missing_ok=True)
        pruned += 1

    ok, detail = (True, "not verified")
    if verify:
        ok, detail = verify_backup(backup_root, snapshot)

    result = BackupResult(
        snapshot=snapshot.name,
        index_bytes=index_bytes + sidecar_bytes,
        blobs_copied=copied,
        blob_bytes_copied=copied_bytes,
        blobs_total=mirror_blobs.count(),
        snapshots_kept=len(list_snapshots(backup_root)),
        snapshots_pruned=pruned,
        verified=ok,
        seconds=round(time.monotonic() - started, 3),
    )
    payload = result.as_json()
    payload["verify_detail"] = detail
    payload["created_at"] = utcnow().isoformat()
    (backup_root / MANIFEST_NAME).write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )
    return result


def restore(backup_root: Path, target_root: Path, *, snapshot: Path | None = None) -> Path:
    """Rebuild a working corpus from a backup into an empty directory.

    Deliberately refuses a non-empty target. Restore is the operation performed
    under pressure, and quietly merging into an existing corpus would be a
    hard mistake to notice and an impossible one to undo.

    Returns:
        The restored corpus root.

    Raises:
        FileExistsError: If ``target_root`` exists and is not empty.
        FileNotFoundError: If the backup holds no snapshot.
    """
    snapshots = list_snapshots(backup_root)
    if not snapshots:
        msg = f"no snapshots in {backup_root}"
        raise FileNotFoundError(msg)
    chosen = snapshot or snapshots[-1]

    if target_root.exists() and any(target_root.iterdir()):
        msg = f"refusing to restore into non-empty {target_root}"
        raise FileExistsError(msg)

    target_root.mkdir(parents=True, exist_ok=True)
    shutil.copy2(chosen, target_root / INDEX_FILENAME)
    shutil.copytree(backup_root / BLOBS_DIRNAME, target_root / BLOBS_DIRNAME, dirs_exist_ok=True)
    return target_root


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns 0 on success, 1 on failure."""
    parser = argparse.ArgumentParser(
        prog="python -m mcpwatch.backup",
        description="Back up, verify, or restore the MCPWatch corpus.",
    )
    parser.add_argument("--corpus", type=Path, default=_default_corpus_root())
    parser.add_argument("--dest", type=Path, default=_default_backup_root())
    parser.add_argument("--keep", type=int, default=DEFAULT_KEEP)
    parser.add_argument(
        "--link",
        action="store_true",
        help="hard-link blobs (same filesystem only; not disk-failure protection)",
    )
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument(
        "--verify-only", action="store_true", help="check an existing backup and exit"
    )
    parser.add_argument(
        "--restore-to", type=Path, default=None, help="rebuild a corpus into an empty directory"
    )
    args = parser.parse_args(argv)

    if args.restore_to is not None:
        try:
            root = restore(args.dest, args.restore_to)
        except (FileExistsError, FileNotFoundError) as exc:
            print(f"restore failed: {exc}", file=sys.stderr)
            return 1
        with Corpus(root) as restored:
            missing = restored.missing_blobs()
            observations = restored.index.count_observations()
        print(
            json.dumps(
                {
                    "restored_to": str(root),
                    "observations": observations,
                    "missing_blobs": len(missing),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1 if missing else 0

    if args.verify_only:
        ok, detail = verify_backup(args.dest)
        print(f"{'OK  ' if ok else 'FAIL'} {args.dest}: {detail}")
        return 0 if ok else 1

    result = backup_corpus(
        args.corpus, args.dest, keep=args.keep, link=args.link, verify=not args.no_verify
    )
    print(json.dumps(result.as_json(), indent=2, sort_keys=True))
    if not result.verified:
        print("backup did not verify", file=sys.stderr)
        return 1
    return 0


def _default_corpus_root() -> Path:
    override = os.environ.get("MCPWATCH_CORPUS")
    return Path(override) if override else Path.home() / "mcpwatch-corpus"


def _default_backup_root() -> Path:
    override = os.environ.get("MCPWATCH_BACKUP")
    return Path(override) if override else Path.home() / "mcpwatch-backup"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
