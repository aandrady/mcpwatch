"""Backup tests. The corpus cannot be re-collected, so these are load-bearing."""

import sqlite3

import pytest

from conftest import MANIFEST, manifest, register
from mcpwatch.backup import (
    backup_corpus,
    list_snapshots,
    main,
    restore,
    verify_backup,
)
from mcpwatch.store import Corpus


def populate(corpus, servers=3, description="Read a file from disk."):
    run_id = corpus.start_run("manifest", "0.1.0")
    for n in range(servers):
        key = register(corpus, f"s{n}.example/mcp")
        corpus.record_snapshot(
            run_id=run_id, server_key=key, layer=MANIFEST, document=manifest(description)
        )
    corpus.finish_run(run_id)
    return run_id


class TestBackup:
    def test_a_backup_captures_index_and_blobs(self, corpus, tmp_path):
        populate(corpus)
        dest = tmp_path / "backup"

        result = backup_corpus(corpus.root, dest)

        assert result.verified is True
        assert result.blobs_copied == corpus.blobs.count()
        assert result.index_bytes > 0
        assert (dest / result.snapshot).is_file()

    def test_backups_are_incremental(self, corpus, tmp_path):
        """Content addressing makes 'copy what is missing' the whole algorithm."""
        populate(corpus)
        dest = tmp_path / "backup"
        backup_corpus(corpus.root, dest)

        second = backup_corpus(corpus.root, dest)

        assert second.blobs_copied == 0
        assert second.blob_bytes_copied == 0
        assert second.verified is True

    def test_new_data_is_picked_up(self, corpus, tmp_path):
        populate(corpus)
        dest = tmp_path / "backup"
        backup_corpus(corpus.root, dest)

        populate(corpus, servers=1, description="A different tool description.")
        third = backup_corpus(corpus.root, dest)

        assert third.blobs_copied > 0

    def test_each_run_adds_a_snapshot_sharing_one_blob_mirror(self, corpus, tmp_path):
        populate(corpus)
        dest = tmp_path / "backup"
        for _ in range(3):
            backup_corpus(corpus.root, dest)

        assert len(list_snapshots(dest)) == 3
        # One mirror serves every snapshot: blobs never change once written.
        assert len(list((dest / "blobs").glob("*/*/*.json.gz"))) == corpus.blobs.count()

    def test_retention_prunes_snapshots_but_never_blobs(self, corpus, tmp_path):
        populate(corpus)
        dest = tmp_path / "backup"
        for _ in range(5):
            backup_corpus(corpus.root, dest, keep=2)

        assert len(list_snapshots(dest)) == 2
        assert len(list((dest / "blobs").glob("*/*/*.json.gz"))) == corpus.blobs.count()

    def test_a_backup_taken_mid_write_is_still_consistent(self, corpus, tmp_path):
        """Collectors run for 40 minutes; backups cannot wait for a quiet moment."""
        populate(corpus)
        dest = tmp_path / "backup"

        run_id = corpus.start_run("manifest", "0.1.0")
        key = register(corpus, "midwrite.example/mcp")
        corpus.record_snapshot(run_id=run_id, server_key=key, layer=MANIFEST, document=manifest())
        # Run left deliberately open, as it would be mid-cycle.
        result = backup_corpus(corpus.root, dest)

        assert result.verified is True

    def test_hard_linking_shares_storage(self, corpus, tmp_path):
        populate(corpus)
        dest = tmp_path / "backup"

        result = backup_corpus(corpus.root, dest, link=True)

        assert result.verified is True
        digest = next(iter(corpus.blobs.iter_digests()))
        assert (dest / "blobs").exists()
        assert corpus.blobs.path_for(digest).stat().st_size > 0


class TestVerify:
    def test_verification_notices_a_missing_blob(self, corpus, tmp_path):
        populate(corpus)
        dest = tmp_path / "backup"
        backup_corpus(corpus.root, dest)

        victim = next(iter((dest / "blobs").glob("*/*/*.json.gz")))
        victim.unlink()

        ok, detail = verify_backup(dest)
        assert ok is False
        assert "missing" in detail

    def test_verification_of_an_empty_destination_fails(self, tmp_path):
        empty = tmp_path / "nothing"
        empty.mkdir()
        ok, detail = verify_backup(empty)
        assert ok is False
        assert "no snapshots" in detail

    def test_verification_leaves_no_staging_directory(self, corpus, tmp_path):
        populate(corpus)
        dest = tmp_path / "backup"
        backup_corpus(corpus.root, dest)
        verify_backup(dest)
        assert not (dest / ".verify").exists()


class TestRestore:
    def test_a_restored_corpus_matches_the_original(self, corpus, tmp_path):
        """The rehearsal WP4 asks for: restore into a clean directory."""
        populate(corpus)
        expected_obs = corpus.index.count_observations()
        expected_blobs = corpus.blobs.count()
        key = "s0.example/mcp"
        expected_sha = corpus.latest_observation(key, layer=MANIFEST).norm_sha

        dest = tmp_path / "backup"
        backup_corpus(corpus.root, dest)

        root = restore(dest, tmp_path / "restored")

        with Corpus(root) as restored:
            assert restored.index.count_observations() == expected_obs
            assert restored.blobs.count() == expected_blobs
            assert restored.latest_observation(key, layer=MANIFEST).norm_sha == expected_sha
            assert restored.missing_blobs() == []
            # The restored corpus is usable, not just readable.
            assert restored.load_bytes(expected_sha)

    def test_the_append_only_trigger_survives_a_restore(self, corpus, tmp_path):
        """Restoring must not quietly produce an editable corpus."""
        populate(corpus)
        dest = tmp_path / "backup"
        backup_corpus(corpus.root, dest)
        root = restore(dest, tmp_path / "restored")

        with Corpus(root) as restored, pytest.raises(sqlite3.IntegrityError, match="append-only"):
            restored.index.connection.execute("DELETE FROM observation")

    def test_restore_refuses_a_non_empty_target(self, corpus, tmp_path):
        populate(corpus)
        dest = tmp_path / "backup"
        backup_corpus(corpus.root, dest)

        occupied = tmp_path / "occupied"
        occupied.mkdir()
        (occupied / "something.txt").write_text("in the way")

        with pytest.raises(FileExistsError, match="non-empty"):
            restore(dest, occupied)

    def test_restore_without_a_backup_fails_loudly(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(FileNotFoundError):
            restore(empty, tmp_path / "target")


class TestCli:
    def test_backup_then_verify_then_restore(self, corpus, tmp_path, capsys):
        populate(corpus)
        dest = tmp_path / "backup"

        assert main(["--corpus", str(corpus.root), "--dest", str(dest)]) == 0
        capsys.readouterr()

        assert main(["--dest", str(dest), "--verify-only"]) == 0
        assert "OK" in capsys.readouterr().out

        assert main(["--dest", str(dest), "--restore-to", str(tmp_path / "restored")]) == 0
        assert '"missing_blobs": 0' in capsys.readouterr().out

    def test_verify_only_fails_on_a_damaged_backup(self, corpus, tmp_path, capsys):
        populate(corpus)
        dest = tmp_path / "backup"
        main(["--corpus", str(corpus.root), "--dest", str(dest)])
        capsys.readouterr()

        next(iter((dest / "blobs").glob("*/*/*.json.gz"))).unlink()

        assert main(["--dest", str(dest), "--verify-only"]) == 1
        assert "FAIL" in capsys.readouterr().out


class TestSnapshotNaming:
    def test_two_backups_in_the_same_second_do_not_collide(self, corpus, tmp_path):
        """Second-resolution names would otherwise overwrite silently."""
        populate(corpus)
        dest = tmp_path / "backup"

        first = backup_corpus(corpus.root, dest)
        second = backup_corpus(corpus.root, dest)

        assert first.snapshot != second.snapshot
        assert len(list_snapshots(dest)) == 2
