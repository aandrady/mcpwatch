"""Blob store tests, centred on the zero-cost-rewrite property."""

import gzip
import hashlib
from pathlib import Path

import pytest

from mcpwatch.store import BlobIntegrityError, BlobNotFoundError, BlobStore

PAYLOAD = b'{"tools":[{"name":"read_file"}]}'


@pytest.fixture
def store(tmp_path: Path) -> BlobStore:
    return BlobStore(tmp_path / "blobs")


class TestLayout:
    def test_digest_is_sha256_of_the_uncompressed_bytes(self, store):
        assert store.put(PAYLOAD).digest == hashlib.sha256(PAYLOAD).hexdigest()

    def test_path_is_two_level_fanout_with_the_full_digest(self, store):
        digest = store.put(PAYLOAD).digest
        path = store.path_for(digest)
        assert path.relative_to(store.root).as_posix() == (
            f"{digest[:2]}/{digest[2:4]}/{digest}.json.gz"
        )
        assert path.is_file()

    def test_stored_file_is_gzip_of_the_original_bytes(self, store):
        digest = store.put(PAYLOAD).digest
        assert gzip.decompress(store.path_for(digest).read_bytes()) == PAYLOAD

    def test_a_bad_digest_cannot_escape_the_root(self, store):
        for bad in ("../../etc/passwd", "ABCD", "z" * 64, "abc"):
            with pytest.raises(ValueError, match="sha256 hex digest"):
                store.path_for(bad)


class TestDeduplication:
    def test_writing_the_same_blob_twice_adds_zero_bytes(self, store):
        first = store.put(PAYLOAD)
        size_after_first = store.disk_usage()

        second = store.put(PAYLOAD)

        assert first.created is True
        assert first.bytes_written > 0
        assert second.created is False
        assert second.bytes_written == 0
        assert second.digest == first.digest
        assert store.disk_usage() == size_after_first
        assert store.count() == 1

    def test_a_rewrite_does_not_touch_the_existing_file(self, store):
        digest = store.put(PAYLOAD).digest
        path = store.path_for(digest)
        before = (path.read_bytes(), path.stat().st_mtime_ns)

        store.put(PAYLOAD)

        assert (path.read_bytes(), path.stat().st_mtime_ns) == before

    def test_an_unchanged_daily_cycle_costs_nothing(self, store):
        """Thirty days of an unchanged server is one blob, not thirty."""
        for _ in range(30):
            store.put(PAYLOAD)
        assert store.count() == 1

    def test_different_content_is_a_different_blob(self, store):
        assert store.put(PAYLOAD).digest != store.put(PAYLOAD + b" ").digest
        assert store.count() == 2

    def test_compression_is_reproducible(self, store, tmp_path):
        other = BlobStore(tmp_path / "other")
        digest = store.put(PAYLOAD).digest
        other.put(PAYLOAD)
        assert store.path_for(digest).read_bytes() == other.path_for(digest).read_bytes()


class TestRead:
    def test_round_trip(self, store):
        digest = store.put(PAYLOAD).digest
        assert store.get(digest) == PAYLOAD

    def test_missing_blob_raises(self, store):
        with pytest.raises(BlobNotFoundError):
            store.get("0" * 64)

    def test_membership(self, store):
        digest = store.put(PAYLOAD).digest
        assert digest in store
        assert "0" * 64 not in store

    def test_corruption_is_detected(self, store):
        digest = store.put(PAYLOAD).digest
        store.path_for(digest).write_bytes(gzip.compress(b'{"tools":[]}', mtime=0))

        with pytest.raises(BlobIntegrityError):
            store.get(digest)

        assert store.get(digest, verify=False) == b'{"tools":[]}'

    def test_iter_digests_lists_everything(self, store):
        digests = {store.put(f'{{"n":{n}}}'.encode()).digest for n in range(5)}
        assert set(store.iter_digests()) == digests


class TestWriteFailure:
    def test_no_temp_files_are_left_behind(self, store):
        store.put(PAYLOAD)
        assert [p.name for p in store.root.rglob(".*.tmp")] == []

    def test_an_interrupted_write_leaves_no_blob(self, store, monkeypatch):
        def boom(*_args, **_kwargs):
            msg = "disk full"
            raise OSError(msg)

        monkeypatch.setattr("mcpwatch.store.blobs.os.replace", boom)
        with pytest.raises(OSError, match="disk full"):
            store.put(PAYLOAD)

        assert store.count() == 0
        assert list(store.root.rglob("*.tmp")) == []
