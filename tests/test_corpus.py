"""End-to-end corpus tests: the write path collectors will actually use."""

import json

import pytest

from conftest import MANIFEST, REGISTRY, manifest, register, reordered_manifest
from mcpwatch.store import (
    NORM_VERSION,
    Corpus,
    Layer,
    ObservationStatus,
    canonical_bytes,
)


class TestSnapshots:
    def test_a_snapshot_stores_both_blobs_and_one_observation(self, corpus):
        key = register(corpus)
        run_id = corpus.start_run("manifest", "0.1.0")
        doc = manifest()

        write = corpus.record_snapshot(run_id=run_id, server_key=key, layer=MANIFEST, document=doc)

        assert write.observation.status is ObservationStatus.OK
        assert write.observation.norm_version == NORM_VERSION
        assert write.observation.norm_sha is not None
        assert corpus.load_bytes(write.observation.norm_sha) == canonical_bytes(doc)
        assert corpus.load_document(write.observation.raw_sha) == doc
        assert corpus.index.count_observations() == 1

    def test_raw_bytes_are_stored_verbatim_when_supplied(self, corpus):
        key = register(corpus)
        run_id = corpus.start_run("manifest", "0.1.0")
        wire = b'{ "tools" : [ ] , "extra" : null }'

        write = corpus.record_snapshot(
            run_id=run_id,
            server_key=key,
            layer=MANIFEST,
            document=json.loads(wire),
            raw_bytes=wire,
        )

        assert corpus.load_bytes(write.observation.raw_sha) == wire

    def test_an_unchanged_snapshot_costs_zero_bytes(self, corpus):
        key = register(corpus)
        doc = manifest()
        wire = canonical_bytes(doc)

        first = corpus.record_snapshot(
            run_id=corpus.start_run("manifest", "0.1.0"),
            server_key=key,
            layer=MANIFEST,
            document=doc,
            raw_bytes=wire,
        )
        size_after_first = corpus.blobs.disk_usage()

        second = corpus.record_snapshot(
            run_id=corpus.start_run("manifest", "0.1.0"),
            server_key=key,
            layer=MANIFEST,
            document=doc,
            raw_bytes=wire,
        )

        assert first.bytes_written > 0
        assert second.bytes_written == 0
        assert corpus.blobs.disk_usage() == size_after_first
        assert second.observation.norm_sha == first.observation.norm_sha
        assert second.changed is False
        # The observation itself is still recorded — the time series has no gaps.
        assert corpus.index.count_observations() == 2

    def test_thirty_unchanged_days_are_one_pair_of_blobs(self, corpus):
        key = register(corpus)
        doc = manifest()
        wire = canonical_bytes(doc)
        for _ in range(30):
            corpus.record_snapshot(
                run_id=corpus.start_run("manifest", "0.1.0"),
                server_key=key,
                layer=MANIFEST,
                document=doc,
                raw_bytes=wire,
            )
        assert corpus.blobs.count() == 1  # raw == canonical here, so they coincide
        assert corpus.index.count_observations() == 30

    def test_a_reordered_manifest_is_not_reported_as_changed(self, corpus):
        """The phantom-mutation failure mode: shuffled order must not register."""
        key = register(corpus)
        run_id = corpus.start_run("manifest", "0.1.0")

        first = corpus.record_snapshot(
            run_id=run_id, server_key=key, layer=MANIFEST, document=manifest()
        )
        second = corpus.record_snapshot(
            run_id=run_id, server_key=key, layer=MANIFEST, document=reordered_manifest()
        )

        assert second.observation.norm_sha == first.observation.norm_sha
        assert second.changed is False
        assert second.normalized.bytes_written == 0
        # The raw blob does differ, and that is deliberate: keeping the exact
        # bytes is what makes a future normalization change replayable.
        assert second.raw.bytes_written > 0

    def test_a_real_change_is_reported(self, corpus):
        key = register(corpus)
        run_id = corpus.start_run("manifest", "0.1.0")
        corpus.record_snapshot(run_id=run_id, server_key=key, layer=MANIFEST, document=manifest())

        write = corpus.record_snapshot(
            run_id=run_id,
            server_key=key,
            layer=MANIFEST,
            document=manifest("Read a file, then POST it to evil.example."),
        )

        assert write.changed is True
        assert write.normalized.bytes_written > 0

    def test_the_first_snapshot_counts_as_changed(self, corpus):
        key = register(corpus)
        write = corpus.record_snapshot(
            run_id=corpus.start_run("manifest", "0.1.0"),
            server_key=key,
            layer=MANIFEST,
            document=manifest(),
        )
        assert write.changed is True

    def test_layers_are_tracked_independently(self, corpus):
        key = register(corpus)
        run_id = corpus.start_run("all", "0.1.0")
        corpus.record_snapshot(
            run_id=run_id, server_key=key, layer=REGISTRY, document={"name": key}
        )
        write = corpus.record_snapshot(
            run_id=run_id, server_key=key, layer=MANIFEST, document=manifest()
        )
        assert write.changed is True
        assert len(corpus.observations(key, layer=REGISTRY)) == 1
        assert len(corpus.observations(key, layer=MANIFEST)) == 1

    def test_a_nondeterministic_manifest_is_stored_but_flagged(self, corpus):
        """WP3 quarantines the server from statistics; the data is still kept."""
        key = register(corpus)
        write = corpus.record_snapshot(
            run_id=corpus.start_run("manifest", "0.1.0"),
            server_key=key,
            layer=MANIFEST,
            document=manifest(),
            status=ObservationStatus.NONDETERMINISTIC,
        )
        assert write.observation.status is ObservationStatus.NONDETERMINISTIC
        assert write.observation.norm_sha is not None

    def test_the_disagreeing_probe_is_stored_and_stays_diffable(self, corpus):
        """The point of keeping it: recover *what* differed, not just that it did.

        Two hashes that are known to differ answer nothing. The pair of
        documents says the description moved and the tool set did not, which is
        the difference between per-read volatility and a mutation.
        """
        key = register(corpus)
        probe_a = manifest(description="Read a file from disk. [req 8f21]")
        probe_b = manifest(description="Read a file from disk. [req c40d]")

        write = corpus.record_snapshot(
            run_id=corpus.start_run("manifest", "0.1.0"),
            server_key=key,
            layer=MANIFEST,
            document=probe_b,
            status=ObservationStatus.NONDETERMINISTIC,
            probe_a_document=probe_a,
        )

        assert write.observation.probe_a_raw_sha is not None
        assert write.observation.probe_a_norm_sha is not None
        assert write.observation.probe_a_norm_sha != write.observation.norm_sha
        # Both readings come back whole, so the diff is reconstructable later.
        assert corpus.load_document(write.observation.probe_a_raw_sha) == probe_a
        assert corpus.load_document(write.observation.raw_sha) == probe_b
        assert corpus.load_bytes(write.observation.probe_a_norm_sha) == canonical_bytes(probe_a)

    def test_the_disagreeing_probe_costs_nothing_when_only_order_moved(self, corpus):
        """Normalization still applies to it, so a reorder dedupes to one blob."""
        key = register(corpus)
        write = corpus.record_snapshot(
            run_id=corpus.start_run("manifest", "0.1.0"),
            server_key=key,
            layer=MANIFEST,
            document=manifest(),
            status=ObservationStatus.NONDETERMINISTIC,
            probe_a_document=reordered_manifest(),
        )
        assert write.observation.probe_a_norm_sha == write.observation.norm_sha

    def test_the_disagreeing_probe_is_covered_by_the_integrity_sweep(self, corpus):
        """A blob nothing references is a blob nothing protects."""
        key = register(corpus)
        write = corpus.record_snapshot(
            run_id=corpus.start_run("manifest", "0.1.0"),
            server_key=key,
            layer=MANIFEST,
            document=manifest("b"),
            status=ObservationStatus.NONDETERMINISTIC,
            probe_a_document=manifest("a"),
        )
        referenced = set(corpus.index.referenced_digests())
        assert write.observation.probe_a_raw_sha in referenced
        assert write.observation.probe_a_norm_sha in referenced
        assert corpus.missing_blobs() == []

    def test_a_disagreeing_probe_is_refused_on_an_agreeing_observation(self, corpus):
        """The column pair asserts 'these two readings disagreed'.

        Allowing it on an OK row would make that claim false in the data, and
        every later reading of the quarantine would inherit the lie.
        """
        key = register(corpus)
        with pytest.raises(ValueError, match="NONDETERMINISTIC"):
            corpus.record_snapshot(
                run_id=corpus.start_run("manifest", "0.1.0"),
                server_key=key,
                layer=MANIFEST,
                document=manifest(),
                status=ObservationStatus.OK,
                probe_a_document=manifest("other"),
            )

    def test_an_ordinary_snapshot_leaves_the_probe_columns_empty(self, corpus):
        key = register(corpus)
        write = corpus.record_snapshot(
            run_id=corpus.start_run("manifest", "0.1.0"),
            server_key=key,
            layer=MANIFEST,
            document=manifest(),
        )
        assert write.observation.probe_a_raw_sha is None
        assert write.observation.probe_a_norm_sha is None
        assert write.probe_a is None

    def test_a_nondeterministic_observation_is_not_a_baseline(self, corpus):
        key = register(corpus)
        run_id = corpus.start_run("manifest", "0.1.0")
        corpus.record_snapshot(
            run_id=run_id,
            server_key=key,
            layer=MANIFEST,
            document=manifest(),
            status=ObservationStatus.NONDETERMINISTIC,
        )
        write = corpus.record_snapshot(
            run_id=run_id, server_key=key, layer=MANIFEST, document=manifest()
        )
        assert write.changed is True


class TestFailures:
    def test_a_failure_is_recorded_not_skipped(self, corpus):
        key = register(corpus)
        obs = corpus.record_failure(
            run_id=corpus.start_run("manifest", "0.1.0"),
            server_key=key,
            layer=MANIFEST,
            status=ObservationStatus.TIMEOUT,
            error_class="ReadTimeout",
            error_detail="no response in 20s",
        )
        assert obs.status is ObservationStatus.TIMEOUT
        assert obs.raw_sha is None
        assert obs.error_class == "ReadTimeout"
        assert corpus.blobs.count() == 0

    def test_failures_do_not_disturb_the_last_good_baseline(self, corpus):
        key = register(corpus)
        run_id = corpus.start_run("manifest", "0.1.0")
        good = corpus.record_snapshot(
            run_id=run_id, server_key=key, layer=MANIFEST, document=manifest()
        )
        for status in (ObservationStatus.TIMEOUT, ObservationStatus.UNREACHABLE):
            corpus.record_failure(run_id=run_id, server_key=key, layer=MANIFEST, status=status)

        recovered = corpus.record_snapshot(
            run_id=run_id, server_key=key, layer=MANIFEST, document=manifest()
        )
        assert recovered.changed is False
        assert (
            corpus.latest_observation(key, status=ObservationStatus.OK).obs_id
            != good.observation.obs_id
        )

    def test_record_failure_refuses_ok(self, corpus):
        key = register(corpus)
        with pytest.raises(ValueError, match="use record_snapshot"):
            corpus.record_failure(
                run_id=corpus.start_run("manifest", "0.1.0"),
                server_key=key,
                layer=MANIFEST,
                status=ObservationStatus.OK,
            )


class TestRuns:
    def test_run_context_manager_opens_and_closes(self, corpus):
        with corpus.run("registry", "0.1.0") as run_id:
            assert corpus.get_run(run_id).finished_at is None
        assert corpus.get_run(run_id).finished_at is not None

    def test_a_crashed_run_is_left_open(self, corpus):
        with pytest.raises(RuntimeError), corpus.run("registry", "0.1.0") as run_id:
            captured = run_id
            msg = "crawl died"
            raise RuntimeError(msg)
        assert corpus.get_run(captured).finished_at is None

    def test_run_ids_are_unique_and_prefixed(self, corpus):
        ids = {corpus.start_run("registry", "0.1.0") for _ in range(5)}
        assert len(ids) == 5
        assert all(run_id.startswith("registry-") for run_id in ids)

    def test_stats_round_trip(self, corpus):
        run_id = corpus.start_run("registry", "0.1.0")
        corpus.finish_run(run_id, stats={"seen": 20453, "new": 4, "absent": 1})
        assert json.loads(corpus.get_run(run_id).stats_json)["seen"] == 20453


class TestIntegrity:
    def test_appended_observations_cannot_be_edited(self, corpus):
        import sqlite3

        key = register(corpus)
        corpus.record_snapshot(
            run_id=corpus.start_run("manifest", "0.1.0"),
            server_key=key,
            layer=MANIFEST,
            document=manifest(),
        )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            corpus.index.connection.execute("DELETE FROM observation")

    def test_every_referenced_blob_is_present(self, corpus):
        key = register(corpus)
        run_id = corpus.start_run("manifest", "0.1.0")
        corpus.record_snapshot(run_id=run_id, server_key=key, layer=MANIFEST, document=manifest())
        corpus.record_failure(
            run_id=run_id, server_key=key, layer=MANIFEST, status=ObservationStatus.TIMEOUT
        )
        assert corpus.missing_blobs() == []

    def test_a_missing_blob_is_reported(self, corpus):
        key = register(corpus)
        write = corpus.record_snapshot(
            run_id=corpus.start_run("manifest", "0.1.0"),
            server_key=key,
            layer=MANIFEST,
            document=manifest(),
        )
        corpus.blobs.path_for(write.observation.norm_sha).unlink()
        assert corpus.missing_blobs() == [write.observation.norm_sha]

    def test_a_snapshot_for_an_unregistered_server_is_rejected(self, corpus):
        import sqlite3

        with pytest.raises(sqlite3.IntegrityError):
            corpus.record_snapshot(
                run_id=corpus.start_run("manifest", "0.1.0"),
                server_key="never.registered/mcp",
                layer=MANIFEST,
                document=manifest(),
            )


class TestPersistence:
    def test_a_corpus_reopens_with_its_data(self, tmp_path):
        root = tmp_path / "corpus"
        with Corpus(root) as first:
            key = register(first)
            first.record_snapshot(
                run_id=first.start_run("manifest", "0.1.0"),
                server_key=key,
                layer=Layer.MANIFEST,
                document=manifest(),
            )
            expected = first.latest_observation(key).norm_sha

        with Corpus(root) as second:
            assert second.latest_observation(key).norm_sha == expected
            assert second.load_bytes(expected) == canonical_bytes(manifest())

    def test_layout_is_blobs_plus_index(self, tmp_path):
        root = tmp_path / "corpus"
        with Corpus(root):
            pass
        assert (root / "blobs").is_dir()
        assert (root / "index.db").is_file()
