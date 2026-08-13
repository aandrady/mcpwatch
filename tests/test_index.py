"""SQLite index tests, centred on the append-only guarantee."""

import sqlite3
from pathlib import Path

import pytest

from mcpwatch.store import (
    SCHEMA_VERSION,
    Layer,
    ObservationIndex,
    ObservationStatus,
    StoreError,
)

SHA = "a" * 64


@pytest.fixture
def index(tmp_path: Path):
    idx = ObservationIndex(tmp_path / "index.db")
    yield idx
    idx.close()


@pytest.fixture
def seeded(index: ObservationIndex) -> ObservationIndex:
    index.insert_run(
        run_id="r1",
        collector="registry",
        collector_version="0.1.0",
        started_at="2026-08-07T00:00:00.000000+00:00",
    )
    index.upsert_server(
        server_key="example.com/mcp",
        registry_name="example.com/mcp",
        repo_url="https://github.com/example/mcp",
        primary_endpoint="https://example.com/mcp",
        seen_at="2026-08-07T00:00:00.000000+00:00",
    )
    return index


def _insert(index: ObservationIndex, **overrides) -> int:
    kwargs = {
        "run_id": "r1",
        "server_key": "example.com/mcp",
        "layer": Layer.MANIFEST,
        "observed_at": "2026-08-07T00:00:00.000000+00:00",
        "status": ObservationStatus.OK,
        "raw_sha": SHA,
        "norm_sha": SHA,
        "norm_version": 1,
    }
    kwargs.update(overrides)
    return index.insert_observation(**kwargs)


class TestSchema:
    def test_wal_mode_is_enabled(self, index):
        mode = index.connection.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"

    def test_foreign_keys_are_enforced(self, index):
        assert index.connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1

    def test_schema_version_is_recorded(self, index):
        assert index.schema_version >= 1

    def test_opening_an_existing_database_is_idempotent(self, tmp_path):
        path = tmp_path / "index.db"
        first = ObservationIndex(path)
        first.close()
        second = ObservationIndex(path)
        assert second.count_observations() == 0
        second.close()


V1_SCHEMA = """
CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE run (
    run_id TEXT PRIMARY KEY, collector TEXT NOT NULL, collector_version TEXT NOT NULL,
    started_at TEXT NOT NULL, finished_at TEXT, stats_json TEXT
);
CREATE TABLE server (
    server_key TEXT PRIMARY KEY, registry_name TEXT NOT NULL, repo_url TEXT,
    primary_endpoint TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
);
CREATE TABLE server_identity (
    identity_id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_key TEXT NOT NULL REFERENCES server(server_key), observed_at TEXT NOT NULL,
    registry_name TEXT NOT NULL, repo_url TEXT, primary_endpoint TEXT
);
CREATE TABLE observation (
    obs_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES run(run_id),
    server_key TEXT NOT NULL REFERENCES server(server_key),
    layer TEXT NOT NULL, observed_at TEXT NOT NULL, status TEXT NOT NULL,
    raw_sha TEXT, norm_sha TEXT, norm_version INTEGER,
    error_class TEXT, error_detail TEXT
);
INSERT INTO schema_meta VALUES('schema_version', '1');
INSERT INTO run VALUES('r1', 'registry', '0.1.0', '2026-08-07T00:00:00.000000+00:00', NULL, NULL);
INSERT INTO server VALUES(
    'example.com/mcp', 'example.com/mcp', NULL, NULL,
    '2026-08-07T00:00:00.000000+00:00', '2026-08-07T00:00:00.000000+00:00'
);
INSERT INTO observation(run_id, server_key, layer, observed_at, status, raw_sha, norm_sha,
                        norm_version)
VALUES('r1', 'example.com/mcp', 'registry', '2026-08-07T00:00:00.000000+00:00', 'ok',
       'aaaa', 'bbbb', 1);
"""


class TestMigration:
    """The corpus cannot be re-collected, so every migration must be additive."""

    @pytest.fixture
    def v1_database(self, tmp_path: Path) -> Path:
        path = tmp_path / "index.db"
        conn = sqlite3.connect(path)
        conn.executescript(V1_SCHEMA)
        conn.commit()
        conn.close()
        return path

    def test_a_v1_corpus_gains_the_new_columns_without_losing_a_row(self, v1_database):
        index = ObservationIndex(v1_database)
        try:
            assert index.schema_version == SCHEMA_VERSION
            assert index.count_observations() == 1
            observation = index.observations("example.com/mcp")[0]
            assert observation.raw_sha == "aaaa"
            assert observation.published_at is None
            # Nothing about the ordering of pre-existing data changes: with no
            # publication date, the chronology key is the observation time.
            assert observation.effective_at == observation.observed_at
            # v3's columns arrive empty on history that predates them, which is
            # the honest value: nobody kept the other probe back then.
            assert observation.probe_a_raw_sha is None
            assert observation.probe_a_norm_sha is None
        finally:
            index.close()

    def test_migrating_twice_is_a_no_op(self, v1_database):
        first = ObservationIndex(v1_database)
        first.close()
        second = ObservationIndex(v1_database)
        try:
            assert second.schema_version == SCHEMA_VERSION
            assert second.count_observations() == 1
        finally:
            second.close()

    def test_a_v2_corpus_migrates_to_v3(self, tmp_path: Path):
        """The production corpus is v2, so this is the path it will take."""
        path = tmp_path / "index.db"
        first = ObservationIndex(path)
        first.close()
        # Strip v3's columns back off to synthesise a v2 database. SQLite can
        # DROP a plain column, which is exactly what makes this reversible.
        conn = sqlite3.connect(path)
        conn.execute("DROP TRIGGER observation_no_update")
        for column in ("probe_a_raw_sha", "probe_a_norm_sha"):
            conn.execute(f"ALTER TABLE observation DROP COLUMN {column}")
        conn.execute("UPDATE schema_meta SET value='2' WHERE key='schema_version'")
        conn.commit()
        conn.close()

        index = ObservationIndex(path)
        try:
            assert index.schema_version == SCHEMA_VERSION
            columns = {
                row["name"] for row in index.connection.execute("PRAGMA table_xinfo(observation)")
            }
            assert {"probe_a_raw_sha", "probe_a_norm_sha"} <= columns
        finally:
            index.close()

    def test_a_corpus_from_a_newer_build_is_refused(self, v1_database):
        conn = sqlite3.connect(v1_database)
        conn.execute("UPDATE schema_meta SET value = '99' WHERE key = 'schema_version'")
        conn.commit()
        conn.close()

        with pytest.raises(StoreError, match="refusing to open"):
            ObservationIndex(v1_database)

    def test_required_indexes_exist(self, index):
        names = {
            row["name"]
            for row in index.connection.execute("SELECT name FROM sqlite_master WHERE type='index'")
        }
        assert {"observation_server_time", "observation_norm_sha"} <= names

    def test_observation_uses_the_server_time_index(self, seeded):
        plan = seeded.connection.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM observation"
            " WHERE server_key = ? ORDER BY observed_at",
            ("example.com/mcp",),
        ).fetchall()
        assert any("observation_server_time" in row["detail"] for row in plan)


class TestAppendOnly:
    def test_update_is_rejected(self, seeded):
        _insert(seeded)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            seeded.connection.execute("UPDATE observation SET status = 'skipped'")
        assert seeded.get_observation(1).status is ObservationStatus.OK

    def test_delete_is_rejected(self, seeded):
        _insert(seeded)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            seeded.connection.execute("DELETE FROM observation")
        assert seeded.count_observations() == 1

    def test_update_of_a_single_column_is_rejected(self, seeded):
        _insert(seeded)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            seeded.connection.execute(
                "UPDATE observation SET norm_sha = ? WHERE obs_id = 1", ("b" * 64,)
            )

    def test_delete_with_a_where_clause_is_rejected(self, seeded):
        _insert(seeded)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            seeded.connection.execute("DELETE FROM observation WHERE obs_id = 1")

    def test_server_identity_is_append_only_too(self, seeded):
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            seeded.connection.execute("DELETE FROM server_identity")

    def test_obs_ids_are_never_reused(self, seeded):
        first = _insert(seeded)
        second = _insert(seeded)
        assert second > first


class TestConstraints:
    def test_unknown_layer_is_rejected(self, seeded):
        with pytest.raises(sqlite3.IntegrityError):
            seeded.connection.execute(
                "INSERT INTO observation(run_id, server_key, layer, observed_at, status)"
                " VALUES('r1', 'example.com/mcp', 'sandbox', 'now', 'ok')"
            )

    def test_unknown_status_is_rejected(self, seeded):
        with pytest.raises(sqlite3.IntegrityError):
            seeded.connection.execute(
                "INSERT INTO observation(run_id, server_key, layer, observed_at, status)"
                " VALUES('r1', 'example.com/mcp', 'manifest', 'now', 'probably_fine')"
            )

    def test_ok_without_hashes_is_rejected(self, seeded):
        """A successful observation that points at nothing is a collector bug."""
        with pytest.raises(sqlite3.IntegrityError):
            _insert(seeded, raw_sha=None)
        with pytest.raises(sqlite3.IntegrityError):
            _insert(seeded, norm_sha=None)
        with pytest.raises(sqlite3.IntegrityError):
            _insert(seeded, norm_version=None)

    def test_failure_without_hashes_is_allowed(self, seeded):
        obs_id = _insert(
            seeded,
            status=ObservationStatus.TIMEOUT,
            raw_sha=None,
            norm_sha=None,
            norm_version=None,
            error_class="ReadTimeout",
        )
        obs = seeded.get_observation(obs_id)
        assert obs.status is ObservationStatus.TIMEOUT
        assert obs.raw_sha is None

    def test_observation_for_an_unknown_server_is_rejected(self, seeded):
        with pytest.raises(sqlite3.IntegrityError):
            _insert(seeded, server_key="never.seen/mcp")

    def test_observation_for_an_unknown_run_is_rejected(self, seeded):
        with pytest.raises(sqlite3.IntegrityError):
            _insert(seeded, run_id="no-such-run")


class TestServers:
    def test_first_seen_and_last_seen_fold_rather_than_overwrite(self, seeded):
        seeded.upsert_server(
            server_key="example.com/mcp",
            registry_name="example.com/mcp",
            repo_url="https://github.com/example/mcp",
            primary_endpoint="https://example.com/mcp",
            seen_at="2026-08-09T00:00:00.000000+00:00",
        )
        # A backfill inserting an older sighting must move first_seen back, not
        # forward, and must not clobber last_seen.
        seeded.upsert_server(
            server_key="example.com/mcp",
            registry_name="example.com/mcp",
            repo_url="https://github.com/example/mcp",
            primary_endpoint="https://example.com/mcp",
            seen_at="2026-04-13T00:00:00.000000+00:00",
        )
        server = seeded.get_server("example.com/mcp")
        assert server.first_seen.startswith("2026-04-13")
        assert server.last_seen.startswith("2026-08-09")

    def test_identity_history_records_only_changes(self, seeded):
        for _ in range(3):
            seeded.upsert_server(
                server_key="example.com/mcp",
                registry_name="example.com/mcp",
                repo_url="https://github.com/example/mcp",
                primary_endpoint="https://example.com/mcp",
                seen_at="2026-08-08T00:00:00.000000+00:00",
            )
        assert len(seeded.identity_history("example.com/mcp")) == 1

    def test_an_endpoint_swap_appends_a_new_identity(self, seeded):
        """Same name, different endpoint — WP6 reads this as REPLACED."""
        seeded.upsert_server(
            server_key="example.com/mcp",
            registry_name="example.com/mcp",
            repo_url="https://github.com/example/mcp",
            primary_endpoint="https://elsewhere.example/mcp",
            seen_at="2026-08-08T00:00:00.000000+00:00",
        )
        history = seeded.identity_history("example.com/mcp")
        assert [row.primary_endpoint for row in history] == [
            "https://example.com/mcp",
            "https://elsewhere.example/mcp",
        ]

    def test_touch_server_widens_the_interval_and_leaves_identity_alone(self, seeded):
        seeded.touch_server("example.com/mcp", seen_at="2026-08-09T00:00:00.000000+00:00")
        # Evidence from before first_seen widens the interval backwards; a
        # backfill reading a 2026-01 version is evidence the server existed then.
        seeded.touch_server("example.com/mcp", seen_at="2026-01-01T00:00:00.000000+00:00")
        server = seeded.get_server("example.com/mcp")
        assert server.last_seen.startswith("2026-08-09")
        assert server.first_seen.startswith("2026-01-01")
        assert server.repo_url == "https://github.com/example/mcp"


class TestQueries:
    def test_observations_come_back_in_chronological_order(self, seeded):
        for day in ("09", "07", "08"):
            _insert(seeded, observed_at=f"2026-08-{day}T00:00:00.000000+00:00")
        days = [obs.observed_at[8:10] for obs in seeded.observations("example.com/mcp")]
        assert days == ["07", "08", "09"]

    def test_latest_observation_can_skip_failures(self, seeded):
        _insert(seeded, observed_at="2026-08-07T00:00:00.000000+00:00")
        _insert(
            seeded,
            observed_at="2026-08-08T00:00:00.000000+00:00",
            status=ObservationStatus.UNREACHABLE,
            raw_sha=None,
            norm_sha=None,
            norm_version=None,
        )
        latest = seeded.latest_observation("example.com/mcp")
        assert latest.status is ObservationStatus.UNREACHABLE

        last_good = seeded.latest_observation("example.com/mcp", status=ObservationStatus.OK)
        assert last_good.observed_at.startswith("2026-08-07")

    def test_layer_filter(self, seeded):
        _insert(seeded, layer=Layer.REGISTRY)
        _insert(seeded, layer=Layer.MANIFEST)
        assert len(seeded.observations("example.com/mcp", layer=Layer.REGISTRY)) == 1

    def test_date_window_is_half_open(self, seeded):
        for day in ("07", "08", "09"):
            _insert(seeded, observed_at=f"2026-08-{day}T00:00:00.000000+00:00")
        window = seeded.observations(
            "example.com/mcp",
            since="2026-08-08T00:00:00.000000+00:00",
            until="2026-08-09T00:00:00.000000+00:00",
        )
        assert [obs.observed_at[8:10] for obs in window] == ["08"]

    def test_lookup_by_norm_sha(self, seeded):
        _insert(seeded)
        _insert(seeded, norm_sha="b" * 64)
        assert len(seeded.observations_by_norm_sha(SHA)) == 1

    def test_status_counts(self, seeded):
        _insert(seeded)
        _insert(
            seeded,
            status=ObservationStatus.AUTH_REQUIRED,
            raw_sha=None,
            norm_sha=None,
            norm_version=None,
        )
        assert seeded.status_counts("r1") == {"ok": 1, "auth_required": 1}


class TestRuns:
    def test_run_lifecycle(self, seeded):
        assert [run.run_id for run in seeded.unfinished_runs()] == ["r1"]
        seeded.finish_run(
            "r1",
            finished_at="2026-08-07T00:10:00.000000+00:00",
            stats={"seen": 20453, "changed": 12},
        )
        assert seeded.unfinished_runs() == []
        assert '"seen":20453' in seeded.get_run("r1").stats_json.replace(" ", "")

    def test_a_crashed_run_stays_open(self, seeded):
        """An unfinished run is WP4's signal that a cycle died mid-flight."""
        assert seeded.get_run("r1").finished_at is None


class TestTransactions:
    def test_a_failed_block_rolls_back(self, seeded):
        with pytest.raises(RuntimeError), seeded.transaction():
            _insert(seeded)
            msg = "collector exploded"
            raise RuntimeError(msg)
        assert seeded.count_observations() == 0

    def test_a_successful_block_commits(self, seeded):
        with seeded.transaction():
            _insert(seeded)
        assert seeded.count_observations() == 1
