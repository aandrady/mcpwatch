"""Health-check tests. These are what make a dead collector loud."""

import json
from datetime import timedelta

from conftest import manifest as manifest_doc
from mcpwatch.health import check_corpus, main
from mcpwatch.store import Layer, ObservationStatus, utcnow


def finished_run(corpus, collector, *, ago_hours=0.0, stats=None):
    """Insert a completed run that started `ago_hours` in the past."""
    started = utcnow() - timedelta(hours=ago_hours)
    run_id = corpus.start_run(collector, "0.1.0", started_at=started)
    corpus.finish_run(run_id, stats=stats or {}, finished_at=started)
    return run_id


def named(report, name):
    return next(c for c in report.checks if c.name == name)


class TestFreshness:
    def test_a_corpus_with_no_runs_is_unhealthy(self, corpus):
        report = check_corpus(corpus)
        assert not report.ok
        assert named(report, "registry.freshness").detail.startswith("no completed run")

    def test_a_recent_run_is_healthy(self, corpus):
        finished_run(corpus, "registry", stats={"servers_seen": 20502, "mode": "full"})
        finished_run(corpus, "manifest", stats={"probed": 10373})
        assert check_corpus(corpus).ok

    def test_a_stale_collector_is_caught(self, corpus):
        """The two-weeks-of-silence failure mode, detected on day two."""
        finished_run(corpus, "registry", ago_hours=72, stats={"servers_seen": 20502})
        finished_run(corpus, "manifest", stats={"probed": 10373})

        report = check_corpus(corpus)

        assert not report.ok
        assert [c.name for c in report.failures] == ["registry.freshness"]

    def test_one_missed_daily_run_is_tolerated(self, corpus):
        finished_run(corpus, "registry", ago_hours=30, stats={"servers_seen": 20502})
        finished_run(corpus, "manifest", ago_hours=30, stats={"probed": 10373})
        assert check_corpus(corpus).ok


class TestCrashedRuns:
    def test_a_run_left_open_overnight_is_caught(self, corpus):
        finished_run(corpus, "registry", stats={"servers_seen": 1})
        finished_run(corpus, "manifest", stats={"probed": 1})
        corpus.start_run("manifest", "0.1.0", started_at=utcnow() - timedelta(hours=20))

        report = check_corpus(corpus)

        assert not report.ok
        assert named(report, "runs.no_stale_open").detail.startswith("1 run")

    def test_a_currently_running_cycle_is_not_flagged(self, corpus):
        finished_run(corpus, "registry", stats={"servers_seen": 1})
        finished_run(corpus, "manifest", stats={"probed": 1})
        corpus.start_run("manifest", "0.1.0")

        assert check_corpus(corpus).ok


class TestCoverage:
    def test_a_collapse_in_servers_seen_is_caught(self, corpus):
        """The registry grows; it does not shrink by half overnight."""
        finished_run(
            corpus, "registry", ago_hours=24, stats={"mode": "full", "servers_seen": 20502}
        )
        finished_run(corpus, "registry", stats={"mode": "full", "servers_seen": 9000})
        finished_run(corpus, "manifest", stats={"probed": 1})

        report = check_corpus(corpus)

        assert not report.ok
        assert "43.9%" in named(report, "registry.coverage").detail

    def test_normal_growth_is_fine(self, corpus):
        finished_run(
            corpus, "registry", ago_hours=24, stats={"mode": "full", "servers_seen": 20453}
        )
        finished_run(corpus, "registry", stats={"mode": "full", "servers_seen": 20502})
        finished_run(corpus, "manifest", stats={"probed": 1})
        assert check_corpus(corpus).ok

    def test_incremental_runs_are_not_compared_against_full_ones(self, corpus):
        """A 41-server delta is not a 99.8% coverage collapse."""
        finished_run(
            corpus, "registry", ago_hours=24, stats={"mode": "full", "servers_seen": 20502}
        )
        finished_run(corpus, "registry", stats={"mode": "incremental", "servers_seen": 41})
        finished_run(corpus, "manifest", stats={"probed": 1})

        assert check_corpus(corpus).ok


class TestNondeterminism:
    def _seed_manifest_run(self, corpus, ok_count, nd_count):
        run_id = corpus.start_run("manifest", "0.1.0")
        for n in range(ok_count + nd_count):
            key = f"s{n}"
            corpus.upsert_server(server_key=key, registry_name=key)
            corpus.record_snapshot(
                run_id=run_id,
                server_key=key,
                layer=Layer.MANIFEST,
                document=manifest_doc(f"tool {n}"),
                status=(
                    ObservationStatus.OK if n < ok_count else ObservationStatus.NONDETERMINISTIC
                ),
            )
        corpus.finish_run(run_id, stats={"probed": ok_count + nd_count})
        return run_id

    def test_a_low_quarantine_rate_is_healthy(self, corpus):
        finished_run(corpus, "registry", stats={"servers_seen": 1})
        self._seed_manifest_run(corpus, ok_count=19, nd_count=1)
        assert check_corpus(corpus).ok

    def test_a_high_quarantine_rate_points_at_our_own_normalization(self, corpus):
        finished_run(corpus, "registry", stats={"servers_seen": 1})
        self._seed_manifest_run(corpus, ok_count=10, nd_count=10)

        report = check_corpus(corpus)

        assert not report.ok
        assert "suspect our normalization first" in named(report, "manifest.nondeterminism").detail


class TestIntegrity:
    def test_a_missing_blob_is_caught(self, corpus):
        finished_run(corpus, "registry", stats={"servers_seen": 1})
        finished_run(corpus, "manifest", stats={"probed": 1})
        run_id = corpus.start_run("registry", "0.1.0")
        corpus.upsert_server(server_key="a", registry_name="a")
        write = corpus.record_snapshot(
            run_id=run_id, server_key="a", layer=Layer.REGISTRY, document={"name": "a"}
        )
        corpus.finish_run(run_id, stats={"servers_seen": 1})
        corpus.blobs.path_for(write.observation.norm_sha).unlink()

        report = check_corpus(corpus)

        assert not report.ok
        assert named(report, "corpus.blobs_present").detail.startswith("1 referenced")


class TestCli:
    def test_exit_code_signals_health(self, corpus, capsys):
        finished_run(corpus, "registry", stats={"servers_seen": 1})
        finished_run(corpus, "manifest", stats={"probed": 1})
        assert main(["--corpus", str(corpus.root)]) == 0

    def test_exit_code_signals_failure(self, corpus, capsys):
        assert main(["--corpus", str(corpus.root)]) == 1
        assert "UNHEALTHY" in capsys.readouterr().err

    def test_json_output_is_machine_readable(self, corpus, capsys):
        finished_run(corpus, "registry", stats={"servers_seen": 1})
        finished_run(corpus, "manifest", stats={"probed": 1})
        main(["--corpus", str(corpus.root), "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["ok"] is True
        assert any(c["name"] == "registry.freshness" for c in payload["checks"])
