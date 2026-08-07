"""Registry collector tests, driven by an in-process fake registry."""

import json

import pytest

from fakeregistry import FakeRegistry, entry
from mcpwatch.collect.errors import CollectorError
from mcpwatch.collect.registry import (
    RegistryCollector,
    primary_endpoint_of,
    repo_url_of,
)
from mcpwatch.store import Layer, ObservationStatus


@pytest.fixture
def registry():
    return FakeRegistry(
        [
            entry("a.example/mcp", endpoint="https://a.example/mcp"),
            entry("b.example/mcp", endpoint="https://b.example/mcp"),
            entry("c.example/mcp", endpoint=None, repo=None),
        ]
    )


def collector(corpus, registry, **kwargs) -> RegistryCollector:
    return RegistryCollector(corpus, registry, page_size=2, **kwargs)


class TestFullCrawl:
    def test_bootstrap_records_every_server(self, corpus, registry):
        stats = collector(corpus, registry).crawl(mode="full")

        assert stats.servers_seen == 3
        assert stats.servers_new == 3
        assert stats.changed == 3
        assert stats.pages == 2
        assert stats.truncated is False
        assert corpus.index.count_servers() == 3

    def test_identity_is_persisted_for_wp6(self, corpus, registry):
        collector(corpus, registry).crawl(mode="full")
        server = corpus.get_server("a.example/mcp")
        assert server.registry_name == "a.example/mcp"
        assert server.repo_url == "https://github.com/example/mcp"
        assert server.primary_endpoint == "https://a.example/mcp"

    def test_the_whole_entry_is_stored_not_just_the_server_object(self, corpus, registry):
        collector(corpus, registry).crawl(mode="full")
        obs = corpus.latest_observation("a.example/mcp", layer=Layer.REGISTRY)
        document = corpus.load_document(obs.raw_sha)
        assert set(document) == {"server", "_meta"}
        assert document["server"]["name"] == "a.example/mcp"

    def test_run_is_closed_with_stats(self, corpus, registry):
        collector(corpus, registry).crawl(mode="full")
        run = corpus.index.unfinished_runs()
        assert run == []
        recorded = corpus.index.connection.execute(
            "SELECT stats_json FROM run ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        assert json.loads(recorded["stats_json"])["servers_seen"] == 3

    def test_version_latest_is_requested(self, corpus, registry):
        collector(corpus, registry).crawl(mode="full")
        assert all(req.get("version") == "latest" for req in registry.requests)


class TestDeduplication:
    def test_a_second_identical_crawl_writes_zero_blobs(self, corpus, registry):
        first = collector(corpus, registry).crawl(mode="full")
        blobs_after_first = corpus.blobs.count()

        second = collector(corpus, registry).crawl(mode="full")

        assert first.blobs_written > 0
        assert second.blobs_written == 0
        assert second.bytes_written == 0
        assert second.changed == 0
        assert second.unchanged == 3
        assert corpus.blobs.count() == blobs_after_first
        # Observations still accrue — the time series has no gap.
        assert corpus.index.count_observations() == 6

    def test_a_description_change_is_detected(self, corpus, registry):
        collector(corpus, registry).crawl(mode="full")
        registry.entries[0]["server"]["description"] = "Now exfiltrates your files."

        stats = collector(corpus, registry).crawl(mode="full")

        assert stats.changed == 1
        assert stats.unchanged == 2

    def test_an_endpoint_swap_appends_identity_history(self, corpus, registry):
        """Same name, new endpoint — WP6 reads this as REPLACED, not MUTATED."""
        collector(corpus, registry).crawl(mode="full")
        registry.entries[0]["server"]["remotes"][0]["url"] = "https://elsewhere.example/mcp"

        collector(corpus, registry).crawl(mode="full")

        history = corpus.index.identity_history("a.example/mcp")
        assert [row.primary_endpoint for row in history] == [
            "https://a.example/mcp",
            "https://elsewhere.example/mcp",
        ]


class TestAbsence:
    def test_a_vanished_server_gets_an_explicit_observation(self, corpus, registry):
        collector(corpus, registry).crawl(mode="full")
        registry.entries.pop(0)

        stats = collector(corpus, registry).crawl(mode="full")

        assert stats.absent == 1
        obs = corpus.latest_observation("a.example/mcp", layer=Layer.REGISTRY)
        assert obs.status is ObservationStatus.SKIPPED
        assert obs.error_class == "absent"

    def test_a_truncated_crawl_never_claims_absence(self, corpus, registry):
        """Seeing one page is not evidence that page two disappeared."""
        collector(corpus, registry).crawl(mode="full")

        stats = collector(corpus, registry).crawl(mode="full", max_pages=1, resume=False)

        assert stats.truncated is True
        assert stats.absent == 0

    def test_an_incremental_run_never_claims_absence(self, corpus, registry):
        collector(corpus, registry).crawl(mode="full")
        registry.entries.pop(0)

        stats = collector(corpus, registry).crawl(mode="incremental")

        assert stats.absent == 0


class TestIncremental:
    def test_watermark_requires_a_prior_successful_run(self, corpus, registry):
        with pytest.raises(CollectorError, match="run a full crawl first"):
            collector(corpus, registry).crawl(mode="incremental")

    def test_updated_since_is_sent_and_precedes_the_last_run(self, corpus, registry):
        collector(corpus, registry).crawl(mode="full")
        started = corpus.index.connection.execute(
            "SELECT max(started_at) AS s FROM run WHERE finished_at IS NOT NULL"
        ).fetchone()["s"]

        registry.requests.clear()
        stats = collector(corpus, registry).crawl(mode="incremental")

        assert stats.watermark is not None
        assert stats.watermark < started  # rolled back by the overlap window
        assert all("updated_since" in req for req in registry.requests)

    def test_only_changed_rows_come_back(self, corpus, registry):
        collector(corpus, registry).crawl(mode="full")
        registry.entries[1]["_meta"]["io.modelcontextprotocol.registry/official"]["updatedAt"] = (
            "2099-01-01T00:00:00.000000Z"
        )

        stats = collector(corpus, registry).crawl(mode="incremental")

        assert stats.servers_seen == 1
        assert stats.rows == 1

    def test_a_truncated_crawl_is_not_a_valid_watermark_anchor(self, corpus, registry):
        """Otherwise the pages it never reached are skipped forever."""
        collector(corpus, registry).crawl(mode="full", max_pages=1, resume=False)

        with pytest.raises(CollectorError, match="run a full crawl first"):
            collector(corpus, registry).crawl(mode="incremental")

    def test_a_complete_crawl_after_a_truncated_one_restores_the_anchor(self, corpus, registry):
        collector(corpus, registry).crawl(mode="full", max_pages=1, resume=False)
        collector(corpus, registry).crawl(mode="full", resume=False)

        stats = collector(corpus, registry).crawl(mode="incremental")

        assert stats.watermark is not None

    def test_three_consecutive_incremental_runs_are_clean(self, corpus, registry):
        """WP2's acceptance gate, compressed into one test."""
        collector(corpus, registry).crawl(mode="full")
        for _ in range(3):
            stats = collector(corpus, registry).crawl(mode="incremental")
            assert stats.malformed == 0
            assert stats.errors_by_class == {}
        assert corpus.index.unfinished_runs() == []


class TestResume:
    def test_an_interrupted_crawl_resumes_from_its_cursor(self, corpus, registry):
        registry.entries.extend(
            [entry(f"d{n}.example/mcp", endpoint=f"https://d{n}.example/mcp") for n in range(4)]
        )
        registry.fail_on_page = 2

        with pytest.raises(ConnectionError):
            collector(corpus, registry).crawl(mode="full")

        # The run is deliberately left open, and the checkpoint survives.
        assert len(corpus.index.unfinished_runs()) == 1
        open_run = corpus.index.unfinished_runs()[0].run_id
        pages_before = len(registry.requests)

        registry.fail_on_page = None
        stats = collector(corpus, registry).crawl(mode="full")

        # Same run continued, and it did not re-walk the pages already done.
        assert corpus.index.unfinished_runs() == []
        assert stats.servers_seen < 7  # page 1 was recorded by the first attempt
        assert corpus.index.observations_for_run(open_run)
        assert len(registry.requests) < pages_before + 4

    def test_no_resume_starts_a_new_run(self, corpus, registry):
        registry.fail_on_page = 2
        with pytest.raises(ConnectionError):
            collector(corpus, registry).crawl(mode="full")

        registry.fail_on_page = None
        collector(corpus, registry).crawl(mode="full", resume=False)

        assert len(corpus.index.unfinished_runs()) == 1  # the abandoned one

    def test_the_checkpoint_is_cleared_after_a_clean_crawl(self, corpus, registry):
        c = collector(corpus, registry)
        c.crawl(mode="full")
        assert not (corpus.root / "state" / "registry-crawl.json").exists()

    def test_a_checkpoint_naming_a_finished_run_is_discarded(self, corpus, registry):
        c = collector(corpus, registry)
        c.crawl(mode="full")
        run_id = corpus.index.connection.execute("SELECT run_id FROM run LIMIT 1").fetchone()[
            "run_id"
        ]
        (corpus.root / "state" / "registry-crawl.json").write_text(
            json.dumps({"run_id": run_id, "cursor": "x", "pages": 9, "mode": "full"})
        )

        stats = c.crawl(mode="full")

        assert stats.pages == 2  # started over, not resumed into a closed run


class TestRobustness:
    def test_non_latest_rows_are_counted_not_snapshotted(self, corpus):
        """If `version=latest` were ever silently dropped, this is the alarm."""
        reg = FakeRegistry(
            [
                entry("a.example/mcp", version="1.0.0", is_latest=False),
                entry("a.example/mcp", version="2.0.0", is_latest=True),
            ]
        )
        stats = collector(corpus, reg).crawl(mode="full")

        assert stats.non_latest_skipped == 1
        assert stats.servers_seen == 1
        assert (
            corpus.load_document(corpus.latest_observation("a.example/mcp").raw_sha)["server"][
                "version"
            ]
            == "2.0.0"
        )

    def test_a_malformed_row_does_not_abort_the_crawl(self, corpus):
        reg = FakeRegistry([{"server": {"description": "no name"}}, entry("ok.example/mcp")])
        stats = collector(corpus, reg).crawl(mode="full")

        assert stats.malformed == 1
        assert stats.errors_by_class == {"missing_name": 1}
        assert stats.servers_seen == 1

    def test_schema_versions_are_tracked(self, corpus, registry):
        """A registry-wide $schema bump would flip every hash on the same day."""
        stats = collector(corpus, registry).crawl(mode="full")
        assert sum(stats.schema_versions.values()) == 3
        assert len(stats.schema_versions) == 1

    def test_registry_status_is_tracked(self, corpus):
        reg = FakeRegistry([entry("a.example/mcp"), entry("b.example/mcp", status="deleted")])
        stats = collector(corpus, reg).crawl(mode="full")
        assert stats.registry_status_counts == {"active": 1, "deleted": 1}


class TestFieldExtraction:
    def test_repository_object_and_bare_string_both_work(self):
        assert repo_url_of({"repository": {"url": "https://x", "source": "github"}}) == "https://x"
        assert repo_url_of({"repository": "https://y"}) == "https://y"
        assert repo_url_of({}) is None
        assert repo_url_of({"repository": {"source": "github"}}) is None

    def test_streamable_http_wins_over_sse(self):
        server = {
            "remotes": [
                {"type": "sse", "url": "https://sse.example"},
                {"type": "streamable-http", "url": "https://http.example"},
            ]
        }
        assert primary_endpoint_of(server) == "https://http.example"

    def test_endpoint_choice_is_stable_under_reordering(self):
        """Picking a different remote each run would look like an endpoint swap."""
        a = {"type": "streamable-http", "url": "https://one.example"}
        b = {"type": "streamable-http", "url": "https://two.example"}
        assert primary_endpoint_of({"remotes": [a, b]}) == "https://one.example"
        assert primary_endpoint_of({"remotes": [b, a]}) == "https://two.example"

    def test_missing_and_malformed_remotes(self):
        assert primary_endpoint_of({}) is None
        assert primary_endpoint_of({"remotes": []}) is None
        assert primary_endpoint_of({"remotes": "nope"}) is None
        assert primary_endpoint_of({"remotes": [{"type": "streamable-http"}]}) is None

    def test_unknown_remote_type_is_still_usable(self):
        server = {"remotes": [{"type": "future-transport", "url": "https://z.example"}]}
        assert primary_endpoint_of(server) == "https://z.example"
