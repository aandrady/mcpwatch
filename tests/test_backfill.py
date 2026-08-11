"""Retrospective backfill tests, driven by an in-process fake registry.

The fake serves both endpoints the real registry does, including the 404 that
``/versions`` returns for a withdrawn server — the behaviour that makes the page
walk the only source of a deleted server's history.
"""

import json

import pytest

from fakeregistry import FakeRegistry, entry
from mcpwatch.collect.backfill import WITHDRAWN_CLASS, BackfillCollector, parse_row
from mcpwatch.collect.manifest import ManifestProber
from mcpwatch.collect.registry import RegistryCollector
from mcpwatch.store import Layer, ObservationStatus, from_iso

APRIL = "2026-04-13T17:33:26.613537Z"
JUNE = "2026-06-01T09:00:00.000000Z"
JULY = "2026-07-27T10:44:51.359634Z"


def chain(name: str, **overrides) -> list[dict]:
    """Three published versions of one server, oldest first."""
    return [
        entry(name, version="1.0.0", updated_at=APRIL, is_latest=False, **overrides),
        entry(name, version="2.0.0", updated_at=JUNE, is_latest=False, **overrides),
        entry(name, version="3.0.0", updated_at=JULY, is_latest=True, **overrides),
    ]


@pytest.fixture
def registry():
    return FakeRegistry(
        [
            *chain("a.example/mcp"),
            entry("b.example/mcp", version="1.0.0", updated_at=JUNE),
        ],
        page_size=2,
        filtering=True,
    )


def backfill(corpus, registry, **kwargs) -> BackfillCollector:
    return BackfillCollector(corpus, registry, page_size=2, **kwargs)


def registry_observations(corpus, server_key):
    return [
        o
        for o in corpus.observations(server_key, layer=Layer.REGISTRY)
        if o.status is ObservationStatus.OK
    ]


class TestWalk:
    def test_every_version_is_stored(self, corpus, registry):
        stats = backfill(corpus, registry).run(phases=("walk",))

        assert stats.versions_stored == 4
        assert stats.servers_seen == 2
        assert stats.servers_new == 2
        assert len(registry_observations(corpus, "a.example/mcp")) == 3

    def test_include_deleted_is_requested_and_version_latest_is_not(self, corpus, registry):
        backfill(corpus, registry).run(phases=("walk",))

        listing = [r for r, u in zip(registry.requests, registry.urls, strict=True) if "?" not in u]
        assert listing, "the walk made no listing requests"
        assert all(r.get("include_deleted") == "true" for r in listing)
        # `version=latest` is WP2's optimization and the one thing that would
        # silently reduce this to a re-crawl of the present.
        assert all("version" not in r for r in listing)

    def test_publication_time_and_observation_time_are_kept_apart(self, corpus, registry):
        backfill(corpus, registry).run(phases=("walk",))

        observations = registry_observations(corpus, "a.example/mcp")
        assert [o.published_at for o in observations] == [
            from_iso(APRIL).isoformat(timespec="microseconds"),
            from_iso(JUNE).isoformat(timespec="microseconds"),
            from_iso(JULY).isoformat(timespec="microseconds"),
        ]
        # We did not observe anything in April; we read about April today.
        assert all(o.observed_at > o.published_at for o in observations)
        assert [o.effective_at for o in observations] == [o.published_at for o in observations]

    def test_history_orders_by_publication_not_by_read_order(self, corpus):
        # Served newest first, as a cursor over a mutating dataset can do.
        rows = chain("a.example/mcp")
        stats = backfill(corpus, FakeRegistry(list(reversed(rows)), filtering=True)).run(
            phases=("walk",)
        )

        assert stats.versions_stored == 3
        versions = [
            corpus.load_document(o.raw_sha)["server"]["version"]
            for o in registry_observations(corpus, "a.example/mcp")
        ]
        assert versions == ["1.0.0", "2.0.0", "3.0.0"]

    def test_current_identity_comes_from_the_latest_version(self, corpus):
        # The old version sorts last by version *string*, so a collector that
        # trusted read order would leave the 2024 endpoint as current identity.
        rows = [
            entry(
                "a.example/mcp",
                version="10.0.0",
                endpoint="https://new.example/mcp",
                updated_at=JULY,
                is_latest=True,
            ),
            entry(
                "a.example/mcp",
                version="9.0.0",
                endpoint="https://old.example/mcp",
                updated_at=APRIL,
                is_latest=False,
            ),
        ]
        backfill(corpus, FakeRegistry(rows, filtering=True)).run(phases=("walk",))

        assert corpus.get_server("a.example/mcp").primary_endpoint == "https://new.example/mcp"

    def test_identity_history_dates_each_endpoint_from_its_first_appearance(self, corpus):
        rows = [
            entry(
                "a.example/mcp",
                version="1.0.0",
                endpoint="https://old.example/mcp",
                updated_at=APRIL,
                is_latest=False,
            ),
            entry(
                "a.example/mcp",
                version="2.0.0",
                endpoint="https://new.example/mcp",
                updated_at=JULY,
                is_latest=True,
            ),
        ]
        backfill(corpus, FakeRegistry(rows, filtering=True)).run(phases=("walk",))

        history = corpus.index.identity_history("a.example/mcp")
        assert [(h.primary_endpoint, h.observed_at) for h in history] == [
            ("https://old.example/mcp", from_iso(APRIL).isoformat(timespec="microseconds")),
            ("https://new.example/mcp", from_iso(JULY).isoformat(timespec="microseconds")),
        ]

    def test_first_seen_reaches_back_to_the_first_publication(self, corpus, registry):
        backfill(corpus, registry).run(phases=("walk",))

        server = corpus.get_server("a.example/mcp")
        assert server.first_seen == from_iso(APRIL).isoformat(timespec="microseconds")

    def test_a_malformed_row_does_not_abort_the_walk(self, corpus):
        reg = FakeRegistry(
            [{"server": {"description": "no name"}}, entry("ok.example/mcp")], filtering=True
        )
        stats = backfill(corpus, reg).run(phases=("walk",))

        assert stats.malformed == 1
        assert stats.errors_by_class == {"malformed_row": 1}
        assert stats.versions_stored == 1

    def test_a_row_without_a_publication_date_is_still_stored(self, corpus):
        row = entry("a.example/mcp")
        del row["_meta"]["io.modelcontextprotocol.registry/official"]["publishedAt"]
        stats = backfill(corpus, FakeRegistry([row], filtering=True)).run(phases=("walk",))

        assert stats.versions_stored == 1
        assert stats.missing_published_at == 1
        observation = registry_observations(corpus, "a.example/mcp")[0]
        assert observation.published_at is None
        # With nothing better, chronology falls back to when we read it.
        assert observation.effective_at == observation.observed_at


class TestIdempotency:
    def test_a_second_backfill_stores_nothing(self, corpus, registry):
        first = backfill(corpus, registry).run(phases=("walk",))
        blobs_after_first = corpus.blobs.count()
        observations_after_first = corpus.index.count_observations()

        second = backfill(corpus, registry).run(phases=("walk",))

        assert first.versions_stored == 4
        assert second.versions_stored == 0
        assert second.versions_skipped == 4
        assert second.bytes_written == 0
        assert corpus.blobs.count() == blobs_after_first
        assert corpus.index.count_observations() == observations_after_first

    def test_it_dates_the_version_the_daily_crawl_captured_undated(self, corpus, registry):
        """The regression that cost a production run.

        The daily crawl stores a server's current version with no publication
        date, because a live crawl has none to give. Skipping the backfill row
        for that version — on the grounds that its bytes are already present —
        drops the date, and with it the newest transition of every server in the
        registry. Same bytes, different fact: it gets stored.
        """
        RegistryCollector(corpus, registry, page_size=2).crawl(mode="full")
        captured = corpus.index.count_observations()
        assert all(o.published_at is None for o in registry_observations(corpus, "a.example/mcp"))

        stats = backfill(corpus, registry).run(phases=("walk",))

        assert stats.versions_skipped == 0
        assert stats.versions_stored == 4
        assert corpus.index.count_observations() == captured + 4
        # Every published version now carries its date, the newest included.
        dated = {
            o.published_at
            for o in registry_observations(corpus, "a.example/mcp")
            if o.published_at is not None
        }
        assert len(dated) == 3

    def test_dating_a_captured_version_costs_no_new_blobs(self, corpus, registry):
        RegistryCollector(corpus, registry, page_size=2).crawl(mode="full")
        blobs_after_crawl = corpus.blobs.count()

        backfill(corpus, registry).run(phases=("walk",))

        # The content was already stored; only the pointer to it is new.
        latest = [
            o
            for o in registry_observations(corpus, "a.example/mcp")
            if o.published_at == from_iso(JULY).isoformat(timespec="microseconds")
        ]
        crawled = [
            o for o in registry_observations(corpus, "a.example/mcp") if o.published_at is None
        ]
        assert latest[0].norm_sha == crawled[0].norm_sha
        assert corpus.blobs.count() == blobs_after_crawl + 4  # the two older versions, raw + norm

    def test_a_second_backfill_after_a_crawl_still_stores_nothing(self, corpus, registry):
        RegistryCollector(corpus, registry, page_size=2).crawl(mode="full")
        backfill(corpus, registry).run(phases=("walk",))
        observations = corpus.index.count_observations()

        stats = backfill(corpus, registry).run(phases=("walk",))

        assert stats.versions_stored == 0
        assert stats.versions_skipped == 4
        assert corpus.index.count_observations() == observations

    def test_an_edit_to_an_already_published_version_is_counted_separately(self, corpus, registry):
        backfill(corpus, registry).run(phases=("walk",))

        # Same version, same publication date, different content: a republish
        # that leaves the version number alone.
        registry.entries[0]["server"]["description"] = "Now exfiltrates your files."
        stats = backfill(corpus, registry).run(phases=("walk",))

        assert stats.versions_stored == 1
        assert stats.versions_restated == 1
        assert len(registry_observations(corpus, "a.example/mcp")) == 4


class TestWithdrawnServers:
    @pytest.fixture
    def withdrawn(self):
        return FakeRegistry(
            [
                entry(
                    "gone.example/mcp",
                    version="1.0.0",
                    updated_at=APRIL,
                    is_latest=False,
                    status="deleted",
                    status_changed_at=JULY,
                ),
                entry(
                    "gone.example/mcp",
                    version="2.0.0",
                    updated_at=JUNE,
                    is_latest=True,
                    status="deleted",
                    status_changed_at=JULY,
                ),
            ],
            filtering=True,
        )

    def test_their_history_is_kept_not_dropped(self, corpus, withdrawn):
        stats = backfill(corpus, withdrawn).run(phases=("walk",))

        assert stats.versions_stored == 2
        assert stats.non_active_rows == 2
        assert len(registry_observations(corpus, "gone.example/mcp")) == 2

    def test_the_withdrawal_itself_is_dated(self, corpus, withdrawn):
        stats = backfill(corpus, withdrawn).run(phases=("walk",))

        assert stats.withdrawals_recorded == 1
        marker = corpus.latest_observation("gone.example/mcp", layer=Layer.REGISTRY)
        assert marker.error_class == WITHDRAWN_CLASS
        assert marker.status is ObservationStatus.SKIPPED
        assert marker.published_at == from_iso(JULY).isoformat(timespec="microseconds")

    def test_the_withdrawal_is_recorded_once(self, corpus, withdrawn):
        backfill(corpus, withdrawn).run(phases=("walk",))
        again = backfill(corpus, withdrawn).run(phases=("walk",))

        assert again.withdrawals_recorded == 0

    def test_a_withdrawn_server_is_not_a_live_probe_target(self, corpus, withdrawn):
        backfill(corpus, withdrawn).run(phases=("walk",))

        # WP3 probes whatever the registry currently lists. A server whose newest
        # Layer-1 record is a withdrawal is not that.
        targets = ManifestProber(corpus).targets()
        assert [t.server_key for t in targets] == []


class TestVerify:
    def test_it_recovers_a_version_the_walk_missed(self, corpus, registry):
        # A walk that stopped early leaves a.example one version short.
        backfill(corpus, registry).run(phases=("walk",), max_pages=1)
        assert len(registry_observations(corpus, "a.example/mcp")) == 2

        stats = backfill(corpus, registry).run(phases=("verify",), resume=False)

        assert stats.versions_recovered == 1
        assert stats.chains_repaired == 1
        assert len(registry_observations(corpus, "a.example/mcp")) == 3

    def test_single_version_servers_are_not_re_read(self, corpus, registry):
        backfill(corpus, registry).run(phases=("walk",))
        before = registry.request_count

        stats = backfill(corpus, registry).run(phases=("verify",), resume=False)

        # Only a.example is worth asking about; b.example has one version and
        # its answer is already in the corpus.
        assert stats.verify_targets == 1
        assert registry.request_count - before == 1

    def test_every_server_is_re_read_when_asked(self, corpus, registry):
        backfill(corpus, registry).run(phases=("walk",))

        stats = backfill(corpus, registry).run(phases=("verify",), verify_scope="all", resume=False)

        assert stats.verify_targets == 2
        assert stats.versions_recovered == 0

    def test_a_server_the_walk_never_saw_is_a_verify_target(self, corpus, registry):
        # WP2 knows the server; the backfill walk has not run at all.
        RegistryCollector(corpus, registry, page_size=2).crawl(mode="full")

        stats = backfill(corpus, registry).run(phases=("verify",), resume=False)

        assert stats.verify_targets == 2
        dated = {
            o.published_at
            for o in registry_observations(corpus, "a.example/mcp")
            if o.published_at is not None
        }
        assert len(dated) == 3, "verify alone recovers the whole chain"

    def test_a_404_from_the_versions_endpoint_is_expected_not_fatal(self, corpus):
        reg = FakeRegistry(
            [
                entry(
                    "gone.example/mcp",
                    version="1.0.0",
                    updated_at=APRIL,
                    is_latest=False,
                    status="deleted",
                    status_changed_at=JULY,
                ),
                entry(
                    "gone.example/mcp",
                    version="2.0.0",
                    updated_at=JUNE,
                    is_latest=True,
                    status="deleted",
                    status_changed_at=JULY,
                ),
            ],
            filtering=True,
        )
        backfill(corpus, reg).run(phases=("walk",))

        stats = backfill(corpus, reg).run(phases=("verify",), resume=False)

        assert stats.verify_not_found == 1
        assert stats.verify_failed == 0
        assert stats.errors_by_class == {"versions_404": 1}

    def test_versions_we_hold_that_the_registry_dropped_are_counted(self, corpus, registry):
        backfill(corpus, registry).run(phases=("walk",))
        registry.entries.pop(0)  # the registry stops listing 1.0.0

        stats = backfill(corpus, registry).run(phases=("verify",), resume=False)

        assert stats.versions_absent_upstream == 1
        # Append-only: what we already recorded stays recorded.
        assert len(registry_observations(corpus, "a.example/mcp")) == 3


class TestResume:
    def test_an_interrupted_walk_resumes_from_its_cursor(self, corpus, registry):
        registry.fail_on_page = 2
        with pytest.raises(ConnectionError):
            backfill(corpus, registry).run(phases=("walk",))
        assert corpus.index.unfinished_runs()

        registry.fail_on_page = None
        stats = backfill(corpus, registry).run(phases=("walk",))

        assert stats.resumed is True
        assert stats.versions_stored == 4  # counters carry across the interruption
        assert corpus.index.unfinished_runs() == []
        assert len(registry_observations(corpus, "a.example/mcp")) == 3

    def test_a_resumed_run_keeps_one_run_id(self, corpus, registry):
        registry.fail_on_page = 2
        with pytest.raises(ConnectionError):
            backfill(corpus, registry).run(phases=("walk",))
        registry.fail_on_page = None
        backfill(corpus, registry).run(phases=("walk",))

        runs = corpus.index.connection.execute(
            "SELECT count(*) AS n FROM run WHERE collector = 'backfill'"
        ).fetchone()["n"]
        assert runs == 1

    def test_the_checkpoint_is_cleared_after_a_clean_run(self, corpus, registry):
        collector = backfill(corpus, registry)
        collector.run(phases=("walk",))
        assert not collector._checkpoint_path.exists()

    def test_no_resume_starts_a_new_run(self, corpus, registry):
        registry.fail_on_page = 2
        with pytest.raises(ConnectionError):
            backfill(corpus, registry).run(phases=("walk",))

        registry.fail_on_page = None
        stats = backfill(corpus, registry).run(phases=("walk",), resume=False)

        assert stats.resumed is False

    def test_a_run_interrupted_in_verify_does_not_re_walk(self, corpus, registry):
        registry.fail_on_versions = "a.example/mcp"
        with pytest.raises(ConnectionError):
            backfill(corpus, registry).run(phases=("walk", "verify"))
        pages_before = registry.pages_served
        assert pages_before > 0

        registry.fail_on_versions = None
        stats = backfill(corpus, registry).run(phases=("walk", "verify"))

        assert stats.resumed is True
        assert registry.pages_served == pages_before, "the finished walk was repeated"
        assert stats.servers_verified == 1

    def test_a_checkpoint_from_another_phase_is_not_silently_discarded(self, corpus, registry):
        registry.fail_on_page = 2
        with pytest.raises(ConnectionError):
            backfill(corpus, registry).run(phases=("walk",))

        registry.fail_on_page = None
        with pytest.raises(Exception, match="checkpointed in phase 'walk'"):
            backfill(corpus, registry).run(phases=("verify",))


class TestRunBookkeeping:
    def test_the_run_is_closed_with_its_stats(self, corpus, registry):
        backfill(corpus, registry).run(phases=("walk", "verify"))

        row = corpus.index.connection.execute(
            "SELECT stats_json FROM run WHERE collector = 'backfill'"
        ).fetchone()
        assert json.loads(row["stats_json"])["versions_stored"] == 4
        assert corpus.index.unfinished_runs() == []

    def test_an_unknown_phase_is_refused(self, corpus, registry):
        with pytest.raises(Exception, match="unknown backfill phase"):
            backfill(corpus, registry).run(phases=("walk", "sideways"))


class TestDeprecatedServers:
    """Deprecated is not deleted, and the difference costs Layer-2 data."""

    @pytest.fixture
    def deprecated(self):
        return FakeRegistry(
            [
                entry("old.example/mcp", version="1.0.0", updated_at=APRIL, is_latest=False),
                entry(
                    "old.example/mcp",
                    version="2.0.0",
                    updated_at=JULY,
                    is_latest=True,
                    status="deprecated",
                    status_changed_at=JULY,
                ),
            ],
            filtering=True,
        )

    def test_a_deprecated_server_is_not_recorded_as_withdrawn(self, corpus, deprecated):
        stats = backfill(corpus, deprecated).run(phases=("walk",))

        assert stats.non_active_rows == 1
        assert stats.withdrawals_recorded == 0

    def test_a_deprecated_server_is_still_a_probe_target(self, corpus, deprecated):
        # It is still listed by the registry and still answers; dropping it
        # would lose Layer-2 observations that cannot be collected later.
        backfill(corpus, deprecated).run(phases=("walk",))

        assert [t.server_key for t in ManifestProber(corpus).targets()] == ["old.example/mcp"]


class TestRowParsing:
    def test_a_row_reports_its_publication_and_withdrawal(self):
        row = parse_row(
            entry("a.example/mcp", status="deleted", updated_at=APRIL, status_changed_at=JULY)
        )
        assert row.server_key == "a.example/mcp"
        assert row.version == "1.0.0"
        assert row.active is False
        assert row.withdrawn_at == from_iso(JULY)

    def test_an_active_row_has_no_withdrawal_date(self):
        assert parse_row(entry("a.example/mcp")).withdrawn_at is None

    def test_a_deprecated_row_has_no_withdrawal_date(self):
        row = parse_row(entry("a.example/mcp", status="deprecated", status_changed_at=JULY))
        assert row.active is False
        assert row.withdrawn_at is None

    def test_an_unparseable_timestamp_is_not_fatal(self):
        row = parse_row(entry("a.example/mcp", published_at="not a date"))
        assert row.published_at is None

    def test_a_row_without_a_name_is_rejected(self):
        assert parse_row({"server": {"version": "1.0.0"}}) is None
        assert parse_row("not an object") is None
