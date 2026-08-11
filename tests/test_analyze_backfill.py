"""Tests for the Layer-1 retrospective report.

Every number here is computed from a corpus built by the real backfill collector
against the fake registry, so the report is exercised end to end rather than
against a hand-arranged database that might not be shaped like the real one.
"""

import json

import pytest

from fakeregistry import FakeRegistry, entry
from mcpwatch.analyze.backfill import build_report, changed_fields, main
from mcpwatch.collect.backfill import BackfillCollector

APRIL = "2026-04-01T00:00:00.000000Z"
MAY = "2026-05-01T00:00:00.000000Z"
JULY = "2026-07-01T00:00:00.000000Z"


@pytest.fixture
def populated(corpus):
    """A corpus holding one server that moved endpoint and one that did not."""
    registry = FakeRegistry(
        [
            entry(
                "swap.example/mcp",
                version="1.0.0",
                updated_at=APRIL,
                is_latest=False,
                endpoint="https://old.example/mcp",
            ),
            entry(
                "swap.example/mcp",
                version="2.0.0",
                updated_at=MAY,
                is_latest=False,
                endpoint="https://new.example/mcp",
                repo="https://github.com/other/mcp",
            ),
            entry(
                "swap.example/mcp",
                version="3.0.0",
                updated_at=JULY,
                is_latest=True,
                endpoint="https://new.example/mcp",
                repo="https://github.com/other/mcp",
                description="Now with more capabilities.",
            ),
            entry("quiet.example/mcp", version="1.0.0", updated_at=APRIL),
        ],
        filtering=True,
    )
    BackfillCollector(corpus, registry, page_size=10).run(phases=("walk",))
    return corpus


class TestPopulation:
    def test_it_counts_servers_versions_and_transitions(self, populated):
        report = build_report(populated)

        assert report.servers_total == 2
        assert report.servers_with_history == 2
        assert report.servers_multi_version == 1
        assert report.versions_total == 4
        assert report.transitions_total == 2  # three versions of one server

    def test_a_withdrawn_server_is_reported(self, corpus):
        registry = FakeRegistry(
            [entry("gone.example/mcp", updated_at=APRIL, status="deleted", status_changed_at=JULY)],
            filtering=True,
        )
        BackfillCollector(corpus, registry, page_size=10).run(phases=("walk",))

        assert build_report(corpus).withdrawn_servers == 1


class TestIntervals:
    def test_gaps_are_measured_between_publication_dates(self, populated):
        report = build_report(populated)

        # April to May is 30 days, May to July is 61.
        assert report.interval_days["min"] == pytest.approx(30.0)
        assert report.interval_days["max"] == pytest.approx(61.0)
        assert report.interval_histogram["7-30d"] == 1
        assert report.interval_histogram["30-90d"] == 1

    def test_an_empty_corpus_reports_no_intervals(self, corpus):
        report = build_report(corpus)
        assert report.interval_days == {}
        assert report.transitions_total == 0


class TestFieldChanges:
    def test_it_names_the_fields_that_moved(self, populated):
        report = build_report(populated)

        # Every transition bumps `version`; only one changes the description.
        assert report.field_changes["version"] == 2
        assert report.field_changes["description"] == 1
        assert report.field_changes["remotes"] == 1
        assert report.field_changes["repository"] == 1

    def test_republishing_identical_content_changes_nothing(self):
        before = {"server": {"name": "a", "version": "1.0.0"}, "_meta": {"x": 1}}
        after = {"server": {"name": "a", "version": "1.0.0"}, "_meta": {"x": 2}}
        # `_meta` moves on every republish; counting it would make every
        # transition look like a change.
        assert changed_fields(before, after) == ()

    def test_an_added_field_counts_as_a_change(self):
        before = {"server": {"name": "a"}}
        after = {"server": {"name": "a", "websiteUrl": "https://x"}}
        assert changed_fields(before, after) == ("websiteUrl",)


class TestSwaps:
    def test_an_endpoint_swap_is_singled_out(self, populated):
        report = build_report(populated)

        assert len(report.endpoint_swaps) == 1
        swap = report.endpoint_swaps[0]
        assert swap.server_key == "swap.example/mcp"
        assert (swap.from_version, swap.to_version) == ("1.0.0", "2.0.0")
        assert swap.gap_days == pytest.approx(30.0)

    def test_a_repository_swap_is_singled_out(self, populated):
        report = build_report(populated)

        assert [t.to_version for t in report.repository_swaps] == ["2.0.0"]

    def test_a_package_identity_swap_is_singled_out(self, corpus):
        def with_package(identifier: str, **kwargs):
            row = entry("pkg.example/mcp", endpoint=None, **kwargs)
            row["server"]["packages"] = [
                {"registryType": "npm", "identifier": identifier, "version": "1.0.0"}
            ]
            return row

        registry = FakeRegistry(
            [
                with_package("safe-mcp", version="1.0.0", updated_at=APRIL, is_latest=False),
                with_package("other-mcp", version="2.0.0", updated_at=MAY, is_latest=True),
            ],
            filtering=True,
        )
        BackfillCollector(corpus, registry, page_size=10).run(phases=("walk",))

        report = build_report(corpus)
        assert len(report.package_identity_swaps) == 1

    def test_swap_lists_can_be_truncated(self, populated):
        report = build_report(populated, swap_limit=0)
        assert report.endpoint_swaps == []


class TestOutput:
    def test_markdown_mentions_the_headline_numbers(self, populated):
        text = build_report(populated).render()

        assert "# MCPWatch — Layer-1 retrospective" in text
        assert "Endpoint and repository swaps" in text
        assert "`swap.example/mcp`" in text

    def test_json_round_trips(self, populated):
        payload = json.loads(json.dumps(build_report(populated).as_json()))

        assert payload["population"]["versions_total"] == 4
        assert payload["endpoint_swaps"][0]["server_key"] == "swap.example/mcp"

    def test_the_cli_writes_a_file(self, populated, tmp_path):
        out = tmp_path / "report.md"
        code = main(["--corpus", str(populated.root), "--out", str(out)])

        assert code == 0
        assert "Layer-1 retrospective" in out.read_text(encoding="utf-8")
