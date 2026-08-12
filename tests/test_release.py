"""Release/output tests.

The pinning replay produces the number this project exists to hand a
practitioner, so its accounting is pinned down here rather than eyeballed in a
report: what counts as blocked, what counts as caught, and what happens to a
ratio when nothing was caught at all.

Site and datasheet rendering are checked for the properties that would be
harmful to get wrong — no server named, caveats present, no crash on an empty
corpus — not for their exact wording.
"""

import json

import pytest

from mcpwatch.diff import Change, ChangeKind, ChangeSet, SeverityFlag, Verdict
from mcpwatch.release import (
    POLICIES,
    Coverage,
    Metrics,
    PinPolicy,
    blocks,
    render_site,
    replay,
    summarise_changesets,
)
from mcpwatch.release.pinning import render
from mcpwatch.store import Layer


def changeset(
    *kinds: ChangeKind,
    flags: tuple[SeverityFlag, ...] = (),
    server: str = "a.example/mcp",
    quarantined: bool = False,
) -> ChangeSet:
    return ChangeSet(
        change_id="c" * 16,
        server_key=server,
        layer=Layer.MANIFEST,
        verdict=Verdict.MUTATED,
        to_obs_id=2,
        to_effective_at="2026-05-01T00:00:00.000000+00:00",
        to_norm_sha="b" * 64,
        from_obs_id=1,
        from_effective_at="2026-04-01T00:00:00.000000+00:00",
        from_norm_sha="a" * 64,
        changes=tuple(Change(kind=kind, path=f"tools/x/{kind}") for kind in kinds),
        flags=flags,
        quarantined=quarantined,
    )


STRICT = POLICIES[0]
PERMISSIVE = POLICIES[-1]


# ------------------------------------------------------------------ blocking ---


class TestBlocking:
    def test_the_strictest_policy_blocks_any_change(self):
        assert blocks(changeset(ChangeKind.TOOL_DESCRIPTION_CHANGED), STRICT)

    def test_a_version_bump_blocks(self):
        # Not an accounting choice: not receiving the new version automatically
        # is exactly what pinning does. Exempting it would price a policy
        # nobody proposes.
        assert blocks(changeset(ChangeKind.VERSION_BUMPED), STRICT)

    def test_a_permissive_policy_passes_a_pure_addition(self):
        assert not blocks(changeset(ChangeKind.TOOL_ADDED), PERMISSIVE)

    def test_one_non_exempt_change_blocks_the_whole_transition(self):
        # A release bundling a typo fix with a new credential parameter is not
        # a typo fix.
        mixed = changeset(ChangeKind.TOOL_DESCRIPTION_CHANGED, ChangeKind.TOOL_REMOVED)
        assert blocks(mixed, PERMISSIVE)

    def test_an_empty_transition_never_blocks(self):
        assert not blocks(changeset(), STRICT)

    def test_description_exemption_waves_through_the_poisoning_surface(self):
        # Documented as a hazard rather than a feature: a description is what
        # the model reads, so exempting it is blind to tool poisoning.
        policy = PinPolicy("d", "", allow_description_changes=True)
        assert not blocks(changeset(ChangeKind.TOOL_DESCRIPTION_CHANGED), policy)


# -------------------------------------------------------------------- replay ---


class TestReplay:
    def test_a_flagged_blocked_transition_counts_as_caught(self):
        sets = [
            changeset(ChangeKind.SCHEMA_PARAM_ADDED, flags=(SeverityFlag.CREDENTIAL_PARAM_ADDED,))
        ]
        (outcome,) = replay(sets, [STRICT])
        assert (outcome.blocked, outcome.caught, outcome.friction) == (1, 1, 0)

    def test_an_unflagged_blocked_transition_is_friction(self):
        (outcome,) = replay([changeset(ChangeKind.VERSION_BUMPED)], [STRICT])
        assert (outcome.blocked, outcome.caught, outcome.friction) == (1, 0, 1)

    def test_a_flagged_transition_a_policy_passes_is_a_miss(self):
        sets = [changeset(ChangeKind.TOOL_ADDED, flags=(SeverityFlag.TOOL_COUNT_GREW,))]
        (outcome,) = replay(sets, [PERMISSIVE])
        assert outcome.missed == 1
        assert outcome.blocked == 0

    def test_quarantined_transitions_are_excluded_entirely(self):
        # Counting our own measurement error as friction would inflate the cost
        # of pinning with phantom mutations.
        (outcome,) = replay([changeset(ChangeKind.VERSION_BUMPED, quarantined=True)], [STRICT])
        assert (outcome.blocked, outcome.passed) == (0, 0)

    def test_the_friction_ratio_is_benign_blocks_per_catch(self):
        sets = [changeset(ChangeKind.VERSION_BUMPED) for _ in range(9)]
        sets.append(
            changeset(ChangeKind.SCHEMA_PARAM_ADDED, flags=(SeverityFlag.NETWORK_PARAM_ADDED,))
        )
        (outcome,) = replay(sets, [STRICT])
        assert outcome.ratio() == pytest.approx(9.0)

    def test_a_ratio_with_nothing_caught_is_undefined_not_infinite(self):
        (outcome,) = replay([changeset(ChangeKind.VERSION_BUMPED)], [STRICT])
        assert outcome.ratio() is None

    def test_the_high_signal_ratio_is_stricter_than_the_permissive_one(self):
        # TOOL_COUNT_GREW is a size change, not a capability change, so it
        # counts under the loose definition and not the strict one.
        sets = [
            changeset(ChangeKind.TOOL_ADDED, flags=(SeverityFlag.TOOL_COUNT_GREW,)),
            changeset(ChangeKind.VERSION_BUMPED),
        ]
        (outcome,) = replay(sets, [STRICT])
        assert outcome.ratio() == pytest.approx(1.0)
        assert outcome.ratio(high_signal=True) is None

    def test_every_default_policy_is_replayed(self):
        outcomes = replay([changeset(ChangeKind.VERSION_BUMPED)])
        assert len(outcomes) == len(POLICIES)
        assert [o.policy.name for o in outcomes] == [p.name for p in POLICIES]

    def test_a_permissive_policy_never_blocks_more_than_a_strict_one(self):
        sets = [
            changeset(ChangeKind.TOOL_ADDED),
            changeset(ChangeKind.TOOL_DESCRIPTION_CHANGED),
            changeset(ChangeKind.SCHEMA_PARAM_ADDED),
            changeset(ChangeKind.TOOL_REMOVED),
        ]
        outcomes = {o.policy.name: o for o in replay(sets)}
        assert outcomes["permissive"].blocked <= outcomes["whole_manifest"].blocked


class TestRender:
    def test_the_report_states_the_proxy_is_not_ground_truth(self):
        text = render(
            replay([changeset(ChangeKind.VERSION_BUMPED)]), layer="manifest", transitions=1
        )
        assert "not an adjudicated finding" in text
        assert "LOWER bound" in text

    def test_an_undefined_ratio_renders_as_not_applicable(self):
        text = render(
            replay([changeset(ChangeKind.VERSION_BUMPED)]), layer="manifest", transitions=1
        )
        assert "n/a" in text


# ------------------------------------------------------------------- metrics ---


class TestMetrics:
    def test_servers_changing_are_counted_once_each(self):
        sets = [
            changeset(ChangeKind.VERSION_BUMPED, server="a/x"),
            changeset(ChangeKind.VERSION_BUMPED, server="a/x"),
            changeset(ChangeKind.VERSION_BUMPED, server="b/y"),
        ]
        metrics = summarise_changesets(sets, layer="manifest", days=5.0)
        assert (metrics.servers, metrics.servers_changed, metrics.changed) == (2, 2, 3)

    def test_quarantined_transitions_do_not_count_as_changes(self):
        sets = [changeset(ChangeKind.VERSION_BUMPED, quarantined=True)]
        metrics = summarise_changesets(sets, layer="manifest", days=5.0)
        assert metrics.changed == 0
        assert metrics.quarantined_transitions == 1

    def test_collection_window_and_history_span_are_reported_separately(self):
        # Layer 1 is collected for days and covers years. Reporting only the
        # collection window would understate it by three orders of magnitude.
        payload = summarise_changesets([], layer="registry", days=5.3, span=1400.0).as_json()
        assert payload["observation_days"] == 5.3
        assert payload["history_span_days"] == 1400.0

    def test_a_layer2_report_carries_its_window_and_forbids_annualising(self):
        payload = summarise_changesets([], layer="manifest", days=5.0).as_json()
        assert payload["observation_days"] == 5.0
        assert "must not be annualised" in str(payload["caveat"])

    def test_an_empty_layer_has_a_zero_rate_rather_than_dividing_by_zero(self):
        assert summarise_changesets([], layer="manifest", days=0.0).mutation_rate == 0.0


# ---------------------------------------------------------------------- site ---


class TestSite:
    def _render(self, divergence=None):
        return render_site(
            coverage=Coverage(servers_tracked=10, layer2_targets=8, layer2_ok=4),
            layers=[Metrics(layer="manifest", observation_days=5.0, servers=3)],
            outcomes=replay([changeset(ChangeKind.VERSION_BUMPED)]),
            pinning_layer="manifest",
            divergence=divergence,
            generated_at="2026-08-12T00:00:00+00:00",
        )

    def test_no_server_is_ever_named(self):
        # Naming is gated on coordinated disclosure, and this page is rebuilt
        # automatically — it is exactly what would leak a name early.
        assert "a.example/mcp" not in self._render()

    def test_the_page_is_self_contained(self):
        page = self._render()
        assert "<script" not in page
        assert "http://" not in page and "https://" not in page

    def test_the_friction_caveat_travels_with_the_table(self):
        assert "lower</em> bound" in self._render()

    def test_it_renders_without_a_divergence_run(self):
        assert "divergence" not in self._render().lower().split("<footer")[0].split("<h2>")[-1]

    def test_a_divergence_run_is_shown_when_present(self):
        page = self._render({"divergence_rate": 0.312, "ci95": [0.22, 0.42], "tools_exercised": 80})
        assert "31.2%" in page
        assert "95% CI" in page

    def test_values_are_html_escaped(self):
        page = render_site(
            coverage=Coverage(),
            layers=[Metrics(layer="<script>", observation_days=0.0)],
            outcomes=[],
            pinning_layer="<img>",
            divergence=None,
            generated_at="x",
        )
        assert "<script>" not in page.split("<style>")[0] + page.split("</style>")[-1]
        assert "&lt;script&gt;" in page


def test_metrics_json_round_trips():
    payload = summarise_changesets([], layer="registry", days=1.0).as_json()
    assert json.loads(json.dumps(payload)) == payload


class TestConcentration:
    """One publisher owning hundreds of servers is not hundreds of samples."""

    def _fleet(self, size: int):
        return [
            changeset(
                ChangeKind.SCHEMA_PARAM_ADDED,
                flags=(SeverityFlag.CREDENTIAL_PARAM_ADDED,),
                server=f"io.github.fleet/server-{i}",
            )
            for i in range(size)
        ]

    def test_a_fleet_wide_edit_is_reported_as_concentrated(self):
        (outcome,) = replay(self._fleet(50), [STRICT])
        top = outcome.concentration()
        assert top is not None
        namespace, count, share = top
        assert (namespace, count) == ("io.github.fleet", 50)
        assert share == pytest.approx(1.0)

    def test_excluding_the_dominant_publisher_changes_the_headline(self):
        sets = [
            *self._fleet(50),
            *(changeset(ChangeKind.VERSION_BUMPED, server=f"other/s{i}") for i in range(20)),
        ]
        (outcome,) = replay(sets, [STRICT])
        # With the fleet counted, 20 benign blocks against 50 catches.
        assert outcome.ratio() == pytest.approx(20 / 50)
        # Without it, 20 benign blocks and nothing caught at all.
        assert outcome.ratio_excluding("io.github.fleet") is None

    def test_concentration_is_none_when_nothing_was_caught(self):
        (outcome,) = replay([changeset(ChangeKind.VERSION_BUMPED)], [STRICT])
        assert outcome.concentration() is None

    def test_the_warning_appears_in_the_report_when_catches_are_concentrated(self):
        text = render(replay(self._fleet(50), [STRICT]), layer="manifest", transitions=50)
        assert "CONCENTRATION WARNING" in text
        assert "io.github.fleet" in text

    def test_no_warning_when_catches_are_spread_across_publishers(self):
        sets = [
            changeset(
                ChangeKind.SCHEMA_PARAM_ADDED,
                flags=(SeverityFlag.CREDENTIAL_PARAM_ADDED,),
                server=f"pub{i}/s",
            )
            for i in range(20)
        ]
        text = render(replay(sets, [STRICT]), layer="manifest", transitions=20)
        assert "CONCENTRATION WARNING" not in text

    def test_the_json_carries_the_adjusted_ratio(self):
        sets = [
            *self._fleet(50),
            changeset(
                ChangeKind.SCHEMA_PARAM_ADDED,
                flags=(SeverityFlag.NETWORK_PARAM_ADDED,),
                server="other/s",
            ),
        ]
        (outcome,) = replay(sets, [STRICT])
        payload = outcome.as_json()
        assert payload["largest_publisher"] == "io.github.fleet"
        assert payload["largest_publisher_share"] == pytest.approx(50 / 51, abs=1e-3)
        assert payload["friction_ratio_excluding_largest"] == pytest.approx(0.0)


class TestPublishedDirectoryNamesNobody:
    """Everything `build` writes lands in a directory a host serves wholesale."""

    def test_per_server_findings_are_stripped_from_the_published_metrics(self):
        from mcpwatch.release.cli import _publishable

        raw = {
            "divergence_rate": 0.31,
            "by_class": {"undeclared_network": 22},
            "findings": [{"server_key": "io.github.someone/mcp", "tool": "t"}],
        }
        published = _publishable(raw)
        assert published is not None
        assert "findings" not in published
        assert "io.github.someone/mcp" not in json.dumps(published)

    def test_the_aggregate_figures_survive_stripping(self):
        from mcpwatch.release.cli import _publishable

        published = _publishable({"divergence_rate": 0.31, "ci95": [0.2, 0.4], "findings": []})
        assert published == {"divergence_rate": 0.31, "ci95": [0.2, 0.4]}

    def test_no_divergence_run_stays_none(self):
        from mcpwatch.release.cli import _publishable

        assert _publishable(None) is None

    def test_the_concentration_finding_survives_without_naming_the_publisher(self):
        from mcpwatch.release.cli import _publishable_pinning

        rows = _publishable_pinning(
            [
                {
                    "policy": "whole_manifest",
                    "largest_publisher": "io.github.someone",
                    "largest_publisher_share": 0.7,
                    "friction_ratio_excluding_largest": 1.4,
                }
            ]
        )
        assert "io.github.someone" not in json.dumps(rows)
        # The methodological point is the share and the adjusted ratio, not who.
        assert rows[0]["largest_publisher_share"] == 0.7
        assert rows[0]["friction_ratio_excluding_largest"] == 1.4

    def test_a_policy_without_a_concentration_finding_is_untouched(self):
        from mcpwatch.release.cli import _publishable_pinning

        assert _publishable_pinning([{"policy": "x", "blocked": 1}]) == [
            {"policy": "x", "blocked": 1}
        ]
