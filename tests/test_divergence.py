"""Divergence harness tests.

Everything that decides whether a publisher gets accused is exercised for real:
the declared-capability extractor, the exercise protocol's exclusions and
argument synthesis, the strace parser, and the scoring. Docker is not — the
harness is validated end to end by running the known-behaviour fixtures against
a live daemon (``python -m mcpwatch.divergence validate``), which is the only
check that proves the instrumentation sees what it claims to.

The bias direction is asserted, not just described. Several tests exist purely
to pin down that an ambiguous description resolves toward *declared*, because
the failure that matters here is a false accusation.
"""

import pytest

from mcpwatch.divergence import (
    Capability,
    CapabilityProfile,
    DivergenceReport,
    Unfillable,
    declared_from_schema,
    declared_from_text,
    declared_profile,
    may_exercise,
    observed_profile,
    parse_sinkhole,
    parse_strace,
    score_tool,
    select_tools,
    synthesize_arguments,
    wilson_interval,
)
from mcpwatch.divergence.protocol import MAX_TOOLS_PER_SERVER, SYNTHETIC_MARKER

# ----------------------------------------------------------------- declared ---


class TestDeclaredFromText:
    def test_prose_naming_the_network_declares_it(self):
        assert Capability.NETWORK in declared_from_text("Fetches a URL over HTTP.")

    def test_prose_naming_a_shell_declares_a_subprocess(self):
        assert Capability.SUBPROCESS in declared_from_text("Runs a shell command.")

    def test_word_boundaries_stop_substring_matches(self):
        # "apiary" is not "api"; this removed a third of the early false hits.
        assert Capability.NETWORK not in declared_from_text("Manages an apiary.")

    def test_pathology_is_not_a_filesystem_path(self):
        assert Capability.FILESYSTEM_READ not in declared_from_text("Summarises pathology reports.")

    def test_empty_text_declares_nothing(self):
        assert declared_from_text("").capabilities == frozenset()


class TestDeclaredFromSchema:
    def test_a_url_parameter_declares_network(self):
        schema = {"properties": {"webhook_url": {"type": "string"}}}
        assert Capability.NETWORK in declared_from_schema(schema)

    def test_a_uri_format_declares_network(self):
        schema = {"properties": {"target": {"type": "string", "format": "uri"}}}
        assert Capability.NETWORK in declared_from_schema(schema)

    def test_a_command_parameter_declares_a_subprocess(self):
        schema = {"properties": {"cmd": {"type": "string"}}}
        assert Capability.SUBPROCESS in declared_from_schema(schema)

    def test_a_parameter_description_counts_as_declaration(self):
        schema = {"properties": {"q": {"type": "string", "description": "Sent to our API."}}}
        assert Capability.NETWORK in declared_from_schema(schema)

    def test_nested_objects_are_walked(self):
        schema = {"properties": {"opts": {"type": "object", "properties": {"url": {}}}}}
        assert Capability.NETWORK in declared_from_schema(schema)

    def test_a_cyclic_schema_terminates(self):
        schema: dict = {"properties": {}}
        schema["properties"]["self"] = schema
        declared_from_schema(schema)  # must return rather than recurse forever


class TestDeclaredProfile:
    def test_the_tool_name_alone_can_declare(self):
        # Terseness is not dishonesty; a tool called fetch_url has said so.
        tool = {"name": "fetch_url", "description": ""}
        assert Capability.NETWORK in declared_profile(tool)

    def test_a_readonly_false_annotation_declares_a_write(self):
        tool = {"name": "x", "description": "", "annotations": {"readOnlyHint": False}}
        assert Capability.FILESYSTEM_WRITE in declared_profile(tool)

    def test_a_bare_tool_declares_nothing(self):
        assert declared_profile({"name": "x", "description": ""}).capabilities == frozenset()

    def test_evidence_is_recorded_for_every_declaration(self):
        profile = declared_profile({"name": "fetch_url", "description": "Downloads a file."})
        assert profile.reasons(Capability.NETWORK)


# ----------------------------------------------------------------- protocol ---


def tool(name: str = "read_thing", **extra) -> dict:
    base = {"name": name, "description": "Reads a thing.", "inputSchema": {"type": "object"}}
    base.update(extra)
    return base


class TestExclusions:
    def test_a_destructive_annotation_is_believed(self):
        decision = may_exercise(tool(annotations={"destructiveHint": True}))
        assert not decision
        assert "destructiveHint" in decision.reason

    def test_a_non_readonly_annotation_is_believed(self):
        assert not may_exercise(tool(annotations={"readOnlyHint": False}))

    @pytest.mark.parametrize(
        "name",
        ["delete_project", "send_email", "transfer_funds", "deploy_release", "run_shell"],
    )
    def test_a_destructive_verb_in_the_name_excludes(self, name):
        assert not may_exercise(tool(name))

    def test_a_destructive_verb_in_the_opening_sentence_excludes(self):
        assert not may_exercise(tool(description="Deletes the named bucket."))

    def test_a_disclaimer_later_in_the_description_does_not_exclude(self):
        # "This does not delete anything" must not read as a delete tool, or the
        # exclusions would remove exactly the tools that documented themselves.
        assert may_exercise(tool(description="Lists buckets. This never deletes anything."))

    def test_an_ordinary_read_tool_is_allowed(self):
        assert may_exercise(tool("get_weather", description="Returns today's forecast."))

    def test_an_unfillable_required_parameter_excludes(self):
        schema = {"type": "object", "required": ["thing"], "properties": {"thing": {"type": "x"}}}
        assert not may_exercise(tool(inputSchema=schema))

    def test_a_nameless_tool_is_excluded(self):
        assert not may_exercise({"description": "?"})


class TestSelection:
    def test_selection_is_capped_per_server(self):
        tools = [tool(f"get_thing_{i}") for i in range(MAX_TOOLS_PER_SERVER + 5)]
        selected, skipped = select_tools(tools)
        assert len(selected) == MAX_TOOLS_PER_SERVER
        assert all("budget" in reason for _, reason in skipped)

    def test_every_exclusion_is_reported_with_its_reason(self):
        selected, skipped = select_tools([tool("get_a"), tool("delete_b")])
        assert [t["name"] for t in selected] == ["get_a"]
        assert skipped == [("delete_b", "name contains 'delete'")]

    def test_selection_is_stable_across_runs(self):
        tools = [tool(f"get_thing_{i}") for i in range(20)]
        first = [t["name"] for t in select_tools(tools)[0]]
        second = [t["name"] for t in select_tools(list(reversed(tools)))[0]]
        assert first == second


class TestSyntheticArguments:
    def test_only_required_parameters_are_filled(self):
        schema = {
            "required": ["a"],
            "properties": {"a": {"type": "string"}, "b": {"type": "string"}},
        }
        assert set(synthesize_arguments(schema)) == {"a"}

    def test_urls_point_at_a_tld_that_cannot_resolve(self):
        schema = {"required": ["url"], "properties": {"url": {"type": "string", "format": "uri"}}}
        assert synthesize_arguments(schema)["url"].endswith(f"/{SYNTHETIC_MARKER}")
        assert ".invalid/" in synthesize_arguments(schema)["url"]

    def test_credential_parameters_get_an_obvious_fake(self):
        schema = {"required": ["api_key"], "properties": {"api_key": {"type": "string"}}}
        assert "not-a-real-credential" in synthesize_arguments(schema)["api_key"]

    def test_paths_stay_inside_the_container_scratch_space(self):
        schema = {"required": ["path"], "properties": {"path": {"type": "string"}}}
        assert synthesize_arguments(schema)["path"].startswith("/tmp/")

    def test_an_enum_picks_a_value_the_schema_named(self):
        schema = {"required": ["mode"], "properties": {"mode": {"enum": ["read", "write"]}}}
        assert synthesize_arguments(schema)["mode"] == "read"

    def test_every_generated_string_is_traceable_to_this_project(self):
        schema = {"required": ["q"], "properties": {"q": {"type": "string"}}}
        assert SYNTHETIC_MARKER in synthesize_arguments(schema)["q"]

    def test_an_unsupported_type_refuses_rather_than_guessing(self):
        schema = {"required": ["x"], "properties": {"x": {"type": "widget"}}}
        with pytest.raises(Unfillable):
            synthesize_arguments(schema)

    def test_no_required_list_means_no_arguments(self):
        assert synthesize_arguments({"properties": {"a": {"type": "string"}}}) == {}


# ------------------------------------------------------------------ observe ---

TRACE = """\
1000.000000 execve("/usr/bin/node", ["node", "server.js"], 0x7ffd) = 0
1000.100000 openat(AT_FDCWD, "/usr/lib/node/index.js", O_RDONLY) = 3
1010.000000 openat(AT_FDCWD, "/home/prober/.aws/credentials", O_RDONLY) = 4
1010.100000 connect(5, {sa_family=AF_INET, sin_port=htons(443)}, 16) = -1 ECONNREFUSED
1010.200000 execve("/bin/sh", ["sh", "-c", "id"], 0x7ffd) = 0
1010.300000 openat(AT_FDCWD, "/tmp/out.txt", O_WRONLY|O_CREAT, 0644) = 6
1010.400000 connect(7, {sa_family=AF_UNIX, sun_path="/run/x.sock"}, 12) = 0
1020.000000 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 8
"""


class TestTraceParsing:
    def test_events_are_parsed_with_timestamps(self):
        events = parse_strace(TRACE)
        assert len(events) == 8
        assert events[0].call == "execve"
        assert events[0].at == 1000.0

    def test_a_pid_prefix_is_tolerated(self):
        events = parse_strace('[pid  42] 1000.5 openat(AT_FDCWD, "/x", O_RDONLY) = 3')
        assert events[0].call == "openat"

    def test_unparseable_lines_are_skipped_not_raised(self):
        assert parse_strace("+++ exited with 0 +++\ngarbage\n") == []

    def test_the_first_quoted_string_is_the_path(self):
        (event,) = parse_strace('1000.0 openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3')
        assert event.path == "/etc/hosts"


class TestObservedProfile:
    def _profile(self, window=(1005.0, 1015.0)):
        return observed_profile(parse_strace(TRACE), [], window)

    def test_a_refused_connection_still_counts_as_network(self):
        # The sinkhole refuses everything on purpose; the reach is the finding.
        assert Capability.NETWORK in self._profile()

    def test_a_unix_socket_is_not_network(self):
        profile = observed_profile(parse_strace(TRACE), [], (1010.35, 1010.45))
        assert Capability.NETWORK not in profile

    def test_an_exec_is_a_subprocess(self):
        assert Capability.SUBPROCESS in self._profile()

    def test_a_credential_path_is_flagged(self):
        assert Capability.CREDENTIAL_ACCESS in self._profile()

    def test_a_write_flag_makes_it_a_write_not_a_read(self):
        profile = observed_profile(parse_strace(TRACE), [], (1010.25, 1010.35))
        assert Capability.FILESYSTEM_WRITE in profile
        assert Capability.FILESYSTEM_READ not in profile

    def test_runtime_library_reads_are_filtered_out(self):
        profile = observed_profile(parse_strace(TRACE), [], (1000.0, 1000.5))
        assert Capability.FILESYSTEM_READ not in profile

    def test_events_outside_the_window_are_excluded(self):
        # The whole reason windows exist: startup would otherwise make every
        # tool on every server look like it touches everything.
        profile = observed_profile(parse_strace(TRACE), [], (1005.0, 1006.0))
        assert profile.capabilities == frozenset()

    def test_sinkhole_records_corroborate_network(self):
        sinkhole = parse_sinkhole([{"at": 1010.15, "kind": "tcp", "sni": "evil.example"}])
        profile = observed_profile([], sinkhole, (1010.0, 1011.0))
        assert Capability.NETWORK in profile
        assert "evil.example" in profile.reasons(Capability.NETWORK)[0]


# -------------------------------------------------------------------- score ---


class TestScoring:
    def test_an_observed_undeclared_capability_is_a_finding(self):
        declared = CapabilityProfile.of((Capability.FILESYSTEM_READ, "says so"))
        observed = CapabilityProfile.of((Capability.NETWORK, "connect()"))
        (finding,) = score_tool("a/b", "t", declared, observed)
        assert finding.divergence_class == "undeclared_network"
        assert finding.evidence == ("connect()",)

    def test_a_declared_capability_is_not_a_finding(self):
        profile = CapabilityProfile.of((Capability.NETWORK, "x"))
        assert score_tool("a/b", "t", profile, profile) == []

    def test_declared_but_not_observed_is_never_scored(self):
        # One-directional: failing to observe is not evidence of absence.
        declared = CapabilityProfile.of((Capability.NETWORK, "says so"))
        assert score_tool("a/b", "t", declared, CapabilityProfile()) == []

    def test_both_filesystem_capabilities_report_as_one_class(self):
        observed = CapabilityProfile.of(
            (Capability.FILESYSTEM_READ, "r"), (Capability.FILESYSTEM_WRITE, "w")
        )
        classes = {
            f.divergence_class for f in score_tool("a/b", "t", CapabilityProfile(), observed)
        }
        assert classes == {"undeclared_filesystem"}


class TestWilson:
    def test_a_zero_count_has_a_nonzero_upper_bound(self):
        # Nothing observed in 100 trials does not mean the true rate is zero,
        # and a report that said so would overclaim.
        low, high = wilson_interval(0, 100)
        assert low == pytest.approx(0.0, abs=1e-9)
        assert 0.0 < high < 0.05

    def test_the_interval_stays_inside_zero_and_one(self):
        for successes, trials in ((0, 1), (1, 1), (5, 10), (99, 100)):
            low, high = wilson_interval(successes, trials)
            assert 0.0 <= low <= high <= 1.0

    def test_more_trials_narrow_the_interval(self):
        narrow = wilson_interval(50, 1000)
        wide = wilson_interval(5, 100)
        assert (narrow[1] - narrow[0]) < (wide[1] - wide[0])

    def test_an_empty_sample_has_no_proportion(self):
        assert wilson_interval(0, 0) == (0.0, 0.0)


class TestReport:
    def test_a_tool_diverging_twice_counts_once(self):
        report = DivergenceReport(tools_exercised=10, servers_exercised=1)
        report.add(
            score_tool(
                "a/b",
                "t",
                CapabilityProfile(),
                CapabilityProfile.of((Capability.NETWORK, "n"), (Capability.SUBPROCESS, "s")),
            )
        )
        assert report.diverging_tools == 1
        assert report.rate()[0] == pytest.approx(0.1)

    def test_the_caveats_travel_with_the_number(self):
        # The number is what gets quoted, so they cannot live in a README.
        assert len(DivergenceReport().as_json()["caveats"]) >= 4

    def test_an_empty_report_renders_without_dividing_by_zero(self):
        assert "0/0" in DivergenceReport().render()
