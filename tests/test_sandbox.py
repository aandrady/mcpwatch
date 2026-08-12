"""Sandbox tests.

The sampling frame, the allocator, and the result folding are exercised for
real. Docker is not: containment is proved by running the canary against a live
daemon (``python -m mcpwatch.sandbox verify``), and a mocked Docker would assert
that we called the flags we meant to call while proving nothing about whether
they contain anything. That check belongs on the host, and its report is stored
in the run stats of every probe cycle.

The one Docker-shaped thing tested here is the SNI parser, because it reads
attacker-influenced bytes and must never raise — a crash there would take down
the sinkhole that exists to record the attempt.
"""

import ast
import importlib.util
import json
from pathlib import Path

import pytest

from mcpwatch.sandbox import Candidate, SampleStore, allocate, candidates, draw
from mcpwatch.sandbox.frame import MINIMUM_PER_STRATUM
from mcpwatch.store import Corpus, Layer, ObservationStatus

CONTAINER_PYTHON = (3, 11)
"""The oldest interpreter anything under ``deploy/`` has to run on.

``driver.py`` runs inside the probe image (node:22-bookworm-slim, Python 3.11);
``sinkhole.py`` runs in python:3.13-alpine. The package itself targets 3.14,
which is a real trap: the formatter applied PEP 758 and rewrote
``except (A, B):`` into ``except A, B:``, valid on 3.14 and a SyntaxError on
3.11. It shipped, and the containment gate caught it only when the canary would
not start.
"""


class TestContainerSideSyntax:
    """Everything under deploy/ must parse on the interpreter it will run on."""

    @pytest.mark.parametrize(
        "path",
        sorted((Path(__file__).resolve().parents[1] / "deploy").rglob("*.py")),
        ids=lambda p: p.name,
    )
    def test_it_parses_on_the_container_interpreter(self, path):
        ast.parse(path.read_text(encoding="utf-8"), feature_version=CONTAINER_PYTHON)


def _load_deploy_module(name: str, *parts: str):
    """Import a module from deploy/, which is not an installed package."""
    path = Path(__file__).resolve().parents[1] / "deploy" / "sandbox" / Path(*parts)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_sinkhole():
    return _load_deploy_module("sinkhole_under_test", "sinkhole", "sinkhole.py")


def _load_driver():
    return _load_deploy_module("driver_under_test", "probe", "driver.py")


def candidate(
    key: str = "a.example/mcp",
    registry: str = "npm",
    versions: int = 3,
    secret: bool = False,
) -> Candidate:
    return Candidate(
        server_key=key,
        registry_type=registry,
        identifier="@a/mcp",
        version="1.0.0",
        version_count=versions,
        declares_secret=secret,
    )


# ------------------------------------------------------------------- strata ---


class TestStrata:
    def test_version_buckets_split_where_the_mutation_signal_does(self):
        assert candidate(versions=1).version_bucket == "1"
        assert candidate(versions=4).version_bucket == "2-4"
        assert candidate(versions=5).version_bucket == "5+"

    def test_the_stratum_crosses_all_three_dimensions(self):
        assert candidate(registry="pypi", versions=9, secret=True).stratum == "pypi/5+/secret"

    def test_the_spec_pins_the_version_it_was_drawn_with(self):
        # A sample that re-probes a floating "latest" measures a moving target.
        assert candidate().as_spec()["version"] == "1.0.0"


# ---------------------------------------------------------------- allocator ---


class TestAllocate:
    def test_allocation_totals_the_requested_size(self):
        sizes = {"a": 2462, "b": 1821, "c": 1046, "d": 10}
        assert sum(allocate(sizes, 400).values()) == 400

    def test_a_rare_stratum_is_not_rounded_out_of_existence(self):
        # 8 servers in 9,197 rounds to zero proportionally; the floor is what
        # keeps the cell in the sample at all.
        quotas = allocate({"huge": 9189, "tiny": 8}, 400)
        assert quotas["tiny"] >= min(MINIMUM_PER_STRATUM, 8)

    def test_a_stratum_is_never_over_drawn_beyond_its_population(self):
        quotas = allocate({"huge": 9000, "tiny": 3}, 400)
        assert quotas["tiny"] <= 3

    def test_an_empty_population_allocates_nothing(self):
        assert allocate({}, 400) == {}


# --------------------------------------------------------------------- draw ---


class TestDraw:
    def test_the_same_seed_draws_the_same_sample(self):
        pool = [candidate(f"s{i}.example/mcp", versions=3) for i in range(200)]
        first, _ = draw(pool, size=40, seed=7)
        second, _ = draw(pool, size=40, seed=7)
        assert [c.server_key for c in first] == [c.server_key for c in second]

    def test_a_different_seed_draws_a_different_sample(self):
        pool = [candidate(f"s{i}.example/mcp", versions=3) for i in range(200)]
        first, _ = draw(pool, size=40, seed=7)
        second, _ = draw(pool, size=40, seed=8)
        assert [c.server_key for c in first] != [c.server_key for c in second]

    def test_every_stratum_present_in_the_pool_is_represented(self):
        pool = [candidate(f"n{i}.example/mcp", "npm", 3) for i in range(500)] + [
            candidate(f"p{i}.example/mcp", "pypi", 9, True) for i in range(6)
        ]
        chosen, sizes = draw(pool, size=100, seed=1)
        assert set(sizes) == {"npm/2-4/nosecret", "pypi/5+/secret"}
        assert {c.stratum for c in chosen} == set(sizes)

    def test_stratum_population_sizes_are_returned_for_reweighting(self):
        pool = [candidate(f"n{i}.example/mcp", "npm", 3) for i in range(500)]
        _, sizes = draw(pool, size=50, seed=1)
        assert sizes == {"npm/2-4/nosecret": 500}


# ---------------------------------------------------------------- the frame ---


def _registry_document(name: str, *, packages: list[dict], remotes: list | None = None) -> dict:
    server: dict = {"name": name, "version": "1.0.0", "packages": packages}
    if remotes:
        server["remotes"] = remotes
    return {"server": server}


def _npm_package(identifier: str = "@a/mcp", *, secret: bool = False) -> dict:
    package: dict = {
        "registryType": "npm",
        "identifier": identifier,
        "version": "1.0.0",
        "transport": {"type": "stdio"},
    }
    if secret:
        package["environmentVariables"] = [{"name": "API_KEY", "isSecret": True}]
    return package


@pytest.fixture
def corpus(tmp_path):
    with Corpus(tmp_path / "corpus") as opened:
        yield opened


def _store(corpus: Corpus, name: str, document: dict) -> None:
    run_id = corpus.start_run("test", "0.0.0")
    corpus.upsert_server(server_key=name, registry_name=name)
    corpus.record_snapshot(
        run_id=run_id,
        server_key=name,
        layer=Layer.REGISTRY,
        document=document,
        status=ObservationStatus.OK,
    )
    corpus.finish_run(run_id, stats={})


class TestCandidates:
    def test_a_stdio_package_server_is_eligible(self, corpus):
        _store(
            corpus, "a.example/mcp", _registry_document("a.example/mcp", packages=[_npm_package()])
        )
        found = list(candidates(corpus))
        assert [c.server_key for c in found] == ["a.example/mcp"]
        assert found[0].identifier == "@a/mcp"

    def test_a_dual_transport_server_is_excluded(self, corpus):
        # WP3 already probes it over HTTP. Probing it both ways would write two
        # different manifests for one server_key and manufacture a mutation
        # every cycle.
        _store(
            corpus,
            "b.example/mcp",
            _registry_document(
                "b.example/mcp",
                packages=[_npm_package()],
                remotes=[{"type": "streamable-http", "url": "https://b.example/mcp"}],
            ),
        )
        assert list(candidates(corpus)) == []

    def test_an_unsupported_registry_type_is_excluded(self, corpus):
        _store(
            corpus,
            "c.example/mcp",
            _registry_document(
                "c.example/mcp",
                packages=[
                    {
                        "registryType": "oci",
                        "identifier": "example/img",
                        "transport": {"type": "stdio"},
                    }
                ],
            ),
        )
        assert list(candidates(corpus)) == []

    def test_a_non_stdio_package_is_excluded(self, corpus):
        package = _npm_package()
        package["transport"] = {"type": "streamable-http"}
        _store(corpus, "d.example/mcp", _registry_document("d.example/mcp", packages=[package]))
        assert list(candidates(corpus)) == []

    def test_declared_launch_arguments_ride_along_in_the_spec(self, corpus):
        package = _npm_package()
        package["packageArguments"] = [{"type": "positional", "value": "mcp"}]
        _store(corpus, "f.example/mcp", _registry_document("f.example/mcp", packages=[package]))
        (found,) = list(candidates(corpus))
        assert found.as_spec()["package_arguments"] == [{"type": "positional", "value": "mcp"}]

    def test_a_declared_secret_lands_in_the_stratum(self, corpus):
        _store(
            corpus,
            "e.example/mcp",
            _registry_document("e.example/mcp", packages=[_npm_package(secret=True)]),
        )
        (found,) = list(candidates(corpus))
        assert found.declares_secret
        assert found.stratum.endswith("/secret")


# --------------------------------------------------------------------- store ---


class TestSampleStore:
    def test_the_frame_records_what_is_needed_to_reweight(self, tmp_path):
        with SampleStore(tmp_path / "sandbox.db") as store:
            members = [candidate(f"s{i}.example/mcp") for i in range(3)]
            store.record_sample(members, {"npm/2-4/nosecret": 9197}, seed=42, size=400)
            (frame,) = store.frames()
            assert frame["seed"] == 42
            assert json.loads(frame["strata_json"]) == {"npm/2-4/nosecret": 9197}
            assert frame["population"] == 9197

    def test_redrawing_never_disturbs_an_existing_member(self, tmp_path):
        with SampleStore(tmp_path / "sandbox.db") as store:
            store.record_sample([candidate("s0.example/mcp")], {"x": 1}, seed=1, size=1)
            added = store.record_sample(
                [candidate("s0.example/mcp"), candidate("s1.example/mcp")], {"x": 2}, seed=1, size=2
            )
            assert added == 1
            assert len(store.members()) == 2

    def test_specs_round_trip_for_the_driver(self, tmp_path):
        with SampleStore(tmp_path / "sandbox.db") as store:
            store.record_sample([candidate()], {"x": 1}, seed=1, size=1)
            (spec,) = store.specs()
            assert spec["identifier"] == "@a/mcp"
            assert spec["registry_type"] == "npm"


# -------------------------------------------------------------- launch argv ---


class TestLaunchArguments:
    """9.7% of the frame declares these; ignoring them starts the wrong program."""

    def setup_method(self):
        self.driver = _load_driver()

    def test_a_positional_subcommand_is_passed_through(self):
        # linebreak-gate prints usage and exits 2 without its `mcp` subcommand.
        spec = {"package_arguments": [{"type": "positional", "value": "mcp"}]}
        assert self.driver.package_arguments(spec) == ["mcp"]

    def test_a_named_argument_carries_its_value(self):
        spec = {"package_arguments": [{"type": "named", "name": "--mode", "value": "server"}]}
        assert self.driver.package_arguments(spec) == ["--mode", "server"]

    def test_a_named_flag_without_a_value_is_still_passed(self):
        spec = {"package_arguments": [{"type": "named", "name": "--stdio"}]}
        assert self.driver.package_arguments(spec) == ["--stdio"]

    def test_a_default_stands_in_for_a_missing_value(self):
        spec = {"package_arguments": [{"type": "positional", "default": "serve"}]}
        assert self.driver.package_arguments(spec) == ["serve"]

    def test_a_declared_argument_with_nothing_to_fill_in_is_skipped(self):
        # Inventing a value would be supplying input to a third-party process
        # rather than enumerating it.
        spec = {"package_arguments": [{"type": "positional", "isRequired": True}]}
        assert self.driver.package_arguments(spec) == []

    def test_no_declaration_produces_no_arguments(self):
        assert self.driver.package_arguments({}) == []

    def test_runtime_arguments_name_which_bin_to_run(self):
        # @clize/clize ships two bins and the default is the CLI, not the server.
        spec = {
            "runtime_arguments": [
                {"type": "named", "name": "--package", "value": "@clize/clize"},
                {"type": "positional", "value": "clize-mcp"},
            ]
        }
        assert self.driver._preferred_bin(spec) == "clize-mcp"

    def test_no_positional_runtime_argument_means_no_preference(self):
        spec = {"runtime_arguments": [{"type": "named", "name": "--package", "value": "x"}]}
        assert self.driver._preferred_bin(spec) is None


# ------------------------------------------------------- failure classifier ---


class TestFailureClassifier:
    """Read off the server's own stderr, measured against the first full cycle."""

    def setup_method(self):
        self.driver = _load_driver()

    def test_an_unpinned_sdk_that_moved_is_its_own_class(self):
        # 26 of 400 sampled servers failed on exactly this: an unpinned
        # dependency on the MCP SDK, which released 2.0 and moved the module.
        klass, undeclared = self.driver.classify_failure(
            {}, "crashed", "ModuleNotFoundError: No module named 'mcp.server.fastmcp'"
        )
        assert klass == "dependency_broken"
        assert undeclared is False

    def test_a_node_module_resolution_failure_counts_too(self):
        klass, _ = self.driver.classify_failure({}, "crashed", "Error: Cannot find module 'zod'")
        assert klass == "dependency_broken"

    def test_a_declared_credential_is_requires_credentials(self):
        spec = {"environment_variables": [{"name": "API_KEY", "isSecret": True}]}
        klass, undeclared = self.driver.classify_failure(
            spec, "crashed", "Error: API_KEY environment variable is required"
        )
        assert klass == "requires_credentials"
        assert undeclared is False

    def test_an_undeclared_credential_is_flagged_as_such(self):
        # The server demands a variable its published record never mentions, so
        # a consumer reading the registry could not know it was needed.
        klass, undeclared = self.driver.classify_failure(
            {}, "crashed", "Error: PERPLEXITY_API_KEY environment variable is required"
        )
        assert klass == "requires_credentials"
        assert undeclared is True

    def test_a_dependency_failure_wins_over_a_credential_mention(self):
        # An import error means it never got far enough to want a credential.
        klass, _ = self.driver.classify_failure(
            {},
            "crashed",
            "ModuleNotFoundError: No module named 'mcp'\nhint: set API_KEY",
        )
        assert klass == "dependency_broken"

    def test_an_unexplained_crash_stays_a_crash(self):
        assert self.driver.classify_failure({}, "crashed", "Segmentation fault")[0] == "crashed"

    def test_classes_decided_earlier_are_left_alone(self):
        # install_failed and timeout are decided by what happened, not by text.
        for klass in ("install_failed", "timeout", "launch_failed"):
            assert self.driver.classify_failure({}, klass, "no module named x")[0] == klass


# ------------------------------------------------------------------ sinkhole ---


class TestSniParser:
    """Reads attacker-influenced bytes, so it must never raise."""

    def setup_method(self):
        self.sinkhole = _load_sinkhole()

    def _client_hello(self, host: bytes) -> bytes:
        server_name = b"\x00" + len(host).to_bytes(2, "big") + host
        ext = (
            b"\x00\x00"
            + (len(server_name) + 2).to_bytes(2, "big")
            + len(server_name).to_bytes(2, "big")
            + server_name
        )
        body = (
            b"\x03\x03"
            + b"\x00" * 32
            + b"\x00"
            + b"\x00\x02\x00\x2f"
            + b"\x01\x00"
            + len(ext).to_bytes(2, "big")
            + ext
        )
        handshake = b"\x01" + len(body).to_bytes(3, "big") + body
        return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake

    def test_it_names_the_destination_a_server_reached_for(self):
        assert self.sinkhole.parse_sni(self._client_hello(b"evil.example")) == "evil.example"

    def test_plain_http_has_no_sni_and_that_is_not_an_error(self):
        assert self.sinkhole.parse_sni(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n") is None

    @pytest.mark.parametrize(
        "payload",
        [b"", b"\x16", b"\x16\x03\x01\xff\xff" + b"\x01" * 40, b"\x16\x03\x01" + b"\xff" * 200],
    )
    def test_malformed_bytes_return_none_instead_of_raising(self, payload):
        assert self.sinkhole.parse_sni(payload) is None

    def test_a_truncated_client_hello_returns_none(self):
        assert self.sinkhole.parse_sni(self._client_hello(b"evil.example")[:30]) is None
