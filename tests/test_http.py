"""Politeness tests. These encode the ethics guardrails, not just behaviour."""

import io
import time
import urllib.error

import pytest

from mcpwatch.collect.errors import HttpStatusError, RateLimitStop, TransportError
from mcpwatch.collect.http import PoliteClient, PolitenessPolicy, user_agent

FAST = PolitenessPolicy(
    max_rps=1000.0, post_request_sleep=0.0, backoff_base=0.001, backoff_cap=0.002
)


class _Response(io.BytesIO):
    """Minimal stand-in for the object urlopen returns."""

    def __init__(self, body: bytes, status: int = 200, headers: dict[str, str] | None = None):
        super().__init__(body)
        self.status = status
        self.headers = _Headers(headers or {})

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()


class _Headers(dict):
    def items(self):
        return super().items()


class _Opener:
    """Replays a scripted sequence of responses or exceptions."""

    def __init__(self, script):
        self.script = list(script)
        self.calls: list[str] = []

    def open(self, request, timeout=None):
        self.calls.append(request.full_url)
        self.headers = dict(request.header_items())
        outcome = self.script.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _http_error(code: int, headers: dict[str, str] | None = None) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://registry.example/v0/servers", code, "err", _Headers(headers or {}), None
    )


class TestUserAgent:
    def test_it_names_the_project_and_a_contact(self):
        ua = user_agent("mcpwatch@iyre.com")
        assert ua == "MCPWatch/0.1 (+mcpwatch@iyre.com) longitudinal MCP security research"

    def test_an_empty_contact_is_refused(self):
        """Crawling 20k third-party servers anonymously is not an option."""
        for blank in ("", "   ", "\t"):
            with pytest.raises(ValueError, match="contact address is required"):
                user_agent(blank)

    def test_every_request_carries_it(self):
        opener = _Opener([_Response(b"{}")])
        client = PoliteClient(contact="a@b.example", policy=FAST, opener=opener)
        client.get("https://registry.example/v0/servers")
        assert "a@b.example" in opener.headers["User-agent"]


class TestRateLimiting:
    def test_requests_are_spaced_by_the_rate_ceiling(self):
        opener = _Opener([_Response(b"{}") for _ in range(3)])
        policy = PolitenessPolicy(max_rps=20.0, post_request_sleep=0.0)
        client = PoliteClient(policy=policy, opener=opener)

        start = time.monotonic()
        for _ in range(3):
            client.get("https://registry.example/v0/servers")
        elapsed = time.monotonic() - start

        assert elapsed >= 0.10  # two enforced gaps of 1/20s

    def test_429s_are_retried_then_the_run_stops(self):
        opener = _Opener([_http_error(429) for _ in range(10)])
        policy = PolitenessPolicy(
            max_rps=1000.0,
            post_request_sleep=0.0,
            backoff_base=0.001,
            backoff_cap=0.002,
            max_429s_per_run=3,
            max_retries=20,
        )
        client = PoliteClient(policy=policy, opener=opener)

        with pytest.raises(RateLimitStop, match="stopping deliberately"):
            client.get("https://registry.example/v0/servers")

        assert client.rate_limit_hits == 4  # budget of 3, the 4th stops the run

    def test_retry_after_is_honoured(self):
        opener = _Opener([_http_error(429, {"Retry-After": "0.01"}), _Response(b"{}")])
        client = PoliteClient(policy=FAST, opener=opener)

        start = time.monotonic()
        client.get("https://registry.example/v0/servers")

        assert time.monotonic() - start >= 0.01


class TestRetries:
    def test_5xx_is_retried_and_then_succeeds(self):
        opener = _Opener([_http_error(503), _http_error(500), _Response(b'{"ok":true}')])
        client = PoliteClient(policy=FAST, opener=opener)

        assert client.get("https://registry.example/v0/servers").json() == {"ok": True}
        assert client.retry_count == 2

    def test_5xx_that_never_clears_raises(self):
        opener = _Opener([_http_error(503) for _ in range(10)])
        client = PoliteClient(policy=FAST, opener=opener)
        with pytest.raises(HttpStatusError, match="retries exhausted"):
            client.get("https://registry.example/v0/servers")

    def test_4xx_is_not_retried(self):
        """A 404 will still be a 404 in one second; hammering it is impolite."""
        opener = _Opener([_http_error(404), _Response(b"{}")])
        client = PoliteClient(policy=FAST, opener=opener)

        with pytest.raises(HttpStatusError) as excinfo:
            client.get("https://registry.example/v0/servers")

        assert excinfo.value.status == 404
        assert len(opener.calls) == 1

    def test_transport_failures_are_retried_then_surface(self):
        opener = _Opener([urllib.error.URLError("dns") for _ in range(10)])
        client = PoliteClient(policy=FAST, opener=opener)
        with pytest.raises(TransportError):
            client.get("https://registry.example/v0/servers")


class TestResponses:
    def test_gzip_bodies_are_decompressed(self):
        import gzip

        payload = gzip.compress(b'{"servers":[]}')
        opener = _Opener([_Response(payload, headers={"Content-Encoding": "gzip"})])
        client = PoliteClient(policy=FAST, opener=opener)

        assert client.get("https://registry.example/v0/servers").json() == {"servers": []}

    def test_query_parameters_are_encoded(self):
        opener = _Opener([_Response(b"{}")])
        client = PoliteClient(policy=FAST, opener=opener)
        client.get("https://registry.example/v0/servers", {"limit": 100, "version": "latest"})
        assert opener.calls[0].endswith("?limit=100&version=latest")
