"""Polite HTTP for MCPWatch collectors.

Deliberately stdlib-only and synchronous. WP2's crawl is a single ordered cursor
walk, so there is nothing to gain from a connection-pooling async client, and
keeping the dependency count at zero keeps deployment to ``uv sync`` on a box
where ``sudo`` needs a password. WP3 probes ~10k hosts concurrently and will
bring its own async client; this module is not it.

What this module actually buys is the politeness contract, in one place where it
can be audited:

* A User-Agent naming the project and a reachable contact address.
* A hard ceiling on request rate, enforced between request *starts* so it holds
  regardless of how fast the host answers.
* Exponential backoff with jitter on 429 and 5xx, honouring ``Retry-After``.
* A hard stop once a host has returned 429 too many times in one run.
"""

import datetime as dt
import gzip
import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Any

from .errors import HttpStatusError, RateLimitStop, TransportError

__all__ = [
    "DEFAULT_CONTACT",
    "HttpResponse",
    "PoliteClient",
    "PolitenessPolicy",
    "user_agent",
]

DEFAULT_CONTACT = "mcpwatch@iyre.com"
"""Mailbox published to every host we touch, so operators can reach a human."""

_UA_TEMPLATE = "MCPWatch/{version} (+{contact}) longitudinal MCP security research"

_RETRYABLE_STATUSES = frozenset({408, 425, 500, 502, 503, 504})


def user_agent(contact: str = DEFAULT_CONTACT, version: str = "0.1") -> str:
    """Build the User-Agent string sent on every collector request.

    Args:
        contact: A reachable address. Must not be blank — crawling thousands of
            third-party servers anonymously is the thing the ethics guardrails
            exist to prevent.
        version: Collector version to advertise.

    Raises:
        ValueError: If ``contact`` is empty or whitespace.
    """
    if not contact.strip():
        msg = "a contact address is required in the User-Agent; refusing to crawl anonymously"
        raise ValueError(msg)
    return _UA_TEMPLATE.format(version=version, contact=contact.strip())


@dataclass(frozen=True, slots=True)
class PolitenessPolicy:
    """Self-imposed limits. The registry publishes none, so we invent our own.

    Attributes:
        max_rps: Ceiling on requests per second, enforced between request
            starts. The registry answers in ~0.4s from the collection host, so
            the effective rate sits below this in practice.
        post_request_sleep: Extra pause after each response body is read.
        max_retries: Retries per request before giving up with
            :class:`~mcpwatch.collect.errors.TransportError`.
        backoff_base: First backoff delay in seconds; doubles each attempt.
        backoff_cap: Ceiling on a single backoff delay.
        max_429s_per_run: Total 429s tolerated across a run before it stops.
        timeout: Per-request socket timeout in seconds.
    """

    max_rps: float = 2.0
    post_request_sleep: float = 0.25
    max_retries: int = 5
    backoff_base: float = 1.0
    backoff_cap: float = 60.0
    max_429s_per_run: int = 5
    timeout: float = 30.0


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """A completed HTTP response with its body already decompressed."""

    status: int
    url: str
    headers: Mapping[str, str]
    body: bytes

    def json(self) -> Any:  # noqa: ANN401 - decoded JSON is genuinely dynamic
        """Parse the body as JSON."""
        return json.loads(self.body)


@dataclass
class _Pacer:
    """Enforces a minimum interval between request starts."""

    min_interval: float
    _last_start: float = field(default=0.0)

    def wait(self) -> None:
        """Block until enough time has passed since the previous request."""
        if self.min_interval <= 0:
            return
        elapsed = time.monotonic() - self._last_start
        if self._last_start and elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_start = time.monotonic()


def _decompress(body: bytes, encoding: str) -> bytes:
    """Undo Content-Encoding. urllib does not do this for us."""
    normalized = encoding.strip().lower()
    if normalized in {"gzip", "x-gzip"}:
        return gzip.decompress(body)
    if normalized == "deflate":
        return zlib.decompress(body)
    return body


def _retry_after_seconds(headers: Mapping[str, str]) -> float | None:
    """Parse a ``Retry-After`` header, which may be seconds or an HTTP date."""
    raw = headers.get("Retry-After")
    if raw is None:
        return None
    raw = raw.strip()
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        target = parsedate_to_datetime(raw)
    except TypeError, ValueError:
        return None
    if target.tzinfo is None:
        target = target.replace(tzinfo=dt.UTC)
    return max(0.0, (target - dt.datetime.now(dt.UTC)).total_seconds())


class PoliteClient:
    """A rate-limited, backing-off HTTP client for read-only crawling.

    One client per run: the 429 budget is per-instance, and exhausting it stops
    that run rather than the process.
    """

    def __init__(
        self,
        *,
        contact: str = DEFAULT_CONTACT,
        version: str = "0.1",
        policy: PolitenessPolicy | None = None,
        opener: urllib.request.OpenerDirector | None = None,
    ) -> None:
        """Build a client.

        Args:
            contact: Contact address for the User-Agent.
            version: Collector version to advertise.
            policy: Politeness limits; the defaults are already conservative.
            opener: Override the urllib opener, for tests.
        """
        self.policy = policy or PolitenessPolicy()
        self.user_agent = user_agent(contact, version)
        self._opener = opener or urllib.request.build_opener()
        self._pacer = _Pacer(min_interval=1.0 / self.policy.max_rps if self.policy.max_rps else 0.0)
        self._rate_limit_hits = 0
        self.request_count = 0
        self.retry_count = 0

    @property
    def rate_limit_hits(self) -> int:
        """How many 429 responses this run has absorbed so far."""
        return self._rate_limit_hits

    def get(self, url: str, params: Mapping[str, str | int] | None = None) -> HttpResponse:
        """GET a URL, retrying transient failures and pacing all requests.

        Args:
            url: Absolute URL.
            params: Query parameters appended to the URL.

        Returns:
            The completed response.

        Raises:
            RateLimitStop: The host's 429 budget for this run is exhausted.
            HttpStatusError: A non-retryable status (4xx other than 429).
            TransportError: Retries were exhausted on a transient failure.
        """
        target = url
        if params:
            query = urllib.parse.urlencode({k: str(v) for k, v in params.items()})
            target = f"{url}?{query}"

        last_detail = ""
        for attempt in range(self.policy.max_retries + 1):
            self._pacer.wait()
            try:
                response = self._open(target)
            except urllib.error.HTTPError as exc:
                headers = dict(exc.headers.items()) if exc.headers else {}
                if exc.code == 429:
                    self._absorb_rate_limit(headers, attempt)
                    last_detail = "rate limited"
                    continue
                if exc.code in _RETRYABLE_STATUSES:
                    if attempt == self.policy.max_retries:
                        raise HttpStatusError(exc.code, target, "retries exhausted") from exc
                    self._back_off(attempt)
                    last_detail = f"status {exc.code}"
                    continue
                raise HttpStatusError(exc.code, target) from exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt == self.policy.max_retries:
                    raise TransportError(f"{target}: {exc}") from exc
                self._back_off(attempt)
                last_detail = str(exc)
                continue

            if self.policy.post_request_sleep:
                time.sleep(self.policy.post_request_sleep)
            return response

        raise TransportError(f"{target}: retries exhausted ({last_detail})")

    def _open(self, target: str) -> HttpResponse:
        """Perform one request with no retry logic."""
        request = urllib.request.Request(
            target,
            headers={
                "User-Agent": self.user_agent,
                "Accept": "application/json",
                "Accept-Encoding": "gzip, deflate",
            },
            method="GET",
        )
        self.request_count += 1
        with self._opener.open(request, timeout=self.policy.timeout) as raw:
            headers = dict(raw.headers.items())
            body = raw.read()
            status = raw.status
        encoding = headers.get("Content-Encoding", "")
        if encoding:
            body = _decompress(body, encoding)
        return HttpResponse(status=status, url=target, headers=headers, body=body)

    def _absorb_rate_limit(self, headers: Mapping[str, str], attempt: int) -> None:
        """Handle a 429: count it, stop the run if the budget is spent, else wait."""
        self._rate_limit_hits += 1
        if self._rate_limit_hits > self.policy.max_429s_per_run:
            msg = (
                f"host returned 429 {self._rate_limit_hits} times this run "
                f"(budget {self.policy.max_429s_per_run}); stopping deliberately"
            )
            raise RateLimitStop(msg)
        delay = _retry_after_seconds(headers)
        if delay is None:
            delay = self._backoff_delay(attempt)
        self.retry_count += 1
        time.sleep(delay)

    def _back_off(self, attempt: int) -> None:
        """Sleep before the next retry."""
        self.retry_count += 1
        time.sleep(self._backoff_delay(attempt))

    def _backoff_delay(self, attempt: int) -> float:
        """Exponential backoff with jitter, so retries do not synchronize."""
        ceiling = min(self.policy.backoff_cap, self.policy.backoff_base * 2.0**attempt)
        return ceiling * (0.5 + random.random() / 2)
