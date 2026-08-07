"""Collectors that append to the MCPWatch corpus.

Layer 1 (:mod:`mcpwatch.collect.registry`) reads registry metadata, which the
registry itself keeps a retrospective history of. Layer 2 reads live tool
manifests, which nobody keeps a history of — that is the irreplaceable one.

Every collector in this package obeys the same rules, which are not negotiable
and are not "add later" items:

* An identifying User-Agent with a reachable contact address on every request.
* Conservative self-imposed rate limits, exponential backoff on 429/5xx, and a
  hard stop when a host keeps saying 429.
* Read-only protocol methods only. Never ``tools/call``. Never credentials.
* Failures are recorded as observations, never skipped. Crawl reliability is a
  reported metric, so a silent gap is worse than a logged error.
"""

from .errors import CollectorError, HttpStatusError, RateLimitStop, TransportError
from .http import DEFAULT_CONTACT, PoliteClient, PolitenessPolicy, user_agent

__all__ = [
    "DEFAULT_CONTACT",
    "CollectorError",
    "HttpStatusError",
    "PoliteClient",
    "PolitenessPolicy",
    "RateLimitStop",
    "TransportError",
    "user_agent",
]
