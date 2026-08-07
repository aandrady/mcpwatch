"""Exceptions raised by MCPWatch collectors."""

__all__ = [
    "CollectorError",
    "HttpStatusError",
    "RateLimitStop",
    "ResumeError",
    "TransportError",
]


class CollectorError(Exception):
    """Base class for every error raised by :mod:`mcpwatch.collect`."""


class TransportError(CollectorError):
    """A request could not be completed after exhausting retries."""


class HttpStatusError(CollectorError):
    """A response carried a status code the collector will not retry.

    Attributes:
        status: The HTTP status code.
        url: The URL that produced it.
    """

    def __init__(self, status: int, url: str, detail: str = "") -> None:
        """Record the status and URL alongside the message."""
        self.status = status
        self.url = url
        suffix = f": {detail}" if detail else ""
        super().__init__(f"HTTP {status} for {url}{suffix}")


# Named for what it is rather than to satisfy N818: this signals a deliberate,
# correct stop, not a malfunction, and "...Error" would misdescribe it.
class RateLimitStop(CollectorError):  # noqa: N818
    """The host returned 429 too many times and the run gave up deliberately.

    This is not a failure to route around. A registry that keeps rate-limiting
    us is telling us to stop, and the ethics guardrails say to listen: the run
    aborts, the partial data it collected stays, and the next scheduled run
    tries again.
    """


class ResumeError(CollectorError):
    """A crawl checkpoint exists but does not match the corpus it points at."""
