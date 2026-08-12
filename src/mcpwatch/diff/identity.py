"""Identity resolution: is this still the same server?

BUILD-PLAN §3 names this as the second-order risk to the dataset, and the
framing is worth keeping in mind: **a mutation you attribute to the wrong
identity is worse than one you miss**, because it silently moves a number rather
than leaving a visible gap.

Three failure modes, all of which corrupt a base rate:

* A server changes its registry name. Walking by name alone sees a
  disappearance and an unrelated creation, and the mutation between them —
  possibly the most interesting one in the corpus — is not merely miscounted but
  invisible.
* A name changes hands, or its owner repoints it at a different repository or
  endpoint. Walking by name alone reports an ordinary content mutation, when
  what happened is that consumers pinning that name now get someone else's code.
* A server disappears and comes back. Treated as one continuous history, the gap
  vanishes; treated as two servers, the return looks like a new publication.

So the primary key is the registry name, reconciled against the repository URL,
the endpoint, and — for Layer 2 — the set of tool names the server offers.
"""

from dataclasses import dataclass

from mcpwatch.store import Corpus

from .types import Verdict

__all__ = ["IdentityIndex", "ServerIdentity", "classify_transition"]


@dataclass(frozen=True, slots=True)
class ServerIdentity:
    """The secondary keys a server presented at one point in time."""

    repo_url: str | None
    endpoint: str | None
    fingerprint: str | None = None
    """Sorted tool names, for Layer 2. None when unknown."""

    @property
    def anchored(self) -> bool:
        """Whether there is anything here to reconcile against.

        A server with no repository, no endpoint and no tools — a package-only
        entry with nothing declared — cannot be told apart from any other such
        server, so it is never claimed as a rename.
        """
        return any((self.repo_url, self.endpoint, self.fingerprint))


def classify_transition(before: ServerIdentity, after: ServerIdentity) -> Verdict:
    """Decide whether a same-name transition is a mutation or a replacement.

    Same name, and the repository or endpoint moved, means whoever holds the
    name is now pointing at something else. That is REPLACED — the case worth
    treating as suspicious by default, because a consumer who pinned the name
    got the substitution silently.

    A server that merely *gains* an endpoint or repository it did not declare
    before is not a replacement. Publishers fill in metadata over time, and
    treating every completed field as a substitution would bury the real ones.
    """
    moved_repo = (
        before.repo_url is not None
        and after.repo_url is not None
        and before.repo_url != after.repo_url
    )
    moved_endpoint = (
        before.endpoint is not None
        and after.endpoint is not None
        and before.endpoint != after.endpoint
    )
    return Verdict.REPLACED if (moved_repo or moved_endpoint) else Verdict.MUTATED


class IdentityIndex:
    """Recognizes servers that reappear under a different name.

    Built once per diff run from the corpus's own identity history, which WP2
    and WP5 have been appending to all along: every distinct
    ``(name, repo, endpoint)`` tuple a server ever presented, with the date it
    first appeared.

    A rename is claimed only when a server's *first* sighting matches the *last*
    sighting of a server that has since gone quiet, on a key strong enough to be
    worth believing. Repository URL is the strongest — it is where the code
    actually lives. Endpoint is next. Both are required to be non-empty; two
    servers sharing "no repository" share nothing.
    """

    def __init__(self, corpus: Corpus) -> None:
        """Index every server's identity keys from the corpus."""
        self._connection = corpus.index.connection
        self._by_repo: dict[str, list[str]] = {}
        self._by_endpoint: dict[str, list[str]] = {}
        self._last_seen: dict[str, str] = {}
        self._first_seen: dict[str, str] = {}

        rows = corpus.index.connection.execute(
            "SELECT server_key, repo_url, primary_endpoint, first_seen, last_seen FROM server"
        ).fetchall()
        for row in rows:
            key = row["server_key"]
            self._first_seen[key] = row["first_seen"]
            self._last_seen[key] = row["last_seen"]
            if repo := (row["repo_url"] or "").strip():
                self._by_repo.setdefault(repo, []).append(key)
            if endpoint := (row["primary_endpoint"] or "").strip():
                self._by_endpoint.setdefault(endpoint, []).append(key)

    def predecessor_of(self, server_key: str, identity: ServerIdentity) -> str | None:
        """Return the server this one appears to have been renamed from.

        Requires the candidate to have stopped being seen no later than this
        server started being seen. Two servers sharing a repository *at the same
        time* are a monorepo publishing twice, not a rename, and that is a
        common enough shape in the registry to matter.
        """
        started = self._first_seen.get(server_key)
        if started is None or not identity.anchored:
            return None

        for index, value in (
            (self._by_repo, identity.repo_url),
            (self._by_endpoint, identity.endpoint),
        ):
            if not value:
                continue
            for candidate in index.get(value, ()):
                if candidate == server_key:
                    continue
                ended = self._last_seen.get(candidate)
                if ended is not None and ended <= started:
                    return candidate
        return None

    def identity_moved_between(self, server_key: str, start: str, end: str) -> bool:
        """Whether the server presented a new identity tuple within a window.

        This is what makes REPLACED detectable on Layer 2. A tool manifest
        carries no repository or endpoint, so a manifest diff alone can never
        see that the server behind it was swapped — but ``server_identity`` has
        recorded every tuple the server ever presented, and a new one appearing
        between two probes is exactly that event.
        """
        row = self._connection.execute(
            """
            SELECT count(*) AS n FROM server_identity
            WHERE server_key = ? AND observed_at > ? AND observed_at <= ?
            """,
            (server_key, start, end),
        ).fetchone()
        return bool(row["n"])
