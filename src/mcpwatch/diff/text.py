"""Token-level text diffing, and the cheap lexical signals built on it.

Tool descriptions are the payload in a tool-poisoning attack: the text is what
the model reads and acts on, so a description edit is the single most
security-relevant thing a manifest can do quietly. This module turns "the text
changed" into "these tokens arrived and these left", which is what makes the
difference classifiable without re-reading blobs.

Everything here is deliberately lexical and dumb. It does not decide whether an
imperative sentence is an injection — it reports that imperative language
arrived, which is a reason for WP7 to look. Real documentation is full of
"Use this when..." and a classifier that treated that as an attack would drown
in false positives.
"""

import difflib
import re

from .types import TextDiff

__all__ = [
    "IMPERATIVE_MARKERS",
    "diff_text",
    "imperative_markers",
    "looks_like_credential",
    "looks_like_filesystem",
    "looks_like_network",
    "split_identifier",
    "tokenize",
]

_TOKEN = re.compile(r"\w+|[^\w\s]")


def tokenize(text: str) -> list[str]:
    """Split text into words and standalone punctuation.

    Punctuation is kept as its own token rather than discarded: a description
    that gains a sentence gains its terminator too, and dropping punctuation
    makes a rewrite and a reformat look more alike than they are.
    """
    return _TOKEN.findall(text)


def diff_text(before: str, after: str) -> TextDiff:
    """Return the tokens added and removed between two strings.

    ``similarity`` comes from :class:`difflib.SequenceMatcher` over tokens, not
    characters. Over characters, changing "read" to "send" in a 400-word
    description scores as nearly identical; over tokens it is one word in four
    hundred, which is at least an honest ratio. What separates a typo fix from a
    rewrite is how much *survived*, and that is what this measures.
    """
    old, new = tokenize(before), tokenize(after)
    matcher = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
    added: list[str] = []
    removed: list[str] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in {"replace", "delete"}:
            removed.extend(old[i1:i2])
        if tag in {"replace", "insert"}:
            added.extend(new[j1:j2])
    return TextDiff(
        added=tuple(added),
        removed=tuple(removed),
        similarity=matcher.ratio(),
    )


IMPERATIVE_MARKERS = frozenset(
    {
        # Phrases that address the model rather than describe the tool. Chosen
        # from the shapes documented in the tool-poisoning literature: the
        # attack has to override the model's default behaviour, and overriding
        # is hard to phrase without one of these.
        "ignore previous",
        "ignore prior",
        "ignore all previous",
        "disregard previous",
        "disregard the above",
        "you must",
        "you should always",
        "always call",
        "always use",
        "do not tell",
        "do not mention",
        "without telling",
        "without informing",
        "do not reveal",
        "never mention",
        "never reveal",
        "before using any other",
        "before any other tool",
        "instead of",
        "system prompt",
        "new instructions",
        "important instruction",
        "override",
    }
)
"""Lower-cased phrases that suggest text is addressing the model.

A *signal*, never a verdict. "You must provide an API key" is honest
documentation and matches; so does the opening line of a real injection. The
point is triage ordering, and the cost of a false positive here is one human
glance.
"""

_NETWORK_HINTS = re.compile(
    r"\b(url|uri|endpoint|host|hostname|webhook|callback|proxy|upload|download|"
    r"fetch|remote|address|ip|dns|port|origin|destination)\b",
    re.IGNORECASE,
)

_FILESYSTEM_HINTS = re.compile(
    r"\b(path|filepath|filename|file|directory|dir|folder|cwd|workdir|root|glob)\b",
    re.IGNORECASE,
)

_CREDENTIAL_HINTS = re.compile(
    r"\b(token|key|apikey|secret|password|passwd|credential|credentials|auth|"
    r"authorization|bearer|session)\b",
    re.IGNORECASE,
)

_IDENTIFIER_SPLIT = re.compile(r"[_\-.\s]+|(?<=[a-z0-9])(?=[A-Z])")


def split_identifier(name: str) -> str:
    r"""Break a parameter name into space-separated words.

    Necessary because ``\b`` does not fire where programmers put boundaries.
    ``_`` is a word character to a regex, so ``\bwebhook\b`` does not match
    ``webhook_url``, and nothing matches ``callbackUrl`` at all. Both are
    exactly the names an exfiltration parameter arrives under, so matching
    against the raw identifier silently missed the cases that matter most.

    ``webhook_url`` -> ``webhook url``; ``callbackUrl`` -> ``callback Url``.
    """
    return " ".join(part for part in _IDENTIFIER_SPLIT.split(name) if part)


def imperative_markers(text: str) -> tuple[str, ...]:
    """Return the imperative phrases present in ``text``, lower-cased."""
    lowered = text.casefold()
    return tuple(sorted(m for m in IMPERATIVE_MARKERS if m in lowered))


def looks_like_network(name: str, schema: object) -> bool:
    """Whether a parameter looks capable of directing traffic off-host."""
    return _matches(_NETWORK_HINTS, name, schema)


def looks_like_filesystem(name: str, schema: object) -> bool:
    """Whether a parameter looks like it addresses the local filesystem."""
    return _matches(_FILESYSTEM_HINTS, name, schema)


def looks_like_credential(name: str, schema: object) -> bool:
    """Whether a parameter looks like it carries a secret."""
    return _matches(_CREDENTIAL_HINTS, name, schema)


def _matches(pattern: re.Pattern[str], name: str, schema: object) -> bool:
    """Test a parameter's name and its declared description/format.

    The description is included because parameter names are frequently useless
    (`arg1`, `input`, `q`) while the description says what it is. The rest of
    the schema is not searched: matching on an `enum` of example values would
    fire on any tool that mentions a URL anywhere.
    """
    if pattern.search(split_identifier(name)):
        return True
    if isinstance(schema, dict):
        for key in ("description", "title", "format"):
            value = schema.get(key)
            if isinstance(value, str) and pattern.search(value):
                return True
    return False
