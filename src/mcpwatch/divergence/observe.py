"""What a tool was observed doing, from syscalls and the sinkhole.

Three instruments, chosen so no single one has to be trusted alone:

*Syscalls* (``strace -f -ttt``) are the primary record — they see the call
regardless of whether it succeeded, which matters when every connection is
being refused by a sinkhole on purpose. A tool that tries to reach an API and
fails has still told us it reaches for an API.

*The sinkhole* corroborates network findings with a destination and a TLS SNI.
``connect()`` to the sinkhole's address says only "something outbound"; the
sinkhole log says which name the server thought it was resolving.

*A filesystem diff* (``docker diff``) corroborates writes at server granularity.
It cannot attribute a write to a specific tool, so it is never the sole evidence
for a finding — it exists to catch a write strace somehow missed.

**Everything is windowed per tool call.** The driver records a wall-clock
timestamp either side of each ``tools/call``, and only events inside a window
count. Without this, every observation would include the server's startup —
which opens hundreds of library files, reads ``/etc/resolv.conf``, and would
make every tool on every server look like it touches the filesystem and the
network. Startup noise is the reason a naive version of this measurement
reports a ~100% divergence rate and is worthless.

**Reads are filtered; writes and execs are not.** A process legitimately opens
its own runtime's files on any lazy import, so reads under :data:`_NOISE_PREFIX`
are dropped. Writes outside the container's scratch space and executions of
another program have no benign background rate worth filtering.
"""

import re
from dataclasses import dataclass
from typing import Any

from .capabilities import Capability, CapabilityProfile

__all__ = ["TraceEvent", "observed_profile", "parse_sinkhole", "parse_strace"]

_LINE = re.compile(
    r"^(?:\[pid\s+\d+\]\s*|\d+\s+)?"  # optional pid prefix, either strace style
    r"(?P<at>\d+\.\d+)\s+"  # -ttt epoch seconds
    r"(?P<call>[a-z_0-9]+)\((?P<args>.*)$"
)

_PATH = re.compile(r'"((?:[^"\\]|\\.)*)"')
_PORT = re.compile(r"sin6?_port=htons\((\d+)\)")
_FAMILY = re.compile(r"sa_family=(AF_[A-Z0-9]+)")

_WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC")

_NOISE_PREFIX = (
    "/usr/",
    "/lib/",
    "/lib64/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/etc/ld.so",
    "/etc/localtime",
    "/etc/nsswitch.conf",
    "/etc/host.conf",
    "/etc/gai.conf",
    "/srv/server/node_modules/",
    "/srv/server/venv/",
    "/srv/probe/",
    "/home/prober/.npm/",
    "/home/prober/.cache/",
)
"""Reads with no signal: a runtime loading itself, and the server's own tree.

Not applied to writes or executions. A process opening its own standard library
is background; a process writing outside its scratch space or running another
program is not.
"""

_CREDENTIAL_PATH = re.compile(
    r"(/\.aws/|/\.ssh/|/\.netrc|/\.npmrc|/\.docker/config|/\.git-credentials|"
    r"/\.config/gcloud|/\.kube/config|/\.gnupg/|/\.pypirc|(^|/)\.env(\.|$)|"
    r"/proc/self/environ|/proc/\d+/environ|id_rsa|id_ed25519|credentials\.json|"
    r"service[_-]account.*\.json)"
)
"""Places secrets are conventionally kept.

Path-based because that is what a syscall shows. Reading an environment variable
is not a syscall and cannot be seen this way, so ``credential_access`` here means
"went looking where credentials live" — a narrower claim than "used a
credential", and the reported wording says so.
"""


@dataclass(frozen=True, slots=True)
class TraceEvent:
    """One syscall the server made."""

    at: float
    call: str
    args: str

    @property
    def path(self) -> str | None:
        """The first quoted path in the arguments, if any."""
        match = _PATH.search(self.args)
        return match.group(1) if match else None


def parse_strace(text: str) -> list[TraceEvent]:
    """Parse ``strace -f -ttt`` output into events.

    Tolerant by design: this reads the output of a tool tracing untrusted code,
    so an unparseable line is skipped rather than raised on. Lines split by
    ``<unfinished ...>`` still carry their arguments, which is all that is read
    here, so both halves parse and the duplicate is harmless — a capability is a
    set membership, not a count.
    """
    events: list[TraceEvent] = []
    for line in text.splitlines():
        match = _LINE.match(line.strip())
        if match:
            events.append(
                TraceEvent(
                    at=float(match.group("at")),
                    call=match.group("call"),
                    args=match.group("args"),
                )
            )
    return events


def parse_sinkhole(records: list[dict[str, Any]]) -> list[tuple[float, str]]:
    """Reduce sinkhole records to ``(timestamp, destination)`` pairs."""
    out: list[tuple[float, str]] = []
    for record in records:
        at = record.get("at")
        if not isinstance(at, (int, float)):
            continue
        if record.get("kind") == "dns" and record.get("query"):
            out.append((float(at), f"DNS {record['query']}"))
        elif record.get("kind") == "tcp":
            name = record.get("sni") or f"port {record.get('dest_port')}"
            out.append((float(at), f"TCP {name}"))
    return out


def _is_noise(path: str) -> bool:
    return path.startswith(_NOISE_PREFIX)


def observed_profile(
    events: list[TraceEvent],
    sinkhole: list[tuple[float, str]],
    window: tuple[float, float],
) -> CapabilityProfile:
    """Fold everything observed inside ``window`` into one profile.

    Args:
        events: Syscalls from the whole session.
        sinkhole: ``(timestamp, destination)`` pairs from the whole session.
        window: ``(start, end)`` wall-clock bounds of one tool call.

    Returns:
        The capabilities observed, each with the syscall that evidenced it.
    """
    start, end = window
    found: list[tuple[Capability, str]] = []

    for event in events:
        if not start <= event.at <= end:
            continue
        path = event.path

        if event.call in ("connect", "sendto", "sendmsg"):
            family = _FAMILY.search(event.args)
            # AF_UNIX is local IPC — a runtime talking to itself, not egress.
            if family and family.group(1) in ("AF_INET", "AF_INET6"):
                port = _PORT.search(event.args)
                where = f"port {port.group(1)}" if port else family.group(1)
                found.append((Capability.NETWORK, f"{event.call}() to {where}"))
            continue

        if event.call in ("execve", "execveat", "posix_spawn", "vfork", "clone3"):
            if event.call in ("execve", "execveat"):
                found.append((Capability.SUBPROCESS, f"{event.call}({path or '?'})"))
            continue

        if event.call in ("open", "openat", "openat2", "creat"):
            if path is None:
                continue
            if _CREDENTIAL_PATH.search(path):
                found.append((Capability.CREDENTIAL_ACCESS, f"opened {path}"))
            if any(flag in event.args for flag in _WRITE_FLAGS):
                found.append((Capability.FILESYSTEM_WRITE, f"opened {path} for writing"))
            elif not _is_noise(path):
                found.append((Capability.FILESYSTEM_READ, f"opened {path}"))
            continue

        if event.call in ("unlink", "unlinkat", "rename", "renameat", "renameat2", "mkdir"):
            found.append((Capability.FILESYSTEM_WRITE, f"{event.call}({path or '?'})"))

    for at, destination in sinkhole:
        if start <= at <= end:
            found.append((Capability.NETWORK, f"reached for {destination}"))

    return CapabilityProfile.of(*found)
