"""The containment gate — run this green before any real package is probed.

WP8's first acceptance criterion is that containment is demonstrated with a
deliberately-exfiltrating server *before* third-party code runs, not asserted
from the flags we passed. This module runs
``deploy/sandbox/testserver/evil_server.py`` inside a real probe container and
checks what it managed to do.

Seven checks, each one a property that would be a distinct incident if it failed:

``network_is_internal``   the sandbox network has no route off the host
``only_sinkhole_attached``  the probe container is on that network and no other
``dns_redirected``        every name resolves to the sinkhole, not to the internet
``egress_recorded``       the sinkhole logged the connection attempts
``no_data_returned``      nothing answered the canary, so nothing was exfiltrated
``host_paths_unreachable``  docker.sock, the corpus, /etc/shadow, /host
``rootfs_not_escaped``    a write outside the working directory fails

The canary reports its own findings through its ``tools/list`` output, so a
containment failure arrives as evidence in the manifest rather than as a silent
pass. A failed check raises :class:`~mcpwatch.sandbox.containment.ContainmentError`
— there is no degraded mode, because the only correct response to unverified
containment is to not run anything.
"""

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcpwatch.store import JsonValue

from .containment import (
    INSTALL_NETWORK,
    PROBE_TIMEOUT,
    SINKHOLE_NETWORK,
    ContainmentError,
    Sandbox,
    docker,
)

__all__ = ["CANARY_CONTAINER", "VerificationReport", "verify"]

CANARY_CONTAINER = "mcpwatch-canary"
CANARY_PATH = "/srv/probe/evil_server.py"


@dataclass(frozen=True, slots=True)
class Check:
    """One containment property and whether it held."""

    name: str
    ok: bool
    detail: str

    def render(self) -> str:
        """One-line human-readable form."""
        return f"[{'PASS' if self.ok else 'FAIL'}] {self.name}: {self.detail}"


@dataclass
class VerificationReport:
    """Every containment check for one verification run."""

    checks: list[Check]

    @property
    def ok(self) -> bool:
        """True when every property held."""
        return all(check.ok for check in self.checks)

    @property
    def failures(self) -> list[Check]:
        """Only the properties that did not hold."""
        return [check for check in self.checks if not check.ok]

    def render(self) -> str:
        """The full report."""
        return "\n".join(check.render() for check in self.checks)

    def as_json(self) -> dict[str, JsonValue]:
        """Render for the corpus, so a run records what it verified."""
        return {
            "ok": self.ok,
            "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in self.checks],
        }


def verify(sandbox: Sandbox, *, keep: bool = False) -> VerificationReport:
    """Run the canary in a real probe container and check what it achieved.

    Args:
        sandbox: A configured sandbox. Its images and networks are built first.
        keep: Leave the canary container in place for inspection afterwards.

    Returns:
        A report; ``ok`` is the gate.
    """
    sandbox.setup()
    checks: list[Check] = []

    internal = docker(
        "network", "inspect", SINKHOLE_NETWORK, "--format", "{{.Internal}}"
    ).stdout.strip()
    checks.append(
        Check(
            "network_is_internal",
            internal == "true",
            f"{SINKHOLE_NETWORK}.Internal={internal!r} (must be 'true': no route off the host)",
        )
    )

    canary = sandbox.repo_root / "deploy" / "sandbox" / "testserver" / "evil_server.py"
    if not canary.is_file():
        msg = f"canary server not found at {canary}"
        raise ContainmentError(msg)

    docker("rm", "-f", CANARY_CONTAINER, check=False)
    spec = {"server_key": "mcpwatch/canary", "command": ["python3", CANARY_PATH]}
    try:
        docker(
            "run",
            "-d",
            *sandbox.run_flags(CANARY_CONTAINER),
            "-e",
            f"MCPWATCH_SPEC={json.dumps(spec)}",
            "--entrypoint",
            "sleep",
            sandbox.probe_image,
            "600",
        )
        docker("cp", str(canary), f"{CANARY_CONTAINER}:{CANARY_PATH}")

        # Same isolation step the real probe performs, exercised here so the
        # test covers the transition rather than a hand-built approximation.
        docker("network", "disconnect", INSTALL_NETWORK, CANARY_CONTAINER)
        docker("network", "connect", SINKHOLE_NETWORK, CANARY_CONTAINER)
        attached = docker(
            "inspect",
            CANARY_CONTAINER,
            "--format",
            "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}",
        ).stdout.split()
        checks.append(
            Check(
                "only_sinkhole_attached",
                attached == [SINKHOLE_NETWORK],
                f"attached to {attached}",
            )
        )

        sandbox.mark_sinkhole()
        time.sleep(0.2)
        payload = sandbox.exec_driver(CANARY_CONTAINER, "probe", timeout=PROBE_TIMEOUT)
        egress = sandbox.collect_egress()
        checks.extend(_check_findings(payload, egress, sandbox))
    finally:
        if not keep:
            docker("rm", "-f", CANARY_CONTAINER, check=False, timeout=60.0)

    return VerificationReport(checks)


def _canary_findings(payload: dict[str, Any]) -> dict[str, Any]:
    """Pull the canary's self-report out of its tool description."""
    for probe in payload.get("probes") or []:
        for tool in probe.get("tools") or []:
            if tool.get("name") == "canary":
                try:
                    parsed = json.loads(tool.get("description") or "{}")
                    return parsed if isinstance(parsed, dict) else {}
                except ValueError:
                    return {}
    return {}


def _check_findings(
    payload: dict[str, Any], egress: list[dict[str, Any]], sandbox: Sandbox
) -> list[Check]:
    """Turn the canary's report and the sinkhole log into checks."""
    checks: list[Check] = []
    findings = _canary_findings(payload)
    if not findings:
        detail = payload.get("detail") or payload.get("status") or "no output"
        return [
            Check(
                "canary_ran",
                False,
                f"the canary produced no findings, so nothing was verified: {str(detail)[:300]}",
            )
        ]

    attempts = findings.get("egress") or []
    sinkhole_ip = sandbox.sinkhole_ip
    resolved = [a.get("resolved") for a in attempts if a.get("resolved")]
    checks.append(
        Check(
            "dns_redirected",
            bool(resolved) and all(address == sinkhole_ip for address in resolved),
            f"resolved {resolved or '[]'} (every name must answer with the sinkhole {sinkhole_ip})",
        )
    )

    tcp = [event for event in egress if event.get("kind") == "tcp"]
    dns = [event for event in egress if event.get("kind") == "dns"]
    checks.append(
        Check(
            "egress_recorded",
            bool(tcp),
            f"sinkhole logged {len(dns)} DNS quer(ies) and {len(tcp)} TCP connection(s); "
            f"SNI seen: {sorted(str(e['sni']) for e in tcp if e.get('sni')) or '[]'}",
        )
    )

    # The sinkhole accepts connections on purpose — that is how an attempt gets
    # recorded rather than merely failing. What must never happen is a *reply*:
    # bytes coming back would mean something other than our sinkhole answered.
    returned = [a.get("response_bytes") or 0 for a in attempts]
    checks.append(
        Check(
            "no_data_returned",
            all(count == 0 for count in returned),
            f"bytes received by the canary: {returned} (must all be 0)",
        )
    )

    reachable = [
        entry
        for entry in findings.get("host_access") or []
        if entry.get("listed") is not None or entry.get("read_bytes") is not None
    ]
    forbidden = [e for e in reachable if e.get("path") != "/escaped-the-container"]
    checks.append(
        Check(
            "host_paths_unreachable",
            not forbidden,
            f"reachable host paths: {[e.get('path') for e in forbidden] or 'none'}",
        )
    )

    escape: dict[str, Any] = next(
        (e for e in findings.get("host_access") or [] if e.get("path") == "/escaped-the-container"),
        {},
    )
    checks.append(
        Check(
            "rootfs_not_escaped",
            escape.get("wrote") is False,
            f"write to / {'succeeded' if escape.get('wrote') else 'refused'}"
            f" ({escape.get('error', 'no error recorded')})",
        )
    )
    return checks


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parents[3]
