"""The sandbox itself — WP8's actual deliverable.

The collection host is not disposable. It is a permanent machine shared with
other workloads and it holds the corpus, which cannot be re-collected. This
module therefore treats containment as the product and manifest enumeration as
a consequence of it, rather than the other way round.

**The lifecycle, and why it takes two containers.** A package must be fetched
from a registry, which needs egress; the server it installs must never have any.

1. An *install* container on ``mcpwatch-install``, an ordinary bridge network
   with working DNS. It installs the pinned version with lifecycle scripts
   disabled, so no publisher code executes while egress exists.
2. ``docker commit`` freezes that filesystem into an ephemeral image, and the
   install container is destroyed.
3. A *probe* container runs that image on ``mcpwatch-sinkhole``, an
   ``--internal`` network whose only other member is our sinkhole, with the
   sinkhole as its only resolver. This is where publisher code finally runs.
4. Both containers and the staged image are removed. Nothing crosses between
   them but the committed filesystem — no volume, no mount, no host path.

The split is forced by ``--dns``, which is fixed when a container is created.
One container cannot have working DNS for the install and sinkholed DNS for the
probe, and without the sinkholed resolver a server's connection attempts fail at
name resolution and are never recorded — indistinguishable, in the data, from a
server that never tried. That is the failure this design exists to avoid, and it
is why the first version of it did not survive its own containment test.

An internal network cannot route off the host, so egress is denied by the
network's construction rather than by rules that could be mis-ordered. The
sinkhole turns a denied connection into a recorded one: WP8 counts egress
attempted during mere enumeration as a finding, and a finding needs evidence.

**What a probe container gets:** no mounts of any kind, every capability
dropped, ``no-new-privileges``, a fixed non-root uid, and hard caps on memory,
CPU, and PIDs. The corpus is not mounted, the Docker socket is not mounted, and
there is no host path in the container's configuration to be tricked into
following.

**What it does not get:** a read-only rootfs. The package has to be installed
into a filesystem the server can then run from, and a server that cannot write
its own working directory fails in ways unrelated to what is being measured. An
ephemeral writable layer with no mounts, no capabilities, and no route off the
host is the smaller risk, and it is destroyed with the container.
"""

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "INSTALL_NETWORK",
    "PROBE_IMAGE",
    "SINKHOLE_IMAGE",
    "SINKHOLE_NETWORK",
    "ContainmentError",
    "Sandbox",
    "SandboxResult",
    "docker",
]

PROBE_IMAGE = "mcpwatch/probe:0.1.0"
SINKHOLE_IMAGE = "mcpwatch/sinkhole:0.1.0"
SINKHOLE_NETWORK = "mcpwatch-sinkhole"
INSTALL_NETWORK = "mcpwatch-install"
SINKHOLE_CONTAINER = "mcpwatch-sinkhole"
STAGED_PREFIX = "mcpwatch/staged"

MEMORY_LIMIT = "1g"
CPU_LIMIT = "1.0"
PID_LIMIT = "256"
"""Caps chosen against a 4-vCPU box shared with workloads that matter.

One CPU and a gigabyte lets a Node or Python server start comfortably while
leaving a runaway unable to disturb a co-tenant. The PID cap is what stops a
fork bomb, which is the cheapest denial-of-service a hostile package can attempt.
"""

INSTALL_TIMEOUT = 600.0

PROBE_TIMEOUT = 420.0
"""Backstop on one `docker exec` of the probe phase.

Set above the driver's own 240s budget plus teardown, deliberately. The driver
is the component that knows how to stop probing and still report; this timeout
firing means the driver itself is wedged, which is a different failure and worth
distinguishing. At 300s it fired routinely on merely-slow servers, and the
exception propagated out of a worker and ended a 400-member cycle at member 99.
"""
SENTINEL = "===MCPWATCH-RESULT==="


class ContainmentError(RuntimeError):
    """The sandbox could not be established, or stopped being trustworthy.

    Raised rather than degraded. Every caller's correct response is to stop:
    probing third-party code without verified containment is the one thing this
    package exists to prevent.
    """


def docker(
    *args: str, timeout: float = 120.0, check: bool = True
) -> subprocess.CompletedProcess[str]:
    """Run one docker command."""
    executable = shutil.which("docker")
    if executable is None:  # pragma: no cover - environment-dependent
        msg = "docker is not on PATH"
        raise ContainmentError(msg)
    # argv is constructed here and never shell-interpolated.
    result = subprocess.run(
        [executable, *args], capture_output=True, text=True, timeout=timeout, check=False
    )
    if check and result.returncode != 0:
        msg = f"docker {' '.join(args[:3])} failed: {(result.stderr or result.stdout).strip()}"
        raise ContainmentError(msg)
    return result


@dataclass(frozen=True, slots=True)
class SandboxResult:
    """What one sandboxed probe produced."""

    server_key: str
    status: str
    probes: tuple[dict[str, Any], ...] = ()
    command: tuple[str, ...] = ()
    used_placeholders: bool = False
    detail: str | None = None
    stderr_tail: str | None = None
    egress: tuple[dict[str, Any], ...] = ()
    seconds: float = 0.0

    @property
    def ok(self) -> bool:
        """Whether two manifests came back."""
        return self.status == "ok" and len(self.probes) == 2

    @property
    def attempted_egress(self) -> bool:
        """Whether the server reached for the network during enumeration.

        A reportable finding in itself: nothing about listing tools requires a
        connection, so a server that opens one during enumeration is doing
        something it did not need to do.
        """
        return any(event.get("kind") == "tcp" for event in self.egress)


@dataclass
class Sandbox:
    """Builds, verifies, and runs the containment described in this module."""

    repo_root: Path
    probe_image: str = PROBE_IMAGE
    sinkhole_image: str = SINKHOLE_IMAGE
    memory: str = MEMORY_LIMIT
    cpus: str = CPU_LIMIT
    pids: str = PID_LIMIT
    _sinkhole_ip: str = field(default="", init=False)
    _log_mark: int = field(default=0, init=False)

    # ------------------------------------------------------------- lifecycle ---

    def build(self) -> None:
        """Build both images. Idempotent; Docker's layer cache does the work."""
        sandbox_dir = self.repo_root / "deploy" / "sandbox"
        docker("build", "-t", self.sinkhole_image, str(sandbox_dir / "sinkhole"), timeout=600.0)
        docker("build", "-t", self.probe_image, str(sandbox_dir / "probe"), timeout=900.0)

    def ensure_networks(self) -> None:
        """Create both networks, the sinkhole one strictly internal.

        ``--internal`` is the containment property that does not depend on us
        getting anything else right: Docker installs no route off the host for
        such a network, so a probe container has nowhere to send a packet even
        if every other control failed.
        """
        existing = docker("network", "ls", "--format", "{{.Name}}").stdout.split()
        if SINKHOLE_NETWORK not in existing:
            docker("network", "create", "--internal", SINKHOLE_NETWORK)
        if INSTALL_NETWORK not in existing:
            docker("network", "create", INSTALL_NETWORK)

        # Verified rather than assumed: a network created without --internal by
        # an earlier build would silently give every probe real egress.
        internal = docker(
            "network", "inspect", SINKHOLE_NETWORK, "--format", "{{.Internal}}"
        ).stdout.strip()
        if internal != "true":
            msg = (
                f"network {SINKHOLE_NETWORK} is not internal; refusing to run. "
                f"Remove it (docker network rm {SINKHOLE_NETWORK}) and let this rebuild it."
            )
            raise ContainmentError(msg)

    def start_sinkhole(self) -> str:
        """Start the sinkhole if it is not already up to date, and return its address.

        Health and image identity are both checked, not just presence. A
        container in ``Restarting`` shows up in ``docker ps`` while being
        useless, and one started from a previous build keeps running the old
        image after ``build()`` has replaced it — both happened, and both
        present as "the sinkhole recorded nothing", which reads like a
        containment pass if the checks are not looking for it.
        """
        state = docker(
            "inspect", SINKHOLE_CONTAINER, "--format", "{{.State.Running}} {{.Image}}", check=False
        ).stdout.split()
        wanted = docker(
            "image", "inspect", self.sinkhole_image, "--format", "{{.Id}}"
        ).stdout.strip()
        healthy = len(state) == 2 and state[0] == "true" and state[1] == wanted

        if not healthy:
            docker("rm", "-f", SINKHOLE_CONTAINER, check=False)
            docker(
                "run",
                "-d",
                "--name",
                SINKHOLE_CONTAINER,
                "--network",
                SINKHOLE_NETWORK,
                # The one capability grant in this package, and it is to our own
                # container: a single iptables REDIRECT so one socket can catch
                # every destination port. Probe containers get --cap-drop ALL.
                "--cap-add",
                "NET_ADMIN",
                "--memory",
                "256m",
                "--pids-limit",
                "128",
                "--restart",
                "unless-stopped",
                self.sinkhole_image,
            )
            time.sleep(2.0)

        address = docker(
            "inspect",
            SINKHOLE_CONTAINER,
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        ).stdout.strip()
        if not address:
            msg = "sinkhole container has no address on the sandbox network"
            raise ContainmentError(msg)
        self._sinkhole_ip = address
        return address

    def setup(self) -> None:
        """Build images, create networks, start the sinkhole, clear staged images."""
        self.build()
        self.ensure_networks()
        self.start_sinkhole()
        self.prune_staged()

    def prune_staged(self) -> None:
        """Remove staged images left behind by an interrupted cycle.

        `probe` removes its own staged image in a `finally`, but a cycle killed
        between the commit and that removal leaks one. Each is a full copy of an
        installed package tree, so on a box with 49 GB free this is worth
        clearing at the start of every cycle rather than after an incident.
        """
        listed = docker(
            "images", f"{STAGED_PREFIX}*", "--format", "{{.Repository}}:{{.Tag}}", check=False
        ).stdout.split()
        for image in listed:
            docker("rmi", "-f", image, check=False, timeout=120.0)

    @property
    def sinkhole_ip(self) -> str:
        """The sinkhole's address on the sandbox network.

        Every name a probe container resolves must answer with this, which is
        what :mod:`~mcpwatch.sandbox.verify` asserts.
        """
        return str(self._sinkhole_ip)

    # ----------------------------------------------------------------- probe ---

    def run_flags(self, name: str, *, isolated: bool = True) -> list[str]:
        """The hardening applied to every probe container.

        Enumerated in one place so the containment test and the real probe
        cannot drift apart — the test asserts against a container started with
        exactly these flags.

        Args:
            name: Container name.
            isolated: Join the sinkhole network with the sinkhole as the only
                resolver. False puts the container on the install network with
                ordinary DNS, which is only ever used for the install phase,
                before any publisher code runs.
        """
        network = [
            "--network",
            SINKHOLE_NETWORK if isolated else INSTALL_NETWORK,
        ]
        if isolated:
            # The reason the phases cannot share a container: --dns is fixed at
            # create time, and pointing it at the sinkhole would leave the
            # install phase unable to resolve the package registry.
            network += ["--dns", self._sinkhole_ip]
        return [
            "--name",
            name,
            *network,
            "--user",
            "10001:10001",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            self.memory,
            "--memory-swap",
            self.memory,  # equal to --memory: no swap headroom
            "--cpus",
            self.cpus,
            "--pids-limit",
            self.pids,
            # No -v, no --mount, no --privileged, and no docker.sock. The corpus
            # is not reachable because it is not named here and nothing in the
            # image knows where it lives.
        ]

    def probe(self, spec: dict[str, Any]) -> SandboxResult:
        """Install and enumerate one package server inside the sandbox.

        Two containers, not one. The first installs with ordinary DNS and is
        then committed to an ephemeral image; the second runs that image on the
        sinkhole network with the sinkhole as its only resolver. ``--dns`` is
        fixed when a container is created, so a single container cannot have
        working DNS during install and sinkholed DNS during the probe — and
        without the second, a server's connection attempts fail at resolution
        and are never recorded, which looks exactly like a server that never
        tried. Nothing crosses between the two but the committed filesystem: no
        volume, no mount, no host path.
        """
        if not self._sinkhole_ip:
            self.start_sinkhole()
        stem = spec["server_key"].replace("/", "-").replace(".", "-")[:40]
        installer, prober = f"mcpwatch-install-{stem}", f"mcpwatch-probe-{stem}"
        image = f"{STAGED_PREFIX}:{stem.lower()}"
        environment = ["-e", f"MCPWATCH_SPEC={json.dumps(spec)}"]
        started = time.monotonic()

        for name in (installer, prober):
            docker("rm", "-f", name, check=False)
        try:
            return self._probe_inner(spec, installer, prober, image, environment, started)
        except ContainmentError:
            # The one failure that must stop everything. Containment is not
            # negotiable per server, and the rest of the sample is not worth
            # probing in a sandbox that just stopped being trustworthy.
            raise
        except Exception as exc:
            # Everything else becomes this server's outcome. A 400-member cycle
            # running unattended cannot be ended by one container behaving in a
            # way we did not anticipate — which is exactly how the first full
            # run died at member 99.
            return SandboxResult(
                server_key=spec["server_key"],
                status="crashed",
                detail=f"{type(exc).__name__}: {exc}"[:2000],
                seconds=round(time.monotonic() - started, 2),
            )
        finally:
            for name in (installer, prober):
                docker("rm", "-f", name, check=False, timeout=60.0)
            docker("rmi", "-f", image, check=False, timeout=120.0)

    def _probe_inner(
        self,
        spec: dict[str, Any],
        installer: str,
        prober: str,
        image: str,
        environment: list[str],
        started: float,
    ) -> SandboxResult:
        """Body of :meth:`probe`, without the cleanup and failure translation."""
        docker(
            "run",
            "-d",
            *self.run_flags(installer, isolated=False),
            *environment,
            "--entrypoint",
            "sleep",
            self.probe_image,
            str(INSTALL_TIMEOUT + 60),
        )
        install = self.exec_driver(installer, "install", timeout=INSTALL_TIMEOUT)
        if install.get("status") != "ok":
            return self._result(spec, install, started)

        docker("commit", installer, image, timeout=300.0)
        docker("rm", "-f", installer, check=False, timeout=60.0)

        # From here on, publisher code runs. It has no route off the host and
        # every name it resolves answers with the sinkhole.
        docker(
            "run",
            "-d",
            *self.run_flags(prober, isolated=True),
            *environment,
            "--entrypoint",
            "sleep",
            image,
            str(PROBE_TIMEOUT + 60),
        )
        self._assert_isolated(prober)
        self.mark_sinkhole()

        result = self.exec_driver(prober, "probe", timeout=PROBE_TIMEOUT)
        result["egress"] = self.collect_egress()
        return self._result(spec, result, started)

    def _assert_isolated(self, name: str) -> None:
        """Refuse to run publisher code in a container with a way out.

        Checked against the running container rather than trusted to the flags
        we passed: this is the last point at which stopping is still free.
        """
        attached = docker(
            "inspect",
            name,
            "--format",
            "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}",
        ).stdout.split()
        if attached != [SINKHOLE_NETWORK]:
            msg = f"container {name} is attached to {attached}, expected only {SINKHOLE_NETWORK}"
            raise ContainmentError(msg)

    def exec_driver(self, name: str, mode: str, *, timeout: float) -> dict[str, Any]:
        """Run one driver phase and parse its result.

        A timeout is an outcome, not an exception. The driver normally bounds
        itself and reports; reaching this means it is wedged, and one wedged
        container must not end the cycle.
        """
        try:
            result = docker(
                "exec", name, "python3", "/srv/probe/driver.py", mode, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "detail": f"the {mode} phase did not return within {timeout:.0f}s",
            }
        _, _, payload = result.stdout.partition(SENTINEL)
        line = payload.strip().splitlines()
        if not line:
            return {
                "status": "crashed",
                "detail": (result.stderr or result.stdout or "no output")[-2000:],
            }
        try:
            parsed = json.loads(line[-1])
        except ValueError:
            return {"status": "crashed", "detail": f"unparseable driver output: {line[-1][:500]}"}
        return parsed if isinstance(parsed, dict) else {"status": "crashed", "detail": "not a dict"}

    # --------------------------------------------------------------- sinkhole ---

    def mark_sinkhole(self) -> None:
        """Record where the sinkhole log currently ends.

        Attempts are attributed by position rather than by source address: the
        log is shared, and a container's address is recycled between probes.
        """
        result = docker(
            "exec",
            SINKHOLE_CONTAINER,
            "sh",
            "-c",
            "wc -l < /var/log/sinkhole/attempts.jsonl 2>/dev/null || echo 0",
            check=False,
        )
        self._log_mark = int(result.stdout.strip() or 0)

    def collect_egress(self) -> list[dict[str, Any]]:
        """Everything the sinkhole recorded since the last mark."""
        mark = self._log_mark
        result = docker(
            "exec",
            SINKHOLE_CONTAINER,
            "sh",
            "-c",
            f"tail -n +{mark + 1} /var/log/sinkhole/attempts.jsonl 2>/dev/null || true",
            check=False,
        )
        events: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if isinstance(event, dict) and event.get("kind") in ("dns", "tcp"):
                events.append(event)
        return events

    @staticmethod
    def _result(spec: dict[str, Any], payload: dict[str, Any], started: float) -> SandboxResult:
        """Fold a driver payload into a typed result."""
        probes = payload.get("probes") or []
        return SandboxResult(
            server_key=spec["server_key"],
            status=str(payload.get("status", "crashed")),
            probes=tuple(p for p in probes if isinstance(p, dict)),
            command=tuple(payload.get("command") or ()),
            used_placeholders=bool(payload.get("used_placeholders")),
            detail=payload.get("detail") or payload.get("bare_launch_error"),
            stderr_tail=payload.get("stderr_tail"),
            egress=tuple(payload.get("egress") or ()),
            seconds=round(time.monotonic() - started, 2),
        )
