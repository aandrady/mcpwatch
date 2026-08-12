"""Runs inside a probe container: launch one MCP server over stdio, enumerate, exit.

Deliberately standalone. It imports nothing from ``mcpwatch`` and is copied into
an image that knows nothing about the corpus, so the process sharing a namespace
with third-party code cannot be induced to touch the observatory's data — there
is no code path to it in this file and no such path in the image.

**It cannot call a tool.** The four read-only methods are a module-level tuple
and ``tools/call`` is not among them, matching the guarantee
:mod:`mcpwatch.collect.mcp` makes for the HTTP prober: absent by construction,
not by discipline.

**It launches the server twice.** The second launch is WP3's double-probe
nondeterminism guard carried over to stdio: a server that randomizes tool order
or embeds a session id in a description otherwise registers a mutation every
single run. Both manifests are returned and the caller compares normalized
hashes. Two launches inside one container rather than two containers is a
deliberate trade — it catches per-process nondeterminism, which is what the
guard is for, without doubling install cost. Install-time nondeterminism is out
of its reach, and the caller pins the package version so that is not the risk.

Output contract: a single line of JSON on stdout after :data:`SENTINEL`. The
server's own stdout is a pipe this process owns, so it cannot corrupt that; its
stderr is captured and a tail returned as evidence for the failure taxonomy.
"""

import json
import os
import shutil
import subprocess
import sys
import threading
import time

SENTINEL = "===MCPWATCH-RESULT==="

PROTOCOL_VERSION = "2025-06-18"
READ_ONLY_METHODS = ("tools/list", "resources/list", "prompts/list")
"""`tools/call` is absent by construction."""

LAUNCH_TIMEOUT = 90.0
"""Wall clock for one launch: spawn, handshake, enumerate, exit."""

REQUEST_TIMEOUT = 30.0
STDERR_TAIL = 4000

PLACEHOLDER = "mcpwatch-placeholder-not-a-real-credential"
"""What a required env var gets when a server refuses to start without one.

Obviously fake on purpose. A server that accepts it and proceeds tells us
something; a server that validates it and exits tells us something too. Neither
outcome involves a real credential existing anywhere in this system.
"""


class Failed(Exception):
    """A launch or handshake failed, with a class name for the taxonomy."""

    def __init__(self, klass: str, detail: str) -> None:
        super().__init__(detail)
        self.klass = klass
        self.detail = detail


# ------------------------------------------------------------------- install ---


def install(spec: dict) -> list[str]:
    """Install the pinned package and return the command that launches it.

    Lifecycle scripts are disabled. ``npm install`` runs ``postinstall`` as
    arbitrary code with network access, and this step happens while the
    container still has egress — enumerating a manifest is not a good enough
    reason to execute a publisher's install hook. Packages that genuinely need
    one fail here and are recorded ``install_failed``, which is a reportable
    property of the ecosystem rather than a gap to paper over.
    """
    registry = spec["registry_type"]
    identifier = spec["identifier"]
    version = spec.get("version")
    pinned = f"{identifier}@{version}" if registry == "npm" and version else identifier
    if registry == "pypi" and version:
        pinned = f"{identifier}=={version}"

    if registry == "npm":
        cmd = ["npm", "install", "--ignore-scripts", "--no-save", "--prefix", "/srv/server", pinned]
    elif registry == "pypi":
        cmd = ["pip", "install", "--no-cache-dir", "--target", "/srv/server/pylib", pinned]
    else:
        raise Failed("install_failed", f"unsupported registry type {registry!r}")

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)
    if result.returncode != 0:
        raise Failed("install_failed", (result.stderr or result.stdout)[-STDERR_TAIL:])
    return launch_command(spec)


def launch_command(spec: dict) -> list[str]:
    """Work out how to start the installed server."""
    explicit = spec.get("command")
    if explicit:
        return list(explicit)
    registry = spec["registry_type"]
    identifier = spec["identifier"]
    if registry == "npm":
        # The package's own bin entry, resolved from the install prefix rather
        # than by asking npx to go back to the network — which it cannot do here.
        binary = identifier.split("/")[-1]
        candidate = f"/srv/server/node_modules/.bin/{binary}"
        if os.path.exists(candidate):
            return [candidate]
        found = shutil.which(binary, path="/srv/server/node_modules/.bin")
        if found:
            return [found]
        raise Failed("launch_failed", f"no bin entry for {identifier} in node_modules/.bin")
    module = identifier.replace("-", "_")
    return [sys.executable, "-m", module]


# --------------------------------------------------------------------- probe ---


class StdioSession:
    """One JSON-RPC conversation with a server over its stdin/stdout."""

    def __init__(self, command: list[str], env: dict[str, str]) -> None:
        """Spawn the server."""
        self.stderr: list[str] = []
        try:
            self.process = subprocess.Popen(  # noqa: S603 - the command is the thing under test
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=env,
                cwd="/srv/server",
            )
        except (OSError, ValueError) as exc:
            raise Failed("launch_failed", str(exc)) from exc
        self._drain = threading.Thread(target=self._read_stderr, daemon=True)
        self._drain.start()
        self._id = 0

    def _read_stderr(self) -> None:
        """Keep the server's stderr from filling its pipe and blocking it."""
        assert self.process.stderr is not None
        for line in self.process.stderr:
            self.stderr.append(line)
            del self.stderr[:-200]

    def stderr_tail(self) -> str:
        """The last of whatever the server complained about."""
        return "".join(self.stderr)[-STDERR_TAIL:]

    def request(self, method: str, params: dict | None = None) -> dict:
        """Issue one request and return its result.

        Raises:
            Failed: On timeout, a dead process, or a JSON-RPC error.
        """
        self._id += 1
        message = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            message["params"] = params
        self._write(message)

        deadline = time.monotonic() + REQUEST_TIMEOUT
        while time.monotonic() < deadline:
            line = self._readline(deadline)
            try:
                payload = json.loads(line)
            except ValueError:
                # Servers routinely print banners to stdout before speaking
                # JSON-RPC. Skipping non-JSON lines is what makes those usable.
                continue
            if not isinstance(payload, dict) or payload.get("id") != self._id:
                continue
            if "error" in payload:
                error = payload["error"] if isinstance(payload["error"], dict) else {}
                raise Failed("protocol_error", f"{method}: {error.get('message')}")
            result = payload.get("result")
            return result if isinstance(result, dict) else {}
        raise Failed("timeout", f"no response to {method} within {REQUEST_TIMEOUT:.0f}s")

    def notify(self, method: str) -> None:
        """Send a notification, tolerating a server that dislikes it."""
        try:
            self._write({"jsonrpc": "2.0", "method": method})
        except Failed:
            return

    def _write(self, message: dict) -> None:
        if self.process.poll() is not None:
            raise Failed("crashed", f"server exited with code {self.process.returncode}")
        try:
            assert self.process.stdin is not None
            self.process.stdin.write(json.dumps(message) + "\n")
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise Failed("crashed", f"server closed its stdin: {exc}") from exc

    def _readline(self, deadline: float) -> str:
        assert self.process.stdout is not None
        line = self.process.stdout.readline()
        if line:
            return line
        if self.process.poll() is not None:
            raise Failed("crashed", f"server exited with code {self.process.returncode}")
        if time.monotonic() >= deadline:
            raise Failed("timeout", "server stopped producing output")
        time.sleep(0.05)
        return ""

    def collect(self) -> dict:
        """Handshake, then the read-only sweep. Never calls a tool."""
        init = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcpwatch", "version": "0.1.0"},
            },
        )
        self.notify("notifications/initialized")

        manifest = {
            "serverInfo": init.get("serverInfo", {}),
            "protocolVersion": init.get("protocolVersion"),
            "capabilities": init.get("capabilities", {}),
        }
        manifest["tools"] = (self.request("tools/list").get("tools")) or []
        for method, key in (("resources/list", "resources"), ("prompts/list", "prompts")):
            try:
                manifest[key] = self.request(method).get(key) or []
            except Failed:
                manifest[key] = None  # optional capability, not a failed probe
        return manifest

    def close(self) -> None:
        """Stop the server, hard if it will not stop politely."""
        try:
            if self.process.stdin:
                self.process.stdin.close()
            self.process.terminate()
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired, OSError:
            self.process.kill()


def probe_once(command: list[str], env: dict[str, str]) -> tuple[dict, str]:
    """One launch, one manifest. Returns the manifest and the stderr tail."""
    session = StdioSession(command, env)
    try:
        return session.collect(), session.stderr_tail()
    finally:
        session.close()


def build_env(spec: dict, *, placeholders: bool) -> dict[str, str]:
    """The environment a server is launched with.

    The host environment is not inherited — only PATH and a HOME. Anything the
    package declared is supplied as an obvious placeholder or not at all.
    """
    env = {
        "PATH": "/srv/server/node_modules/.bin:/usr/local/bin:/usr/bin:/bin",
        "HOME": "/home/prober",
        "NODE_PATH": "/srv/server/node_modules",
        "PYTHONPATH": "/srv/server/pylib",
        "MCPWATCH_SANDBOX": "1",
    }
    if placeholders:
        for declared in spec.get("environment_variables") or []:
            name = declared.get("name")
            if name:
                env[str(name)] = declared.get("default") or PLACEHOLDER
    return env


COMMAND_FILE = "/srv/probe/launch.json"
"""Where the install phase leaves the command the probe phase will run.

The two phases are separate ``docker exec`` calls into one container, because
between them the runner swaps the container off the egress network and onto the
sinkhole. Install needs a package registry; the server it installed must never
have one.
"""


def _install_phase(spec: dict) -> int:
    """Install only, and record how to launch what was installed."""
    result: dict = {"server_key": spec.get("server_key"), "status": "ok"}
    started = time.monotonic()
    try:
        command = install(spec)
        result["command"] = command
        with open(COMMAND_FILE, "w", encoding="utf-8") as handle:
            json.dump(command, handle)
    except Failed as exc:
        result["status"] = exc.klass
        result["detail"] = exc.detail[-STDERR_TAIL:]
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        result["detail"] = "install exceeded its budget"
    except Exception as exc:  # noqa: BLE001 - a driver crash must still report
        result["status"] = "crashed"
        result["detail"] = f"{type(exc).__name__}: {exc}"
    result["seconds"] = round(time.monotonic() - started, 2)
    print(SENTINEL)
    print(json.dumps(result))
    return 0


def main() -> int:
    """Install, or probe twice. Always exits 0 with a verdict on stdout."""
    spec = json.loads(os.environ["MCPWATCH_SPEC"])
    mode = sys.argv[1] if len(sys.argv) > 1 else "probe"
    if mode == "install":
        return _install_phase(spec)

    result: dict = {
        "server_key": spec.get("server_key"),
        "status": "ok",
        "probes": [],
        "used_placeholders": False,
    }
    started = time.monotonic()
    try:
        # An explicit command in the spec wins, which is how the containment
        # test launches its canary without installing anything.
        command = spec.get("command")
        if not command:
            with open(COMMAND_FILE, encoding="utf-8") as handle:
                command = json.load(handle)
        result["command"] = command

        used_placeholders = False
        try:
            first, stderr = probe_once(command, build_env(spec, placeholders=False))
        except Failed as bare:
            # A server that will not start without its declared variables is a
            # documented population, not a failure to hide. Retry once with
            # obvious placeholders and record that this is what happened.
            if not (spec.get("environment_variables") or []):
                raise
            used_placeholders = True
            result["bare_launch_error"] = f"{bare.klass}: {bare.detail[:500]}"
            first, stderr = probe_once(command, build_env(spec, placeholders=True))

        second, _ = probe_once(command, build_env(spec, placeholders=used_placeholders))
        result["probes"] = [first, second]
        result["used_placeholders"] = used_placeholders
        result["stderr_tail"] = stderr
    except Failed as exc:
        result["status"] = exc.klass
        result["detail"] = exc.detail[-STDERR_TAIL:]
    except OSError as exc:
        result["status"] = "install_failed"
        result["detail"] = f"no launch command recorded: {exc}"
    except Exception as exc:  # noqa: BLE001 - a driver crash must still report
        result["status"] = "crashed"
        result["detail"] = f"{type(exc).__name__}: {exc}"

    result["seconds"] = round(time.monotonic() - started, 2)
    print(SENTINEL)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
