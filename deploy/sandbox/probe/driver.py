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

NODE_PREFIX = "/srv/server"
VENV = "/srv/server/venv"

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

    if registry == "npm":
        pinned = f"{identifier}@{version}" if version else identifier
        run(
            ["npm", "install", "--ignore-scripts", "--no-save", "--prefix", NODE_PREFIX, pinned],
            "install_failed",
        )
        return npm_command(identifier, spec) + package_arguments(spec)
    if registry == "pypi":
        pinned = f"{identifier}=={version}" if version else identifier
        # A venv, not `pip install --target`. `--target` does not generate the
        # console-script entry points a server declares, so the launcher would
        # have to guess a module name from the distribution name — which is what
        # the first version did, and it is wrong often enough to dominate the
        # failure taxonomy with our bugs instead of the ecosystem's.
        run([sys.executable, "-m", "venv", VENV], "install_failed")
        before = set(os.listdir(f"{VENV}/bin"))
        run([f"{VENV}/bin/pip", "install", "--no-cache-dir", pinned], "install_failed")
        return venv_command(identifier, before, spec) + package_arguments(spec)
    raise Failed("install_failed", f"unsupported registry type {registry!r}")


def run(cmd: list[str], klass: str) -> None:
    """Run an install step, raising with its output on failure."""
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)
    if result.returncode != 0:
        raise Failed(klass, (result.stderr or result.stdout)[-STDERR_TAIL:])


def package_arguments(spec: dict) -> list[str]:
    """Arguments the registry says the package's own binary needs.

    Several servers ship as a CLI whose MCP mode is a subcommand — without
    these, `linebreak-gate` prints its usage and exits 2, which is
    indistinguishable from a broken package unless you read the stderr.

    Only arguments carrying a concrete value are passed. A declared-but-empty
    required argument is one we have nothing to fill in, and inventing a value
    would be supplying input to a third-party process rather than enumerating it.
    """
    argv: list[str] = []
    for item in spec.get("package_arguments") or []:
        value = item.get("value")
        if value is None:
            value = item.get("default")
        if item.get("type") == "named":
            name = item.get("name")
            if not name:
                continue
            argv.append(str(name))
            if value is not None:
                argv.append(str(value))
        elif value is not None:
            argv.append(str(value))
    return argv


def _preferred_bin(spec: dict) -> str | None:
    """A bin name named by the runtime arguments, if there is one.

    `runtimeArguments` target npx or uvx, which this sandbox deliberately does
    not use — it installs the pinned version itself rather than letting a
    launcher resolve one over a network it does not have. But a positional among
    them frequently names *which* bin to run, and that is the one piece of the
    declaration still worth honouring: `@clize/clize` ships two bins and the
    default is the CLI, not the server.
    """
    for item in spec.get("runtime_arguments") or []:
        if item.get("type") == "positional" and item.get("value"):
            return str(item["value"])
    return None


def npm_command(identifier: str, spec: dict) -> list[str]:
    """Resolve an npm package's launch command from its own ``package.json``.

    The ``bin`` field, not the package name. A scoped package almost never has
    a bin entry matching the last path segment (``@perplexity-ai/mcp-server``
    ships ``perplexity-mcp``), and guessing produced 8 spurious
    ``launch_failed`` results in the first validation run.

    Invoked through ``node`` rather than executed directly: the entry point is a
    JavaScript file whose executable bit and shebang are whatever the publisher's
    tarball happened to carry, and one of them was missing both.
    """
    manifest = os.path.join(NODE_PREFIX, "node_modules", identifier, "package.json")
    try:
        with open(manifest, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise Failed("launch_failed", f"unreadable package.json for {identifier}: {exc}") from exc

    entry = data.get("bin")
    if isinstance(entry, dict):
        preferred = _preferred_bin(spec)
        entry = entry.get(preferred) if preferred in entry else next(iter(entry.values()), None)
    if not isinstance(entry, str):
        # No bin field. `main` is the module a consumer would import, and a
        # stdio server frequently ships as exactly that.
        entry = data.get("main")
    if not isinstance(entry, str):
        raise Failed("launch_failed", f"{identifier} declares neither bin nor main")

    path = os.path.join(NODE_PREFIX, "node_modules", identifier, entry)
    if not os.path.exists(path):
        raise Failed("launch_failed", f"{identifier} points at {entry}, which is not installed")
    return ["node", path]


def venv_command(identifier: str, before: set, spec: dict) -> list[str]:
    """Find the console script a PyPI distribution installed into the venv.

    Identified by what appeared in ``bin`` during the install rather than by
    transforming the distribution name: the two differ often, and the set
    difference is exact.
    """
    after = set(os.listdir(f"{VENV}/bin"))
    scripts = sorted(after - before - {"__pycache__"})
    preferred = _preferred_bin(spec)
    if preferred and preferred in scripts:
        return [f"{VENV}/bin/{preferred}"]
    if scripts:
        # Prefer a script whose name resembles the distribution when a package
        # installs several, so the choice is stable across cycles.
        stem = identifier.replace("_", "-").lower()
        scripts.sort(key=lambda name: (stem not in name.lower(), name))
        return [f"{VENV}/bin/{scripts[0]}"]

    # No console script. Fall back to the module, which is what `python -m`
    # would run, trying both spellings of the distribution name.
    for module in (identifier.replace("-", "_"), identifier):
        probe = subprocess.run(
            [f"{VENV}/bin/python", "-c", f"import importlib.util as u; u.find_spec('{module}')"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if probe.returncode == 0:
            return [f"{VENV}/bin/python", "-m", module]
    raise Failed("launch_failed", f"{identifier} installed no console script and no import matched")


# --------------------------------------------------------------------- probe ---


class StdioSession:
    """One JSON-RPC conversation with a server over its stdin/stdout."""

    def __init__(self, command: list[str], env: dict[str, str]) -> None:
        """Spawn the server."""
        self.stderr: list[str] = []
        try:
            # The command is the thing under test; it runs sinkholed and capped.
            self.process = subprocess.Popen(
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
        except (subprocess.TimeoutExpired, OSError):
            self.process.kill()


def probe_once(command: list[str], env: dict[str, str]) -> tuple[dict, str]:
    """One launch, one manifest. Returns the manifest and the stderr tail.

    A failure carries the server's stderr out with it. "exited with code 1" on
    its own says nothing about whether the server wanted a credential, a network
    it no longer has, or a newer runtime, and that distinction is the whole
    point of reporting a failure taxonomy rather than a success rate.
    """
    session = StdioSession(command, env)
    try:
        return session.collect(), session.stderr_tail()
    except Failed as exc:
        tail = session.stderr_tail().strip()
        if tail:
            exc.detail = f"{exc.detail}; server said: {tail[-1200:]}"
        raise
    finally:
        session.close()


def build_env(spec: dict, *, placeholders: bool) -> dict[str, str]:
    """The environment a server is launched with.

    The host environment is not inherited — only PATH and a HOME. Anything the
    package declared is supplied as an obvious placeholder or not at all.
    """
    env = {
        "PATH": f"{VENV}/bin:{NODE_PREFIX}/node_modules/.bin:/usr/local/bin:/usr/bin:/bin",
        "HOME": "/home/prober",
        "NODE_PATH": f"{NODE_PREFIX}/node_modules",
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

The phases run in two different containers — install needs a package registry
and the server it installed must never have one — and the second is committed
from the first, so this file travels with the filesystem.
"""


CREDENTIAL_HINTS = ("api key", "api_key", "token", "credential", "unauthor", "must be set")
"""Phrases a server uses when what it is missing is a secret.

Checked against the server's own stderr after a placeholder launch has already
failed. Coarse on purpose: this separates `requires_credentials` from `crashed`
in the reported taxonomy, and over-calling it would understate real breakage,
so it fires only when a placeholder was already tried and rejected.
"""


def _credentials_wanted(spec: dict, detail: str) -> bool:
    """Whether a failure is best explained by a credential we will never supply."""
    declared = spec.get("environment_variables") or []
    if not any(item.get("isSecret") or item.get("isRequired") for item in declared):
        return False
    lowered = detail.casefold()
    return any(hint in lowered for hint in CREDENTIAL_HINTS)


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
    used_placeholders = False
    try:
        # An explicit command in the spec wins, which is how the containment
        # test launches its canary without installing anything.
        command = spec.get("command")
        if not command:
            with open(COMMAND_FILE, encoding="utf-8") as handle:
                command = json.load(handle)
        result["command"] = command
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
        # A server that refuses to start without a real secret is a documented
        # population, not breakage. It is only called that after an obviously
        # fake placeholder was already offered and rejected.
        wanted = used_placeholders and _credentials_wanted(spec, exc.detail)
        result["status"] = "requires_credentials" if wanted else exc.klass
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
