"""Runs inside an isolated container: invoke planned tools under strace.

**This is the only file in MCPWatch that issues ``tools/call``.** Everywhere
else the absence is structural — :mod:`mcpwatch.collect.mcp` and ``driver.py``
have no code path to it, so no amount of misconfiguration can make the nightly
collectors invoke a third party's tool. That guarantee is worth keeping, so the
capability lives here, in a file the collectors do not import and the scheduled
units do not run.

**It decides nothing.** Which tools to call and what arguments to pass arrive as
a plan in ``MCPWATCH_PLAN``, built by :mod:`mcpwatch.divergence.protocol` on the
host where the rules are unit-tested and auditable. This file executes the plan
in the order given and refuses to invent a call that is not in it. Duplicating
the exclusion policy here — in code that runs beside untrusted processes and is
harder to test — is exactly how the policy and its tests would drift apart.

**It runs only where nothing can get out.** The container has no route off the
host, every name resolves to a sinkhole, there are no mounts, and every
capability is dropped except ``SYS_PTRACE``, which strace needs to observe the
process it started. ptrace is confined to this container's own PID namespace;
it grants nothing on the host.

Output contract matches ``driver.py``: one line of JSON after the sentinel, with
per-call wall-clock windows so the host can attribute syscalls to the tool that
caused them.
"""

import json
import os
import subprocess
import time

import driver  # the probe image ships both; reuse the session and launch logic

SENTINEL = driver.SENTINEL

TRACE_PATH = "/tmp/mcpwatch-trace.log"  # noqa: S108 - the container's own tmpfs
MAX_TRACE_BYTES = 400_000
"""How much trace to ship back.

A chatty server can emit megabytes. The tail is kept rather than the head: the
interesting syscalls happen during tool calls, which are last, while the head is
the runtime loading itself.
"""

CALL_TIMEOUT = 25.0
"""Per tool call. Short deliberately — a tool that has not answered in 25s has
already made whatever syscalls it was going to make on the way in, and the
observation does not need its result."""

SETTLE_SECONDS = 0.75
"""Grace after a call returns, before the window closes.

A tool that fires an async request and answers immediately would otherwise have
its connection land outside the window and go unobserved. Slightly generous is
the right error: an event attributed to the wrong tool on the same server is a
smaller mistake than a divergence missed entirely.
"""

TRACED_SYSCALLS = (
    "openat,open,openat2,creat,connect,sendto,sendmsg,execve,execveat,"
    "unlink,unlinkat,rename,renameat,renameat2,mkdir,mkdirat"
)


def traced(command: list[str]) -> list[str]:
    """Wrap a launch command in strace.

    ``-f`` follows children, which is the point — a tool that shells out does it
    in a subprocess. ``-ttt`` gives epoch timestamps so the host can window
    events against the call boundaries recorded below.
    """
    return [
        "strace",
        "-f",
        "-ttt",
        "-qq",
        "-s",
        "120",
        "-e",
        f"trace={TRACED_SYSCALLS}",
        "-o",
        TRACE_PATH,
        *command,
    ]


def read_trace() -> tuple[str, bool]:
    """Return the trace tail and whether it was truncated."""
    try:
        size = os.path.getsize(TRACE_PATH)
        with open(TRACE_PATH, encoding="utf-8", errors="replace") as handle:
            if size > MAX_TRACE_BYTES:
                handle.seek(size - MAX_TRACE_BYTES)
                handle.readline()  # discard the partial line seek landed in
                return handle.read(), True
            return handle.read(), False
    except OSError as exc:
        return f"[trace unavailable: {exc}]", False


def call_tool(session: driver.StdioSession, name: str, arguments: dict) -> dict:
    """Issue one ``tools/call`` and record when it happened.

    The window is what makes attribution possible: syscalls outside every window
    belong to startup, and counting them would make every tool on every server
    look like it touches the disk and the network.
    """
    started = time.time()
    record: dict = {"tool": name, "arguments": arguments}
    try:
        result = session.request("tools/call", {"name": name, "arguments": arguments})
        record["ok"] = True
        # The result itself is not the measurement — what the process *did*
        # while producing it is. Keep a fingerprint, not the payload.
        record["result_keys"] = sorted(result)[:10]
        record["is_error"] = bool(result.get("isError"))
    except driver.Failed as exc:
        # A refused call is still an observation. The tool usually opened its
        # socket or read its config before deciding the argument was wrong.
        record["ok"] = False
        record["error"] = f"{exc.klass}: {exc.detail[:400]}"
    except Exception as exc:  # noqa: BLE001 - one bad tool must not end the session
        record["ok"] = False
        record["error"] = f"{type(exc).__name__}: {exc}"

    time.sleep(SETTLE_SECONDS)
    record["window"] = [started, time.time()]
    return record


def main() -> int:
    """Launch the server under strace, run the plan, report."""
    spec = json.loads(os.environ["MCPWATCH_SPEC"])
    plan = json.loads(os.environ.get("MCPWATCH_PLAN") or "[]")
    result: dict = {"server_key": spec.get("server_key"), "status": "ok", "calls": []}
    started = time.monotonic()

    session = None
    try:
        command = spec.get("command")
        if not command:
            with open(driver.COMMAND_FILE, encoding="utf-8") as handle:
                command = json.load(handle)
        result["command"] = command

        session = driver.StdioSession(
            traced(command), driver.build_env(spec, placeholders=bool(spec.get("placeholders")))
        )
        session.collect()  # initialize + enumerate, exactly as the WP8 probe does
        result["ready_at"] = time.time()

        for step in plan:
            name = step.get("tool")
            if not name:
                continue
            result["calls"].append(call_tool(session, str(name), step.get("arguments") or {}))
    except driver.Failed as exc:
        result["status"] = exc.klass
        result["detail"] = exc.detail[-driver.STDERR_TAIL :]
    except (OSError, ValueError) as exc:
        result["status"] = "crashed"
        result["detail"] = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001 - a driver crash must still report
        result["status"] = "crashed"
        result["detail"] = f"{type(exc).__name__}: {exc}"
    finally:
        if session is not None:
            result["stderr_tail"] = session.stderr_tail()
            session.close()

    # Read the trace after the session is closed so strace has flushed.
    time.sleep(0.3)
    trace, truncated = read_trace()
    result["trace"] = trace
    result["trace_truncated"] = truncated
    result["seconds"] = round(time.monotonic() - started, 2)

    print(SENTINEL)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
