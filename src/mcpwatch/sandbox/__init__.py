"""Package-server sandbox enumeration — WP8.

Half the ecosystem ships as npm or PyPI packages over stdio and is invisible to
WP3's HTTP prober. It is also the half where malicious code is easiest to hide,
because the code runs on the victim's machine rather than the publisher's.
Reaching it means executing third-party code, on a permanent host that holds an
irreplaceable corpus — so this package is organised around containment first and
enumeration second:

* :mod:`~mcpwatch.sandbox.containment` — the sandbox: an internal Docker network
  with no route off the host, a sinkhole that records every connection attempt,
  and probe containers with no mounts, no capabilities, and hard resource caps.
* :mod:`~mcpwatch.sandbox.verify` — the gate. Runs a deliberately-exfiltrating
  canary and checks seven containment properties. ``probe`` re-runs it every
  cycle and refuses to start if any fails.
* :mod:`~mcpwatch.sandbox.frame` — the stratified sampling frame. Full coverage
  is unaffordable, so the sample is fixed, seeded, and re-probed unchanged; the
  frame is stored so results can be reweighted to population base rates.

Never calls a tool, never supplies a real credential, and never mounts the
corpus. See :mod:`mcpwatch.sandbox.cli` for the run order.
"""

from .containment import ContainmentError, Sandbox, SandboxResult
from .frame import Candidate, SampleStore, allocate, candidates, draw
from .verify import VerificationReport, verify

__all__ = [
    "Candidate",
    "ContainmentError",
    "SampleStore",
    "Sandbox",
    "SandboxResult",
    "VerificationReport",
    "allocate",
    "candidates",
    "draw",
    "verify",
]
