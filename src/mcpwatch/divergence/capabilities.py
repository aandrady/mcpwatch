"""The capability vocabulary both halves of WP9 are expressed in.

Divergence is a comparison, so the declared side and the observed side have to
speak the same language. Four capabilities, chosen because each is something a
tool either does or does not do, and each is independently observable from
outside the process:

``NETWORK``            opened a connection to anything
``FILESYSTEM_READ``    opened a file it did not ship with
``FILESYSTEM_WRITE``   created or modified a file
``SUBPROCESS``         executed another program
``CREDENTIAL_ACCESS``  read somewhere secrets are conventionally kept

Deliberately coarse. A finer vocabulary — "network egress to api.example.com" —
would be more useful and far less measurable: the declared side is derived from
prose, and prose rarely names hosts. A capability that cannot be extracted from
a description with reasonable agreement cannot appear in a divergence rate
without inventing the disagreement.

The asymmetry that matters: **observing a capability is evidence, not observing
one is not.** A tool that never opened a socket during its exercise may still be
able to; it was invoked once, with synthetic arguments, on one code path. So
this package only ever reports *undeclared* capabilities — observed and not
declared. The reverse (declared and not observed) is recorded as ``unexercised``
and never scored, because it is far more likely to mean the exercise missed the
path than that the description lied.
"""

from dataclasses import dataclass
from enum import StrEnum

__all__ = ["DIVERGENCE_CLASS", "Capability", "CapabilityProfile"]


class Capability(StrEnum):
    """One thing a tool can do, declared or observed."""

    NETWORK = "network"
    FILESYSTEM_READ = "filesystem_read"
    FILESYSTEM_WRITE = "filesystem_write"
    SUBPROCESS = "subprocess"
    CREDENTIAL_ACCESS = "credential_access"


DIVERGENCE_CLASS: dict[Capability, str] = {
    Capability.NETWORK: "undeclared_network",
    Capability.FILESYSTEM_READ: "undeclared_filesystem",
    Capability.FILESYSTEM_WRITE: "undeclared_filesystem",
    Capability.SUBPROCESS: "undeclared_subprocess",
    Capability.CREDENTIAL_ACCESS: "undeclared_credential_access",
}
"""WP9's four reported divergence classes.

Both filesystem capabilities collapse into one class because the brief names
four, and because the read/write distinction is about *what* a tool touched
rather than whether its description was honest. The profile keeps them apart;
the reported rate does not.
"""


@dataclass(frozen=True, slots=True)
class CapabilityProfile:
    """What a tool declares, or what it was observed doing.

    Attributes:
        capabilities: The set held.
        evidence: Per capability, why — a rule name and the text or syscall that
            triggered it. A divergence finding without evidence is an assertion,
            and this one accuses a publisher of shipping a description that does
            not match the code.
    """

    capabilities: frozenset[Capability] = frozenset()
    evidence: tuple[tuple[Capability, str], ...] = ()

    def __contains__(self, capability: object) -> bool:
        """Whether this profile holds ``capability``."""
        return capability in self.capabilities

    def undeclared_against(self, declared: CapabilityProfile) -> frozenset[Capability]:
        """Capabilities this profile holds that ``declared`` does not.

        One-directional on purpose — see the module docstring. Observing a
        capability is evidence; failing to observe one is not.
        """
        return self.capabilities - declared.capabilities

    def reasons(self, capability: Capability) -> tuple[str, ...]:
        """Every recorded reason this profile holds ``capability``."""
        return tuple(why for held, why in self.evidence if held is capability)

    def merge(self, other: CapabilityProfile) -> CapabilityProfile:
        """Union of two profiles, keeping both sets of evidence."""
        return CapabilityProfile(
            capabilities=self.capabilities | other.capabilities,
            evidence=self.evidence + other.evidence,
        )

    @classmethod
    def of(cls, *pairs: tuple[Capability, str]) -> CapabilityProfile:
        """Build a profile from (capability, reason) pairs."""
        return cls(capabilities=frozenset(c for c, _ in pairs), evidence=pairs)
