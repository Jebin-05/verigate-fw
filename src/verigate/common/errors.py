"""Domain exceptions.

Every failure that can influence a verdict is raised as one of these so callers can map it to
``REJECT`` (verification failed) or ``DEFER`` (a dependency was unavailable) — never ``APPROVE``.
"""


class VerigateError(Exception):
    """Base class for all VeriGate-FW domain errors."""


class VerificationError(VerigateError):
    """A cryptographic or structural check failed; the input must be rejected."""


class ChainError(VerigateError):
    """The blockchain RPC or a contract call failed; the decision must be deferred."""


class IpfsError(VerigateError):
    """An IPFS put/get failed or the fetched bytes did not match the CID; defer."""


class CanonicalError(VerigateError):
    """The value cannot be canonicalised deterministically (float, huge int, bad key)."""
