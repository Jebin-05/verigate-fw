"""Publisher reputation (P4-03, ADR-0006): receipts move it up, rejects move it down (EWMA).

``rep' = rep + alpha · (signal − rep)`` in basis points, ``signal = 10 000`` for a confirmed
install receipt and ``0`` for a release-level REJECT. The gateway account (``GATEWAY_ROLE``)
writes the new value with ``PublisherRegistry.setReputation``; a chain failure is logged and the
update is retried on the next signal (reputation is advisory input to the policy, never a
security check on its own).
"""

from __future__ import annotations

import asyncio

from eth_account.signers.local import LocalAccount

from verigate.common.chain import ChainClient
from verigate.common.errors import ChainError
from verigate.common.logging import get_logger

log = get_logger(__name__)

BASIS = 10_000
RECEIPT_SIGNAL = BASIS
REJECT_SIGNAL = 0


def ewma(rep_bp: int, signal_bp: int, alpha_bp: int) -> int:
    """Exponentially weighted update in basis points (pure, integer, rounds half away from zero)."""
    for name, v in (("rep", rep_bp), ("signal", signal_bp), ("alpha", alpha_bp)):
        if not 0 <= v <= BASIS:
            raise ValueError(f"{name} out of range: {v}")
    delta = alpha_bp * (signal_bp - rep_bp)
    whole, rest = divmod(abs(delta), BASIS)
    step = whole + (1 if 2 * rest >= BASIS else 0)
    return rep_bp + (step if delta >= 0 else -step)


class ReputationUpdater:
    """Applies :func:`ewma` on-chain for the publisher of a release."""

    def __init__(self, chain: ChainClient, account: LocalAccount, alpha_bp: int) -> None:
        self.chain = chain
        self.account = account
        self.alpha_bp = alpha_bp
        self.updates = 0
        self.failures = 0

    def _apply(self, publisher_id: bytes, signal: int) -> int | None:
        record = self.chain.get_publisher(publisher_id)
        if not record.exists:
            return None
        new = ewma(record.reputation_bp, signal, self.alpha_bp)
        if new == record.reputation_bp:
            return new
        self.chain.send(
            self.chain.publishers.functions.setReputation(publisher_id, new), self.account
        )
        return new

    async def signal(self, publisher_id: bytes, signal: int, why: str) -> int | None:
        """Apply one signal; returns the new reputation or ``None`` on failure/unknown publisher."""
        try:
            new = await asyncio.to_thread(self._apply, publisher_id, signal)
        except ChainError as exc:
            self.failures += 1
            log.warning("reputation.update_failed", publisher_id=publisher_id.hex(), error=str(exc))
            return None
        if new is not None:
            self.updates += 1
            log.info(
                "reputation.updated", publisher_id=publisher_id.hex(), reputation_bp=new, why=why
            )
        return new

    async def on_receipt(self, publisher_id: bytes) -> int | None:
        """A device confirmed an install."""
        return await self.signal(publisher_id, RECEIPT_SIGNAL, "receipt")

    async def on_reject(self, publisher_id: bytes, why: str) -> int | None:
        """A release of this publisher was rejected."""
        return await self.signal(publisher_id, REJECT_SIGNAL, why)
