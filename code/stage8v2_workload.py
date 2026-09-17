"""
Stage 8 v2 — deterministic transaction workload generator.

Transactions are 256-byte opaque payloads whose bytes are derived
solely from (round, txn_index). This makes the workload:
    - reproducible from seed alone (no external RNG)
    - byte-identical across all validators/regions in the same round
    - independent of any external service

The commitment_root binds transactions cryptographically to the
Fairness Witness proof via the frozen Stage 3 LeaderOnlyWitness.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import List


TXN_SIZE_BYTES = 256


def make_transaction(round_number: int, txn_index: int) -> bytes:
    """Deterministic 256-byte transaction payload."""
    h = hashlib.sha256()
    h.update(b"STAGE8V2_TXN|")
    h.update(struct.pack(">II", round_number, txn_index))
    seed = h.digest()  # 32 bytes
    # Expand to 256 bytes deterministically via SHAKE-like chaining
    parts: List[bytes] = [seed]
    while sum(len(p) for p in parts) < TXN_SIZE_BYTES:
        nxt = hashlib.sha256(parts[-1] + b"expand").digest()
        parts.append(nxt)
    return b"".join(parts)[:TXN_SIZE_BYTES]


def make_batch(round_number: int, batch_size: int) -> List[bytes]:
    return [make_transaction(round_number, i) for i in range(batch_size)]


def batch_commitment_root(round_number: int, batch: List[bytes]) -> bytes:
    """
    Compute the commitment_root binding this batch of transactions.
    Used as the commitment_root field in the frozen Stage 3
    LeaderOnlyWitness.
    """
    h = hashlib.sha256()
    h.update(b"STAGE8V2_ROOT|")
    h.update(struct.pack(">II", round_number, len(batch)))
    inner = hashlib.sha256()
    for txn in batch:
        inner.update(txn)
    h.update(inner.digest())
    return h.digest()


@dataclass(frozen=True)
class BatchSummary:
    round_number: int
    batch_size: int
    commitment_root_hex: str
    batch_bytes: int


def batch_summary(round_number: int, batch_size: int) -> BatchSummary:
    """Compute batch summary WITHOUT keeping the transaction bytes
    in memory beyond the commitment_root — useful when the leader
    needs to publish the commitment but validators verify only the
    commitment field."""
    batch = make_batch(round_number, batch_size)
    root = batch_commitment_root(round_number, batch)
    return BatchSummary(
        round_number=round_number,
        batch_size=batch_size,
        commitment_root_hex=root.hex(),
        batch_bytes=batch_size * TXN_SIZE_BYTES,
    )
