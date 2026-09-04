#!/usr/bin/env python3
"""
LEADER SELECTION — Stage 2 of Reviewer Remediation
====================================================
Exact stake-proportional leader selection using a canonical
StakeSnapshot and half-open cumulative-stake intervals.

Modes:
  stake_interval       — default; exact P(leader=i) = stake_i / total_stake
  legacy_k5_selection  — legacy duplicate-free K=5 procedure (isolated only)

The default MUST be stake_interval. Production execution MUST NOT
silently fall back to legacy_k5_selection.

Dependencies: Python >= 3.10 (standard library only).
Licence:      Apache-2.0
"""

import hashlib
import struct
import json
import bisect
from typing import List, Tuple, Dict, Optional


# ══════════════════════════════════════════════════════════
#  EXCEPTIONS
# ══════════════════════════════════════════════════════════

class StakeSnapshotError(Exception):
    """Raised when a stake snapshot fails validation."""
    pass


class LeaderSelectionError(Exception):
    """Raised for leader-selection failures."""
    pass


# ══════════════════════════════════════════════════════════
#  CANONICAL STAKE SNAPSHOT
# ══════════════════════════════════════════════════════════

class StakeSnapshot:
    """
    Deterministic snapshot of the active validator set with
    cumulative-stake intervals [start, end).

    Interval invariants:
      - Every validator i has interval [interval_start_i, interval_end_i)
      - interval_start_0 = 0
      - interval_end_i = interval_start_{i+1}
      - interval_end_{n-1} = total_stake
      - Intervals cover [0, total_stake) exactly, no gaps, no overlaps
      - Zero-stake validators have empty intervals and are never selectable

    All arithmetic is integer. No floating point.
    """

    DOMAIN_SEPARATOR = b"STAKE_SNAPSHOT_V1"

    def __init__(self, validators: List[Dict]):
        """
        validators: list of dicts with fields
            validator_id (int, >=0)
            public_key   (bytes, 32 bytes for Ed25519)
            stake        (int, >=0)
        """
        self._validate_and_canonicalise(validators)
        self._compute_intervals()
        self._compute_commitment()

    # ── Validation ──

    def _validate_and_canonicalise(self, validators: List[Dict]):
        if not validators:
            raise StakeSnapshotError("empty validator list")

        seen_ids = set()
        canonical = []

        for v in validators:
            if not isinstance(v, dict):
                raise StakeSnapshotError(f"validator entry must be dict, got {type(v).__name__}")

            for f in ("validator_id", "public_key", "stake"):
                if f not in v:
                    raise StakeSnapshotError(f"validator missing required field: {f}")

            vid = v["validator_id"]
            pk = v["public_key"]
            stake = v["stake"]

            if not isinstance(vid, int) or vid < 0:
                raise StakeSnapshotError(f"malformed validator_id: {vid!r}")
            if not isinstance(pk, (bytes, bytearray)):
                raise StakeSnapshotError(f"public_key must be bytes, got {type(pk).__name__}")
            if len(pk) != 32:
                raise StakeSnapshotError(
                    f"public_key must be exactly 32 bytes (Ed25519), got {len(pk)}"
                )
            if not isinstance(stake, int):
                raise StakeSnapshotError(f"stake must be int, got {type(stake).__name__}")
            if stake < 0:
                raise StakeSnapshotError(f"negative stake for validator {vid}: {stake}")
            if stake > (1 << 64) - 1:
                raise StakeSnapshotError(
                    f"stake exceeds uint64 range for validator {vid}: {stake}"
                )
            if vid in seen_ids:
                raise StakeSnapshotError(f"duplicate validator_id: {vid}")
            seen_ids.add(vid)

            canonical.append({
                "validator_id": vid,
                "public_key": bytes(pk),
                "stake": stake,
            })

        # Canonical order: validator_id ascending
        canonical.sort(key=lambda x: x["validator_id"])

        total = sum(v["stake"] for v in canonical)
        if total <= 0:
            raise StakeSnapshotError(f"zero total stake: {total}")
        if total > (1 << 64) - 1:
            raise StakeSnapshotError(
                f"total_stake exceeds uint64 range: {total}"
            )

        self._validators = canonical
        self._total_stake = total

    def _compute_intervals(self):
        self._starts = []
        self._ends = []
        cursor = 0
        for v in self._validators:
            self._starts.append(cursor)
            cursor += v["stake"]
            self._ends.append(cursor)

        # Invariant checks — these are protocol correctness, so
        # raise explicit exceptions rather than asserting.
        if self._ends[-1] != self._total_stake:
            raise StakeSnapshotError(
                f"interval end {self._ends[-1]} != total_stake {self._total_stake}"
            )
        if self._starts[0] != 0:
            raise StakeSnapshotError(f"first interval_start must be 0, got {self._starts[0]}")
        for i in range(1, len(self._validators)):
            if self._starts[i] != self._ends[i - 1]:
                raise StakeSnapshotError(f"gap/overlap between intervals {i-1} and {i}")

    def _compute_commitment(self):
        """Deterministic commitment hash over canonical serialisation."""
        h = hashlib.sha256()
        h.update(self.DOMAIN_SEPARATOR)
        h.update(struct.pack(">I", len(self._validators)))
        h.update(struct.pack(">Q", self._total_stake))
        for v, s, e in zip(self._validators, self._starts, self._ends):
            h.update(struct.pack(">I", v["validator_id"]))
            h.update(struct.pack(">H", len(v["public_key"])))
            h.update(v["public_key"])
            h.update(struct.pack(">Q", v["stake"]))
            h.update(struct.pack(">Q", s))
            h.update(struct.pack(">Q", e))
        self._commitment = h.digest()

    # ── Public accessors ──

    @property
    def total_stake(self) -> int:
        return self._total_stake

    @property
    def n(self) -> int:
        return len(self._validators)

    @property
    def commitment(self) -> bytes:
        return self._commitment

    def validator(self, idx: int) -> Dict:
        return dict(self._validators[idx])

    def interval(self, idx: int) -> Tuple[int, int]:
        return self._starts[idx], self._ends[idx]

    def find_interval(self, u: int) -> int:
        """
        Binary search for the validator whose interval [start, end) contains u.
        Zero-stake validators have empty intervals and are never returned.
        """
        if not (0 <= u < self._total_stake):
            raise LeaderSelectionError(f"u={u} outside [0, {self._total_stake})")
        # bisect_right on starts gives the first index with start > u; subtract 1.
        idx = bisect.bisect_right(self._starts, u) - 1
        # Because zero-stake validators have starts[i] == ends[i] == starts[i+1],
        # bisect may point at a zero-stake entry. Move forward until we hit a real one.
        while idx < len(self._validators) - 1 and self._starts[idx] == self._ends[idx]:
            idx += 1
        # Sanity check
        s, e = self._starts[idx], self._ends[idx]
        if not (s <= u < e):
            raise LeaderSelectionError(f"interval lookup failed: u={u}, idx={idx}, [{s},{e})")
        return idx

    def to_dict(self) -> Dict:
        """Canonical JSON-serialisable form for artefacts."""
        return {
            "domain_separator": self.DOMAIN_SEPARATOR.decode(),
            "n_validators": self.n,
            "total_stake": self.total_stake,
            "commitment_sha256": self.commitment.hex(),
            "validators": [
                {
                    "validator_id": v["validator_id"],
                    "public_key_hex": v["public_key"].hex(),
                    "stake": v["stake"],
                    "interval_start": s,
                    "interval_end": e,
                }
                for v, s, e in zip(self._validators, self._starts, self._ends)
            ],
        }


# ══════════════════════════════════════════════════════════
#  UNBIASED SELECTOR (SHA-256 + rejection sampling)
# ══════════════════════════════════════════════════════════

SELECTOR_DOMAIN = b"LEADER_SELECT_V1"
HASH_RANGE = 1 << 256


def _selector_hash(chain_id: bytes, round_number: int, view_number: int,
                   vdf_output: bytes, commitment_root: bytes,
                   snapshot_commitment: bytes, counter: int) -> int:
    """
    SHA-256 of canonical, length-prefixed selector input.
    Returns an integer in [0, 2^256).

    Fields in order:
        DOMAIN | chain_id | round | view | vdf_output |
        commitment_root | snapshot_commitment | counter

    snapshot_commitment is bound explicitly so the selector transcript
    always authenticates the stake snapshot used for interval lookup,
    independently of what round-level commitment_root the caller supplies.
    """
    h = hashlib.sha256()
    h.update(SELECTOR_DOMAIN)
    h.update(struct.pack(">H", len(chain_id))); h.update(chain_id)
    h.update(struct.pack(">I", round_number))
    h.update(struct.pack(">I", view_number))
    h.update(struct.pack(">H", len(vdf_output))); h.update(vdf_output)
    h.update(struct.pack(">H", len(commitment_root))); h.update(commitment_root)
    h.update(struct.pack(">H", len(snapshot_commitment))); h.update(snapshot_commitment)
    h.update(struct.pack(">I", counter))
    return int.from_bytes(h.digest(), "big")


def _unbiased_reduce(chain_id: bytes, round_number: int, view_number: int,
                     vdf_output: bytes, commitment_root: bytes,
                     snapshot_commitment: bytes,
                     total_stake: int, max_retries: int = 256) -> Tuple[int, int]:
    """
    Rejection sampling to produce an unbiased integer u in [0, total_stake).

    range = 2^256
    limit = range - (range mod total_stake)
    If R >= limit: rehash with incremented counter (bias-free retry).
    Otherwise u = R mod total_stake.

    Returns (u, counter_used).
    """
    if total_stake <= 0:
        raise LeaderSelectionError(f"invalid total_stake: {total_stake}")
    limit = HASH_RANGE - (HASH_RANGE % total_stake)
    for counter in range(max_retries):
        R = _selector_hash(chain_id, round_number, view_number,
                           vdf_output, commitment_root,
                           snapshot_commitment, counter)
        if R < limit:
            return R % total_stake, counter
    # Astronomically unlikely: 2^-256 per attempt
    raise LeaderSelectionError(
        f"rejection sampling exhausted after {max_retries} retries"
    )


# ══════════════════════════════════════════════════════════
#  MODE: stake_interval  (DEFAULT)
# ══════════════════════════════════════════════════════════

def _select_stake_interval(snapshot: StakeSnapshot, chain_id: bytes,
                           round_number: int, view_number: int,
                           vdf_output: bytes, commitment_root: bytes
                           ) -> Tuple[int, int, int]:
    """
    Exact stake-proportional leader selection.
    Returns (leader_index, u, retry_counter).
    """
    u, counter = _unbiased_reduce(chain_id, round_number, view_number,
                                  vdf_output, commitment_root,
                                  snapshot.commitment,
                                  snapshot.total_stake)
    idx = snapshot.find_interval(u)
    return idx, u, counter


# ══════════════════════════════════════════════════════════
#  MODE: legacy_k5_selection  (ISOLATED, NOT DEFAULT)
# ══════════════════════════════════════════════════════════

def _select_legacy_k5(snapshot: StakeSnapshot, chain_id: bytes,
                      round_number: int, view_number: int,
                      vdf_output: bytes, commitment_root: bytes,
                      K: int = 5) -> Tuple[int, int, int]:
    """
    LEGACY behaviour: draw K distinct candidates by stake weight,
    then pick one uniformly at random from the candidate set.

    This procedure CAPS any individual validator's leadership
    probability at 1/K (20% for K=5). It is retained ONLY for
    reproducing the pre-remediation experiments. Production
    execution MUST NOT use this mode.
    """
    if snapshot.n < K:
        raise LeaderSelectionError(
            f"legacy_k5_selection requires >= {K} validators, got {snapshot.n}"
        )
    candidates = []
    counter = 0
    while len(candidates) < K and counter < 1000:
        u, sub_counter = _unbiased_reduce(chain_id, round_number, view_number,
                                          vdf_output, commitment_root,
                                          snapshot.commitment,
                                          snapshot.total_stake)
        idx = snapshot.find_interval(u)
        if idx not in candidates:
            candidates.append(idx)
        counter += 1
        # Rotate seed by re-hashing (deterministic)
        vdf_output = hashlib.sha256(vdf_output + b"K5" + struct.pack(">I", counter)).digest()

    if len(candidates) < K:
        raise LeaderSelectionError("could not fill K distinct candidates")

    # Uniform pick among K candidates
    u_final = _selector_hash(chain_id, round_number, view_number,
                             vdf_output, commitment_root,
                             snapshot.commitment, 9999) % K
    return candidates[u_final], u_final, counter


# ══════════════════════════════════════════════════════════
#  PUBLIC API
# ══════════════════════════════════════════════════════════

DEFAULT_MODE = "stake_interval"
LEGACY_MODE = "legacy_k5_selection"


def select_leader(snapshot: StakeSnapshot, chain_id: bytes,
                  round_number: int, view_number: int,
                  vdf_output: bytes, commitment_root: bytes,
                  mode: str = DEFAULT_MODE) -> Dict:
    """
    Select the leader for (round_number, view_number) using the
    verified VDF output and the authenticated stake snapshot.

    mode:
      stake_interval        (DEFAULT) exact P(leader=i) = stake_i / total_stake
      legacy_k5_selection   ISOLATED — caps probability at 1/K, not stake-proportional

    Returns a dict:
      {
        mode, leader_index, leader_id, leader_stake,
        u, rejection_counter, snapshot_commitment_hex
      }
    """
    if mode == DEFAULT_MODE:
        idx, u, counter = _select_stake_interval(
            snapshot, chain_id, round_number, view_number,
            vdf_output, commitment_root
        )
    elif mode == LEGACY_MODE:
        idx, u, counter = _select_legacy_k5(
            snapshot, chain_id, round_number, view_number,
            vdf_output, commitment_root
        )
    else:
        raise LeaderSelectionError(
            f"unknown mode: {mode!r}; expected {DEFAULT_MODE!r} or {LEGACY_MODE!r}"
        )

    v = snapshot.validator(idx)
    return {
        "mode": mode,
        "leader_index": idx,
        "leader_id": v["validator_id"],
        "leader_stake": v["stake"],
        "u": u,
        "rejection_counter": counter,
        "snapshot_commitment_hex": snapshot.commitment.hex(),
    }
