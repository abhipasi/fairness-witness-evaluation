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

    def _leaf_hash_sumtree(self, v: Dict) -> bytes:
        """
        Sum-tree leaf hash. Deliberately excludes interval_start/end:
        for a sum tree, the interval is DERIVED from tree position and
        sibling stake sums during verification, not committed directly
        in the leaf -- committing it directly would let a verifier only
        check "this exact claimed interval hashes correctly," which is
        exactly the plain-inclusion weakness the reviewer flagged.
        """
        h = hashlib.sha256()
        h.update(b"STAKE_SNAPSHOT_LEAF_V1")
        h.update(struct.pack(">I", v["validator_id"]))
        h.update(struct.pack(">H", len(v["public_key"])))
        h.update(v["public_key"])
        h.update(struct.pack(">Q", v["stake"]))
        return h.digest()

    @staticmethod
    def _node_hash_sum(left_hash: bytes, left_sum: int,
                        right_hash: bytes, right_sum: int) -> bytes:
        """
        Merkle SUM tree node hash: binds each child's stake total into the
        parent hash, not just its hash. This is what lets a verifier trust
        a sibling's claimed stake_sum during proof verification -- lying
        about it breaks the hash chain up to the root.
        """
        h = hashlib.sha256()
        h.update(b"STAKE_SNAPSHOT_SUMNODE_V1")
        h.update(left_hash)
        h.update(struct.pack(">Q", left_sum))
        h.update(right_hash)
        h.update(struct.pack(">Q", right_sum))
        return h.digest()

    def _compute_commitment(self):
        """
        Merkle SUM tree commitment over the canonical validator set.

        Unlike a plain Merkle tree (which only proves "this leaf exists
        somewhere in the set"), a sum tree additionally binds each
        subtree's total stake into the hash above it. This lets a light
        client, given ONLY one validator's own leaf data and its O(log n)
        proof, cryptographically DERIVE that validator's exact
        [interval_start, interval_end) stake interval relative to the
        ENTIRE population -- without ever seeing the other validators'
        identities or stakes individually -- and thereby verify that a
        given VDF-derived value u falls uniquely inside that interval.
        A plain inclusion proof cannot support this: it has no way to
        bind sibling subtrees' stake totals, so a verifier has no basis
        for trusting a claimed interval_start/interval_end pair at all.

        Odd node counts at any level are handled by duplicating the last
        node (hash AND stake_sum), which callers must replicate exactly.
        """
        leaves = [
            (self._leaf_hash_sumtree(v), v["stake"])
            for v in self._validators
        ]
        self._sum_levels = [leaves]
        level = leaves
        PHANTOM_HASH = hashlib.sha256(b"STAKE_SNAPSHOT_PHANTOM_PAD_V1").digest()
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                lh, ls = level[i]
                if i + 1 < len(level):
                    rh, rs = level[i + 1]
                else:
                    # Real sum-tree padding: a phantom node with stake_sum=0.
                    # Duplicating the real last node (as in a plain Merkle
                    # tree) would double-count its stake at every level
                    # where padding occurs, inflating the root's total
                    # stake above the true total -- this was caught by
                    # cross-checking against real deployment data, where
                    # n=48 is not a power of 2 and padding occurs at the
                    # 3-node level, silently adding phantom stake.
                    rh, rs = PHANTOM_HASH, 0
                nxt.append((self._node_hash_sum(lh, ls, rh, rs), ls + rs))
            self._sum_levels.append(nxt)
            level = nxt
        root_hash, root_sum = level[0] if level else (b"\x00" * 32, 0)

        h = hashlib.sha256()
        h.update(self.DOMAIN_SEPARATOR)
        h.update(b"MERKLE_SUM_V1")
        h.update(struct.pack(">I", len(self._validators)))
        h.update(struct.pack(">Q", self._total_stake))
        h.update(root_hash)
        h.update(struct.pack(">Q", root_sum))
        self._commitment = h.digest()
        self._merkle_root = root_hash
        self._merkle_root_sum = root_sum

    def sum_tree_proof(self, idx: int) -> Dict:
        """
        Return a Merkle SUM inclusion proof for the validator at canonical
        index idx. Unlike merkle_proof(), each sibling entry here also
        carries its subtree's stake_sum, which is what lets a verifier
        derive this validator's exact interval from the proof alone.
        """
        if not (0 <= idx < len(self._validators)):
            raise StakeSnapshotError(f"index out of range: {idx}")
        PHANTOM_HASH = hashlib.sha256(b"STAKE_SNAPSHOT_PHANTOM_PAD_V1").digest()
        siblings = []
        pos = idx
        for level in self._sum_levels[:-1]:
            is_right = (pos % 2 == 1)
            sib_idx = pos - 1 if is_right else pos + 1
            if sib_idx >= len(level):
                # Phantom padding sibling: zero stake, matching tree
                # construction exactly -- NOT a duplicate of our own
                # (hash, stake_sum), which would double-count our stake.
                sib_hash, sib_sum = PHANTOM_HASH, 0
            else:
                sib_hash, sib_sum = level[sib_idx]
            siblings.append({
                "hash": sib_hash,
                "stake_sum": sib_sum,
                "is_right_sibling": not is_right,
            })
            pos //= 2
        v = self._validators[idx]
        return {
            "validator_id": v["validator_id"],
            "public_key": v["public_key"],
            "stake": v["stake"],
            "leaf_index": idx,
            "siblings": siblings,
            "num_validators": len(self._validators),
            "total_stake": self._total_stake,
        }

    @property
    def merkle_root(self) -> bytes:
        return self._merkle_root

    @property
    def merkle_root_sum(self) -> int:
        return self._merkle_root_sum

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


# ══════════════════════════════════════════════════════════
#  LIGHT-CLIENT / AUTHENTICATED STAKE VERIFICATION
# ══════════════════════════════════════════════════════════
#
# Everything below operates WITHOUT a StakeSnapshot instance -- a light
# client never downloads or trusts the full 48-validator list. It only
# needs: (1) a trusted merkle_root (obtained once, out-of-band, or
# transitively via a chain of previously-verified certificates), (2) the
# certificate itself (signer ids + signatures + the claimed stake/pubkey
# for each signer), and (3) one small inclusion proof per signer.

class LightClientVerificationError(Exception):
    """Raised when light-client verification of a proof or certificate fails."""
    pass


def _node_hash_sum_standalone(left_hash: bytes, left_sum: int,
                               right_hash: bytes, right_sum: int) -> bytes:
    h = hashlib.sha256()
    h.update(b"STAKE_SNAPSHOT_SUMNODE_V1")
    h.update(left_hash)
    h.update(struct.pack(">Q", left_sum))
    h.update(right_hash)
    h.update(struct.pack(">Q", right_sum))
    return h.digest()


def derive_interval_from_sum_proof(proof: Dict) -> Tuple[int, int, bytes, int]:
    """
    Walk a Merkle SUM proof from leaf to root, deriving:
      - interval_start: total stake of every validator ordered before this
        one, computed ONLY from sibling stake_sum values along the path
        (never from the individual validators themselves)
      - interval_end: interval_start + this validator's own stake
      - recomputed root hash and root stake_sum, for the caller to check
        against a trusted commitment

    This is the core difference from a plain Merkle proof: the interval
    is DERIVED and cryptographically bound, not claimed and merely
    checked for inclusion. A validator (or a compromised prover) cannot
    claim a wider interval than they actually have, because every
    sibling's stake_sum is bound into the hash chain up to the root --
    tampering with any stake_sum invalidates the root hash.
    """
    h = hashlib.sha256()
    h.update(b"STAKE_SNAPSHOT_LEAF_V1")
    h.update(struct.pack(">I", proof["validator_id"]))
    h.update(struct.pack(">H", len(proof["public_key"])))
    h.update(proof["public_key"])
    h.update(struct.pack(">Q", proof["stake"]))
    node_hash = h.digest()
    leaf_stake = proof["stake"]

    node_sum = leaf_stake
    offset_before = 0  # cumulative stake of validators strictly before this one

    for sib in proof["siblings"]:
        if sib["is_right_sibling"]:
            # our subtree is the LEFT child; sibling (right) comes AFTER
            # us in canonical order -- does not shift our offset_before
            node_hash = _node_hash_sum_standalone(
                node_hash, node_sum, sib["hash"], sib["stake_sum"])
        else:
            # our subtree is the RIGHT child; sibling (left) comes BEFORE
            # us -- its entire stake is added to our offset_before
            offset_before += sib["stake_sum"]
            node_hash = _node_hash_sum_standalone(
                sib["hash"], sib["stake_sum"], node_hash, node_sum)
        node_sum += sib["stake_sum"]

    interval_start = offset_before
    interval_end = offset_before + leaf_stake
    return interval_start, interval_end, node_hash, node_sum


def verify_leader_selection_proof(proof: Dict, u: int,
                                   trusted_merkle_root: bytes,
                                   trusted_root_sum: int) -> Dict:
    """
    THE function the reviewer's comment requires: proves that a specific
    VDF-derived value u falls UNIQUELY inside a specific validator's
    stake interval, relative to the ENTIRE population -- using only that
    validator's own leaf data and an O(log n) sibling proof, never the
    full 48-validator list.

    This is stronger than a plain inclusion proof. A plain proof only
    shows "this leaf is somewhere in the committed set" -- it cannot
    stop a prover from claiming an interval wider than they actually
    have, because sibling stakes are never bound into anything the
    verifier can check. Here, interval_start and interval_end are
    DERIVED from the proof's sibling stake_sum values, which are
    themselves cryptographically bound into the root hash -- so lying
    about any sibling's stake breaks the root check.

    Returns a dict with the derived interval, whether the root matched,
    and whether u falls inside the derived interval. Raises
    LightClientVerificationError if the root does not match (a
    structurally invalid or tampered proof) rather than returning a
    silently-false result for that case.
    """
    interval_start, interval_end, root_hash, root_sum = \
        derive_interval_from_sum_proof(proof)

    if root_hash != trusted_merkle_root or root_sum != trusted_root_sum:
        raise LightClientVerificationError(
            "proof does not recompute to the trusted root -- "
            "tampered, malformed, or wrong validator data"
        )

    u_in_interval = interval_start <= u < interval_end

    return {
        "validator_id": proof["validator_id"],
        "derived_interval_start": interval_start,
        "derived_interval_end": interval_end,
        "u": u,
        "u_in_interval": u_in_interval,
        "root_verified": True,
    }


def verify_merkle_inclusion(proof: Dict, trusted_merkle_root: bytes,
                             trusted_root_sum: int = None) -> bool:
    """
    Backward-compatible plain-inclusion check: confirms the proof
    recomputes to the trusted root. Does NOT by itself prove a claimed
    interval is correct relative to the population -- use
    verify_leader_selection_proof for that. Kept for certificate/quorum
    verification (light_client_verify_certificate), where only "is this
    signer a genuine validator with this stake" is required, not a
    specific-interval / uniqueness proof.
    """
    try:
        _, _, root_hash, root_sum = derive_interval_from_sum_proof(proof)
    except Exception:
        return False
    if trusted_root_sum is not None and root_sum != trusted_root_sum:
        return False
    return root_hash == trusted_merkle_root


def verify_snapshot_commitment(num_validators: int, total_stake: int,
                                merkle_root: bytes, root_sum: int,
                                claimed_commitment: bytes) -> bool:
    """
    Verify that a claimed top-level `commitment` (as embedded in a
    certificate) is correctly derived from (num_validators, total_stake,
    merkle_root, root_sum). A light client typically learns merkle_root
    from a genesis checkpoint or a prior verified certificate.
    """
    h = hashlib.sha256()
    h.update(StakeSnapshot.DOMAIN_SEPARATOR)
    h.update(b"MERKLE_SUM_V1")
    h.update(struct.pack(">I", num_validators))
    h.update(struct.pack(">Q", total_stake))
    h.update(merkle_root)
    h.update(struct.pack(">Q", root_sum))
    return h.digest() == claimed_commitment


def light_client_verify_certificate(signers: List[Dict], payload_fn,
                                     trusted_merkle_root: bytes,
                                     total_stake: int,
                                     required_stake: int) -> Dict:
    """
    Full light-client verification of a certificate's stake-weighted
    validity, using ONLY the certificate's own contents and each signer's
    individual Merkle inclusion proof -- never the full validator list.

    signers: list of dicts, one per certificate signer, each containing:
        validator_id, public_key, stake, siblings (the sum-tree proof
        fields, as returned by StakeSnapshot.sum_tree_proof), signature
        (bytes)
    payload_fn: callable(validator_id: int) -> bytes. The real protocol
        (see prepare_vote_payload in view_change.py) has EACH SIGNER sign
        a payload that embeds their OWN validator_id -- signers do not
        all sign one shared message. Callers verifying a real PC/FC
        should pass e.g.
        `lambda vid: prepare_vote_payload(chain_id, round_number,
         view_number, round_context_hash, proposal_digest, vid)`.
        For test/demo use with a genuinely shared message, pass
        `lambda vid: signed_message`.
    trusted_merkle_root: the root the light client already trusts
    total_stake: total stake claimed for this snapshot (light client
        trusts this the same way it trusts trusted_merkle_root)
    required_stake: minimum summed proven stake needed (the quorum
        threshold expressed in stake units, not validator count)

    Returns a dict summarising the outcome. Raises
    LightClientVerificationError on any individual failure (bad proof,
    bad signature, duplicate signer) rather than silently skipping it --
    a light client must not partially trust a malformed certificate.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError as e:
        raise LightClientVerificationError(f"ed25519 support unavailable: {e}")

    seen_ids = set()
    proven_stake = 0
    verified_signers = []

    for s in signers:
        vid = s["validator_id"]
        if vid in seen_ids:
            raise LightClientVerificationError(f"duplicate signer in certificate: {vid}")
        seen_ids.add(vid)

        proof = {
            "validator_id": vid,
            "public_key": s["public_key"],
            "stake": s["stake"],
            "siblings": s["siblings"],
        }
        if not verify_merkle_inclusion(proof, trusted_merkle_root):
            raise LightClientVerificationError(
                f"Merkle inclusion proof failed for validator {vid} -- "
                f"this signer is NOT provably part of the trusted validator set"
            )

        this_signer_payload = payload_fn(vid)
        try:
            Ed25519PublicKey.from_public_bytes(s["public_key"]).verify(
                s["signature"], this_signer_payload
            )
        except InvalidSignature:
            raise LightClientVerificationError(
                f"signature verification failed for validator {vid}"
            )

        proven_stake += s["stake"]
        verified_signers.append(vid)

    quorum_met = proven_stake >= required_stake

    return {
        "verified_signers": verified_signers,
        "proven_stake": proven_stake,
        "required_stake": required_stake,
        "total_stake": total_stake,
        "quorum_met": quorum_met,
    }
