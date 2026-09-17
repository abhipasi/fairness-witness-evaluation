#!/usr/bin/env python3
"""
Stage 5 — View change, prepare/commit, and timeout certificates.

Implements PBFT-style safety-preserving view change on top of the frozen
Stage-2 leader selector and Stage-3 finality-certificate/witness format.

Not a new BFT protocol — a concrete implementation of the standard
Propose → Prepare → Commit → (Timeout → NewView) message flow around the
existing Fairness Witness validity predicate.

Design highlights
-----------------
- Prepare and Commit each require q = 2f+1 distinct valid Ed25519 signatures.
- Prepare Certificates enable prepared-value carryover across views.
- Timeout Certificates require q distinct TimeoutVotes for the same
  (chain, round, timed_out_view, target_view, round_context_hash).
- target_view == timed_out_view + 1 — arbitrary view skipping is impossible;
  a chain of TCs is required to enter view v > 0.
- Prepared-value carryover: TimeoutVotes report the signer's highest valid
  PrepareCertificate. When a TC is formed, the new leader MUST re-propose
  the highest prepared proposal digest (if any). Honest validators reject
  an unrelated proposal.
- All certificates use domain-separated canonical binary serialization.

Stage 5 additions live in a NEW module. Stage 0-4 files are unmodified.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


# ══════════════════════════════════════════════════════════
#  CONSTANTS AND DOMAINS
# ══════════════════════════════════════════════════════════

STAGE5_PROTOCOL_VERSION = 1

# Domain separators — every signed byte-string is prefixed with one of these
DOMAIN_ROUND_CONTEXT   = b"FW_ROUND_CONTEXT_V1"
DOMAIN_PREPARE_VOTE    = b"FW_PREPARE_VOTE_V1"
DOMAIN_COMMIT_VOTE     = b"FW_COMMIT_VOTE_V1"
DOMAIN_TIMEOUT_VOTE    = b"FW_TIMEOUT_VOTE_V1"

# Fixed sizes
ED25519_SIG_SIZE = 64
ED25519_PUBKEY_SIZE = 32
SHA256_SIZE = 32

# Certificate versions
PC_VERSION = 1   # PrepareCertificate
CC_VERSION = 1   # CommitCertificate (a Stage-3 FC alias exists — we use FC for finality)
TC_VERSION = 1   # TimeoutCertificate
NV_VERSION = 1   # NewViewEvidence


# ══════════════════════════════════════════════════════════
#  EXCEPTIONS
# ══════════════════════════════════════════════════════════

class ViewChangeError(Exception):
    """Raised on any Stage-5 verification failure or malformed input."""


# ══════════════════════════════════════════════════════════
#  ROUND CONTEXT HASH
# ══════════════════════════════════════════════════════════

def compute_round_context_hash(chain_id: bytes,
                                round_number: int,
                                vdf_output: bytes,
                                commitment_root: bytes,
                                snapshot_commitment: bytes) -> bytes:
    """
    Domain-separated hash binding the immutable per-round state.

    The value is invariant across all views of the same round. All Stage-5
    votes and certificates bind this hash so that a timeout/view-change
    signed under one round cannot be replayed into another.
    """
    h = hashlib.sha256()
    h.update(DOMAIN_ROUND_CONTEXT)
    h.update(struct.pack(">H", len(chain_id))); h.update(chain_id)
    h.update(struct.pack(">I", round_number))
    h.update(struct.pack(">H", len(vdf_output))); h.update(vdf_output)
    h.update(struct.pack(">H", len(commitment_root))); h.update(commitment_root)
    h.update(struct.pack(">H", len(snapshot_commitment))); h.update(snapshot_commitment)
    return h.digest()


# ══════════════════════════════════════════════════════════
#  PREPARE VOTES / CERTIFICATE
# ══════════════════════════════════════════════════════════

def prepare_vote_payload(chain_id: bytes, round_number: int, view_number: int,
                          round_context_hash: bytes, proposal_digest: bytes,
                          validator_id: int) -> bytes:
    """Canonical byte string a PrepareVote signature covers."""
    if len(round_context_hash) != SHA256_SIZE:
        raise ViewChangeError("round_context_hash must be 32 bytes")
    if len(proposal_digest) != SHA256_SIZE:
        raise ViewChangeError("proposal_digest must be 32 bytes")
    return (
        DOMAIN_PREPARE_VOTE
        + struct.pack(">B", STAGE5_PROTOCOL_VERSION)
        + struct.pack(">H", len(chain_id)) + bytes(chain_id)
        + struct.pack(">II", round_number, view_number)
        + round_context_hash
        + proposal_digest
        + struct.pack(">I", validator_id)
    )


@dataclass(frozen=True)
class PrepareVote:
    chain_id: bytes
    round_number: int
    view_number: int
    round_context_hash: bytes
    proposal_digest: bytes
    validator_id: int
    signature: bytes    # Ed25519, 64 B

    def payload(self) -> bytes:
        return prepare_vote_payload(
            self.chain_id, self.round_number, self.view_number,
            self.round_context_hash, self.proposal_digest, self.validator_id,
        )


def sign_prepare_vote(sk: Ed25519PrivateKey, chain_id, round_number, view_number,
                       round_context_hash, proposal_digest, validator_id) -> PrepareVote:
    payload = prepare_vote_payload(chain_id, round_number, view_number,
                                     round_context_hash, proposal_digest, validator_id)
    sig = sk.sign(payload)
    return PrepareVote(chain_id, round_number, view_number,
                        round_context_hash, proposal_digest, validator_id, sig)


@dataclass(frozen=True)
class PrepareCertificateSigner:
    validator_id: int
    signature: bytes


@dataclass(frozen=True)
class PrepareCertificate:
    version: int
    chain_id: bytes
    round_number: int
    view_number: int
    round_context_hash: bytes
    proposal_digest: bytes
    signers: Tuple[PrepareCertificateSigner, ...]


def serialize_prepare_certificate(pc: PrepareCertificate) -> bytes:
    if pc.version != PC_VERSION:
        raise ViewChangeError(f"unsupported PC version: {pc.version}")
    signer_ids = [s.validator_id for s in pc.signers]
    if signer_ids != sorted(signer_ids):
        raise ViewChangeError("PC signers not in canonical ascending order")
    if len(set(signer_ids)) != len(signer_ids):
        raise ViewChangeError("PC contains duplicate signers")
    if len(pc.signers) > 0xFFFF:
        raise ViewChangeError("PC too many signers")
    if len(pc.round_context_hash) != SHA256_SIZE:
        raise ViewChangeError("PC round_context_hash must be 32 bytes")
    if len(pc.proposal_digest) != SHA256_SIZE:
        raise ViewChangeError("PC proposal_digest must be 32 bytes")
    out = bytearray()
    out.append(pc.version)
    out.extend(struct.pack(">H", len(pc.chain_id))); out.extend(pc.chain_id)
    out.extend(struct.pack(">II", pc.round_number, pc.view_number))
    out.extend(pc.round_context_hash)
    out.extend(pc.proposal_digest)
    out.extend(struct.pack(">H", len(pc.signers)))
    for s in pc.signers:
        if len(s.signature) != ED25519_SIG_SIZE:
            raise ViewChangeError(f"PC signer {s.validator_id}: bad sig size")
        out.extend(struct.pack(">I", s.validator_id))
        out.extend(s.signature)
    return bytes(out)


def deserialize_prepare_certificate(data: bytes) -> PrepareCertificate:
    if not isinstance(data, (bytes, bytearray)):
        raise ViewChangeError("PC input must be bytes")
    b = bytes(data); p = 0
    try:
        version = b[p]; p += 1
        if version != PC_VERSION:
            raise ViewChangeError(f"unsupported PC version: {version}")
        (nchain,) = struct.unpack(">H", b[p:p+2]); p += 2
        chain_id = b[p:p+nchain]; p += nchain
        if len(chain_id) != nchain:
            raise ViewChangeError("PC chain_id truncated")
        round_number, view_number = struct.unpack(">II", b[p:p+8]); p += 8
        ctx_hash = b[p:p+SHA256_SIZE]; p += SHA256_SIZE
        prop_digest = b[p:p+SHA256_SIZE]; p += SHA256_SIZE
        (nsigners,) = struct.unpack(">H", b[p:p+2]); p += 2
        signers = []
        for _ in range(nsigners):
            (vid,) = struct.unpack(">I", b[p:p+4]); p += 4
            sig = b[p:p+ED25519_SIG_SIZE]; p += ED25519_SIG_SIZE
            if len(sig) != ED25519_SIG_SIZE:
                raise ViewChangeError("PC signer sig truncated")
            signers.append(PrepareCertificateSigner(vid, sig))
    except (struct.error, IndexError) as e:
        raise ViewChangeError(f"PC deserialize error: {e}")
    if p != len(b):
        raise ViewChangeError(f"PC trailing bytes: parsed {p}, total {len(b)}")
    pc = PrepareCertificate(version, chain_id, round_number, view_number,
                              ctx_hash, prop_digest, tuple(signers))
    serialize_prepare_certificate(pc)  # canonical revalidation
    return pc


def verify_prepare_certificate(pc: PrepareCertificate,
                                snapshot_pubkeys: dict,
                                quorum: int) -> Tuple[bool, str]:
    """
    Verify a PC against a mapping validator_id -> ed25519_public_key_bytes.
    Returns (True, "OK") or (False, reason).
    """
    if pc.version != PC_VERSION:
        return False, f"unsupported PC version {pc.version}"
    ids = [s.validator_id for s in pc.signers]
    if ids != sorted(ids):
        return False, "PC signers not in canonical order"
    if len(set(ids)) != len(ids):
        return False, "PC duplicate signers"
    for sid in ids:
        if sid not in snapshot_pubkeys:
            return False, f"PC unknown signer {sid}"
    payload = prepare_vote_payload(pc.chain_id, pc.round_number, pc.view_number,
                                    pc.round_context_hash, pc.proposal_digest, 0)
    # payload construction actually takes the validator_id; each signer signs their own
    for s in pc.signers:
        their_payload = prepare_vote_payload(pc.chain_id, pc.round_number, pc.view_number,
                                             pc.round_context_hash, pc.proposal_digest,
                                             s.validator_id)
        try:
            Ed25519PublicKey.from_public_bytes(snapshot_pubkeys[s.validator_id]).verify(
                s.signature, their_payload)
        except InvalidSignature:
            return False, f"PC signer {s.validator_id}: signature invalid"
        except Exception as ex:
            return False, f"PC signer {s.validator_id}: parse error: {ex}"
    if len(pc.signers) < quorum:
        return False, f"PC quorum not met: {len(pc.signers)} < {quorum}"
    return True, "OK"


def build_prepare_certificate(votes: List[PrepareVote]) -> PrepareCertificate:
    """
    Build a canonical PC from a list of PrepareVotes.
    All votes must share (chain, round, view, ctx, digest); signers are
    canonically ordered by validator_id.
    """
    if not votes:
        raise ViewChangeError("no prepare votes")
    first = votes[0]
    for v in votes[1:]:
        if (v.chain_id, v.round_number, v.view_number, v.round_context_hash,
            v.proposal_digest) != (first.chain_id, first.round_number,
                                     first.view_number, first.round_context_hash,
                                     first.proposal_digest):
            raise ViewChangeError("prepare votes disagree on chain/round/view/ctx/digest")
    seen = set()
    signers = []
    for v in votes:
        if v.validator_id in seen:
            raise ViewChangeError(f"duplicate signer {v.validator_id}")
        seen.add(v.validator_id)
        signers.append(PrepareCertificateSigner(v.validator_id, v.signature))
    signers.sort(key=lambda s: s.validator_id)
    return PrepareCertificate(
        PC_VERSION, first.chain_id, first.round_number, first.view_number,
        first.round_context_hash, first.proposal_digest, tuple(signers),
    )


# ══════════════════════════════════════════════════════════
#  TIMEOUT VOTES / CERTIFICATE
# ══════════════════════════════════════════════════════════

def timeout_vote_payload(chain_id: bytes, round_number: int, timed_out_view: int,
                          target_view: int, round_context_hash: bytes,
                          validator_id: int,
                          highest_prepared_view: int,
                          highest_prepared_digest: bytes) -> bytes:
    """Canonical bytes a TimeoutVote signature covers.

    `highest_prepared_view = -1` and `highest_prepared_digest = 32 zero bytes`
    encode "no prepared value seen yet"."""
    if len(round_context_hash) != SHA256_SIZE:
        raise ViewChangeError("round_context_hash must be 32 bytes")
    if len(highest_prepared_digest) != SHA256_SIZE:
        raise ViewChangeError("highest_prepared_digest must be 32 bytes")
    if target_view != timed_out_view + 1:
        raise ViewChangeError("target_view must be timed_out_view + 1")
    # Encode -1 as 0xFFFFFFFF (i.e. u32 max)
    hpv_encoded = 0xFFFFFFFF if highest_prepared_view < 0 else highest_prepared_view
    return (
        DOMAIN_TIMEOUT_VOTE
        + struct.pack(">B", STAGE5_PROTOCOL_VERSION)
        + struct.pack(">H", len(chain_id)) + bytes(chain_id)
        + struct.pack(">III", round_number, timed_out_view, target_view)
        + round_context_hash
        + struct.pack(">I", validator_id)
        + struct.pack(">I", hpv_encoded)
        + highest_prepared_digest
    )


@dataclass(frozen=True)
class TimeoutVote:
    chain_id: bytes
    round_number: int
    timed_out_view: int
    target_view: int
    round_context_hash: bytes
    validator_id: int
    highest_prepared_view: int      # -1 for none
    highest_prepared_digest: bytes  # 32 zero bytes for none
    signature: bytes

    def payload(self) -> bytes:
        return timeout_vote_payload(
            self.chain_id, self.round_number, self.timed_out_view,
            self.target_view, self.round_context_hash, self.validator_id,
            self.highest_prepared_view, self.highest_prepared_digest,
        )


NO_PREPARED_VIEW = -1
NO_PREPARED_DIGEST = b"\x00" * SHA256_SIZE


def sign_timeout_vote(sk: Ed25519PrivateKey, chain_id, round_number,
                       timed_out_view, target_view, round_context_hash,
                       validator_id,
                       highest_prepared_view: int = NO_PREPARED_VIEW,
                       highest_prepared_digest: bytes = NO_PREPARED_DIGEST) -> TimeoutVote:
    payload = timeout_vote_payload(chain_id, round_number, timed_out_view,
                                    target_view, round_context_hash, validator_id,
                                    highest_prepared_view, highest_prepared_digest)
    sig = sk.sign(payload)
    return TimeoutVote(chain_id, round_number, timed_out_view, target_view,
                        round_context_hash, validator_id,
                        highest_prepared_view, highest_prepared_digest, sig)


@dataclass(frozen=True)
class TimeoutCertificateSigner:
    validator_id: int
    highest_prepared_view: int
    highest_prepared_digest: bytes
    signature: bytes


@dataclass(frozen=True)
class TimeoutCertificate:
    version: int
    chain_id: bytes
    round_number: int
    timed_out_view: int
    target_view: int
    round_context_hash: bytes
    signers: Tuple[TimeoutCertificateSigner, ...]


def serialize_timeout_certificate(tc: TimeoutCertificate) -> bytes:
    if tc.version != TC_VERSION:
        raise ViewChangeError(f"unsupported TC version: {tc.version}")
    if tc.target_view != tc.timed_out_view + 1:
        raise ViewChangeError("TC target_view must be timed_out_view + 1")
    ids = [s.validator_id for s in tc.signers]
    if ids != sorted(ids):
        raise ViewChangeError("TC signers not in canonical order")
    if len(set(ids)) != len(ids):
        raise ViewChangeError("TC duplicate signers")
    if len(tc.signers) > 0xFFFF:
        raise ViewChangeError("TC too many signers")
    if len(tc.round_context_hash) != SHA256_SIZE:
        raise ViewChangeError("TC round_context_hash must be 32 bytes")
    out = bytearray()
    out.append(tc.version)
    out.extend(struct.pack(">H", len(tc.chain_id))); out.extend(tc.chain_id)
    out.extend(struct.pack(">III", tc.round_number, tc.timed_out_view, tc.target_view))
    out.extend(tc.round_context_hash)
    out.extend(struct.pack(">H", len(tc.signers)))
    for s in tc.signers:
        if len(s.signature) != ED25519_SIG_SIZE:
            raise ViewChangeError("TC signer bad sig size")
        if len(s.highest_prepared_digest) != SHA256_SIZE:
            raise ViewChangeError("TC signer bad highest_prepared_digest size")
        hpv_encoded = 0xFFFFFFFF if s.highest_prepared_view < 0 else s.highest_prepared_view
        out.extend(struct.pack(">II", s.validator_id, hpv_encoded))
        out.extend(s.highest_prepared_digest)
        out.extend(s.signature)
    return bytes(out)


def deserialize_timeout_certificate(data: bytes) -> TimeoutCertificate:
    if not isinstance(data, (bytes, bytearray)):
        raise ViewChangeError("TC input must be bytes")
    b = bytes(data); p = 0
    try:
        version = b[p]; p += 1
        if version != TC_VERSION:
            raise ViewChangeError(f"unsupported TC version: {version}")
        (nchain,) = struct.unpack(">H", b[p:p+2]); p += 2
        chain_id = b[p:p+nchain]; p += nchain
        if len(chain_id) != nchain:
            raise ViewChangeError("TC chain_id truncated")
        round_number, timed_out_view, target_view = struct.unpack(">III", b[p:p+12]); p += 12
        ctx_hash = b[p:p+SHA256_SIZE]; p += SHA256_SIZE
        (nsigners,) = struct.unpack(">H", b[p:p+2]); p += 2
        signers = []
        for _ in range(nsigners):
            vid, hpv_encoded = struct.unpack(">II", b[p:p+8]); p += 8
            hpv = -1 if hpv_encoded == 0xFFFFFFFF else hpv_encoded
            hpd = b[p:p+SHA256_SIZE]; p += SHA256_SIZE
            sig = b[p:p+ED25519_SIG_SIZE]; p += ED25519_SIG_SIZE
            if len(sig) != ED25519_SIG_SIZE:
                raise ViewChangeError("TC signer sig truncated")
            signers.append(TimeoutCertificateSigner(vid, hpv, hpd, sig))
    except (struct.error, IndexError) as e:
        raise ViewChangeError(f"TC deserialize error: {e}")
    if p != len(b):
        raise ViewChangeError(f"TC trailing bytes: parsed {p}, total {len(b)}")
    tc = TimeoutCertificate(version, chain_id, round_number, timed_out_view,
                              target_view, ctx_hash, tuple(signers))
    serialize_timeout_certificate(tc)
    return tc


def verify_timeout_certificate(tc: TimeoutCertificate,
                                 snapshot_pubkeys: dict,
                                 quorum: int) -> Tuple[bool, str]:
    """Verify a TC against a validator_id -> pk_bytes mapping."""
    if tc.version != TC_VERSION:
        return False, f"unsupported TC version {tc.version}"
    if tc.target_view != tc.timed_out_view + 1:
        return False, "TC target_view must be timed_out_view + 1"
    ids = [s.validator_id for s in tc.signers]
    if ids != sorted(ids):
        return False, "TC signers not in canonical order"
    if len(set(ids)) != len(ids):
        return False, "TC duplicate signers"
    for sid in ids:
        if sid not in snapshot_pubkeys:
            return False, f"TC unknown signer {sid}"
    for s in tc.signers:
        payload = timeout_vote_payload(
            tc.chain_id, tc.round_number, tc.timed_out_view, tc.target_view,
            tc.round_context_hash, s.validator_id,
            s.highest_prepared_view, s.highest_prepared_digest,
        )
        try:
            Ed25519PublicKey.from_public_bytes(snapshot_pubkeys[s.validator_id]).verify(
                s.signature, payload)
        except InvalidSignature:
            return False, f"TC signer {s.validator_id}: signature invalid"
        except Exception as ex:
            return False, f"TC signer {s.validator_id}: parse error: {ex}"
    if len(tc.signers) < quorum:
        return False, f"TC quorum not met: {len(tc.signers)} < {quorum}"
    return True, "OK"


def build_timeout_certificate(votes: List[TimeoutVote]) -> TimeoutCertificate:
    if not votes:
        raise ViewChangeError("no timeout votes")
    first = votes[0]
    for v in votes[1:]:
        if (v.chain_id, v.round_number, v.timed_out_view, v.target_view,
            v.round_context_hash) != (first.chain_id, first.round_number,
                                        first.timed_out_view, first.target_view,
                                        first.round_context_hash):
            raise ViewChangeError("timeout votes disagree on core fields")
    seen = set()
    signers = []
    for v in votes:
        if v.validator_id in seen:
            raise ViewChangeError(f"duplicate signer {v.validator_id}")
        seen.add(v.validator_id)
        signers.append(TimeoutCertificateSigner(
            v.validator_id, v.highest_prepared_view,
            v.highest_prepared_digest, v.signature))
    signers.sort(key=lambda s: s.validator_id)
    return TimeoutCertificate(TC_VERSION, first.chain_id, first.round_number,
                                 first.timed_out_view, first.target_view,
                                 first.round_context_hash, tuple(signers))


def highest_prepared_from_tc(tc: TimeoutCertificate) -> Tuple[int, bytes]:
    """
    Extract the highest (view, digest) reported across the TC signers.
    Returns (-1, NO_PREPARED_DIGEST) if no signer reported a prepared value.
    Ties on view broken by lexicographic order of the digest (deterministic).
    """
    best_v, best_d = NO_PREPARED_VIEW, NO_PREPARED_DIGEST
    for s in tc.signers:
        if s.highest_prepared_view > best_v:
            best_v, best_d = s.highest_prepared_view, s.highest_prepared_digest
        elif s.highest_prepared_view == best_v and s.highest_prepared_view >= 0:
            if s.highest_prepared_digest > best_d:
                best_d = s.highest_prepared_digest
    return best_v, best_d


# ══════════════════════════════════════════════════════════
#  TIMEOUT BACKOFF SCHEDULE
# ══════════════════════════════════════════════════════════

def timeout_for_view(view: int, base_ms: int = 250, cap_ms: int = 60_000) -> int:
    """
    Exponential backoff: τ(v) = min(base_ms · 2^v, cap_ms).

    Monotonic. Guarantees that once GST is reached and honest-to-honest
    delay is bounded by Δ, τ(v) eventually exceeds Δ for a sufficiently
    large v — a necessary precondition for post-GST liveness. The cap
    ensures τ does not grow unboundedly across long faulty phases.
    """
    if view < 0:
        raise ValueError("view must be non-negative")
    return min(base_ms << view, cap_ms)


# ══════════════════════════════════════════════════════════
#  STAGE-5 FINALIZED-ROUND WRAPPER
# ══════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ViewChangeStep:
    """One step in a view-change chain — a TC that authorised entry into
    a specific view. Optionally carries a PC used for prepared-value
    carryover (highest prepared, per Stage 5 § 12)."""
    timeout_certificate: TimeoutCertificate
    highest_prepared_certificate: Optional[PrepareCertificate]


@dataclass(frozen=True)
class Stage5FinalizedRound:
    """
    Wraps a Stage-3 CompleteWitness together with the sequence of view
    changes (if any) that authorised entry into the final view.

    - complete_witness_bytes: byte-exact frozen Stage-3 output
    - view_change_chain: len == final_view; entry k authorises view k+1
                          (from timed_out_view=k to target_view=k+1).
      For final_view=0 the chain is empty.
    """
    complete_witness_bytes: bytes
    view_change_chain: Tuple[ViewChangeStep, ...]
