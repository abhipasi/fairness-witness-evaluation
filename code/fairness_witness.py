#!/usr/bin/env python3
"""
FAIRNESS WITNESS — Stage 3 Canonical Serialization + Complete Witness
======================================================================
Two explicit witness types:

  LeaderOnlyWitness      Pre-finality leader/proposal evidence.
                         Includes VDF output, Wesolowski proof, selected
                         leader identity, interval bounds, proposal digest,
                         and the leader's proposal signature.

  CompleteWitness        LeaderOnlyWitness + FinalityCertificate.
                         Adds Ed25519 vote signatures from >= quorum
                         validators, proving BFT finality.

Canonical binary serialisation. No JSON, no pickle. Big-endian throughout.
Round-trip guarantee: serialize(deserialize(b)) == b for every valid b.

CONSTRAINTS honoured (Stage 3 rules § 24):
  - production_vdf.py            NOT modified
  - vdf_public_params.json       NOT modified
  - leader_selection.py          NOT modified
  - tests/test_stake_selection.py NOT modified

Dependencies:
  - Python >= 3.10
  - cryptography (for Ed25519 signatures)
  - production_vdf.ResearchWesolowskiVDF (Stage 1)
  - leader_selection.StakeSnapshot, select_leader (Stage 2)
"""

import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Tuple, Optional

from production_vdf import ResearchWesolowskiVDF
from leader_selection import StakeSnapshot, select_leader, DEFAULT_MODE


# ══════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════

WITNESS_VERSION = 1
PROPOSAL_DIGEST_DOMAIN = b"FW_PROPOSAL_DIGEST_V1"

# Fixed field sizes for Stage-3 witness serialisation
ED25519_PUBKEY_SIZE   = 32
ED25519_SIG_SIZE      = 64
SHA256_SIZE           = 32
RSA2048_ELEMENT_SIZE  = 256   # both y and pi

# For each field family, format uses big-endian fixed integers plus
# length-prefixed variable bytes only where the field is genuinely
# variable-length (chain_id, VDF output, VDF proof).


# ══════════════════════════════════════════════════════════
#  EXCEPTIONS
# ══════════════════════════════════════════════════════════

class WitnessError(Exception):
    """Raised for any witness serialisation or verification failure."""
    pass


# ══════════════════════════════════════════════════════════
#  DATACLASSES
# ══════════════════════════════════════════════════════════

@dataclass(frozen=True)
class LeaderOnlyWitness:
    witness_version: int
    protocol_version: int
    chain_id: bytes
    round_number: int
    view_number: int
    prev_vdf_output: bytes         # SHA-256 digest, 32 B
    commitment_root: bytes         # CBRC root, 32 B
    snapshot_commitment: bytes     # StakeSnapshot commitment, 32 B
    total_stake: int
    vdf_output_y: bytes            # RSA-2048 element, 256 B
    vdf_proof_pi: bytes            # RSA-2048 element, 256 B
    leader_id: int
    leader_pubkey: bytes           # Ed25519, 32 B
    leader_stake: int
    leader_interval_start: int
    leader_interval_end: int
    proposal_digest: bytes         # SHA-256, 32 B
    proposal_signature: bytes      # Ed25519, 64 B


@dataclass(frozen=True)
class QCSigner:
    validator_id: int
    signature: bytes               # Ed25519, 64 B


@dataclass(frozen=True)
class FinalityCertificate:
    proposal_digest: bytes         # SHA-256, 32 B — MUST match witness
    round_number: int
    view_number: int
    signers: Tuple[QCSigner, ...]  # canonical ascending validator_id


@dataclass(frozen=True)
class CompleteWitness:
    leader_witness: LeaderOnlyWitness
    finality_certificate: FinalityCertificate


# ══════════════════════════════════════════════════════════
#  PROPOSAL DIGEST
# ══════════════════════════════════════════════════════════

def compute_proposal_digest(chain_id: bytes,
                            round_number: int,
                            view_number: int,
                            commitment_root: bytes,
                            snapshot_commitment: bytes,
                            vdf_output_y: bytes,
                            leader_id: int) -> bytes:
    """
    Canonical proposal digest binding the fields the leader is signing.
    Domain-separated, length-prefixed for variable-length fields.

    Format:
        DOMAIN | u16 len(chain_id) | chain_id | u32 round | u32 view
        | u16 len(commitment_root) | commitment_root
        | u16 len(snapshot_commitment) | snapshot_commitment
        | u16 len(vdf_output_y) | vdf_output_y
        | u32 leader_id
    """
    h = hashlib.sha256()
    h.update(PROPOSAL_DIGEST_DOMAIN)
    h.update(struct.pack(">H", len(chain_id))); h.update(chain_id)
    h.update(struct.pack(">I", round_number))
    h.update(struct.pack(">I", view_number))
    h.update(struct.pack(">H", len(commitment_root))); h.update(commitment_root)
    h.update(struct.pack(">H", len(snapshot_commitment))); h.update(snapshot_commitment)
    h.update(struct.pack(">H", len(vdf_output_y))); h.update(vdf_output_y)
    h.update(struct.pack(">I", leader_id))
    return h.digest()


# ══════════════════════════════════════════════════════════
#  BINARY SERIALISATION — LEADER-ONLY WITNESS
# ══════════════════════════════════════════════════════════

def _write_fixed(buf: bytearray, name: str, data: bytes, expected: int):
    """Write fixed-size field or raise WitnessError."""
    if len(data) != expected:
        raise WitnessError(f"{name}: expected {expected} bytes, got {len(data)}")
    buf.extend(data)


def _write_lp16(buf: bytearray, name: str, data: bytes):
    """Write uint16-length-prefixed variable field."""
    if len(data) > 0xFFFF:
        raise WitnessError(f"{name}: too long ({len(data)} bytes)")
    buf.extend(struct.pack(">H", len(data)))
    buf.extend(data)


def serialize_leader_witness(w: LeaderOnlyWitness) -> bytes:
    """
    Deterministic canonical binary encoding.

    Field order and widths:
        u8   witness_version
        u8   protocol_version
        u16 + var    chain_id
        u32  round_number
        u32  view_number
        32B  prev_vdf_output
        32B  commitment_root
        32B  snapshot_commitment
        u64  total_stake
        u16 + var    vdf_output_y     (256 B for RSA-2048)
        u16 + var    vdf_proof_pi     (256 B for RSA-2048)
        u32  leader_id
        32B  leader_pubkey            (Ed25519)
        u64  leader_stake
        u64  leader_interval_start
        u64  leader_interval_end
        32B  proposal_digest
        64B  proposal_signature       (Ed25519)
    """
    if not (0 <= w.witness_version <= 0xFF):
        raise WitnessError(f"witness_version out of range: {w.witness_version}")
    if not (0 <= w.protocol_version <= 0xFF):
        raise WitnessError(f"protocol_version out of range: {w.protocol_version}")

    buf = bytearray()
    buf.append(w.witness_version)
    buf.append(w.protocol_version)
    _write_lp16(buf, "chain_id", w.chain_id)
    buf.extend(struct.pack(">II", w.round_number, w.view_number))
    _write_fixed(buf, "prev_vdf_output", w.prev_vdf_output, SHA256_SIZE)
    _write_fixed(buf, "commitment_root", w.commitment_root, SHA256_SIZE)
    _write_fixed(buf, "snapshot_commitment", w.snapshot_commitment, SHA256_SIZE)
    buf.extend(struct.pack(">Q", w.total_stake))
    _write_lp16(buf, "vdf_output_y", w.vdf_output_y)
    _write_lp16(buf, "vdf_proof_pi", w.vdf_proof_pi)
    buf.extend(struct.pack(">I", w.leader_id))
    _write_fixed(buf, "leader_pubkey", w.leader_pubkey, ED25519_PUBKEY_SIZE)
    buf.extend(struct.pack(">QQQ", w.leader_stake,
                           w.leader_interval_start, w.leader_interval_end))
    _write_fixed(buf, "proposal_digest", w.proposal_digest, SHA256_SIZE)
    _write_fixed(buf, "proposal_signature", w.proposal_signature, ED25519_SIG_SIZE)
    return bytes(buf)


def deserialize_leader_witness(b: bytes) -> LeaderOnlyWitness:
    """Round-trip inverse of serialize_leader_witness. Rejects malformed input."""
    if not isinstance(b, (bytes, bytearray)):
        raise WitnessError("input must be bytes")
    p = 0
    try:
        witness_version = b[p]; p += 1
        if witness_version != WITNESS_VERSION:
            raise WitnessError(f"unsupported witness_version: {witness_version}")
        protocol_version = b[p]; p += 1

        (cid_len,) = struct.unpack(">H", b[p:p+2]); p += 2
        chain_id = bytes(b[p:p+cid_len]); p += cid_len
        if len(chain_id) != cid_len:
            raise WitnessError("chain_id truncated")

        round_number, view_number = struct.unpack(">II", b[p:p+8]); p += 8
        prev_vdf_output = bytes(b[p:p+SHA256_SIZE]); p += SHA256_SIZE
        commitment_root = bytes(b[p:p+SHA256_SIZE]); p += SHA256_SIZE
        snapshot_commitment = bytes(b[p:p+SHA256_SIZE]); p += SHA256_SIZE
        (total_stake,) = struct.unpack(">Q", b[p:p+8]); p += 8

        (y_len,) = struct.unpack(">H", b[p:p+2]); p += 2
        vdf_output_y = bytes(b[p:p+y_len]); p += y_len
        if len(vdf_output_y) != y_len:
            raise WitnessError("vdf_output_y truncated")

        (pi_len,) = struct.unpack(">H", b[p:p+2]); p += 2
        vdf_proof_pi = bytes(b[p:p+pi_len]); p += pi_len
        if len(vdf_proof_pi) != pi_len:
            raise WitnessError("vdf_proof_pi truncated")

        (leader_id,) = struct.unpack(">I", b[p:p+4]); p += 4
        leader_pubkey = bytes(b[p:p+ED25519_PUBKEY_SIZE]); p += ED25519_PUBKEY_SIZE
        leader_stake, leader_interval_start, leader_interval_end = \
            struct.unpack(">QQQ", b[p:p+24]); p += 24
        proposal_digest = bytes(b[p:p+SHA256_SIZE]); p += SHA256_SIZE
        proposal_signature = bytes(b[p:p+ED25519_SIG_SIZE]); p += ED25519_SIG_SIZE
    except (struct.error, IndexError) as e:
        raise WitnessError(f"deserialize error: {e}")

    if p != len(b):
        raise WitnessError(f"trailing bytes: parsed {p}, total {len(b)}")

    # Sanity: fixed sizes actually read the expected bytes
    if any(len(x) != expected for x, expected in [
        (prev_vdf_output, SHA256_SIZE),
        (commitment_root, SHA256_SIZE),
        (snapshot_commitment, SHA256_SIZE),
        (leader_pubkey, ED25519_PUBKEY_SIZE),
        (proposal_digest, SHA256_SIZE),
        (proposal_signature, ED25519_SIG_SIZE),
    ]):
        raise WitnessError("fixed-length field truncated")

    return LeaderOnlyWitness(
        witness_version=witness_version,
        protocol_version=protocol_version,
        chain_id=chain_id,
        round_number=round_number, view_number=view_number,
        prev_vdf_output=prev_vdf_output,
        commitment_root=commitment_root,
        snapshot_commitment=snapshot_commitment,
        total_stake=total_stake,
        vdf_output_y=vdf_output_y, vdf_proof_pi=vdf_proof_pi,
        leader_id=leader_id, leader_pubkey=leader_pubkey,
        leader_stake=leader_stake,
        leader_interval_start=leader_interval_start,
        leader_interval_end=leader_interval_end,
        proposal_digest=proposal_digest,
        proposal_signature=proposal_signature,
    )


# ══════════════════════════════════════════════════════════
#  BINARY SERIALISATION — FINALITY CERTIFICATE
# ══════════════════════════════════════════════════════════

def serialize_finality_certificate(fc: FinalityCertificate) -> bytes:
    """
    Format:
        32B  proposal_digest
        u32  round_number
        u32  view_number
        u16  signer_count
        signer_count × (u32 validator_id, 64B signature)
    Signers MUST already be in canonical order (validator_id ascending).
    """
    _write_fixed(bytearray(), "proposal_digest", fc.proposal_digest, SHA256_SIZE)

    # Enforce canonical order + uniqueness before serialising
    ids = [s.validator_id for s in fc.signers]
    if ids != sorted(ids):
        raise WitnessError("signers not in canonical order (validator_id ascending)")
    if len(set(ids)) != len(ids):
        raise WitnessError("duplicate signer validator_id in certificate")
    if len(fc.signers) > 0xFFFF:
        raise WitnessError(f"too many signers: {len(fc.signers)}")

    buf = bytearray()
    buf.extend(fc.proposal_digest)
    buf.extend(struct.pack(">II", fc.round_number, fc.view_number))
    buf.extend(struct.pack(">H", len(fc.signers)))
    for s in fc.signers:
        if len(s.signature) != ED25519_SIG_SIZE:
            raise WitnessError(f"signer {s.validator_id}: signature size")
        buf.extend(struct.pack(">I", s.validator_id))
        buf.extend(s.signature)
    return bytes(buf)


def deserialize_finality_certificate(b: bytes) -> FinalityCertificate:
    if not isinstance(b, (bytes, bytearray)):
        raise WitnessError("input must be bytes")
    p = 0
    try:
        proposal_digest = bytes(b[p:p+SHA256_SIZE]); p += SHA256_SIZE
        if len(proposal_digest) != SHA256_SIZE:
            raise WitnessError("proposal_digest truncated")
        round_number, view_number = struct.unpack(">II", b[p:p+8]); p += 8
        (signer_count,) = struct.unpack(">H", b[p:p+2]); p += 2

        signers = []
        for _ in range(signer_count):
            (vid,) = struct.unpack(">I", b[p:p+4]); p += 4
            sig = bytes(b[p:p+ED25519_SIG_SIZE]); p += ED25519_SIG_SIZE
            if len(sig) != ED25519_SIG_SIZE:
                raise WitnessError("signature truncated")
            signers.append(QCSigner(vid, sig))
    except (struct.error, IndexError) as e:
        raise WitnessError(f"deserialize FC error: {e}")

    if p != len(b):
        raise WitnessError(f"FC trailing bytes: parsed {p}, total {len(b)}")

    # Canonical order + uniqueness after deserialise
    ids = [s.validator_id for s in signers]
    if ids != sorted(ids):
        raise WitnessError("signers not in canonical order")
    if len(set(ids)) != len(ids):
        raise WitnessError("duplicate signer in certificate")

    return FinalityCertificate(
        proposal_digest=proposal_digest,
        round_number=round_number, view_number=view_number,
        signers=tuple(signers),
    )


# ══════════════════════════════════════════════════════════
#  BINARY SERIALISATION — COMPLETE WITNESS
# ══════════════════════════════════════════════════════════

def serialize_complete_witness(cw: CompleteWitness) -> bytes:
    """
    Format:
        u32 len(leader_bytes) | leader_bytes | u32 len(fc_bytes) | fc_bytes
    """
    lb = serialize_leader_witness(cw.leader_witness)
    fb = serialize_finality_certificate(cw.finality_certificate)
    return struct.pack(">I", len(lb)) + lb + struct.pack(">I", len(fb)) + fb


def deserialize_complete_witness(b: bytes) -> CompleteWitness:
    if not isinstance(b, (bytes, bytearray)):
        raise WitnessError("input must be bytes")
    p = 0
    try:
        (lb_len,) = struct.unpack(">I", b[p:p+4]); p += 4
        lb = bytes(b[p:p+lb_len]); p += lb_len
        if len(lb) != lb_len:
            raise WitnessError("leader witness section truncated")
        (fb_len,) = struct.unpack(">I", b[p:p+4]); p += 4
        fb = bytes(b[p:p+fb_len]); p += fb_len
        if len(fb) != fb_len:
            raise WitnessError("finality certificate section truncated")
    except (struct.error, IndexError) as e:
        raise WitnessError(f"deserialize CW error: {e}")

    if p != len(b):
        raise WitnessError(f"CW trailing bytes: parsed {p}, total {len(b)}")

    lw = deserialize_leader_witness(lb)
    fc = deserialize_finality_certificate(fb)
    return CompleteWitness(leader_witness=lw, finality_certificate=fc)


# ══════════════════════════════════════════════════════════
#  FULL-NODE VERIFIER
# ══════════════════════════════════════════════════════════

def verify_complete_witness(cw: CompleteWitness,
                            snapshot: StakeSnapshot,
                            vdf: ResearchWesolowskiVDF,
                            quorum: int,
                            T: int = 1000) -> Tuple[bool, str]:
    """
    Full-node verification. Assumes access to an authenticated StakeSnapshot
    (Stage-4 will handle light-client stake-authentication separately).

    Returns (True, "OK") or (False, reason_string).
    Runs all 18 checks specified in the Stage 3 § 9 acceptance criteria.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    lw = cw.leader_witness
    fc = cw.finality_certificate

    # 1. supported version
    if lw.witness_version != WITNESS_VERSION:
        return False, f"unsupported witness_version {lw.witness_version}"

    # 2. round / view consistency between leader witness and FC
    if fc.round_number != lw.round_number:
        return False, "FC round does not match leader witness round"
    if fc.view_number != lw.view_number:
        return False, "FC view does not match leader witness view"

    # 3. snapshot_commitment equals supplied authenticated snapshot
    if lw.snapshot_commitment != snapshot.commitment:
        return False, "snapshot_commitment does not match authenticated snapshot"

    # 4. total_stake matches snapshot
    if lw.total_stake != snapshot.total_stake:
        return False, "total_stake mismatch"

    # 5. production Wesolowski proof verifies
    valid, _ = vdf.verify_protocol(
        lw.protocol_version, lw.chain_id, lw.round_number,
        lw.prev_vdf_output, lw.commitment_root, T,
        lw.vdf_output_y, lw.vdf_proof_pi,
    )
    if not valid:
        return False, "Wesolowski VDF proof failed"

    # 6. Stage-2 selector re-runs to the same leader
    recomputed = select_leader(
        snapshot=snapshot,
        chain_id=lw.chain_id,
        round_number=lw.round_number,
        view_number=lw.view_number,
        vdf_output=lw.vdf_output_y,
        commitment_root=lw.commitment_root,
        mode=DEFAULT_MODE,
    )
    if recomputed["leader_index"] != _snapshot_index_of(snapshot, lw.leader_id):
        return False, "recomputed leader does not match witness leader"

    # 7. leader identity fields match snapshot
    idx = _snapshot_index_of(snapshot, lw.leader_id)
    v = snapshot.validator(idx)
    if v["stake"] != lw.leader_stake:
        return False, "leader_stake mismatch with snapshot"
    if v["public_key"] != lw.leader_pubkey:
        return False, "leader_pubkey mismatch with snapshot"
    s, e = snapshot.interval(idx)
    if (s, e) != (lw.leader_interval_start, lw.leader_interval_end):
        return False, "leader interval mismatch with snapshot"

    # 8. proposal digest recomputes
    expected_digest = compute_proposal_digest(
        lw.chain_id, lw.round_number, lw.view_number,
        lw.commitment_root, lw.snapshot_commitment,
        lw.vdf_output_y, lw.leader_id,
    )
    if expected_digest != lw.proposal_digest:
        return False, "proposal_digest recomputation mismatch"

    # 9. proposal signature verifies
    try:
        Ed25519PublicKey.from_public_bytes(lw.leader_pubkey).verify(
            lw.proposal_signature, lw.proposal_digest
        )
    except InvalidSignature:
        return False, "proposal_signature invalid"
    except Exception as ex:
        return False, f"proposal_signature parse error: {ex}"

    # 10. FC references the same proposal digest
    if fc.proposal_digest != lw.proposal_digest:
        return False, "FC proposal_digest does not match leader witness"

    # 11. signer IDs unique, sorted, known
    signer_ids = [s.validator_id for s in fc.signers]
    if signer_ids != sorted(signer_ids):
        return False, "FC signers not in canonical order"
    if len(set(signer_ids)) != len(signer_ids):
        return False, "FC contains duplicate signers"
    known_ids = {snapshot.validator(i)["validator_id"] for i in range(snapshot.n)}
    for sid in signer_ids:
        if sid not in known_ids:
            return False, f"FC contains unknown signer: {sid}"

    # 12. every QC signature verifies
    for s in fc.signers:
        idx_s = _snapshot_index_of(snapshot, s.validator_id)
        pk = snapshot.validator(idx_s)["public_key"]
        try:
            Ed25519PublicKey.from_public_bytes(pk).verify(s.signature, fc.proposal_digest)
        except InvalidSignature:
            return False, f"signer {s.validator_id}: signature invalid"
        except Exception as ex:
            return False, f"signer {s.validator_id}: signature parse error: {ex}"

    # 13. signer count >= quorum
    if len(fc.signers) < quorum:
        return False, f"quorum not met: {len(fc.signers)} < {quorum}"

    return True, "OK"


def _snapshot_index_of(snapshot: StakeSnapshot, validator_id: int) -> int:
    """Locate a validator by validator_id in the snapshot; -1 if absent."""
    for i in range(snapshot.n):
        if snapshot.validator(i)["validator_id"] == validator_id:
            return i
    raise WitnessError(f"validator_id {validator_id} not in snapshot")
