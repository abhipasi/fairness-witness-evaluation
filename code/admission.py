"""Receiver checks for the explicitly scoped view-zero experiment.

Context and committee are supplied by the experiment coordinator. This does
not authenticate a checkpoint, implement recovery, or assert BFT safety.
"""
import hashlib
import struct
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from fairness_witness import (
    WitnessError, deserialize_leader_witness, serialize_leader_witness,
    deserialize_complete_witness, serialize_complete_witness, CompleteWitness,
    deserialize_finality_certificate, compute_proposal_digest,
)
from leader_selection import select_leader, DEFAULT_MODE, LeaderSelectionError
from production_vdf import VDFError, ResearchWesolowskiVDF
from strict_witness import verify_bytes
from stage8v2_workload import batch_commitment_root, TXN_SIZE_BYTES
from view_change import (deserialize_prepare_certificate, serialize_prepare_certificate,
                         verify_prepare_certificate, compute_round_context_hash, ViewChangeError)


class AdmissionError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise AdmissionError(reason)


def check_context(snapshot, vdf, context):
    require(type(vdf) is ResearchWesolowskiVDF, 'unsupported VDF')
    require(type(context.fault_bound) is int and 0 <= 3*context.fault_bound < snapshot.n, 'fault bound')
    require(context.protocol_version == 1 and isinstance(context.chain_id, bytes), 'protocol context')
    require(type(context.round_number) is int and 0 <= context.round_number <= 0xffffffff, 'round context')
    require(len(context.prev_vdf_output) == len(context.commitment_root) == 32, 'context width')
    require(type(context.difficulty_T) is int, 'difficulty type')
    vdf._validate_T(context.difficulty_T)
    require(vdf.N.bit_length() == 2048 and vdf.N_byte_size == 256, 'modulus size')
    digest = hashlib.sha256(b'RSA_MODULUS_V1'+vdf.N.to_bytes(256,'big')).hexdigest()
    require(digest == context.modulus_hash_sha256 == vdf.params_hash, 'modulus binding')
    keys = [snapshot.validator(i)['public_key'] for i in range(snapshot.n)]
    require(len(set(keys)) == snapshot.n, 'duplicate committee keys')


def check_leader(raw, snapshot, vdf, context):
    check_context(snapshot, vdf, context)
    require(isinstance(raw, bytes) and 0 < len(raw) <= 65536, 'leader size')
    lw = deserialize_leader_witness(raw)
    require(serialize_leader_witness(lw) == raw, 'canonical leader encoding')
    require(lw.witness_version == 1 and lw.view_number == 0, 'unsupported witness or recovery view')
    for field in ('protocol_version','chain_id','round_number','prev_vdf_output','commitment_root'):
        require(getattr(lw, field) == getattr(context, field), 'context '+field)
    require(lw.snapshot_commitment == snapshot.commitment and lw.total_stake == snapshot.total_stake, 'stake snapshot')
    valid, _ = vdf.verify_protocol(lw.protocol_version,lw.chain_id,lw.round_number,
                                  lw.prev_vdf_output,lw.commitment_root,context.difficulty_T,
                                  lw.vdf_output_y,lw.vdf_proof_pi)
    require(valid, 'VDF proof')
    selection = select_leader(snapshot,lw.chain_id,lw.round_number,0,lw.vdf_output_y,lw.commitment_root,DEFAULT_MODE)
    idx = selection['leader_index']
    record = snapshot.validator(idx)
    require((lw.leader_id,lw.leader_pubkey,lw.leader_stake) ==
            (record['validator_id'],record['public_key'],record['stake']), 'selected leader')
    require((lw.leader_interval_start,lw.leader_interval_end) == snapshot.interval(idx), 'leader interval')
    require(lw.proposal_digest == compute_proposal_digest(lw.chain_id,lw.round_number,0,
            lw.commitment_root,lw.snapshot_commitment,lw.vdf_output_y,lw.leader_id), 'proposal digest')
    Ed25519PublicKey.from_public_bytes(lw.leader_pubkey).verify(lw.proposal_signature,lw.proposal_digest)
    return lw


def check_body(raw, count, expected_count, context):
    require(type(count) is int and count == expected_count and count >= 0, 'batch count')
    require(isinstance(raw, bytes) and len(raw) == count*TXN_SIZE_BYTES, 'batch wire size')
    if count:
        transactions = [raw[i:i+TXN_SIZE_BYTES] for i in range(0,len(raw),TXN_SIZE_BYTES)]
        require(batch_commitment_root(context.round_number,transactions) == context.commitment_root, 'batch commitment')
    return raw


def check_pc(raw, snapshot, context, lw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= 65536, 'PC size')
    pc = deserialize_prepare_certificate(raw)
    require(serialize_prepare_certificate(pc) == raw, 'canonical PC encoding')
    require((pc.chain_id,pc.round_number,pc.view_number,pc.proposal_digest) ==
            (context.chain_id,context.round_number,0,lw.proposal_digest), 'PC context')
    ctx = compute_round_context_hash(context.chain_id,context.round_number,lw.vdf_output_y,
                                     context.commitment_root,snapshot.commitment)
    require(pc.round_context_hash == ctx, 'PC round context')
    keys = {snapshot.validator(i)['validator_id']:snapshot.validator(i)['public_key'] for i in range(snapshot.n)}
    q = (snapshot.n+context.fault_bound)//2+1
    require(q <= len(pc.signers) <= snapshot.n, 'PC quorum bounds')
    ok, why = verify_prepare_certificate(pc,keys,q)
    require(ok, why)
    return pc


def check_fc(raw, leader_raw, snapshot, vdf, context):
    require(isinstance(raw, bytes) and 0 < len(raw) <= 65536, 'FC size')
    lw = deserialize_leader_witness(leader_raw)
    fc = deserialize_finality_certificate(raw)
    full = struct.pack('>I',len(leader_raw))+leader_raw+struct.pack('>I',len(raw))+raw
    ok, why = verify_bytes(full,snapshot,vdf,context)
    require(ok, why)
    return full


MALFORMED = (AdmissionError,WitnessError,VDFError,LeaderSelectionError,ViewChangeError,
             InvalidSignature,ValueError,TypeError,KeyError,IndexError,OverflowError,struct.error)
