"""Full-node view-0 verification against caller-authenticated context.

Wire format remains the preserved V1 encoding. This wrapper does not authenticate
the supplied snapshot/context, implement recovery, or change consensus messages.
"""
from dataclasses import dataclass
import hashlib,struct
from fairness_witness import deserialize_complete_witness,serialize_complete_witness,verify_complete_witness,WitnessError
from production_vdf import ResearchWesolowskiVDF,VDFError

@dataclass(frozen=True)
class TrustedContext:
    chain_id: bytes
    round_number: int
    prev_vdf_output: bytes
    commitment_root: bytes
    difficulty_T: int
    modulus_hash_sha256: str
    fault_bound: int
    protocol_version: int = 1

def verify_bytes(data: bytes, snapshot, vdf, context: TrustedContext):
    """Return (accepted, reason). Never derive trust inputs from witness bytes.

    Count-based quorum q=floor((n+f)/2)+1; valid only for n>3f and a trusted
    unique-key committee. Stake controls leadership, not this voting threshold.
    View>0 is rejected until the recovery certificate chain is implemented.
    """
    try:
        if not isinstance(data,bytes) or not 0<len(data)<=1_048_576:
            return False,'invalid witness byte type or length'
        if type(vdf) is not ResearchWesolowskiVDF:
            return False,'unsupported VDF implementation'
        if type(context.fault_bound) is not int or not 0<=3*context.fault_bound<snapshot.n:
            return False,'invalid committee fault bound'
        if context.protocol_version!=1 or not isinstance(context.chain_id,bytes) or not 0<len(context.chain_id)<=65535:
            return False,'unsupported protocol context'
        if type(context.round_number) is not int or not 0<=context.round_number<=0xffffffff:
            return False,'invalid round context'
        if len(context.prev_vdf_output)!=32 or len(context.commitment_root)!=32:
            return False,'invalid context hash width'
        vdf._validate_T(context.difficulty_T)
        if type(context.difficulty_T) is not int:return False,'invalid difficulty type'
        if vdf.N.bit_length()!=2048 or vdf.N_byte_size!=256:
            return False,'unsupported modulus width'
        modulus_hash=hashlib.sha256(b'RSA_MODULUS_V1'+vdf.N.to_bytes(256,'big')).hexdigest()
        if modulus_hash!=context.modulus_hash_sha256 or vdf.params_hash!=modulus_hash:
            return False,'VDF parameters do not match trusted context'
        keys=[snapshot.validator(i)['public_key'] for i in range(snapshot.n)]
        if len(set(keys))!=snapshot.n:return False,'committee contains duplicate public keys'
        cw=deserialize_complete_witness(data);lw=cw.leader_witness
        if serialize_complete_witness(cw)!=data:return False,'noncanonical encoding'
        if lw.view_number!=0 or cw.finality_certificate.view_number!=0:
            return False,'recovery-view witness not supported by this verifier'
        for field in ('protocol_version','chain_id','round_number','prev_vdf_output','commitment_root'):
            if getattr(lw,field)!=getattr(context,field):return False,f'{field} differs from trusted context'
        quorum=(snapshot.n+context.fault_bound)//2+1
        if not quorum<=len(cw.finality_certificate.signers)<=snapshot.n:
            return False,'certificate signer count outside trusted quorum/committee bounds'
        return verify_complete_witness(cw,snapshot,vdf,quorum,context.difficulty_T)
    except (WitnessError,VDFError,ValueError,TypeError,OverflowError,struct.error,KeyError,IndexError) as exc:
        return False,f'malformed witness or context: {type(exc).__name__}'
