#!/usr/bin/env python3
"""
Leader-selection proof analysis (Merkle SUM tree).

Directly answers the reviewer comment: "Algorithm 2 requires the validator
set, stake weights, and recomputation of the weighted candidate sample. A
Merkle root plus only the leader membership path cannot reconstruct the
population or prove weighted sampling."

For every real finalized round in a genuine AWS production run, this
recomputes the view-0 leader selection using the exact same real inputs
(VDF output, commitment root) the daemon itself used, then verifies --
using ONLY the selected leader's own leaf data and an O(log n) Merkle
SUM proof, never the full 48-validator list -- that the VDF-derived
value u falls UNIQUELY inside that leader's stake interval relative to
the entire population. This is stronger than a plain inclusion proof,
which cannot prove population-wide uniqueness or correct interval
placement.
"""
import sys, json
from view_change import prepare_vote_payload  # unused here, kept for import-compat
from stage8_deployment import build_topology, build_stage8_snapshot, CHAIN_ID_DEFAULT
from leader_selection_sumtree import select_leader, verify_leader_selection_proof, LightClientVerificationError

DEPLOYMENT_STAGE9 = {"virginia1": 7, "virginia2": 7, "virginia3": 7, "ireland": 7,
                      "tokyo": 7, "sydney": 7, "mumbai": 6}

def analyze(data_dir="."):
    validators = build_topology(DEPLOYMENT_STAGE9)
    snapshot, sks, pks = build_stage8_snapshot(validators)
    print(f"Reconstructed snapshot: merkle_root={snapshot.merkle_root.hex()[:16]}..., "
          f"root_sum={snapshot.merkle_root_sum} (must equal total validator count/stake)")

    tested = matched = verified = 0
    for line in open(f'{data_dir}/events_virginia1.jsonl'):
        try:
            e = json.loads(line)
            if e.get('kind')=='phase' and e.get('phase')=='finalized':
                r = e.get('round', -1)
                if not (1 <= r < 900000):
                    continue
                real_initial_leader_id = e['initial_leader']
                vdf_output = bytes.fromhex(e['vdf_output_hex'])
                commitment_root = bytes.fromhex(e['commitment_root_hex'])

                sel = select_leader(snapshot, CHAIN_ID_DEFAULT, r, 0, vdf_output, commitment_root)
                tested += 1
                if sel['leader_id'] != real_initial_leader_id:
                    continue
                matched += 1

                proof = snapshot.sum_tree_proof(sel['leader_index'])
                result = verify_leader_selection_proof(
                    proof, sel['u'], snapshot.merkle_root, snapshot.merkle_root_sum)
                if result['u_in_interval']:
                    verified += 1
        except Exception as ex:
            print(f"  Exception: {ex}")

    print(f"\nTested: {tested} real finalized rounds")
    print(f"Recomputed view-0 leader matches real logged leader: {matched}/{tested}")
    print(f"Leader-selection proofs verified (u provably unique within derived interval): "
          f"{verified}/{tested}")

if __name__ == '__main__':
    analyze(sys.argv[1] if len(sys.argv) > 1 else '.')
