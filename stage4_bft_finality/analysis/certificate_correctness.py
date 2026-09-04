#!/usr/bin/env python3
"""BFT finality (PC/FC certificate formation) correctness analysis across S0-S7.
Point SCENARIO_PATHS at the raw event logs from each scenario's own data directory
(see the corresponding stages/campaign archives in this repository)."""
import json

SCENARIO_PATHS = {
    'S0': '../stage0_baseline/data/events_virginia1.jsonl',
    'S1': '../stage1_vdf/../TODO_point_to_S1_data/events_virginia1.jsonl',
    'S2': '../stage3_byzantine_security/data/S2/events_virginia1.jsonl',
    'S3': '../stage3_byzantine_security/data/S3/events_virginia1.jsonl',
    # S4-S7: point at corresponding campaign data locations
}

def analyze():
    totals = {'pc_formed':0, 'fc_formed':0, 'pc_bad':0, 'fc_bad':0}
    print(f"{'Sc':>4} {'PC_formed':>10} {'PC_min':>7} {'PC_max':>7} {'FC_formed':>10} {'FC_min':>7} {'FC_max':>7}")
    for sid, path in SCENARIO_PATHS.items():
        try:
            f = open(path)
        except FileNotFoundError:
            continue
        pc_signers, fc_signers = [], []
        for line in f:
            try:
                e = json.loads(line)
                if e.get('kind')=='phase' and e.get('phase')=='pc_formed':
                    pc_signers.append(e.get('n_signers', 0))
                if e.get('kind')=='phase' and e.get('phase')=='fc_formed':
                    fc_signers.append(e.get('n_signers', 0))
            except: pass
        if pc_signers or fc_signers:
            print(f"{sid:>4} {len(pc_signers):>10} {min(pc_signers) if pc_signers else 0:>7} "
                  f"{max(pc_signers) if pc_signers else 0:>7} {len(fc_signers):>10} "
                  f"{min(fc_signers) if fc_signers else 0:>7} {max(fc_signers) if fc_signers else 0:>7}")
            totals['pc_formed'] += len(pc_signers)
            totals['fc_formed'] += len(fc_signers)
            totals['pc_bad'] += sum(1 for x in pc_signers if x < 32)
            totals['fc_bad'] += sum(1 for x in fc_signers if x < 32)
    print()
    print(f"TOTALS: PC formed={totals['pc_formed']}, FC formed={totals['fc_formed']}")
    print(f"PC certificates with <32 signers (quorum violation, should be 0): {totals['pc_bad']}")
    print(f"FC certificates with <32 signers (quorum violation, should be 0): {totals['fc_bad']}")

if __name__ == '__main__':
    analyze()
