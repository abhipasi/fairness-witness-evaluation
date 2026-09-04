# Stage 0 — Baseline Protocol Validation

## Objective
Establish clean-path (no injected faults) consensus behaviour across the real 5-region,
7-instance, 48-validator deployment, at production scale (200 measured rounds + 20 warmup),
using the Fairness Witness protocol at quorum q=32.

## Environment
- 5 AWS geographic regions: US East (Virginia ×3), Europe (Ireland), Asia (Tokyo), Oceania (Sydney), South Asia (Mumbai)
- 7 EC2 instances (c5.xlarge), 48 logical validators
- BFT quorum q=32 (general formula `q = floor((n+f)/2) + 1`, f = floor((n-1)/3))
- Daemon: `stage9_node_daemon_v2.py`, VDF-paced leader derivation (T_vdf=95000 iterations)
- Batch size: 100 transactions/round (production baseline)

## Method
The launcher (`stage9_launcher.py`, not included in this stage's minimal package — see
Stage 9 package for the full orchestration tooling) invokes the daemon identically on all
7 instances: 6 workers launched in parallel, then the master, per the campaign config's
`production` profile for scenario `S0` (`fault: none`, `byzantine_ids: []`).

Reproduction command (master node):
```
python3 stage9_node_daemon_v2.py --region virginia1 \
  --endpoints endpoints_daemon.json --deployment stage9 \
  --T-vdf 95000 --out-dir <out_dir> --scenario-id S0 \
  --fault-json '{"scenario_id":"S0","fault":"none","byzantine_ids":[]}' \
  --round-timeout-base-ms 4000 --master --cfg-name S0 \
  --rounds 200 --warmup-rounds 20 --inter-round-ms 4000 \
  --sync-after-ms 3000 --hold-seconds 30 --batch-size 100
```
(Identical command on the 6 worker nodes, omitting `--master` and the round/timing
arguments, which only the master supplies.)

## Analysis
Run the analyzer against the resulting 7-region event log directory:
```
python3 stage9_analyze.py --campaign-root <campaign_dir> --out-dir <analysis_out>
```
The analyzer independently re-validates every certificate at the byte level (not the
daemon's self-reported `pc_verified`/`fc_verified` flags), counting invalid votes toward
PC/TC/CC/FC and conflicting FCs from first principles.

## Results (verified 2026-09-01, run STAGE0_BASELINE_RUN1)

| Metric | Value |
|---|---|
| Attempted (measured rounds) | 200 |
| Finalized | 200 |
| Finalization rate | 100% |
| Conflicting FCs | 0 |
| Invalid votes counted in PC/TC/CC/FC | 0/0/0/0 |
| TC signatures checked / valid | 512 / 512 |
| Avg finality latency | 3,536 ms |
| Avg VDF time | 2,632 ms |

All 200 measured rounds finalized cleanly, confirmed network-wide (independently
cross-checked across all 7 regions' logs, not relying on any single node's count). See
`MANUSCRIPT_SUMMARY.md` for the manuscript-ready narrative and provenance.

## Data
Raw event logs for this run: `data/events_<region>.jsonl` (one per region, 7 total).

## Status
**COMPLETE.** This stage's evidence is finalized and independently verified.
