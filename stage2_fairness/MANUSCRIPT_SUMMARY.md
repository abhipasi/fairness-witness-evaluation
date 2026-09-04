# Stage 2 — Manuscript Summary

**Manuscript section:** Fairness Evaluation
**Status:** 🟢 Complete and independently verified
**Run date:** 2026-09-01

## Result Table

| Metric | Value |
|---|---|
| Stake configuration | 6 validators × stake=500 ("large") + 42 validators × stake=100 ("regular"); 5:1 ratio |
| Measured rounds | 500 / 500 finalized (100%) |
| Conflicting FCs | 0 |
| Invalid votes admitted (PC/TC/CC/FC) | 0/0/0/0 |
| TC signatures checked / valid | 1,408 / 1,408 |
| Validators reachable as leader | 48 / 48 |
| Observed large:regular selection ratio | 4.00 (expected 5.00) |
| **Chi-square statistic (df=47)** | **43.560** |
| **P-value** | **0.6158** |

## Ready Narrative Text

> To evaluate fairness under non-uniform stake distributions, the deployment's default
> equal-stake configuration was replaced with a deliberately weighted distribution: six
> validators (one per region) were assigned five times the stake of the remaining
> forty-two, and a 500-round, fault-free campaign was executed on the full 5-region,
> 48-validator AWS deployment. All 500 rounds finalized with zero safety violations. A
> chi-square goodness-of-fit test comparing each validator's observed leader-selection
> frequency against its stake-proportional expected frequency yielded χ² = 43.56 (df=47,
> p = 0.616), failing to reject the null hypothesis that selection follows the
> configured stake weighting. All 48 validators were selected as leader at least once,
> with the high-stake validators selected roughly four times as often as low-stake
> validators (expected: five times), consistent with fair, stake-proportional leader
> election under real, geographically-distributed network conditions.

## Caveats
The leader-selection sample (495 of 500 measured rounds) is drawn from the master
node's own log, which — consistent with a pattern observed throughout this evaluation
— can slightly undercount due to the master's log finalizing before it receives every
peer's last confirmation at campaign shutdown. This affects sample size by under 1% and
does not meaningfully change the statistical conclusion.

The chosen 5:1 stake ratio and 6-large/42-regular split, while realistic, are one
specific configuration; this result demonstrates fairness holds under this
configuration, not an exhaustive sweep of possible stake distributions.

## Provenance
- Modified daemon: `code/stage9_node_daemon_v2_weighted.py` — a minimal, additive,
  backward-compatible patch (new opt-in `--stake-mode weighted` flag; default behaviour
  unchanged) applied to the same daemon validated in Stages 0-1
  (base SHA-256: `27b24003e34150909f5ecc8c1838fc1bcdbb671be41046d20d33b2508adcb2a3`)
- Leader selection code (unmodified from Stage 1): `code/leader_selection.py`
- Full statistical output: `analysis/fairness_analysis_output.txt`
- Raw data: `data/events_<region>.jsonl` (7 files)
- Campaign ID: `STAGE2_FAIRNESS_RUN3` (the third orchestration attempt; the first two
  failed due to tooling bugs unrelated to the protocol — see README.md for the full
  honest account)
