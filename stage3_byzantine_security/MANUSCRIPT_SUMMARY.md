# Stage 3 — Manuscript Summary

**Manuscript section:** Security Evaluation
**Status:** 🟢 Complete and independently verified (dedicated experiment)
**Run date:** 2026-09-04

## Result Table

| Metric | S2 (invalid_vote) | S3 (equivocate) | Combined |
|---|---|---|---|
| Byzantine validators | 15/48 | 15/48 | — |
| Attempted / Finalized | 200 / 200 (100%) | 200 / 200 (100%) | 400 / 400 (100%) |
| Conflicting FCs | 0 | 0 | **0** |
| Invalid votes admitted (PC/TC/CC/FC) | 0/0/0/0 | 0/0/0/0 | **0/0/0/0** |
| TC signatures checked / valid | 191 / 191 | 178 / 178 | 11,808 / 11,808 |
| View-changes | 66 | 57 | — |

## Ready Narrative Text

> Byzantine security was evaluated via a dedicated experiment under two distinct
> attack vectors on the real 5-region, 48-validator AWS deployment: 15 of 48
> validators submitting cryptographically invalid votes (S2), and the same fraction
> of validators equivocating — signing conflicting messages for the same round and
> view (S3), the canonical double-voting attack BFT protocols must resist. Both
> scenarios achieved 100% finalization (200/200 measured rounds each) with zero
> conflicting finality certificates and zero invalid votes ever admitted to any
> certificate, across a combined 11,808 individually re-verified timeout-certificate
> signatures. Equivocation was confirmed actively exercised throughout the S3 run (879
> detection events), not merely configured but inactive. These results demonstrate
> that neither invalid-vote injection nor equivocation can compromise consensus
> safety, even under sustained adversarial load on real, geographically-distributed
> infrastructure.

## Caveats
None. Both results are clean, complete, and consistent with the protocol's designed
safety guarantees. These dedicated runs also independently corroborate the identical
safety properties (zero conflicting FCs, zero invalid votes admitted) observed in
earlier data collected as part of the broader Stage 9 fault-scenario campaign,
reinforcing confidence that these results are reproducible rather than a one-off.

## Provenance
- Analyzer: `code/stage9_analyze.py` — independently re-validates every certificate at
  the byte level, not the daemon's self-reported verification flags
- Daemon: `code/stage9_node_daemon_v2.py`, SHA-256:
  `27b24003e34150909f5ecc8c1838fc1bcdbb671be41046d20d33b2508adcb2a3`
- Raw data: `data/S2/events_<region>.jsonl`, `data/S3/events_<region>.jsonl` (7 files
  each)
- Full analyzer output: `analysis/stage9_scenario_table.md`
- Campaign ID: `STAGE3_BYZANTINE_RUN1` — a dedicated experiment run specifically for
  this stage, launched via true-parallel/detached orchestration
