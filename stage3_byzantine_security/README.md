# Stage 3 — Byzantine Security Testing

## Objective
Demonstrate the protocol's core safety guarantees under two distinct Byzantine attack
vectors: validators submitting cryptographically invalid votes, and validators
equivocating (signing conflicting messages for the same round/view). Confirm that
neither attack ever results in an invalid vote being admitted to a certificate, nor a
conflicting finality certificate ever forming.

## Why No New Run Was Needed
This stage maps directly onto two scenarios from the Stage 9 fault-scenario campaign,
already executed on the real 5-region, 48-validator AWS deployment and independently
verified: **S2 (invalid_vote)** and **S3 (equivocate)**. Both were re-verified against
the current analyzer for this stage's package (see `analysis/stage9_scenario_table.md`).

## Environment
Real 5-region, 7-instance, 48-validator AWS deployment, quorum q=32, production profile
(200 measured + 20 warmup rounds, batch_size=100).

## Attack Configurations

**S2 — Invalid Vote:** 15 of 48 validators (ids 5,6,12,13,19,20,26,27,33,34,40,41,45,46,47)
submit cryptographically invalid votes (malformed signatures) on every round where they
participate.

**S3 — Equivocation:** The same 15 validators instead sign genuinely conflicting
messages — multiple, contradictory votes for the same round/view — the classic
double-voting Byzantine attack that BFT protocols must specifically defend against.

## Method
Each scenario's raw event logs were independently re-validated at the byte level: every
PC, TC, CC, and FC's signatures are re-verified against the canonical stake snapshot
from first principles (not the daemon's self-reported `pc_verified`/`fc_verified`
flags), and every finalized round is checked for conflicting finality certificates.

Reproduction: `python3 code/stage9_analyze.py --campaign-root data --out-dir <out>`

## Results

| Metric | S2 (invalid_vote) | S3 (equivocate) |
|---|---|---|
| Attempted / Finalized | 200 / 200 (100%) | 200 / 200 (100%) |
| Conflicting FCs | **0** | **0** |
| Invalid votes counted (PC/TC/CC/FC) | 0/0/0/0 | 0/0/0/0 |
| View-change events | 61 | 55 |

**Combined (S2+S3):** 18,784 TC signatures individually re-verified, zero invalid. Zero
invalid votes admitted to any certificate across 400 total measured rounds. Zero
conflicting finality certificates.

For S3 specifically, 877 equivocation-related events were recorded across the campaign
(equivocating votes actively detected and excluded), confirming the attack was genuinely
exercised throughout the run, not merely configured but inactive.

## Interpretation
Both attack vectors were fully absorbed by the protocol at 100% finalization: invalid
votes are cryptographically rejected before they can be counted toward any certificate,
and equivocating validators' conflicting signatures never allow two different blocks to
both reach finality. This holds under adversarial conditions on real, geographically
distributed infrastructure — not just in a controlled local simulation.

## Status
**COMPLETE.** Evidence drawn from existing, independently-verified production data;
re-confirmed for this package.
