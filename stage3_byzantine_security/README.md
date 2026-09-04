# Stage 3 — Byzantine Security Testing

## Objective
Demonstrate the protocol's core safety guarantees under two distinct Byzantine attack
vectors: validators submitting cryptographically invalid votes, and validators
equivocating (signing conflicting messages for the same round/view). Confirm that
neither attack ever results in an invalid vote being admitted to a certificate, nor a
conflicting finality certificate ever forming.

## Dedicated Experiment
This stage's evidence comes from a **purpose-built experiment**: fresh, independent
`invalid_vote` and `equivocate` campaigns, 200 measured + 20 warmup rounds each,
executed on the real 5-region, 7-instance, 48-validator AWS deployment specifically for
this stage. Run ID: `STAGE3_BYZANTINE_RUN1`.

Both scenarios used the standard, unmodified launcher and daemon (no code changes
required, since `invalid_vote` and `equivocate` are pre-existing, well-defined fault
configurations), launched via the proven parallel-launch/detached-process pattern.

## Environment
Real 5-region, 7-instance, 48-validator AWS deployment, quorum q=32, production
profile.

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
| TC signatures checked / valid | 191 / 191 | 178 / 178 |
| View-change events | 66 | 57 |

**Combined (S2+S3):** 11,808 TC signatures individually re-verified, zero invalid. Zero
invalid votes admitted to any certificate across 400 total measured rounds. Zero
conflicting finality certificates.

For S3 specifically, 879 equivocation-related events were recorded across the dedicated
run, confirming the attack was actively and continuously exercised throughout, not
merely configured but inactive.

## Interpretation
Both attack vectors were fully absorbed by the protocol at 100% finalization: invalid
votes are cryptographically rejected before they can be counted toward any certificate,
and equivocating validators' conflicting signatures never allow two different blocks to
both reach finality. This holds under adversarial conditions on real, geographically
distributed infrastructure — not just in a controlled local simulation.

## Status
**COMPLETE.** Dedicated, purpose-built experiment (not reused data) — fresh runs
independently confirm the same safety properties observed in the original Stage 9
fault-scenario campaign, reinforcing confidence in the result's reproducibility.
