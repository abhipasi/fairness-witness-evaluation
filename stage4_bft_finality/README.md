# Stage 4 — BFT Finality Validation

## Objective
Verify that Prepare Certificate (PC), Commit Certificate (CC), and Final Certificate
(FC) formation is structurally and cryptographically correct: certificates only form
when quorum (q=32) is genuinely reached, every signature within a formed certificate is
valid, and no two conflicting certificates ever both reach finality.

## Why No New Run Was Needed
Certificate formation is exercised and logged in every round of every scenario already
executed in the Stage 9 fault-scenario campaign. This stage draws together that
evidence — already independently verified per-scenario — into a single, dedicated
correctness report, rather than requiring a new experiment.

## Environment
Real 5-region, 7-instance, 48-validator AWS deployment, quorum q=32, across 8
independently-verified scenarios (S0 baseline plus S1-S7 fault conditions).

## Method
Two independent checks, both applied to real production data:

**1. Structural correctness (signer count):** every `pc_formed` and `fc_formed` event
records `n_signers` — the number of validators whose signatures are included. A
correctly-functioning protocol must never form a certificate with fewer than q=32
signers. This was checked across all 236 certificates formed in the available data
(`analysis/certificate_correctness.py`, output in
`analysis/certificate_correctness_output.txt`).

**2. Cryptographic correctness (independent signature re-validation):** the analyzer
(`code/stage9_analyze.py`) re-verifies every certificate's signatures at the byte level
against the canonical stake snapshot — not the daemon's own self-reported verification
flags — counting any invalid vote that was nonetheless counted toward a certificate,
and any pair of conflicting FCs. This check was already performed and reported for
every scenario in the Stage 9 campaign (see Stage 3's package for the S2/S3 detail, and
the campaign-wide totals below).

## Results

### Structural correctness (signer counts)

| Sc | PC formed | PC signers (min/max) | FC formed | FC signers (min/max) |
|---|---|---|---|---|
| S0 | 30 | 32/32 | 30 | 32/32 |
| S1 | 32 | 32/32 | 32 | 32/32 |
| S2 | 39 | 32/32 | 39 | 32/32 |
| S3 | 28 | 32/32 | 28 | 32/32 |
| S4 | 23 | 32/32 | 23 | 32/32 |
| S5 | 27 | 32/32 | 27 | 32/32 |
| S6 | 32 | 32/32 | 32 | 32/32 |
| S7 | 25 | 32/32 | 25 | 32/32 |
| **Total** | **236** | — | **236** | — |

**Every single certificate formed had exactly 32 signers — never below quorum.**
(Note: counts are from the master-node view only; a certificate is recorded as "formed"
by whichever node constructs it — typically that round's leader — so per-scenario
totals are well below 200 by design, not a data-loss artifact.)

### Cryptographic correctness (campaign-wide, from independent byte-level re-validation)

| Metric | Value |
|---|---|
| Conflicting FCs (across full campaign) | 0 |
| Invalid votes admitted to any PC/TC/CC/FC | 0 |
| TC signatures individually checked | 46,000+ (campaign-wide) |
| Invalid TC signatures found | 0 |

## Status
**COMPLETE.** Certificate formation is confirmed structurally correct (always exactly
at quorum) and cryptographically correct (zero invalid signatures ever admitted, zero
conflicting certificates) across every fault condition tested.
