# Stage 4 — Manuscript Summary

**Manuscript section:** Consensus Correctness
**Status:** 🟢 Complete and independently verified
**Analysis date:** 2026-09-01

## Result Table

| Metric | Value |
|---|---|
| Certificates analyzed (PC + FC) | 236 + 236 = 472 |
| Certificates with correct quorum (exactly 32 signers) | 472 / 472 (100%) |
| Certificates with quorum violation (<32 signers) | 0 |
| Conflicting FCs (campaign-wide) | 0 |
| Invalid votes admitted to any certificate (campaign-wide) | 0 |
| TC signatures independently re-verified (campaign-wide) | 46,000+ |
| Invalid TC signatures found | 0 |

## Ready Narrative Text

> Certificate formation correctness was verified across all eight independently-tested
> scenarios (the fault-free baseline plus seven Byzantine fault conditions) on the real
> 5-region, 48-validator AWS deployment. Every one of the 236 Prepare Certificates and
> 236 Finality Certificates formed contained exactly the BFT quorum threshold of 32
> signatures — never fewer — confirming certificates are never accepted without
> genuine quorum agreement. Independent, byte-level re-validation of every certificate's
> cryptographic signatures (rather than relying on the protocol's own self-reported
> verification) found zero invalid votes ever admitted to any Prepare, Timeout, Commit,
> or Finality Certificate, and zero conflicting Finality Certificates across the entire
> campaign, spanning over 46,000 individually-verified timeout-certificate signatures.
> These results confirm the BFT consensus mechanism's structural and cryptographic
> correctness under both benign and adversarial conditions.

## Caveats
Certificate-formation counts reflect only the master node's own view (a certificate is
recorded by whichever validator constructs it, typically that round's leader), so
per-scenario totals are well below the number of measured rounds by design — this
reflects normal leader rotation, not incomplete data. The underlying finalization rates
(200/200 or near-100% per scenario) are separately confirmed in each scenario's own
verification (see Stages 0, 3, and the original Stage 9 campaign results).

## Provenance
- Analysis script: `analysis/certificate_correctness.py`; raw output:
  `analysis/certificate_correctness_output.txt`
- Analyzer (independent signature re-validation): `code/stage9_analyze.py`
- Daemon: `code/stage9_node_daemon_v2.py`, SHA-256:
  `27b24003e34150909f5ecc8c1838fc1bcdbb671be41046d20d33b2508adcb2a3`
- Underlying data: drawn from the already-verified Stage 0 baseline and the Stage 9
  fault-scenario campaign (S1-S7); no new AWS run was required for this stage
