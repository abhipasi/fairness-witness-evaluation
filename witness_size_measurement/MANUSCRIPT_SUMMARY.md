# Witness Size Measurement — Manuscript Summary

**Manuscript section:** Response to Reviewer (PDF pages 11, 16)
**Status:** 🟢 Complete — directly resolves Comments 5, 6, and 12
**Analysis date:** 2026-09-04

## Result Table

| Component | Real, Measured Size |
|---|---|
| `LeaderOnlyWitness` | **807 bytes** |
| `FinalityCertificate` (32 signers) | **2,218 bytes** |
| `CompleteWitness` (full artifact) | **3,033 bytes (≈3 KB)** |

Confirmed identical and deterministic across 29 independent real rounds from a
verified AWS production run.

## Ready Narrative Text

> In response to reviewer concerns that the witness size was estimated rather than
> measured (Comment 12), and that the stated field sizes and VDF element sizes did
> not match a genuine RSA-2048 Wesolowski construction (Comments 5-6), a complete
> witness was constructed and serialized using the actual implementation against
> real data from a verified AWS production run. The real VDF output and proof are
> genuine 256-byte RSA-2048 group elements, consistent with a real unknown-order-
> group construction rather than a placeholder. The resulting `LeaderOnlyWitness`
> measures 807 bytes, and the complete witness — including a genuine 32-signer
> finality certificate — measures 3,033 bytes, confirming the reviewer's prediction
> that a correctly-sized production witness would be measured in kilobytes. This
> measurement was verified deterministic and reproducible across 29 independent
> real consensus rounds.

## Caveats
This measures the witness structure as currently implemented in the codebase
(`fairness_witness.py`). If the manuscript text itself still describes the earlier
412/444-byte estimate or 16/64-byte mock VDF sizes, that text needs updating to
reference these real, measured values instead — this analysis provides the
corrected numbers but does not itself edit the manuscript.

## Provenance
- Code: `code/fairness_witness.py` (witness/certificate structures and
  serialization, unmodified from the validated implementation)
- Analysis script: `analysis/measure_witness_size.py`; output:
  `analysis/measure_witness_size_output.txt`
- Underlying data: drawn from the already-verified Stage 0 baseline (200/200
  finalized, zero safety violations); no new AWS run was required
