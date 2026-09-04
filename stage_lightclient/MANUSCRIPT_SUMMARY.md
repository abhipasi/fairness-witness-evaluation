# Light-Client / Authenticated Stake Verification — Manuscript Summary

**Manuscript section:** Consensus Correctness / Response to Reviewer (PDF page 21)
**Status:** 🟢 Complete and independently verified (dedicated experiment)
**Run date:** 2026-09-04

## Directly Addresses This Reviewer Comment
> "Algorithm 2 requires the validator set, stake weights, and recomputation of the
> weighted candidate sample. A Merkle root plus only the leader membership path
> cannot reconstruct the population or prove weighted sampling. Provide
> authenticated candidate and cumulative-stake proofs, or remove the claim."

## Result Table

| Metric | Value |
|---|---|
| Network-wide finalization | 200/200 (100%) |
| Real rounds tested | 196 |
| Recomputed leader matches real logged leader | 196/196 (100%) |
| Leader-selection proofs verified | **196/196 (100%)** |
| Proof size per validator | ≤6 hashes + 6 stake values (≤240 bytes) for 48 validators |

## Ready Narrative Text

> In response to the reviewer's observation that a plain Merkle membership path
> cannot reconstruct the validator population or prove weighted sampling, the
> stake-snapshot commitment was redesigned as a Merkle SUM tree, in which every
> internal node additionally commits to its subtree's total stake. This allows a
> verifier, given only a single validator's own data and an O(log n) proof, to
> cryptographically derive that validator's exact cumulative-stake interval
> relative to the entire population — not merely confirm the validator's presence
> in the set — and thereby verify that a VDF-derived selector value falls uniquely
> within that interval. This was validated against 196 real, network-produced
> leader selections from a dedicated 200-round campaign on the actual 5-region,
> 48-validator AWS deployment: for every round, the view-0 leader was correctly
> recomputed using the real VDF output and commitment root the protocol itself
> used, and the corresponding leader-selection proof correctly and uniquely
> verified the selection in 100% of cases.

## Caveats
Two genuine issues were found and corrected during development, both documented
in full in `README.md`: (1) a sum-tree-specific padding bug that silently inflated
the derived total stake when the validator count is not a power of two (caught by
cross-checking the derived total against the true validator count before trusting
any proof), and (2) an initial validation attempt that mixed data from an earlier,
incompatible commitment scheme with the corrected sum-tree verifier, which was
resolved by re-running the dedicated experiment with the actual code being
validated. Both are presented honestly as part of the development record rather
than omitted.

## Provenance
- Modified code: `code/leader_selection_sumtree.py` (Merkle SUM tree construction,
  per-validator proof generation, standalone derivation-and-verification functions)
- Analysis script: `analysis/leader_selection_proof_verify.py`; output:
  `analysis/leader_selection_proof_output.txt`
- Raw data: `data/events_<region>.jsonl` (7 files), campaign ID `SUMTREE_RUN1`
- Base daemon SHA-256 (unmodified): `27b24003e34150909f5ecc8c1838fc1bcdbb671be41046d20d33b2508adcb2a3`
