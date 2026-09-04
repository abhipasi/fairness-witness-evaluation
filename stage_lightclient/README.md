# Light-Client / Authenticated Stake Verification — Leader-Selection Proofs

## Reviewer Comment This Addresses
> "Light-client verification claim is unsupported. Algorithm 2 requires the validator
> set, stake weights, and recomputation of the weighted candidate sample. A Merkle
> root plus only the leader membership path cannot reconstruct the population or
> prove weighted sampling. Provide authenticated candidate and cumulative-stake
> proofs, or remove the claim."

## What Was Wrong Before
An earlier iteration of this work built a **plain Merkle tree** over the validator
set — each proof only demonstrates "this validator's data is somewhere in the
committed set." This is exactly the weakness the reviewer identified: a plain
inclusion proof cannot bind sibling subtrees' stake totals, so it cannot prove a
claimed `[interval_start, interval_end)` is correct relative to the *entire*
population, nor that a given VDF-derived value `u` falls *uniquely* inside one
validator's interval rather than some other, wider or overlapping claim.

## What This Implements
A **Merkle SUM tree**: every internal node commits to both a hash and the *total
stake* of its subtree — `H(left_hash || left_stake_sum || right_hash ||
right_stake_sum)`. This is what makes cumulative-stake proofs possible:

- A verifier, given only a target validator's own `(id, public_key, stake)` and an
  O(log n) sibling proof (each sibling carrying its own subtree's stake_sum), can
  **derive** that validator's exact `interval_start`/`interval_end` — purely from
  the proof, cryptographically bound at every level.
- The population-wide uniqueness the reviewer requires falls out directly: a
  prover cannot claim a wider interval than they actually have, because doing so
  requires lying about a sibling's stake_sum, which breaks the root-hash check.
- `verify_leader_selection_proof()` combines this with the check `interval_start
  <= u < interval_end`, directly proving weighted-sampling correctness for a
  specific selection — not just "this leaf exists."

## Method
1. `code/leader_selection_sumtree.py` replaces the snapshot's flat-hash commitment
   with the Merkle SUM tree described above (see file docstrings for the exact
   node-hash construction and the critical zero-stake phantom-padding fix, below).
2. A dedicated, fresh 200-round clean campaign (`SUMTREE_RUN1`) was executed on the
   real 5-region, 48-validator AWS deployment with this code deployed.
3. For every real finalized round, the view-0 leader selection was recomputed
   using the *exact* real inputs the daemon itself used (`vdf_output_hex`,
   `commitment_root_hex`, both logged verbatim in the event stream), confirmed to
   match the real logged leader, then verified via a real sum-tree proof generated
   from the reconstructed snapshot.

Reproduction: `python3 analysis/leader_selection_proof_verify.py <data_dir>`

## A Real Bug Found and Fixed During Development
Padding a Merkle tree with an odd node count by duplicating the last node (the
standard convention for a plain Merkle tree) is **incorrect for a sum tree**:
duplicating a node's `(hash, stake_sum)` pair also duplicates its stake
contribution, silently inflating the root's total stake whenever padding occurs at
any level. With n=48 validators (not a power of 2), this occurs at the 3-node
level and inflated the derived total from 48 to 64. Caught by cross-checking
`root_sum` against the true validator count before trusting any proof output;
fixed by using a zero-stake phantom node for padding instead of a duplicate.

## A Second Issue Found and Corrected: Version Consistency
An initial validation attempt against real AWS data showed only 3/196 leaders
matching — not a bug in the sum-tree logic itself, but a genuine methodological
error: the analysis reconstructed the snapshot using the sum-tree code while the
actual AWS run had been executed with an *earlier* plain-Merkle patch, which
produces a different `commitment` value and therefore a different derived VDF
selector. Re-running the dedicated experiment with the sum-tree version actually
deployed resolved this completely (196/196 match).

## Results

| Metric | Value |
|---|---|
| Network-wide finalization | 200/200 (100%) |
| Real rounds tested | 196 |
| Recomputed view-0 leader matches real logged leader | **196/196 (100%)** |
| Leader-selection proofs verified (u provably unique in derived interval) | **196/196 (100%)** |

Every real, network-produced leader selection from this dedicated AWS run was
verified using only the selected leader's own data plus a small (≤6-hash) proof —
never the full 48-validator list — with the derived interval cryptographically
bound to the entire population's stake distribution.

## Status
**COMPLETE.** This directly answers the reviewer's specific technical objection:
authenticated candidate proofs (Merkle inclusion) and cumulative-stake proofs
(the sum-tree's derived interval, bound via sibling stake sums) are both provided,
validated against real, dedicated AWS-produced data — not synthetic keys, and not
data generated under a different, incompatible commitment scheme.
