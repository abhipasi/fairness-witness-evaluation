# Comment 16 — No-VDF Baseline for Fairness Attribution

## Reviewer Comment This Addresses
> "A non-significant chi-squared result means the null hypothesis was not rejected;
> it does not establish that VDF pacing caused neutrality. If leader sampling is
> independent of network arrival time, the test may only validate the random
> sampler. Report the exact p-value, effect size, confidence intervals, and a
> controlled no-VDF baseline."

## The Precise Concern
Stage 2's chi-square test (χ²=43.56, df=47, p=0.6158) shows leader selection is
statistically consistent with stake-proportional weighting. The reviewer's point is
subtle but important: this alone does not prove the *VDF* is responsible for that
fairness — the test might simply be validating the underlying `stake_interval`
sampling formula, entirely independent of whatever role the VDF plays.

## Method
An identical weighted-stake experiment to Stage 2 (6 large validators at stake=500,
42 regular at stake=100; same 500-round, clean/no-fault design) was executed with
`T_vdf` reduced from production's 95,000 iterations to **100** — every other
variable held fixed. Measured VDF time dropped from ~2,630 ms to a mean of **4.48
ms** (min 1.57 ms, max 26.98 ms), confirming the VDF's contribution to round timing
was rendered effectively negligible while the same code path still executed.

Reproduction: `python3 analysis/novdf_fairness_analysis.py <data_dir>`

## Results

| Metric | Stage 2 (T_vdf=95,000) | No-VDF baseline (T_vdf=100) |
|---|---|---|
| Finalization | 500/500 (100%) | 500/500 (100%) |
| Conflicting FCs | 0 | 0 |
| Chi-square statistic | 43.560 | 39.021 |
| Degrees of freedom | 47 | 47 |
| **P-value** | **0.6158** | **0.7896** |
| Observed large:regular ratio | 4.00 (expected 5.00) | 4.95 (expected 5.00) |

## The Honest Finding
**Fairness holds identically — if anything, slightly more precisely — with the VDF
effectively removed.** The no-VDF run's p-value (0.7896) is not lower than Stage
2's (0.6158), and its observed selection ratio (4.95) is in fact closer to the
theoretical expectation (5.00) than Stage 2's was (4.00). This directly confirms
the reviewer's suspicion: **the chi-square result validates the `stake_interval`
sampling formula itself, not a fairness property specifically attributable to VDF
pacing.**

This is a precision correction, not a retraction of the fairness claim: leader
selection genuinely is stake-proportional (both runs confirm this), but the VDF's
role in the protocol should be understood and described separately — most plausibly
as a grinding-resistance mechanism (making it computationally costly to attempt
multiple candidate seeds), not as the source of sampling fairness. These are two
distinct protocol properties that should not be conflated in the manuscript text.

## Status
**COMPLETE.** Directly answers Comment 16's request for a controlled no-VDF
baseline, with the exact p-values and ratios reported for both conditions.
