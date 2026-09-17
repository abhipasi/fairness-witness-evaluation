# Comment 16 — Manuscript Summary

**Status:** Complete
**Run date:** 2026-09-05
**Campaign ID:** `NOVDF_BASELINE_RUN1`

> **Superseded for manuscript use.** The submitted article reports the
> block-paired Controlled Pacing Contrast rather than this run. This directory
> is retained as the earlier, unpaired comparison of the same parameter. See
> "Relationship to the pacing contrast" below.

## Result Table

| Metric | With VDF (T_vdf = 95,000) | No-VDF baseline (T_vdf = 100) |
|---|---|---|
| Finalization | 500/500 | 500/500 |
| Chi-square (df = 47) | 43.560 | 39.021 |
| P-value | 0.6158 | 0.7896 |
| Large:regular selection ratio | 4.00 (theoretical 5.00) | 4.95 (theoretical 5.00) |

## What was run

An identical weighted-stake configuration — six validators at five times the
stake of the remaining forty-two — with the VDF iteration count reduced from
95,000 to 100, lowering measured VDF time from approximately 2,630 ms to a
mean of 4.48 ms. Both arms finalized every round.

## What the result shows

Stake-proportional selection is observed in both arms. Neither arm's
goodness-of-fit test rejects the null at conventional levels (p = 0.62 paced,
p = 0.79 unpaced), and the observed large-to-regular selection ratio is closer
to its theoretical value in the unpaced arm (4.95) than in the paced arm
(4.00).

## What the result does not show

Two non-significant tests do not establish that the two conditions are
equivalent, and they do not identify which mechanism is responsible for the
observed selection behaviour. The design is unpaired: the arms ran at
different times, so network conditions were not held fixed between them. A
goodness-of-fit test over validator identities reports only whether a null is
rejected; it supplies no effect estimate and no interval, so the comparison
has no stated resolution.

No causal claim about VDF pacing and selection fairness follows from this run,
and the article makes none.

## Relationship to the pacing contrast

The article reports a block-paired contrast of the same parameter
(`pacing_contrast/`): 20 paired blocks, 5,000 rounds per arm, regional share
of initial selection with Student-*t* intervals across blocks and a Holm
correction across regions. That design controls for drift in network
conditions by pairing and reports the effect with its uncertainty. This run is
its predecessor and is retained for completeness of the record.

## Provenance

- Weighted-stake daemon as used in Stage 2:
  `code/stage9_node_daemon_v2_weighted.py`
- Analysis script: `analysis/novdf_fairness_analysis.py`;
  output: `analysis/novdf_fairness_output.txt`
- Raw data: `data/events_<region>.jsonl`, seven regions
