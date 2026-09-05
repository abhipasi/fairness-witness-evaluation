# Comment 16 — Manuscript Summary

**Manuscript section:** Response to Reviewer (PDF page 17) / Fairness Evaluation
**Status:** 🟢 Complete
**Run date:** 2026-09-05

## Result Table

| Metric | With VDF (T_vdf=95,000) | No-VDF baseline (T_vdf=100) |
|---|---|---|
| Finalization | 500/500 | 500/500 |
| Chi-square (df=47) | 43.560 | 39.021 |
| **P-value** | 0.6158 | **0.7896** |
| Large:regular selection ratio | 4.00 (theoretical: 5.00) | 4.95 (theoretical: 5.00) |

## Ready Narrative Text

> To address the concern that a non-significant chi-square result alone does not
> establish that VDF pacing causes leader-selection neutrality, a controlled
> no-VDF baseline was run: an identical weighted-stake experiment (6 validators at
> 5× the stake of the remaining 42) with VDF iteration count reduced from 95,000 to
> 100, reducing measured VDF time from ~2,630 ms to a mean of 4.48 ms while holding
> every other variable fixed. The resulting chi-square test (χ²=39.02, df=47,
> p=0.79) shows fairness at least as strong as the VDF-paced condition (p=0.62),
> with the observed selection ratio (4.95, vs. a theoretical 5.00) closer to
> expectation than the VDF-paced run's (4.00). This confirms that stake-
> proportional fairness is a property of the underlying sampling formula, not a
> consequence specifically attributable to VDF pacing; the VDF's role in the
> protocol is understood separately as a grinding-resistance mechanism.

## Caveats
This experiment isolates fairness/sampling correctness from VDF pacing but does not
by itself address the VDF's grinding-resistance claim (Comments 7, 18, 19, which
concern the attacker-model and hardware-sensitivity aspects of grinding resistance
specifically) — those remain separate, unaddressed items. This result should be
read as a precision correction to the fairness argument, clarifying which
mechanism is responsible for which protocol property, not as evidence about
grinding resistance itself.

## Provenance
- Same weighted-stake daemon patch as Stage 2:
  `code/stage9_node_daemon_v2_weighted.py` (unmodified from Stage 2)
- Analysis script: `analysis/novdf_fairness_analysis.py`; output:
  `analysis/novdf_fairness_output.txt`
- Raw data: `data/events_<region>.jsonl` (7 files)
- Campaign ID: `NOVDF_BASELINE_RUN1`
