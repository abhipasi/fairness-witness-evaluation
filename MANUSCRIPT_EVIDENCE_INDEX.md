# Manuscript Evidence Index

Single entry point for locating verified evidence when writing/updating the manuscript.
Each row links to that stage's `MANUSCRIPT_SUMMARY.md` — the manuscript-ready version of
the results, with narrative text, caveats, and provenance already prepared.

| Stage | Manuscript Section | Status | Summary |
|---|---|---|---|
| 0 — Baseline protocol validation | Experimental Setup / Baseline | 🟢 Complete | [stage0_baseline/MANUSCRIPT_SUMMARY.md](stage0_baseline/MANUSCRIPT_SUMMARY.md) |
| 1 — VDF integration validation | VDF Performance Analysis | 🟢 Complete | [stage1_vdf/MANUSCRIPT_SUMMARY.md](stage1_vdf/MANUSCRIPT_SUMMARY.md) |
| 2 — Fairness Witness validation | Fairness Evaluation | 🟢 Complete | [stage2_fairness/MANUSCRIPT_SUMMARY.md](stage2_fairness/MANUSCRIPT_SUMMARY.md) |
| 3 — Byzantine security testing | Security Evaluation | 🟢 Complete | [stage3_byzantine_security/MANUSCRIPT_SUMMARY.md](stage3_byzantine_security/MANUSCRIPT_SUMMARY.md) |
| 4 — BFT finality validation | Consensus Correctness | 🟢 Complete | [stage4_bft_finality/MANUSCRIPT_SUMMARY.md](stage4_bft_finality/MANUSCRIPT_SUMMARY.md) |
| Extra — Light-client / authenticated stake verification | Consensus Correctness / Security | 🟢 Complete | [stage_lightclient/MANUSCRIPT_SUMMARY.md](stage_lightclient/MANUSCRIPT_SUMMARY.md) |
| Extra — Witness size (real, measured) | Response to Reviewer (Comments 5, 6, 12) | 🟢 Complete | [witness_size_measurement/MANUSCRIPT_SUMMARY.md](witness_size_measurement/MANUSCRIPT_SUMMARY.md) |
| 5 — View-change and recovery | Liveness Evaluation | ⬜ Not started | — |
| 6 — Distributed deployment | System Implementation | ⬜ Not started | — |
| 7 — AWS infrastructure validation | Experimental Setup | ⬜ Not started | — |
| 8 — Throughput benchmark | Performance Evaluation | ⬜ Not started | — |
| 9 — Full adversarial campaign | Security & Robustness Evaluation | ⬜ Not started | — |

**Status legend:** ⬜ Not started · 🟡 In progress · 🟢 Complete and verified

## How to use this when writing the manuscript
1. Find the stage matching your section in the table above.
2. Open its `MANUSCRIPT_SUMMARY.md` for the result table + ready narrative text + caveats.
3. Cite the provenance (SHA-256 hashes, run date) listed there if a reviewer asks how the
   number was obtained.
4. The stage's own `README.md` (in the same folder) has full reproduction steps if deeper
   verification is ever needed.
