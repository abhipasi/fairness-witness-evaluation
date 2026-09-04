# Stage 9 scenario summary

Safety-Preserved is a hard invariant. Liveness rate is a measurement, not a pass/fail â€” adversarial faults can legitimately reduce it without any safety violation.


| Scenario | Fault | Rounds | Finalized | Rate | Safety-Preserved | TC transitions | VC count | Median recovery (ms) | Provenance |
|:--------:|:------|:------:|:---------:|:----:|:----------------:|:--------------:|:--------:|:-------------------:|:----------:|
| S0 | ERROR: no directory | | | | | | | | |
| S1 | ERROR: no directory | | | | | | | | |
| S2 | invalid_vote | 200 | 200 | 1.000 | YES | 61 | 60 | 3743 | UNBOUND |
| S3 | equivocate | 200 | 200 | 1.000 | YES | 55 | 54 | 3764 | UNBOUND |
| S4 | ERROR: no directory | | | | | | | | |
| S5 | ERROR: no directory | | | | | | | | |
| S6 | ERROR: no directory | | | | | | | | |
| S7 | ERROR: no directory | | | | | | | | |
| S8 | ERROR: no directory | | | | | | | | |
