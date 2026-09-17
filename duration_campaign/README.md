# Predeclared duration campaign

**Article:** Results and Analysis — Predeclared Duration Campaign

## Objective

Test the same frozen core over long fixed windows against a stability
definition declared before launch, and report every planned attempt
including failures.

## Procedure

Fifteen planned runs: five fixed genesis seeds for each of three profiles
(B256, B1024, W1024), at T = 95,000, n = 48, f = 15, q = 32. Each run has
300 s of local warm-up followed by a fixed 1,800-s measurement window. Only
unique payloads finalised and persisted inside the window enter its
numerator. R_j is the lowest of the seven local rates. Stability requires
every host to pass all declared window, drift, resource and telemetry
checks.

Thirteen attempts completed with artifact passes; two failed operationally
and are retained without replacement. Failed attempts retain no accepted
rate. Directories for failed attempts are kept as diagnostic evidence and
are excluded from accepted-rate aggregates.

## Retained outputs

Per-file SHA-256 values for everything in this campaign are in
`RECORDS_SHA256.txt` at the repository root, keyed by the paths below.

- `d13_duration_20260907T231544_02be99f8` — T=1000, batch=1024, regions=7, validators=48, 8 metadata files
- `d13_duration_20260907T232452_9ec6be58` — T=95000, batch=256, regions=7, validators=48, 8 metadata files
- `d13_duration_20260908T001640_3575fb9e` — T=95000, batch=1024, regions=7, validators=48, 8 metadata files
- `d13_duration_20260908T012602_a195a32b` — T=95000, batch=1024, regions=7, validators=48, 8 metadata files
- `d13_duration_20260908T023322_4693b0f9` — T=95000, batch=256, regions=7, validators=48, 8 metadata files
- `d13_duration_20260908T032526_70eb46c4` — T=95000, batch=1024, regions=7, validators=48, 8 metadata files
- `d13_duration_20260908T043837_50fe7d8d` — T=95000, batch=1024, regions=7, validators=48, 8 metadata files
- `d13_duration_20260908T093045_a640a3cc` — T=95000, batch=256, regions=7, validators=48, 8 metadata files
- `d13_duration_20260908T102120_6540b325` — T=95000, batch=1024, regions=7, validators=48, 8 metadata files
- `d13_duration_20260908T112449_5c9509ef` — T=95000, batch=1024, regions=7, validators=48, 8 metadata files
- `d13_duration_20260908T235602_09dad248` — T=95000, batch=256, regions=7, validators=48, 8 metadata files
- `d13_duration_20260909T010458_aaf89c87` — T=95000, batch=1024, regions=7, validators=48, 8 metadata files
- `d13_duration_20260909T023133_662de34c` — T=95000, batch=1024, regions=7, validators=48, 7 metadata files
- `d13_duration_20260910T204511_da2fdd36` — T=95000, batch=256, regions=7, validators=48, 8 metadata files
- `d13_duration_20260910T213628_7b1c101e` — T=95000, batch=1024, regions=7, validators=48, 8 metadata files
- `d13_duration_20260910T225030_47639775` — T=95000, batch=1024, regions=7, validators=48, 8 metadata files

## Provenance

Each run directory contains `provenance.json` recording the frozen core file
hashes, the Python version, the host, and the effective parameters for that
run. Those hashes can be checked against `CODE_SHA256.txt` at the repository
root.

## What these records support

This campaign supports the duration campaign table and outcomes figure. It is not evidence for any other claim in
the article.
