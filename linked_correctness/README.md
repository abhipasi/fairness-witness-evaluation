# Linked WAN correctness

**Article:** Results and Analysis — Linked WAN Correctness

## Objective

Establish that the linked v3 core reaches finality on the deployed seven-
host topology, and record the observed recovery and view-change behaviour,
including the case that reaches view 32 without finality.

## Procedure

Two runs of the linked v3 core at T = 95,000 across the seven AWS hosts, 48
logical identities, count quorum q = 32. Scenario directories under each run
hold the per-host event journals. The article reports this as correctness
evidence, not as a liveness result.

## Retained outputs

Per-file SHA-256 values for everything in this campaign are in
`RECORDS_SHA256.txt` at the repository root, keyed by the paths below.

- `fw_linked_v3_20260906T123725Z_0fe32127` — T=1000, 5 metadata files
- `fw_linked_v3_20260906T124231Z_f1c0b44c` — T=95000, 5 metadata files

## Provenance

Each run directory contains `provenance.json` recording the frozen core file
hashes, the Python version, the host, and the effective parameters for that
run. Those hashes can be checked against `CODE_SHA256.txt` at the repository
root.

## What these records support

This campaign supports the linked correctness discussion and the reported view-32 case. It is not evidence for any other claim in
the article.
