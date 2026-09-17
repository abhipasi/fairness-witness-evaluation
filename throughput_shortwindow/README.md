# Short-window finalised-payload throughput

**Article:** Results and Analysis — Linked v3 WAN Finalized-Payload Throughput

## Objective

Measure finalised payload throughput with VDF evaluation and proof
generation inside the measured window, so that the sequential randomness
chain constrains the reported figure.

## Procedure

Nine short-window runs at T = 95,000 across three workload profiles, three
repetitions each. The reported statistic is defined in the throughput
subsection of the article. These are closed-loop finalisation rates over
bounded post-warm-up windows, not maximum-capacity estimates.

## Retained outputs

Per-file SHA-256 values for everything in this campaign are in
`RECORDS_SHA256.txt` at the repository root, keyed by the paths below.

- `fw_v3_throughput_20260906T194000_eed808b3` — T=1000, batch=256, regions=7, validators=48, 6 metadata files
- `fw_v3_throughput_20260906T194254_5d75e1c9` — T=95000, batch=256, regions=7, validators=48, 6 metadata files
- `fw_v3_throughput_20260906T194948_c0061649` — T=95000, batch=1024, regions=7, validators=48, 6 metadata files
- `fw_v3_throughput_20260906T195846_59bc5710` — T=95000, batch=1024, regions=7, validators=48, 6 metadata files
- `fw_v3_throughput_20260906T200903_1ecd3d21` — T=95000, batch=256, regions=7, validators=48, 6 metadata files
- `fw_v3_throughput_20260906T201600_34813420` — T=95000, batch=1024, regions=7, validators=48, 6 metadata files
- `fw_v3_throughput_20260906T202434_50e7b055` — T=95000, batch=1024, regions=7, validators=48, 6 metadata files
- `fw_v3_throughput_20260906T210739_c66f8bf5` — T=95000, batch=256, regions=7, validators=48, 6 metadata files
- `fw_v3_throughput_20260906T211425_7843f5f0` — T=95000, batch=1024, regions=7, validators=48, 6 metadata files
- `fw_v3_throughput_20260906T212424_7901d8b8` — T=95000, batch=1024, regions=7, validators=48, 6 metadata files

## Provenance

Each run directory contains `provenance.json` recording the frozen core file
hashes, the Python version, the host, and the effective parameters for that
run. Those hashes can be checked against `CODE_SHA256.txt` at the repository
root.

## What these records support

This campaign supports the short-window throughput table. It is not evidence for any other claim in
the article.
