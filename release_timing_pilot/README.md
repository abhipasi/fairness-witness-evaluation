# Release-timing pilot and native selection audit

**Article:** Results and Analysis — Release-Timing Pilot and Native Selection Audit

## Objective

Size a possible main study of release-timing arms and audit native selection
behaviour.

## Procedure

Pilot blocks over three release arms (immediate, wait, VDF) with injected
delay, target-stratified with per-block seeds, run across the seven hosts.
The campaign plan records this as a pilot covering the v2 short scheduled-
election release mechanism, explicitly not native v3 and not geographic
fairness, and its analysis specification excludes the pilot phase from
inference.

The precision forecasts derived from it are reported in the article; all
candidate designs fail the declared 0.200 s gate for both contrasts.

## Retained outputs

Per-file SHA-256 values for everything in this campaign are in
`RECORDS_SHA256.txt` at the repository root, keyed by the paths below.

- `d08_d16_79a1310938e650c4` — 1 metadata files
- `d08_d16_dee32fafd6096282` — 1 metadata files

## Provenance

Each run directory contains `provenance.json` recording the frozen core file
hashes, the Python version, the host, and the effective parameters for that
run. Those hashes can be checked against `CODE_SHA256.txt` at the repository
root.

## What these records support

This campaign supports the main-study precision forecast table. It is not evidence for any other claim in
the article.
