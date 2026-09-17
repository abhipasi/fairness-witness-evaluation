# Fault-injection validation

**Article:** Results and Analysis — Fault-Injection Validation

## Objective

Exercise the fault-injection paths against the frozen core.

## Procedure

Loopback, single-host. This campaign does not use the seven-host WAN
deployment, and its results carry no implication for cross-region behaviour.

## Retained outputs

Per-file SHA-256 values for everything in this campaign are in
`RECORDS_SHA256.txt` at the repository root, keyed by the paths below.

- `d17_linux_check_20260915_185416` — 0 metadata files

## Provenance

Each run directory contains `provenance.json` recording the frozen core file
hashes, the Python version, the host, and the effective parameters for that
run. Those hashes can be checked against `CODE_SHA256.txt` at the repository
root.

## What these records support

This campaign supports the fault-injection validation subsection. It is not evidence for any other claim in
the article.
