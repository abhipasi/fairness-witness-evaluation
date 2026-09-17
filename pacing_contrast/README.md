# Controlled pacing contrast

**Article:** Results and Analysis — Controlled Pacing Contrast

## Objective

Contrast paced and effectively unpaced execution on the frozen v3 core while
holding selection configuration, placement, quorum and workload fixed, and
report the effect with its uncertainty.

## Procedure

Twenty blocks, each containing one paced run at T = 95,000 and one unpaced run
at T = 100, launched adjacently with block order alternating so that drift in
network conditions reaches both arms alike. Each run has 20 warm-up and 250
measured rounds, giving 5,000 finalized rounds per arm. Both arms finalize
empty proposal bodies. Regional share is attributed by the initial selected
identity, not by the identity that ultimately proposed.

The paced arm of this campaign ran with a transport fault in the node adapter,
disclosed in the article: recovery occurred in 1,638 of 5,000 paced rounds and
in none of the unpaced rounds. The initial-selection contrast is unaffected;
the round-time medians are an upper bound for the paced arm. The corrected
adapter is in `code/` and is not the version used here.

## Retained outputs

Per-host run manifests (`manifest_<region>.jsonl`), the campaign runner, and
both analysis scripts. `paired_pacing_analysis_v2.py` is the one whose output
the article reports; it attributes by initial leader and stratifies by
recovery. The event journals are in the archived record store and are covered
by `RECORDS_SHA256.txt` at the repository root.

## What these records support

The regional share table and the round-time decomposition in the Controlled
Pacing Contrast subsection. Not evidence for any other claim in the article.
