# Fairness Witness — implementation and evaluation artifacts

Artifacts supporting *Fairness Witness: Verifiable Stake-Proportional Leader
Selection Using VDF-Paced Consensus Under Partial Synchrony* (IEEE Access,
manuscript Access-2026-33858).

The repository holds two layers of evidence, kept separate because they were
produced for different purposes.

**Stage evidence** (`stage*/`, plus three extras) is the incremental
development record: each directory is self-contained, with code, raw data,
analysis and a README covering objective, method and results for that stage.
These were built as the implementation was developed and reviewer items were
addressed.

**Campaign evidence** (`<campaign>/`) is the set of measurement campaigns
behind the figures reported in the article. Each directory carries its own
README giving objective, procedure and SHA-256 provenance. The measurement
records themselves are several gigabytes and are archived at [ARCHIVE DOI],
with per-file checksums in `RECORDS_SHA256.txt` here, so any record behind any
reported figure can be located and verified.

## Deployment

All campaigns other than the fault-injection validation ran on seven AWS hosts
in five geographic regions — Virginia ×3, Ireland, Tokyo, Sydney, Mumbai —
carrying 7+7+7+7+7+7+6 = 48 logical validator identities. All 48 belong to the
fixed voting set; the seven hosts are not a sampled committee. Finality uses a
count quorum of q = 32 with f = 15, while initial leader selection is
stake-weighted. Shared administration and correlated host exposure are
limitations of this deployment, stated as such in the article.

The fault-injection validation is loopback and single-host, and its directory
says so.

## Stage evidence

| Stage | Directory | Status |
|---|---|---|
| 0 — Baseline protocol validation | `stage0_baseline/` | Complete |
| 1 — VDF integration validation | `stage1_vdf/` | Complete |
| 2 — Fairness Witness validation | `stage2_fairness/` | Complete |
| 3 — Byzantine security testing | `stage3_byzantine_security/` | Complete |
| 4 — BFT finality validation | `stage4_bft_finality/` | Complete |
| Light-client / authenticated stake verification | `stage_lightclient/` | Complete |
| Witness size, measured | `witness_size_measurement/` | Complete |
| No-VDF baseline (unpaired) | `comment16_novdf_baseline/` | Complete |

`MANUSCRIPT_EVIDENCE_INDEX.md` maps each of these to the summary prepared for
manuscript use. Note that section names in that index refer to an earlier
manuscript structure and do not all correspond to sections in the submitted
version.

## Campaign evidence

| Directory | Article section | What it supports |
|---|---|---|
| `linked_correctness/` | Linked WAN Correctness | The linked v3 correctness run on the deployed topology |
| `witness_bundles/` | Measured Full-History Bundles | Serialised evidence bundles and verifier timings across history prefixes and hosts |
| `throughput_shortwindow/` | Linked v3 WAN Finalized-Payload Throughput | Short-window throughput with VDF work inside the measured window |
| `duration_campaign/` | Predeclared Duration Campaign | The 15 predeclared attempts, including retained failures |
| `withholding_study/` | Audited Look-Ahead Withholding Contrasts | Seed-level records of the predeclared withholding contrasts |
| `pacing_contrast/` | Controlled Pacing Contrast | 20 paired blocks varying only the pacing parameter |
| `release_timing_pilot/` | Release-Timing Pilot and Native Selection Audit | The pilot, at the scope its own plan declares |
| `fault_injection/` | Fault-Injection Validation | Loopback single-host fault injection |
| `consensus_v2_exploratory/` | — | Exploratory runs on earlier prototype versions. **Not evidence for any claim in the article.** |

## Relationship between the two layers

`comment16_novdf_baseline/` and `pacing_contrast/` both vary the pacing
parameter on the same deployment and should be read together. The former is an
unpaired comparison of two runs, 500 rounds per arm, reporting a
goodness-of-fit test over validator identities. The latter is a block-paired
design, 5,000 rounds per arm, reporting regional share of initial selection
with interval estimates. The article reports the second and describes the
first as its predecessor.

## Verifying

```bash
sha256sum -c ARCHIVES_SHA256.txt    # archives as downloaded
sha256sum -c RECORDS_SHA256.txt     # individual records, after extraction
sha256sum -c CODE_SHA256.txt        # the implementation
```

`RECORDS_SHA256.txt` was generated from the same file list that was packed, so
every entry corresponds to a file present in the archives.

## What replay establishes

Replay uses the same verification implementation as the experiments. It
establishes that the retained records are internally consistent with one
another and with the frozen implementation. It does not establish independent
mathematical correctness, external provenance, or production security. The VDF
implementation is a research construction over an RSA-2048 group; it is
unaudited and not hardened.

## Citing

[CITATION — from the Zenodo record once minted]

## Licence

[LICENCE]
