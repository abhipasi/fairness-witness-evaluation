#!/usr/bin/env python3
"""Fill the <LIST THE RUN DIRECTORIES HERE> placeholders from the metadata
that was collected, and write READMEs for the two campaigns the generator
did not cover.

Reads each run's STUDY.json, provenance.json or launch record for parameters
worth showing (T_vdf, batch, rounds, region set) and lists what it finds.
Where a field is absent it says so rather than guessing.

Run from the repository root:
    python3 fill_campaign_readmes.py
"""
import os, json, glob, re

CAMPAIGNS = ["linked_correctness", "witness_bundles", "throughput_shortwindow",
             "duration_campaign", "withholding_study", "release_timing_pilot",
             "fault_injection", "consensus_v2_exploratory"]

FIELDS = ["T_vdf", "T", "batch_size", "batch", "rounds", "warmup",
          "scenario_id", "profile", "n_validators", "quorum",
          "round_timeout_base_ms", "inter_round_ms"]


def probe(run_dir):
    """Pull a few identifying parameters out of whatever metadata is present."""
    found, regions = {}, set()
    for path in glob.glob(f"{run_dir}/**/*.json", recursive=True):
        try:
            d = json.load(open(path))
        except Exception:
            continue
        stack = [d]
        while stack:
            cur = stack.pop()
            if isinstance(cur, dict):
                for k, v in cur.items():
                    if k in FIELDS and isinstance(v, (int, float, str)):
                        found.setdefault(k, v)
                    elif k in ("region", "local_region") and isinstance(v, str):
                        regions.add(v)
                    elif isinstance(v, (dict, list)):
                        stack.append(v)
            elif isinstance(cur, list):
                stack.extend(x for x in cur if isinstance(x, (dict, list)))
    if regions:
        found["regions"] = len(regions)
    return found


def describe(run_dir):
    f = probe(run_dir)
    bits = []
    for key, label in (("T_vdf", "T"), ("T", "T"), ("batch_size", "batch"),
                       ("batch", "batch"), ("rounds", "rounds"),
                       ("regions", "regions"), ("n_validators", "validators")):
        if key in f and label not in [b.split("=")[0] for b in bits]:
            bits.append(f"{label}={f[key]}")
    nfiles = sum(len(fs) for _, _, fs in os.walk(run_dir))
    bits.append(f"{nfiles} metadata files")
    return ", ".join(bits)


def fill(campaign):
    readme = os.path.join(campaign, "README.md")
    if not os.path.exists(readme):
        return None
    body = open(readme, encoding="utf-8").read()
    ph = "<LIST THE RUN DIRECTORIES HERE, one line each, with a word on what each is>"
    if ph not in body:
        return f"{campaign}: placeholder already filled"
    runs = sorted(d for d in os.listdir(campaign)
                  if os.path.isdir(os.path.join(campaign, d)))
    if not runs:
        lines = "_No run directories; see the archived record store._"
    else:
        lines = "\n".join(f"- `{r}` — {describe(os.path.join(campaign, r))}"
                          for r in runs)
    open(readme, "w", encoding="utf-8").write(body.replace(ph, lines))
    return f"{campaign}: {len(runs)} runs listed"


EXTRA = {
"pacing_contrast": """# Controlled pacing contrast

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
""",

"throughput_batch_sweep": """# Throughput batch sweep

**Article:** not cited in the submitted version.

## Objective

Measure finalized-payload throughput across batch sizes on the deployed
topology, with VDF evaluation inside the measured window, to locate the point
at which pacing stops being the binding constraint.

## Procedure

Three blocks over six batch sizes (1,000 to 12,000), paced at T = 95,000 and
unpaced at T = 100, 20 warm-up and 100 measured rounds per run, giving three
repetitions at each batch size in each arm. Round timeout raised to 15,000 ms
for the larger batches.

## Retained outputs

The run manifest, which records the wall-clock seconds, batch size, arm and
timeout for every run. The event journals are in the archived record store.

## Status

Retained for completeness. The submitted article does not report these
results.
"""
}


def main():
    for c in CAMPAIGNS:
        r = fill(c)
        if r:
            print(" ", r)
    for name, text in EXTRA.items():
        if os.path.isdir(name):
            p = os.path.join(name, "README.md")
            if os.path.exists(p):
                print(f"  {name}: README exists, left alone")
            else:
                open(p, "w", encoding="utf-8").write(text)
                print(f"  {name}: README written")
    left = os.popen("grep -l 'LIST THE RUN DIRECTORIES' */README.md 2>/dev/null").read().split()
    print("\nplaceholders remaining:", left or "none")


if __name__ == "__main__":
    main()
