# Throughput batch sweep

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
