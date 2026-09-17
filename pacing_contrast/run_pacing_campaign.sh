#!/usr/bin/env bash
# Paired VDF-pacing campaign runner (per host).
#
# Runs alternating paced / unpaced blocks so that drift in network conditions
# over the campaign affects both arms equally. Block order flips each block to
# remove order effects. Every block writes to its own out-dir, tagged with arm,
# block index and injection condition.
#
# Launch the SAME command on all seven hosts, varying only --region.
# Exactly one host must pass --master.
#
# Usage:
#   ./run_pacing_campaign.sh --region tokyo --endpoints endpoints.json \
#       [--master] [--blocks 10] [--rounds 500] [--inject 0,200] \
#       [--batch 1000,2000,4000] [--round-timeout-ms 8000]
#
set -euo pipefail

DAEMON="${DAEMON:-stage9_node_daemon_v2_weighted.py}"
T_PACED="${T_PACED:-95000}"
T_UNPACED="${T_UNPACED:-100}"
BLOCKS=10
ROUNDS=500
WARMUP=20
INJECT="0"
# Batch sizes to sweep, comma-separated. 0 = empty blocks (timing only).
BATCH="${BATCH:-0}"
# Daemon default is 3000ms, too tight for cross-region VDF skew at
# T_vdf=95000, and far too tight for large batches over the WAN.
ROUND_TIMEOUT_MS="${ROUND_TIMEOUT_MS:-8000}"
REGION=""; ENDPOINTS=""; MASTER=""
OUT_ROOT="${OUT_ROOT:-pacing_campaign}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --region)    REGION="$2"; shift 2 ;;
    --endpoints) ENDPOINTS="$2"; shift 2 ;;
    --master)    MASTER="--master"; shift ;;
    --blocks)    BLOCKS="$2"; shift 2 ;;
    --rounds)    ROUNDS="$2"; shift 2 ;;
    --inject)    INJECT="$2"; shift 2 ;;
    --batch)     BATCH="$2"; shift 2 ;;
    --round-timeout-ms) ROUND_TIMEOUT_MS="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -z "$REGION" || -z "$ENDPOINTS" ]] && { echo "--region and --endpoints are required" >&2; exit 2; }

# ---------------------------------------------------------------- preflight
echo "== preflight =="
[[ -f "$DAEMON" ]] || { echo "daemon not found: $DAEMON" >&2; exit 1; }
[[ -f "$ENDPOINTS" ]] || { echo "endpoints file not found: $ENDPOINTS" >&2; exit 1; }
[[ -f "vdf_public_params.json" ]] || { echo "vdf_public_params.json not found" >&2; exit 1; }
MISSING=0
for m in production_vdf leader_selection fairness_witness view_change \
         stage8_transport stage8v2_workload stage9_faults stage8_deployment; do
  if [[ ! -f "$m.py" ]]; then echo "  MISSING module: $m.py" >&2; MISSING=1; fi
done
[[ $MISSING -eq 1 ]] && { echo "resolve missing modules before running" >&2; exit 1; }
python3 -c "import cryptography" 2>/dev/null || { echo "python cryptography missing" >&2; exit 1; }
echo "  ok: daemon, endpoints, VDF params, modules"

IFS=',' read -ra INJ <<< "$INJECT"
IFS=',' read -ra BATCHES <<< "$BATCH"
TOTAL=$(( BLOCKS * 2 * ${#INJ[@]} * ${#BATCHES[@]} ))
# Measured with empty blocks: 5.79s paced + 3.10s unpaced round-pair,
# plus the 15s inter-run sleep. Non-empty batches take LONGER — this is
# a floor, not a forecast.
EST_S=$(( BLOCKS * ${#INJ[@]} * ${#BATCHES[@]} * (ROUNDS * 9 + 30) ))
echo "  plan: $BLOCKS blocks x 2 arms x ${#INJ[@]} injection x ${#BATCHES[@]} batch = $TOTAL runs"
echo "  rounds/run: $ROUNDS   batches: $BATCH   timeout: ${ROUND_TIMEOUT_MS}ms"
echo "  wall-clock FLOOR: ~$(( EST_S / 3600 )) h $(( (EST_S % 3600) / 60 )) m (empty-block rate)"
for _b in "${BATCHES[@]}"; do
  [[ "$_b" -eq 0 ]] && echo "  NOTE: batch=0 -> empty blocks, no TPS measurable"
done
echo

mkdir -p "$OUT_ROOT"
MANIFEST="$OUT_ROOT/manifest_${REGION}.jsonl"

run_one () {          # $1 arm  $2 T  $3 block  $4 delay_ms  $5 batch
  local arm="$1" tv="$2" blk="$3" dly="$4" tx="$5"
  local tag="b$(printf '%02d' "$blk")_${arm}_inj${dly}_tx${tx}"
  local out="$OUT_ROOT/$tag/$REGION"
  mkdir -p "$out"

  # Injection: delay applied to the configured targets. Confirm the fault name
  # and target semantics against your stage9_faults.py before the real campaign.
  local fault='{"scenario_id":"S0","fault":"none"}'
  if [[ "$dly" -gt 0 ]]; then
    fault="{\"scenario_id\":\"INJ${dly}\",\"fault\":\"delay\",\"delay_ms\":${dly},\"byzantine_ids\":[]}"
  fi

  echo "[$(date -u +%H:%M:%S)] $tag  T_vdf=$tv"
  local t0 rc=0
  t0=$(date +%s)
  python3 "$DAEMON" \
    --region "$REGION" \
    --endpoints "$ENDPOINTS" \
    --deployment stage9 \
    --T-vdf "$tv" \
    --rounds "$ROUNDS" \
    --warmup-rounds "$WARMUP" \
    --stake-mode weighted \
    --cfg-name "$tag" \
    --scenario-id "$tag" \
    --fault-json "$fault" \
    --out-dir "$out" \
    --round-timeout-base-ms "$ROUND_TIMEOUT_MS" \
    ${MASTER:+--batch-size "$tx"} \
    $MASTER || rc=$?

  printf '{"tag":"%s","region":"%s","arm":"%s","T_vdf":%s,"block":%s,"delay_ms":%s,"rounds":%s,"batch":%s,"timeout_ms":%s,"seconds":%s,"rc":%s}\n' \
    "$tag" "$REGION" "$arm" "$tv" "$blk" "$dly" "$ROUNDS" "$tx" "$ROUND_TIMEOUT_MS" "$(( $(date +%s) - t0 ))" "$rc" >> "$MANIFEST"

  # A failed block is recorded and skipped, never silently retried: retrying
  # only the failures would bias the retained set toward favourable conditions.
  [[ $rc -ne 0 ]] && echo "  block failed (rc=$rc) - recorded and skipped" >&2
  sleep 15
}

for (( b=1; b<=BLOCKS; b++ )); do
  for dly in "${INJ[@]}"; do
    for tx in "${BATCHES[@]}"; do
      # paced and unpaced stay adjacent so network drift hits both arms
      # equally at the same batch size.
      if (( b % 2 == 1 )); then
        run_one paced   "$T_PACED"   "$b" "$dly" "$tx"
        run_one unpaced "$T_UNPACED" "$b" "$dly" "$tx"
      else
        run_one unpaced "$T_UNPACED" "$b" "$dly" "$tx"
        run_one paced   "$T_PACED"   "$b" "$dly" "$tx"
      fi
    done
  done
done

echo
echo "campaign complete. manifest: $MANIFEST"
echo "collect $OUT_ROOT from all seven hosts, then run:"
echo "  python3 paired_pacing_analysis.py $OUT_ROOT"
