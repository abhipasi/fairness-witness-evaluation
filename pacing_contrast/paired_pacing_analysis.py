#!/usr/bin/env python3
"""
Block-paired analysis of the VDF-pacing campaign.

Expects the layout written by run_pacing_campaign.sh:

    pacing_campaign/b01_paced_inj0/<region>/events_*.jsonl
    pacing_campaign/b01_unpaced_inj0/<region>/events_*.jsonl
    ...

Confidence intervals come from variation ACROSS BLOCKS, not from resampling
pooled rounds. Rounds within a block share network conditions, a genesis seed
and a deployment state, so treating them as independent understates
uncertainty. The block is the experimental unit.

Usage:
    python3 paired_pacing_analysis.py pacing_campaign [--inject 0]
"""
import sys, os, json, glob, math, argparse
from collections import Counter, defaultdict

try:
    from scipy import stats
except ImportError:
    sys.exit("scipy required:  pip install scipy")

LARGE_IDS = {0, 8, 16, 24, 32, 40}      # stake 500; all others stake 100


def load_block(block_dir):
    """One round is recorded once per host; deduplicate on round number."""
    per_round, vmap, lat = {}, {}, defaultdict(list)
    for path in glob.glob(f"{block_dir}/*/events_*.jsonl"):
        for line in open(path):
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("kind") != "phase" or e.get("phase") != "finalized":
                continue
            r, reg = e.get("round", -1), e.get("leader_region")
            if not (1 <= r < 900000) or not reg:
                continue
            if e.get("leader_id") is not None:
                vmap[e["leader_id"]] = reg
            per_round.setdefault(r, reg)
            ms = e.get("finality_latency_ms")
            if ms is not None and e.get("region"):
                lat[e["region"]].append(ms)
    return per_round, vmap, lat


def discover(root, inject):
    blocks = defaultdict(dict)
    for d in sorted(glob.glob(f"{root}/b*_*_inj*")):
        name = os.path.basename(d)
        try:
            b, arm, inj = name.split("_")
            inj = int(inj.replace("inj", ""))
        except ValueError:
            continue
        if inj != inject:
            continue
        blocks[int(b[1:])][arm] = d
    return {b: v for b, v in blocks.items() if {"paced", "unpaced"} <= set(v)}


def expected_shares(vmap):
    stake = Counter()
    for vid, reg in vmap.items():
        stake[reg] += 500 if vid in LARGE_IDS else 100
    total = sum(stake.values()) or 1
    return {r: stake[r] / total for r in stake}, stake


def ci_of_mean(xs, conf=0.95):
    """Student-t interval on the block mean. With few blocks this is wide,
    and that width is the honest statement of what the campaign can resolve."""
    n = len(xs)
    if n < 2:
        return float("nan"), float("nan")
    m = sum(xs) / n
    sd = math.sqrt(sum((x - m) ** 2 for x in xs) / (n - 1))
    h = stats.t.ppf(0.5 + conf / 2, n - 1) * sd / math.sqrt(n)
    return m - h, m + h


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--inject", type=int, default=0,
                    help="injection level in ms to analyse (default 0)")
    a = ap.parse_args()

    blocks = discover(a.root, a.inject)
    if not blocks:
        sys.exit(f"no paired blocks found under {a.root} at injection {a.inject} ms")

    per_block, vmap_all, lat = {}, {}, {"paced": defaultdict(list),
                                        "unpaced": defaultdict(list)}
    for b, arms in sorted(blocks.items()):
        rec = {}
        for arm, d in arms.items():
            pr, vm, la = load_block(d)
            rec[arm] = pr
            vmap_all.update(vm)
            for k, v in la.items():
                lat[arm][k].extend(v)
        per_block[b] = rec

    exp_share, stake = expected_shares(vmap_all)
    regions = sorted(exp_share)

    print(f"paired blocks        : {len(per_block)}")
    print(f"injection level      : {a.inject} ms")
    print(f"validators mapped    : {len(vmap_all)}")
    tot = {arm: sum(len(per_block[b][arm]) for b in per_block)
           for arm in ("paced", "unpaced")}
    print(f"rounds               : paced {tot['paced']}, unpaced {tot['unpaced']}")

    # ---- per-region share shift, block-paired -----------------------------
    print("\n=== REGIONAL SHARE SHIFT (unpaced minus paced), block-paired ===")
    print(f"{'region':<14}{'expected':>10}{'mean delta pp':>15}{'95% CI (pp)':>22}")
    widest = 0.0
    for r in regions:
        deltas = []
        for b, rec in per_block.items():
            pa, pb = rec["paced"], rec["unpaced"]
            if not pa or not pb:
                continue
            sa = sum(1 for v in pa.values() if v == r) / len(pa)
            sb = sum(1 for v in pb.values() if v == r) / len(pb)
            deltas.append((sb - sa) * 100)
        if len(deltas) < 2:
            continue
        m = sum(deltas) / len(deltas)
        lo, hi = ci_of_mean(deltas)
        widest = max(widest, abs(lo), abs(hi))
        print(f"{r:<14}{exp_share[r]:>9.2%}{m:>15.2f}   [{lo:+6.2f}, {hi:+6.2f}]")
    print(f"\nwidest CI bound      : +/-{widest:.2f} pp")
    print("This is the bound the campaign supports. It is not a neutrality result.")

    # ---- pooled homogeneity test -----------------------------------------
    ca = Counter(v for b in per_block for v in per_block[b]["paced"].values())
    cb = Counter(v for b in per_block for v in per_block[b]["unpaced"].values())
    table = [[ca.get(r, 0) for r in regions], [cb.get(r, 0) for r in regions]]
    chi2, p, dof, _ = stats.chi2_contingency(table)
    n = sum(map(sum, table))
    v = math.sqrt(chi2 / n) if n else float("nan")
    print("\n=== POOLED HOMOGENEITY TEST ===")
    print(f"H0: regional leader share is independent of the pacing parameter")
    print(f"chi2 = {chi2:.3f}, df = {dof}, p = {p:.4g}, n = {n}, Cramer's V = {v:.4f}")
    crit = stats.chi2.ppf(0.95, dof)
    lo_v, hi_v = 0.0, 1.0
    for _ in range(60):
        w = (lo_v + hi_v) / 2
        pw = 1 - stats.ncx2.cdf(crit, dof, w ** 2 * n)
        lo_v, hi_v = (lo_v, w) if pw > 0.80 else (w, hi_v)
    print(f"detectable V at 80% power = {w:.4f}  (observed {v:.4f})")

    # ---- latency ----------------------------------------------------------
    print("\n=== FINALITY LATENCY BY HOST REGION (ms) ===")
    print(f"{'region':<14}{'paced med':>12}{'unpaced med':>14}{'delta':>10}")
    meds = {}
    for r in sorted(set(lat["paced"]) | set(lat["unpaced"])):
        xa, xb = sorted(lat["paced"].get(r, [])), sorted(lat["unpaced"].get(r, []))
        if not xa or not xb:
            continue
        ma, mb = xa[len(xa) // 2], xb[len(xb) // 2]
        meds[r] = (ma, mb)
        print(f"{r:<14}{ma:>12.1f}{mb:>14.1f}{mb - ma:>+10.1f}")
    if meds:
        shifts = [mb - ma for ma, mb in meds.values()]
        spread_a = max(m[0] for m in meds.values()) - min(m[0] for m in meds.values())
        spread_b = max(m[1] for m in meds.values()) - min(m[1] for m in meds.values())
        print(f"\ncommon shift range   : {min(shifts):.1f} to {max(shifts):.1f} ms")
        print(f"between-region spread: paced {spread_a:.1f} ms, unpaced {spread_b:.1f} ms")
        print("A common pacing delay shifts every region by a near-identical amount")
        print("and leaves the between-region spread intact.")


if __name__ == "__main__":
    main()
