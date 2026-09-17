#!/usr/bin/env python3
"""
Block-paired analysis of the VDF-pacing campaign, stratified by recovery.

Differences from paired_pacing_analysis.py, and why each matters:

  1. ATTRIBUTION. The finalized record carries initial_leader, final_leader
     and leader_region, where leader_region follows leader_id == final_leader.
     Attributing regional share by leader_region therefore counts RECOVERY
     leaders as if they were initial selections. The paced arm recovers in a
     substantial fraction of rounds and the unpaced arm almost never does, so
     that attribution compares unlike quantities. Initial stake-interval
     selection is measured by initial_leader; that is what this script uses.

  2. STRATIFICATION. Results are reported twice: over all finalized rounds,
     and over clean rounds only (view_changes == 0). If the two agree, the
     recovery path is not driving the contrast. If they disagree, the
     all-rounds figure cannot support a selection claim.

  3. POOLED TEST. The original pools ~10,000 rounds into one chi-squared while
     its own docstring argues the block is the experimental unit. Rounds inside
     a block share network conditions, a genesis seed and deployment state, so
     the pooled n is inflated roughly 500-fold and p is anti-conservative. The
     pooled test is retained for continuity, explicitly labelled, and a
     block-level paired test is reported alongside it.

  4. LATENCY. Reported as round_ms, and decomposed into the local VDF interval
     and the BFT interval, so that between-region spread can be attributed to
     per-host VDF evaluation speed rather than to network position. No
     conclusion is hardcoded.

Usage:
    python3 paired_pacing_analysis_v2.py pacing_campaign [--inject 0]
"""
import sys, os, json, glob, math, argparse
from collections import Counter, defaultdict

try:
    from scipy import stats
except ImportError:
    sys.exit("scipy required:  pip install scipy --break-system-packages")

LARGE_IDS = {0, 8, 16, 24, 32, 40}      # stake 500; all others stake 100


def load_block(block_dir):
    """Deduplicate on round: each round is recorded once per host.

    Returns rounds keyed by round number, each carrying the initial leader,
    the final leader, the view-change count and timing fields."""
    rounds, vmap = {}, {}
    lat = defaultdict(list)          # recording region -> [(round_ms, vdf, bft, vc)]
    for path in glob.glob(f"{block_dir}/*/events_*.jsonl"):
        for line in open(path, errors="replace"):
            if '"finalized"' not in line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("kind") != "phase" or e.get("phase") != "finalized":
                continue
            r = e.get("round", -1)
            if not (1 <= r < 900000):
                continue

            # leader_id is the FINAL leader; this pairing builds vid -> region
            if e.get("leader_id") is not None and e.get("leader_region"):
                vmap[e["leader_id"]] = e["leader_region"]

            if r not in rounds:
                rounds[r] = {
                    "initial_leader": e.get("initial_leader"),
                    "final_leader": e.get("final_leader", e.get("leader_id")),
                    "final_region": e.get("leader_region"),
                    "view_changes": e.get("view_changes", 0) or 0,
                }
            reg = e.get("region")
            if reg:
                lat[reg].append((
                    e.get("round_ms"),
                    e.get("vdf_ms_this_region"),
                    e.get("bft_ms_this_region"),
                    e.get("view_changes", 0) or 0,
                ))
    return rounds, vmap, lat


def discover(root, inject):
    blocks = defaultdict(dict)
    for d in sorted(glob.glob(f"{root}/b*_*_inj*")):
        parts = os.path.basename(d).split("_")
        if len(parts) < 3:
            continue
        b, arm, inj = parts[0], parts[1], parts[2]
        try:
            if int(inj.replace("inj", "")) != inject:
                continue
            blocks[int(b[1:])][arm] = d
        except ValueError:
            continue
    return {b: v for b, v in blocks.items() if {"paced", "unpaced"} <= set(v)}


def expected_shares(vmap):
    stake = Counter()
    for vid, reg in vmap.items():
        stake[reg] += 500 if vid in LARGE_IDS else 100
    total = sum(stake.values()) or 1
    return {r: stake[r] / total for r in stake}


def ci_of_mean(xs, conf=0.95):
    n = len(xs)
    if n < 2:
        return float("nan"), float("nan"), float("nan")
    m = sum(xs) / n
    sd = math.sqrt(sum((x - m) ** 2 for x in xs) / (n - 1))
    h = stats.t.ppf(0.5 + conf / 2, n - 1) * sd / math.sqrt(n)
    return m, m - h, m + h


def median(xs):
    s = sorted(x for x in xs if x is not None)
    return s[len(s) // 2] if s else float("nan")


def share_table(per_block, regions, exp_share, clean_only, vmap):
    """Block-paired share shift using INITIAL leader attribution."""
    rows, widest = [], 0.0
    for r in regions:
        deltas = []
        for b, rec in per_block.items():
            frac = {}
            for arm in ("paced", "unpaced"):
                rs = rec[arm]
                if clean_only:
                    rs = {k: v for k, v in rs.items() if v["view_changes"] == 0}
                if not rs:
                    frac = {}
                    break
                hits = sum(1 for v in rs.values()
                           if vmap.get(v["initial_leader"]) == r)
                frac[arm] = hits / len(rs)
            if len(frac) == 2:
                deltas.append((frac["unpaced"] - frac["paced"]) * 100)
        if len(deltas) < 2:
            continue
        m, lo, hi = ci_of_mean(deltas)
        widest = max(widest, abs(lo), abs(hi))
        rows.append((r, exp_share.get(r, float("nan")), m, lo, hi))
    return rows, widest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--inject", type=int, default=0)
    a = ap.parse_args()

    blocks = discover(a.root, a.inject)
    if not blocks:
        sys.exit(f"no paired blocks under {a.root} at injection {a.inject} ms")

    per_block, vmap, lat = {}, {}, {"paced": defaultdict(list),
                                     "unpaced": defaultdict(list)}
    for b, arms in sorted(blocks.items()):
        rec = {}
        for arm, d in arms.items():
            rs, vm, la = load_block(d)
            rec[arm] = rs
            vmap.update(vm)
            for k, v in la.items():
                lat[arm][k].extend(v)
        per_block[b] = rec

    exp_share = expected_shares(vmap)
    regions = sorted(exp_share)

    # ---- provenance -------------------------------------------------------
    tot, vc_rounds, unmapped = {}, {}, 0
    for arm in ("paced", "unpaced"):
        rs = [v for b in per_block for v in per_block[b][arm].values()]
        tot[arm] = len(rs)
        vc_rounds[arm] = sum(1 for v in rs if v["view_changes"] > 0)
        unmapped += sum(1 for v in rs if vmap.get(v["initial_leader"]) is None)

    print(f"paired blocks        : {len(per_block)}")
    print(f"injection level      : {a.inject} ms")
    print(f"validators mapped    : {len(vmap)} of 48")
    print(f"rounds               : paced {tot['paced']}, unpaced {tot['unpaced']}")
    for arm in ("paced", "unpaced"):
        pct = 100 * vc_rounds[arm] / tot[arm] if tot[arm] else 0
        print(f"rounds with recovery : {arm:<8} {vc_rounds[arm]:>5}  ({pct:.1f}%)")
    if unmapped:
        print(f"WARNING: {unmapped} rounds have an initial_leader absent from the")
        print("         vid->region map; those rounds count toward no region.")
    if len(vmap) < 48:
        print(f"WARNING: only {len(vmap)} of 48 validators observed as a final")
        print("         leader, so the vid->region map is incomplete.")

    # ---- share shift, both strata ----------------------------------------
    for clean_only in (False, True):
        label = ("CLEAN ROUNDS ONLY (view_changes == 0)" if clean_only
                 else "ALL FINALIZED ROUNDS")
        print(f"\n=== REGIONAL SHARE SHIFT by INITIAL leader — {label} ===")
        print("    (unpaced minus paced, block-paired, 95% t interval on 20 blocks)")
        print(f"{'region':<14}{'expected':>10}{'mean delta pp':>15}{'95% CI (pp)':>22}")
        rows, widest = share_table(per_block, regions, exp_share, clean_only, vmap)
        for r, exp, m, lo, hi in rows:
            flag = "  *" if (lo > 0 or hi < 0) else ""
            print(f"{r:<14}{exp:>9.2%}{m:>15.2f}   [{lo:+6.2f}, {hi:+6.2f}]{flag}")
        print(f"resolution bound     : +/-{widest:.2f} pp"
              "   (* = interval excludes zero)")

    # ---- tests ------------------------------------------------------------
    print("\n=== HOMOGENEITY, POOLED OVER ROUNDS (anti-conservative) ===")
    ca = Counter(vmap.get(v["initial_leader"])
                 for b in per_block for v in per_block[b]["paced"].values())
    cb = Counter(vmap.get(v["initial_leader"])
                 for b in per_block for v in per_block[b]["unpaced"].values())
    table = [[ca.get(r, 0) for r in regions], [cb.get(r, 0) for r in regions]]
    if min(map(sum, table)) > 0:
        chi2, p, dof, _ = stats.chi2_contingency(table)
        n = sum(map(sum, table))
        v = math.sqrt(chi2 / n)
        print(f"chi2 = {chi2:.3f}, df = {dof}, p = {p:.4g}, n = {n}, "
              f"Cramer's V = {v:.4f}")
        print("n counts ROUNDS, not blocks. Rounds within a block share network")
        print("conditions, seed and deployment state, so this p-value is")
        print("optimistic. Prefer the block-level test below.")

    print("\n=== HOMOGENEITY, BLOCK LEVEL (20 paired units) ===")
    for clean_only in (False, True):
        lbl = "clean" if clean_only else "all"
        pvals = []
        for r in regions:
            deltas = []
            for b, rec in per_block.items():
                f = {}
                for arm in ("paced", "unpaced"):
                    rs = rec[arm]
                    if clean_only:
                        rs = {k: v for k, v in rs.items()
                              if v["view_changes"] == 0}
                    if not rs:
                        f = {}
                        break
                    f[arm] = sum(1 for v in rs.values()
                                 if vmap.get(v["initial_leader"]) == r) / len(rs)
                if len(f) == 2:
                    deltas.append(f["unpaced"] - f["paced"])
            if len(deltas) > 1 and any(d != 0 for d in deltas):
                pvals.append((r, stats.wilcoxon(deltas).pvalue))
        if pvals:
            print(f"  [{lbl}] Wilcoxon signed-rank on per-block deltas, "
                  f"Holm-corrected over {len(pvals)} regions:")
            order = sorted(pvals, key=lambda t: t[1])
            k = len(order)
            prev = 0.0
            for i, (r, p) in enumerate(order):
                adj = min(1.0, max(prev, (k - i) * p))
                prev = adj
                mark = "  *" if adj < 0.05 else ""
                print(f"      {r:<12} p = {p:.4f}   adj = {adj:.4f}{mark}")

    # ---- latency ----------------------------------------------------------
    for clean_only in (False, True):
        label = "clean rounds" if clean_only else "all rounds"
        print(f"\n=== ROUND TIME BY HOST REGION, {label} (ms, medians) ===")
        print(f"{'region':<12}{'paced':>10}{'unpaced':>10}{'delta':>10}"
              f"{'paced VDF':>11}{'paced BFT':>11}")
        meds = {}
        for r in sorted(set(lat["paced"]) | set(lat["unpaced"])):
            def pick(arm, idx):
                return [t[idx] for t in lat[arm].get(r, [])
                        if (not clean_only or t[3] == 0)]
            pa, pb = pick("paced", 0), pick("unpaced", 0)
            if not pa or not pb:
                continue
            ma, mb = median(pa), median(pb)
            meds[r] = (ma, mb)
            print(f"{r:<12}{ma:>10.1f}{mb:>10.1f}{mb - ma:>+10.1f}"
                  f"{median(pick('paced', 1)):>11.1f}"
                  f"{median(pick('paced', 2)):>11.1f}")
        if len(meds) > 1:
            sa = max(m[0] for m in meds.values()) - min(m[0] for m in meds.values())
            sb = max(m[1] for m in meds.values()) - min(m[1] for m in meds.values())
            shifts = [mb - ma for ma, mb in meds.values()]
            print(f"\n  between-region spread: paced {sa:.1f} ms, "
                  f"unpaced {sb:.1f} ms  (ratio {sa / sb:.1f}x)" if sb else "")
            print(f"  common shift range   : {min(shifts):.1f} to {max(shifts):.1f} ms")
            print("  Spread is reported, not interpreted. If the paced spread")
            print("  exceeds the unpaced spread, compare the paced VDF column")
            print("  across regions before attributing it to network position.")


if __name__ == "__main__":
    main()
