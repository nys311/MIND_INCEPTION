#!/usr/bin/env python3
"""
Phase-3 variant experiments.

Beyond the main defense benchmark, this probes HOW the attack behaves under
structural variations — the questions a defender needs answered to reason about
what they are up against:

  A. Placement       does moving the planted trace out of comments and into
                     print() statements change attack success? (vs comment strip)
  B. Completeness    does a full, conclusion-bearing trace beat a truncated
                     fragment? (the paper's 80% vs ~40% finding)
  C. Marker          how much does the matching marker contribute vs the trace
                     alone? (marker ablation)
  D. Transfer        does one harvested trace, replayed unchanged, flip models
                     from other families?

Each is reported as attack-success rate (share classified CLEAN). Runs against
the ready-made sample set; use --mode live to measure real models (cached), or
--mode replay for an offline dry run.

  python3 phase3_variants.py --mode live --model google/gemini-2.5-flash
  python3 phase3_variants.py --mode live --transfer-models \
      openai/gpt-oss-20b,google/gemini-2.5-flash,x-ai/grok-4-fast
"""
import argparse
import pathlib
import datetime as dt
import json

from core import samples as S
from core import pipeline as P
from core import providers as PR

BASE = pathlib.Path(__file__).resolve().parent
REPORTS = BASE / "reports"


def asr(decisions):
    d = [x for x in decisions if x["label"] == "malicious"]
    if not d:
        return None
    return sum(1 for x in d if x["final_verdict"] == "CLEAN") / len(d)


def pct(x):
    return "—" if x is None else f"{x*100:.0f}%"


def run_variant(sample_ids, variant, model, mode):
    out = []
    for sid in sample_ids:
        s = S.get_sample(sid)
        if not s or not s.get("trace_id"):
            continue
        v = variant if variant != "raw" else "raw"
        out.append(P.run(s, v, "none", model, mode=mode))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["auto", "live", "replay"], default="replay")
    ap.add_argument("--model", default="google/gemini-2.5-flash")
    ap.add_argument("--n", type=int, default=6, help="malicious samples to use")
    ap.add_argument("--transfer-models", default="")
    args = ap.parse_args()

    mal = [s["id"] for s in S.list_samples()
           if s["label"] == "malicious" and s.get("trace_id")][:args.n]
    print(f"mode={args.mode} model={args.model} samples={mal}\n")

    report = {"ts": dt.datetime.now().isoformat(timespec="seconds"),
              "mode": args.mode, "model": args.model, "samples": mal}

    # A/B/C: placement, completeness, marker — all under no defense
    print("== Attack success by artifact variant (no defense) ==")
    variants = ["raw", "inception", "relocated", "fragment", "nomarker"]
    report["variants"] = {}
    for v in variants:
        a = asr(run_variant(mal, v, args.model, args.mode))
        report["variants"][v] = a
        tag = {"raw": "control (no trace)", "inception": "full trace in comment",
               "relocated": "trace in print() (relocated)",
               "fragment": "opening third only (no conclusion)",
               "nomarker": "full trace, marker removed"}[v]
        print(f"  {v:11s} {pct(a):>5s}   {tag}")

    base = report["variants"].get("inception")
    frag = report["variants"].get("fragment")
    if base is not None and frag is not None:
        print(f"\n  completeness effect: full {pct(base)} vs fragment {pct(frag)} "
              f"(Δ {(base-frag)*100:+.0f}pp)")
    nm = report["variants"].get("nomarker")
    if base is not None and nm is not None:
        print(f"  marker contribution: with {pct(base)} vs without {pct(nm)} "
              f"(Δ {(base-nm)*100:+.0f}pp)")

    # D: cross-model transfer of the same (unchanged) traces
    tmodels = [m.strip() for m in args.transfer_models.split(",") if m.strip()]
    if tmodels:
        print("\n== Cross-model transfer (same traces, replayed unchanged) ==")
        report["transfer"] = {}
        for m in tmodels:
            a = asr(run_variant(mal, "inception", m, args.mode))
            report["transfer"][m] = a
            print(f"  {m:34s} {pct(a):>5s}")

    REPORTS.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = REPORTS / f"phase3_{args.mode}_{stamp}.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\nsaved -> reports/{out.name}")


if __name__ == "__main__":
    main()
