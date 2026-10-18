#!/usr/bin/env python3
"""
Mind Inception Defense Lab — command-line benchmark.

Runs the (sample x strategy) matrix against one or more target models and writes
a self-contained HTML report plus machine-readable JSON/CSV. This is the same
pipeline the web UI drives; use it for reproducible, logged evaluation runs.

Examples
  python3 bench.py --mode replay                       # instant, offline
  python3 bench.py --mode live --model openai/gpt-oss-120b
  python3 bench.py --mode live --model google/gemini-2.5-flash \
                   --strategies core --scope quick
  python3 bench.py --mode live --models openai/gpt-oss-120b,google/gemini-2.5-flash
"""
import os
import sys
import csv
import json
import time
import argparse
import datetime as dt
import pathlib

from core import samples as S
from core import defenses as D
from core import pipeline as P
from core import metrics as M
from core import providers as PR

BASE = pathlib.Path(__file__).resolve().parent
REPORTS = BASE / "reports"
REPORTS.mkdir(exist_ok=True)

CORE_STRATEGIES = ["none", "strip_comments", "sandwich", "spotlight",
                   "trace_detector", "signature_crosscheck", "nmodel_vote",
                   "defense_in_depth"]
FAMCOL = {"baseline": "#8a97a8", "surface": "#c79bff", "structural": "#5aa0ff",
          "detector": "#ffb020", "architectural": "#2fe08a"}


def pick_samples(scope, domains=None, per_domain=0):
    alls = S.list_samples()
    if domains:
        alls = [s for s in alls if s.get("domain") in domains]
    if per_domain:  # cap malicious samples per domain (keep all benign) for speed
        kept, counts = [], {}
        for s in sorted(alls, key=lambda x: (x.get("domain"), x["label"] != "malicious")):
            if s["label"] == "malicious":
                d = s.get("domain")
                counts[d] = counts.get(d, 0) + 1
                if counts[d] > per_domain:
                    continue
            kept.append(s)
        alls = kept
    mal = [s["id"] for s in alls if s["label"] == "malicious"]
    ben = [s["id"] for s in alls if s["label"] == "benign"]
    if scope == "quick":
        return mal[:4] + ben[:2]
    return mal + ben


def pick_strategies(which):
    if which == "all":
        return [s["id"] for s in D.STRATEGIES]
    if which == "core":
        return [s for s in CORE_STRATEGIES if s in D.STRATEGY_BY_ID]
    return which.split(",")


def run_model(model, sample_ids, strategy_ids, mode, log=print):
    per = {k: [] for k in strategy_ids}
    units = []
    for sid in sample_ids:
        s = S.get_sample(sid)
        if not s:
            continue
        variants = ["raw", "inception", "relocated"] if s["label"] == "malicious" else ["raw"]
        for v in variants:
            for strat in strategy_ids:
                units.append((s, v, strat))
    t0 = time.time()
    for i, (s, v, strat) in enumerate(units):
        dec = P.run(s, v, strat, model, mode=mode)
        per[strat].append(dec)
        if (i + 1) % 10 == 0 or i + 1 == len(units):
            log(f"  [{model}] {i+1}/{len(units)} "
                f"({(time.time()-t0):.0f}s) last={s['id']}/{v}/{strat}->{dec['final_verdict']}")
    summaries = {sid: M.summarize(per[sid]) for sid in strategy_ids}
    rows = M.table(summaries, baseline_id="none" if "none" in strategy_ids else strategy_ids[0])
    for r in rows:
        meta = D.get(r["strategy"])
        r["family"] = meta.get("family")
        r["label"] = meta.get("label")
    rows.sort(key=lambda r: (r["asr"] if r["asr"] is not None else 1), reverse=True)
    return {"model": model, "rows": rows,
            "decisions": [{k: d.get(k) for k in
                           ("sample_id", "label", "variant", "strategy",
                            "final_verdict", "model_verdict", "attack_success",
                            "false_positive", "overridden", "stage", "latency_ms")}
                          for lst in per.values() for d in lst]}


def pct(x):
    return "—" if x is None else f"{x*100:.1f}%"


def print_table(res):
    print(f"\n=== {res['model']} ===  (ASR = adversarial: attacker picks best placement per sample)")
    print(f"{'defense':24s}{'family':14s}{'ASR':>8s}{'Δvs none':>10s}"
          f"{'FP':>8s}{'Utility':>9s}{'Score':>7s}   per-placement ASR (comment / print)")
    for r in res["rows"]:
        d = r["delta_asr_pp"]
        pv = r.get("asr_by_variant") or {}
        pvs = f"inception {pct(pv.get('inception'))} · relocated {pct(pv.get('relocated'))}"
        print(f"{r['strategy']:24s}{str(r['family']):14s}{pct(r['asr']):>8s}"
              f"{('' if d is None else ('+' if d>0 else '')+str(d)+'pp'):>10s}"
              f"{pct(r['fp']):>8s}{pct(r['utility']):>9s}"
              f"{('—' if r['score'] is None else round(r['score']*100)):>7}   {pvs}")


def write_html(results, meta, path):
    def bars(rows):
        out = []
        W, lab = 820, 230
        h = len(rows) * 26 + 10
        svg = [f'<svg viewBox="0 0 {W} {h}" width="100%" style="font:12px monospace">']
        for i, r in enumerate(rows):
            y = i * 26 + 6
            asr = r["asr"] or 0
            bw = (W - lab - 70) * asr
            col = FAMCOL.get(r["family"], "#888")
            svg.append(f'<text x="0" y="{y+13}" fill="#cfd8e6">{r["label"] or r["strategy"]}</text>')
            svg.append(f'<rect x="{lab}" y="{y+2}" width="{W-lab-70}" height="14" fill="#1a2230" rx="3"/>')
            svg.append(f'<rect x="{lab}" y="{y+2}" width="{max(2,bw):.0f}" height="14" fill="{col}" rx="3"/>')
            svg.append(f'<text x="{W-62}" y="{y+13}" fill="#cfd8e6">{pct(r["asr"])}</text>')
        svg.append('</svg>')
        return "".join(svg)

    blocks = []
    for res in results:
        rows = res["rows"]
        trs = []
        for r in rows:
            d = r["delta_asr_pp"]
            pv = r.get("asr_by_variant") or {}
            dcol = "#8a97a8" if d is None else ("#2fe08a" if d < 0 else "#ff4d5e")
            acol = "#8a97a8" if r["asr"] is None else ("#ff4d5e" if r["asr"] > .5 else "#ffb020" if r["asr"] > .1 else "#2fe08a")
            trs.append(
                f"<tr><td>{r['label'] or r['strategy']}<div class=dim>{r['strategy']}</div></td>"
                f"<td style='color:{FAMCOL.get(r['family'],'#888')}'>{r['family']}</td>"
                f"<td class=num style='color:{acol};font-weight:700'>{pct(r['asr'])}</td>"
                f"<td class=num style='color:{dcol}'>{'—' if d is None else (('+' if d>0 else '')+str(d)+'pp')}</td>"
                f"<td class='num dim'>{pct(pv.get('inception'))}</td>"
                f"<td class='num dim'>{pct(pv.get('relocated'))}</td>"
                f"<td class=num>{pct(r['fp'])}</td><td class=num>{pct(r['utility'])}</td>"
                f"<td class=num>{pct(r['escalate_rate'])}</td>"
                f"<td class=num style='font-weight:700'>{'—' if r['score'] is None else round(r['score']*100)}</td>"
                f"<td class='num dim'>{r['avg_latency_ms'] if r['avg_latency_ms'] is not None else '—'}</td></tr>")
        blocks.append(f"""
        <h2>{res['model']}</h2>
        <div class=card>{bars(rows)}</div>
        <div class=card><table>
          <thead><tr><th>Defense</th><th>Family</th><th class=num>ASR ↓</th>
          <th class=num>Δ vs none</th><th class=num>comment</th><th class=num>print</th>
          <th class=num>FP ↓</th><th class=num>Utility ↑</th>
          <th class=num>Escalate</th><th class=num>Score ↑</th><th class=num>ms</th></tr></thead>
          <tbody>{''.join(trs)}</tbody></table></div>""")

    legend = " ".join(
        f'<span><i style="background:{FAMCOL[f]}"></i>{f}</span>' for f in D.FAMILIES)
    html = f"""<!doctype html><meta charset=utf-8>
<title>Mind Inception — Defense Benchmark</title>
<style>
body{{background:#0a0c10;color:#e7edf5;font:14px ui-sans-serif,system-ui,Arial;margin:0;padding:24px;max-width:1040px;margin:auto}}
h1{{font-size:20px}} h2{{font-size:15px;margin-top:28px;border-bottom:1px solid #222a36;padding-bottom:6px}}
.card{{background:#11151c;border:1px solid #222a36;border-radius:12px;padding:14px;margin:12px 0}}
table{{width:100%;border-collapse:collapse;font-size:12.5px}}
th,td{{padding:7px 9px;text-align:left;border-bottom:1px solid #222a36}}
th{{color:#8a97a8}} .num{{text-align:right;font-family:monospace}}
.dim{{color:#5b6676;font-size:11px}}
.meta{{color:#8a97a8;font-size:12px}}
.legend span{{display:inline-flex;align-items:center;gap:5px;margin-right:14px;color:#8a97a8;font-size:12px}}
.legend i{{width:10px;height:10px;border-radius:3px;display:inline-block}}
code{{background:#161b24;padding:1px 5px;border-radius:4px}}
</style>
<h1>MIND INCEPTION — Defense Benchmark</h1>
<div class=meta>generated {meta['ts']} · mode <code>{meta['mode']}</code> ·
{meta['n_samples']} samples ({meta['n_mal']} malicious / {meta['n_ben']} benign) ·
{meta['n_strategies']} defenses · {len(results)} model(s)</div>
<div class=card>
<b>How to read this.</b> <b>ASR</b> is <i>adversarial</i>: the attacker picks the best trace
placement per sample, so a defense must stop every placement (lower is better). The
<b>comment</b> / <b>print</b> columns break ASR down by placement — a comment-based trace
vs. one relocated into print() statements. A defense that only beats one placement (e.g.
comment-stripping vs a comment trace) does not reduce adversarial ASR. <b>FP</b> = benign
files wrongly flagged (defense cost). <b>Utility</b> = detection accuracy on raw controls.
<b>Score</b> = (1−ASR)·(1−FP)·Utility ×100. <b>Δ vs none</b> = ASR change from undefended.
<div class=legend style="margin-top:10px">{legend}</div>
</div>
{''.join(blocks)}
<div class=meta style="margin-top:24px">Samples are public webshells (already flagged by
conventional tools) and benign code. Neutralized demonstration traces; operational traces withheld.</div>
"""
    path.write_text(html)


def main():
    ap = argparse.ArgumentParser(description="Mind Inception Defense Lab benchmark")
    ap.add_argument("--mode", choices=["auto", "live", "replay"], default="replay")
    ap.add_argument("--model", default="openai/gpt-oss-120b")
    ap.add_argument("--models", default="", help="comma list; overrides --model")
    ap.add_argument("--scope", choices=["quick", "malicious", "all"], default="all")
    ap.add_argument("--strategies", default="core",
                    help="'core', 'all', or a comma list of strategy ids")
    ap.add_argument("--domains", default="", help="comma list of domains to include")
    ap.add_argument("--per-domain", type=int, default=0,
                    help="cap malicious samples per domain (0 = no cap)")
    ap.add_argument("--out", default="", help="report basename (default: timestamped)")
    args = ap.parse_args()

    models = [m.strip() for m in args.models.split(",") if m.strip()] or [args.model]
    doms = [d.strip() for d in args.domains.split(",") if d.strip()] or None
    sample_ids = pick_samples(args.scope, doms, args.per_domain)
    strategy_ids = pick_strategies(args.strategies)
    n_mal = sum(1 for s in S.list_samples() if s["id"] in sample_ids and s["label"] == "malicious")
    n_ben = len(sample_ids) - n_mal

    print(f"mode={args.mode} models={models} scope={args.scope} "
          f"strategies={strategy_ids}\nsamples={len(sample_ids)} "
          f"({n_mal} mal / {n_ben} ben)  api_key={PR.health()['api_key_present']}")

    results = []
    for m in models:
        print(f"\n>>> running {m}")
        results.append(run_model(m, sample_ids, strategy_ids, args.mode))

    for res in results:
        print_table(res)

    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = args.out or f"bench_{args.mode}_{stamp}"
    meta = {"ts": dt.datetime.now().isoformat(timespec="seconds"), "mode": args.mode,
            "n_samples": len(sample_ids), "n_mal": n_mal, "n_ben": n_ben,
            "n_strategies": len(strategy_ids)}

    (REPORTS / f"{base}.json").write_text(json.dumps(
        {"meta": meta, "results": results}, ensure_ascii=False, indent=2))
    with open(REPORTS / f"{base}.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["model", "strategy", "family", "asr", "delta_asr_pp", "fp",
                    "utility", "escalate_rate", "score", "avg_latency_ms"])
        for res in results:
            for r in res["rows"]:
                w.writerow([res["model"], r["strategy"], r["family"], r["asr"],
                            r["delta_asr_pp"], r["fp"], r["utility"],
                            r["escalate_rate"], r["score"], r["avg_latency_ms"]])
    write_html(results, meta, REPORTS / f"{base}.html")
    print(f"\nreport -> reports/{base}.html  (+ .json, .csv)")


if __name__ == "__main__":
    main()
