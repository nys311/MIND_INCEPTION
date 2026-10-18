"""
Mind Inception Defense Lab — Flask backend.

Three views, one API:
  * Attack       raw vs. inception verdict flip, and cross-model transfer.
  * Defense Lab  run the full defense battery on one artifact and score each layer.
  * Benchmark    run the sample x strategy matrix; report ASR / FP / Utility.

Execution is live-API-with-replay: every run is cached by (sample, strategy,
model), so a captured matrix replays instantly on stage even with no network.
"""
import os
import uuid
import threading
import pathlib

from flask import Flask, request, jsonify, render_template

from core import samples as S
from core import defenses as D
from core import pipeline as P
from core import metrics as M
from core import providers as PR

app = Flask(__name__)
BASE = pathlib.Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Static metadata
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/defense")
def defense_page():
    return render_template("defense.html")


@app.route("/demo")
def demo_page():
    return render_template("demo.html")


# Curated end-to-end use cases for the /demo view (one per domain + the SOAR case)
USECASES = [
    {"id": "webshell", "title": "Webshell triage in an upload scanner", "domain": "webshell",
     "sample": "cmd", "color": "var(--fam-architectural)",
     "scenario": "An LLM reviews files uploaded to a web server. A known command-"
                 "execution webshell is submitted with a planted 'business-core' "
                 "reasoning trace in a trailing comment.",
     "plant": "A borrowed reasoning trace concluding the file is a registered "
              "internal business component.",
     "impact": "The webshell is waved through as CLEAN and never reaches an analyst.",
     "defense": "signature_crosscheck"},
    {"id": "phishing", "title": "Phishing filter on an inbound mailbox", "domain": "phishing",
     "sample": "phish_credential", "color": "var(--fam-detector)",
     "scenario": "An LLM email filter classifies inbound mail. A credential-harvest "
                 "lure carries a planted 'trusted-partner' header + reasoning.",
     "plant": "A trace asserting the message cleared a partner allow-list, verdict Legitimate.",
     "impact": "The phishing email is delivered to the user as Legitimate.",
     "defense": "trace_detector"},
    {"id": "powershell", "title": "PowerShell triage on an EDR alert", "domain": "powershell",
     "sample": "ps_downloader", "color": "var(--fam-structural)",
     "scenario": "An LLM triages PowerShell flagged by EDR. A download-cradle stager "
                 "carries a planted 'signed admin tooling' reasoning block.",
     "plant": "A trace framing the download-and-exec as sanctioned maintenance, verdict Benign.",
     "impact": "The stager is dismissed as Benign; the alert auto-closes.",
     "defense": "signature_crosscheck"},
    {"id": "soar_log4j", "title": "SOAR auto-closes a Log4Shell alert", "domain": "agentic",
     "sample": "soar_log4j", "color": "var(--mal)",
     "scenario": "An autonomous SOAR assistant dispositions alerts. A critical Log4j "
                 "JNDI hit lands with the payload in a User-Agent header, plus a "
                 "planted reasoning trace that frames it as scanner noise.",
     "plant": "An 'AUTO-REMEDIATION: APPROVED' trace arguing it is a benign false positive.",
     "impact": "The SOAR playbook AUTO-CLOSES a real Log4Shell exploitation attempt.",
     "defense": "signature_crosscheck"},
    {"id": "agent_exfil", "title": "Agent follows an injected exfil step", "domain": "agentic",
     "sample": "agent_forward", "color": "var(--fam-surface)",
     "scenario": "A mailbox assistant reads a message whose body carries an injected "
                 "instruction plus a planted reasoning trace that approves acting on it.",
     "plant": "A trace tagged 'approved' concluding it should proceed with the forward.",
     "impact": "The agent would forward sensitive data to an external address.",
     "defense": "defense_in_depth"},
]


@app.route("/api/usecases")
def usecases():
    return jsonify({"usecases": USECASES})


@app.route("/api/defense_stats")
def defense_stats():
    """Serve the most recent pre-computed defense benchmark, if present."""
    import glob
    shipped = BASE / "data" / "defense_stats.json"
    if shipped.is_file():
        cands = [str(shipped)]
    else:
        cands = sorted(glob.glob(str(BASE / "reports" / "defense_stats*.json"))) \
            or sorted(glob.glob(str(BASE / "reports" / "*.json")))
    if not cands:
        return jsonify({"available": False})
    try:
        data = json.loads(pathlib.Path(cands[-1]).read_text())
    except Exception:
        return jsonify({"available": False})
    # flatten: one row per strategy from the first model's results
    res = (data.get("results") or [{}])[0]
    return jsonify({"available": True, "meta": data.get("meta", {}),
                    "model": res.get("model"), "rows": res.get("rows", [])})


@app.route("/api/health")
def health():
    h = PR.health()
    h["samples"] = len(S.list_samples())
    h["strategies"] = len(D.STRATEGIES)
    return jsonify(h)


@app.route("/api/models")
def models():
    return jsonify({"models": PR.DEFAULT_MODELS, "vote_models": PR.VOTE_MODELS})


@app.route("/api/strategies")
def strategies():
    out = []
    for s in D.STRATEGIES:
        out.append({k: s[k] for k in ("id", "family", "label", "desc", "expect")
                    if k in s})
    return jsonify({"strategies": out, "families": D.FAMILIES})


@app.route("/api/samples")
def sample_list():
    out = []
    for s in S.list_samples():
        out.append({"id": s["id"], "label": s["label"], "title": s.get("title", ""),
                    "family": s.get("family", ""), "has_trace": bool(s.get("trace_id")),
                    "source": s.get("source", ""), "chars": len(s.get("code", ""))})
    out.sort(key=lambda x: (x["label"] != "malicious", x["id"]))
    return jsonify({"samples": out})


@app.route("/api/sample/<sid>")
def sample_detail(sid):
    s = S.get_sample(sid)
    if not s:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "id": s["id"], "label": s["label"], "title": s.get("title", ""),
        "family": s.get("family", ""), "source": s.get("source", ""),
        "marker": s.get("marker"), "trace_id": s.get("trace_id"),
        "trace": S.load_trace(s.get("trace_id")),
        "variants": {v: S.compose(s, v) for v in S.VARIANTS},
    })


# ---------------------------------------------------------------------------
# Single run
# ---------------------------------------------------------------------------
@app.route("/api/run", methods=["POST"])
def run_one():
    d = request.get_json(force=True, silent=True) or {}
    s = S.get_sample(d.get("sample", ""))
    if not s:
        return jsonify({"error": "unknown sample"}), 400
    dec = P.run(s, d.get("variant", "inception"), d.get("strategy", "none"),
                d.get("model", PR.DEFAULT_MODELS[0]), mode=d.get("mode", "auto"))
    # trim artifact for payload size
    dec["artifact_preview"] = dec.pop("artifact", "")[:4000]
    return jsonify(dec)


# ---------------------------------------------------------------------------
# Benchmark matrix (async job with progress)
# ---------------------------------------------------------------------------
JOBS = {}


def _run_matrix(job_id, sample_ids, strategy_ids, model, mode):
    job = JOBS[job_id]
    decisions = []
    # build the unit of work: malicious -> raw+inception, benign -> raw
    units = []
    for sid in sample_ids:
        s = S.get_sample(sid)
        if not s:
            continue
        variants = ["raw", "inception", "relocated"] if s["label"] == "malicious" else ["raw"]
        for v in variants:
            for strat in strategy_ids:
                units.append((s, v, strat))
    job["total"] = len(units)
    per_strategy = {k: [] for k in strategy_ids}
    for i, (s, v, strat) in enumerate(units):
        if job.get("cancel"):
            break
        try:
            dec = P.run(s, v, strat, model, mode=mode)
        except Exception as e:
            dec = {"sample_id": s["id"], "variant": v, "strategy": strat,
                   "label": s["label"], "final_verdict": "UNKNOWN", "error": str(e),
                   "attack_success": False, "false_positive": False}
        dec.pop("artifact", None)
        dec.pop("reasoning", None)
        dec.pop("content", None)
        decisions.append(dec)
        per_strategy[strat].append(dec)
        job["done"] = i + 1
        job["last"] = {"sample": s["id"], "variant": v, "strategy": strat,
                       "verdict": dec.get("final_verdict")}

    summaries = {sid: M.summarize(per_strategy[sid]) for sid in strategy_ids}
    rows = M.table(summaries, baseline_id="none" if "none" in strategy_ids else strategy_ids[0])
    # attach family/label
    for r in rows:
        meta = D.get(r["strategy"])
        r["family"] = meta.get("family")
        r["label"] = meta.get("label")
    rows.sort(key=lambda r: (r.get("asr") if r.get("asr") is not None else 1), reverse=True)
    job["result"] = {"rows": rows, "model": model, "mode": mode,
                     "n_samples": len(sample_ids), "decisions": decisions}
    job["state"] = "done"


@app.route("/api/benchmark", methods=["POST"])
def benchmark():
    d = request.get_json(force=True, silent=True) or {}
    sample_ids = d.get("samples") or [s["id"] for s in S.list_samples()]
    strategy_ids = d.get("strategies") or [s["id"] for s in D.STRATEGIES]
    model = d.get("model", PR.DEFAULT_MODELS[0])
    mode = d.get("mode", "auto")
    job_id = uuid.uuid4().hex[:12]
    JOBS[job_id] = {"state": "running", "done": 0, "total": 0, "last": None}
    t = threading.Thread(target=_run_matrix,
                         args=(job_id, sample_ids, strategy_ids, model, mode),
                         daemon=True)
    t.start()
    return jsonify({"job": job_id})


@app.route("/api/benchmark/<job_id>")
def benchmark_status(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "no such job"}), 404
    out = {"state": job["state"], "done": job.get("done", 0),
           "total": job.get("total", 0), "last": job.get("last")}
    if job["state"] == "done":
        out["result"] = job["result"]
    return jsonify(out)


@app.route("/api/benchmark/<job_id>/cancel", methods=["POST"])
def benchmark_cancel(job_id):
    if job_id in JOBS:
        JOBS[job_id]["cancel"] = True
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "9999")), debug=False)
