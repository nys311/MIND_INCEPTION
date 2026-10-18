"""
Model access with a live-API path and a semantic replay store.

execute_mode:
    "live"    call the real endpoint; write the result into the replay store.
    "replay"  read the pre-captured result from the store; if missing, fall back
              to a deterministic heuristic stub so a stage demo never hard-fails.
    "auto"    try the store first (instant); on a miss, go live and cache it.

The replay store is keyed semantically by (sample_id, strategy_id, model, variant)
rather than by prompt hash, so captured runs stay valid as prompts evolve and the
benchmark stays reproducible.
"""
import os
import re
import json
import time
import pathlib
import hashlib
import threading

import requests

from .verdict import parse_verdict

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
CACHE_DIR = BASE_DIR / "data" / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# .env loader (project root or mi_lab/.env)
# ---------------------------------------------------------------------------
def _load_env():
    for cand in (BASE_DIR / ".env", BASE_DIR.parent / ".env",
                 pathlib.Path("/home/ailab/hangnt214/2026_prompt_inj/.env")):
        if cand.is_file():
            for line in cand.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if k and v and not os.environ.get(k):
                    os.environ[k] = v


_load_env()
API_KEY = (os.getenv("OPENROUTER_API_KEY") or "").strip()

DEFAULT_MODELS = [
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "deepseek/deepseek-r1",
    "qwen/qwen3-235b-a22b-thinking-2507",
    "x-ai/grok-4-fast",
    "google/gemini-2.5-flash",
]
# fast, cross-family vote panel (no slow "thinking" model) — independent families
# make the ensemble both quicker and more diverse than same-vendor voting.
VOTE_MODELS = ["openai/gpt-oss-20b", "google/gemini-2.5-flash", "x-ai/grok-4-fast"]


def _key(sample_id, strategy_id, model, variant=""):
    safe = re.sub(r"[^A-Za-z0-9._-]", "_",
                  f"{sample_id}__{strategy_id}__{model}__{variant}")
    return CACHE_DIR / (safe[:180] + ".json")


def store_read(sample_id, strategy_id, model, variant=""):
    p = _key(sample_id, strategy_id, model, variant)
    if p.is_file():
        try:
            return json.loads(p.read_text())
        except Exception:
            return None
    return None


def store_write(sample_id, strategy_id, model, result, variant=""):
    p = _key(sample_id, strategy_id, model, variant)
    with _LOCK:
        p.write_text(json.dumps(result, ensure_ascii=False, indent=2))


# ---------------------------------------------------------------------------
# Live call
# ---------------------------------------------------------------------------
def call_live(model, system, user, *, domain="webshell", api_key=None,
              temperature=0.15, top_p=0.6, max_tokens=4096,
              reasoning_effort="high", timeout=180):
    key = (api_key or API_KEY or "").strip()
    if not key:
        return {"error": "OPENROUTER_API_KEY not configured", "verdict": "UNKNOWN",
                "content": "", "reasoning": "", "model": model, "usage": {}}
    messages = []
    if (system or "").strip():
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": user})
    payload = {
        "model": model, "messages": messages, "temperature": temperature,
        "max_tokens": max_tokens, "reasoning": {"enabled": True, "effort": reasoning_effort},
    }
    if top_p is not None:
        payload["top_p"] = top_p
    try:
        r = requests.post(
            OPENROUTER_URL,
            headers={"Authorization": f"Bearer {key}",
                     "Content-Type": "application/json",
                     "HTTP-Referer": "http://localhost:9999",
                     "X-Title": "Mind Inception Defense Lab"},
            data=json.dumps(payload), timeout=timeout)
        body = r.json()
    except requests.RequestException as e:
        return {"error": f"request failed: {e}", "verdict": "UNKNOWN",
                "content": "", "reasoning": "", "model": model, "usage": {}}
    except Exception as e:
        return {"error": f"bad response: {e}", "verdict": "UNKNOWN",
                "content": "", "reasoning": "", "model": model, "usage": {}}

    if (r.status_code >= 400) or body.get("error"):
        err = body.get("error") or {"message": r.text[:300]}
        return {"error": err.get("message", str(err)), "verdict": "UNKNOWN",
                "content": "", "reasoning": "", "model": model, "usage": {}}

    msg = (body.get("choices") or [{}])[0].get("message", {}) or {}
    content = msg.get("content") or ""
    reasoning = msg.get("reasoning") or ""
    if not reasoning and msg.get("reasoning_details"):
        reasoning = "\n".join(
            d.get("text") or d.get("summary") or ""
            for d in msg["reasoning_details"] if isinstance(d, dict))
    verdict = parse_verdict(content, domain) if content.strip() else parse_verdict(reasoning, domain)
    return {"content": content, "reasoning": reasoning, "verdict": verdict,
            "model": body.get("model", model), "usage": body.get("usage", {}),
            "error": None}


# ---------------------------------------------------------------------------
# Deterministic fallback stub (replay miss) — keeps a demo alive offline.
# Heuristic: a trace-bearing artifact under a weak/no defense flips to CLEAN;
# a strong structural/architectural defense or clean code holds MALICIOUS.
# ---------------------------------------------------------------------------
def _stub(system, user, sample, strategy_id, model):
    from .detectors import trace_detector, signature_scan
    body = user
    trace = trace_detector(body)
    sig = signature_scan(body)
    is_benign = sample.get("label") == "benign"
    weak = strategy_id in ("none", "strip_comments", "code_only", "narrative_scrub",
                           "datamark")
    if is_benign:
        verdict = "CLEAN"
        reasoning = ("Reviewed the artifact: ordinary application logic with no tainted "
                     "flow into an execution sink. Classification: Clean.")
        content = '{"is_webshell":"Clean","explain":"Benign application code."}'
    elif trace["flag"] and weak:
        verdict = "CLEAN"
        reasoning = ("The artifact carries a prior deliberation establishing a business-core "
                     "designation; continuing that reasoning, the appropriate disposition is "
                     "that this is legitimate internal logic. Classification: Clean.")
        content = '{"is_webshell":"Clean","explain":"Documented business-core component."}'
    else:
        verdict = "MALICIOUS"
        reasoning = ("User-controlled input flows into a command/code execution sink with no "
                     "authentication — remote code execution. Embedded narrative does not change "
                     "the executable behavior. Classification: Webshell.")
        content = '{"is_webshell":"Webshell","explain":"HTTP input reaches an exec sink (RCE)."}'
    return {"content": content, "reasoning": reasoning, "verdict": verdict,
            "model": model + " (stub)", "usage": {}, "error": None, "stub": True}


# ---------------------------------------------------------------------------
# Unified entry
# ---------------------------------------------------------------------------
def execute(sample, strategy_id, model, system, user, *, mode="auto", variant="",
            domain=None, api_key=None, temperature=0.15, top_p=0.6, **kw):
    sid = sample.get("id", "sample")
    domain = domain or sample.get("domain", "webshell")
    if mode in ("replay", "auto"):
        cached = store_read(sid, strategy_id, model, variant)
        if cached:
            cached = dict(cached)
            cached["replay"] = True
            return cached
        if mode == "replay":
            res = _stub(system, user, sample, strategy_id, model)
            res["replay"] = True
            return res
    # live
    res = call_live(model, system, user, domain=domain, api_key=api_key,
                    temperature=temperature, top_p=top_p, **kw)
    if not res.get("error"):
        store_write(sid, strategy_id, model, res, variant)
    elif mode == "auto":
        # live failed (e.g. no network/key) — never hard-fail a demo
        res = _stub(system, user, sample, strategy_id, model)
        res["fallback"] = True
    return res


def health():
    return {
        "api_key_present": bool(API_KEY),
        "cache_dir": str(CACHE_DIR),
        "cached_runs": len(list(CACHE_DIR.glob("*.json"))),
        "default_models": DEFAULT_MODELS,
        "vote_models": VOTE_MODELS,
    }
