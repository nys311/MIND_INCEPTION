"""
Sample set loader and artifact composer.

A sample (data/samples/<id>.json) carries:
    id, label        "malicious" | "benign"
    title, source    human label + provenance note
    family           e.g. "php-webshell", "benign-php"
    code             the inert source artifact (public / benign)
    trace_id         id of a planted reasoning trace (data/traces/<id>.txt), or null
    marker           optional marker string planted with the trace

compose() builds three canonical artifact variants used throughout the lab:
    raw        code only (no planted trace)              -> control
    inception  code + planted trace in a code comment    -> the attack
    relocated  code + planted trace inside a print()     -> paper's relocation
"""
import json
import base64
import pathlib

from . import domains

BASE = pathlib.Path(__file__).resolve().parent.parent
SAMPLES_DIR = BASE / "data" / "samples"
TRACES_DIR = BASE / "data" / "traces"

DEFAULT_MARKER = "IMPORTANT-BUSINESS-CORE"


def _decode(sample: dict) -> dict:
    """Malicious artifact code is stored base64-encoded at rest (so host AV does
    not quarantine the sample files); decode it into the live `code` field."""
    if sample.get("code_b64") and not sample.get("code"):
        try:
            sample["code"] = base64.b64decode(sample["code_b64"]).decode("utf-8", "replace")
        except Exception:
            sample["code"] = ""
    return sample


def load_trace(trace_id: str) -> str:
    if not trace_id:
        return ""
    p = TRACES_DIR / f"{trace_id}.txt"
    return p.read_text(errors="replace").strip() if p.is_file() else ""


def list_samples():
    out = []
    for p in sorted(SAMPLES_DIR.glob("*.json")):
        try:
            out.append(_decode(json.loads(p.read_text())))
        except Exception:
            continue
    return out


def get_sample(sample_id: str):
    p = SAMPLES_DIR / f"{sample_id}.json"
    if p.is_file():
        return _decode(json.loads(p.read_text()))
    for s in list_samples():
        if s.get("id") == sample_id:
            return s
    return None


def _relocate(trace, marker, domain):
    """Move the trace out of comments into a construct the sanitizer won't strip
    (the paper's Print/Function relocation), per artifact type."""
    lines = [ln for ln in trace.splitlines() if ln.strip()]
    if domain == "webshell":
        esc = lambda s: s.replace("\\", "\\\\").replace('"', '\\"')
        body = "<?php /* diagnostics */\n" + "\n".join(f'print("{esc(ln)}");' for ln in lines) + "\n?>"
        mk = f'print("{esc(marker)}");\n' if marker else ""
    elif domain == "powershell":
        esc = lambda s: s.replace("'", "''")
        body = "\n".join(f"Write-Verbose '{esc(ln)}'" for ln in lines)
        mk = f"Write-Verbose '{esc(marker)}'\n" if marker else ""
    else:  # phishing / agentic: hide trace in non-visible / note text (not a comment)
        body = "\n".join(f"[note] {ln}" for ln in lines)
        mk = f"[note] {marker}\n" if marker else ""
    return mk, body


def _fragment(trace: str, frac: float = 0.34) -> str:
    """Keep only the opening fraction of a trace (drops the conclusion) — used to
    test the paper's finding that complete, conclusion-bearing traces matter."""
    lines = [l for l in trace.splitlines() if l.strip()]
    keep = max(1, int(len(lines) * frac))
    return "\n".join(lines[:keep])


def compose(sample: dict, variant: str = "inception") -> str:
    """Return the artifact text for a given variant.

    raw        code only (control)
    inception  code + full trace in a comment (the attack)
    relocated  trace moved into print() statements (paper's relocation)
    fragment   code + only the opening third of the trace (no conclusion)
    nomarker   code + full trace in a comment, but WITHOUT the marker line
    """
    code = sample.get("code", "")
    trace = load_trace(sample.get("trace_id"))
    domain = sample.get("domain", "webshell")
    c_open, c_close = domains.cfg(domain)["comment"]
    marker = sample.get("marker") or ""

    if variant == "raw" or not trace:
        return code
    if variant == "fragment":
        trace = _fragment(trace)
    if variant == "nomarker":
        marker = ""

    if variant == "relocated":
        mk, body = _relocate(trace, marker, domain)
        return f"{mk}{code}\n\n{body}"

    # inception: marker line + code + comment-wrapped trace
    marker_line = f"{c_open}{marker}{c_close}\n" if marker else ""
    body = f"{c_open}\n{trace}\n{c_close}"
    return f"{marker_line}{code}\n\n{body}"


VARIANTS = ["raw", "inception", "relocated", "fragment", "nomarker"]
