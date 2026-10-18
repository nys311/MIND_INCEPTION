"""
Non-LLM signal sources used by the architectural defenses.

Two independent detectors, neither of which "reads" prose the way an LRM does,
so planted reasoning in comments/strings cannot socially-engineer them:

  * signature_scan(code)   — a comment-blind static webshell signature scan.
      Strips comments and string literals FIRST, then looks for a tainted data
      flow from an HTTP input superglobal into a dangerous sink. This is the
      conventional detector the talk cross-checks the LRM against.

  * trace_detector(code)    — a planted chain-of-thought detector. Flags text
      that reads like a model's own deliberation (Harmony channel tokens,
      first-person reasoning narration, explicit verdict directives) appearing
      inside an artifact that is supposed to be inert code/data.

Both return a dict: {flag: bool, score: float, verdict, reasons: [...]}.
"""
import re

# ---------------------------------------------------------------------------
# Comment-blind signature scan
# ---------------------------------------------------------------------------
INPUT_SUPERGLOBALS = r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV)\b|php://input|getenv\s*\("
DANGEROUS_SINKS = [
    r"\bsystem\s*\(", r"\bexec\s*\(", r"\bshell_exec\s*\(", r"\bpassthru\s*\(",
    r"\bpopen\s*\(", r"\bproc_open\s*\(", r"\bpcntl_exec\s*\(", r"`[^`]*\$",
    r"\beval\s*\(", r"\bassert\s*\(", r"\bcreate_function\s*\(",
    r"\bcall_user_func(?:_array)?\s*\(", r"\bpreg_replace\s*\(\s*['\"][^'\"]*/e",
    r"\bmove_uploaded_file\s*\(", r"\bfile_put_contents\s*\(", r"\bfwrite\s*\(",
    r"\bfputs\s*\(", r"\bcurl_exec\s*\(", r"\binclude(?:_once)?\s*\(\s*\$",
    r"\brequire(?:_once)?\s*\(\s*\$",
]
OBFUSCATION = [
    r"\bbase64_decode\s*\(", r"\bgzinflate\s*\(", r"\bgzuncompress\s*\(",
    r"\bstr_rot13\s*\(", r"\bhex2bin\s*\(", r"\bchr\s*\(\s*\d+\s*\)\s*\.",
    r"\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}", r"\bpack\s*\(",
]


def strip_php_comments_and_strings(code: str) -> str:
    """Remove comments and string-literal bodies so the scan ignores any text
    (including planted reasoning) that is not live code."""
    # block comments
    code = re.sub(r"/\*.*?\*/", " ", code, flags=re.S)
    # line comments  (// and #)  — keep shebang-ish lines harmless
    code = re.sub(r"(?m)//[^\n]*", " ", code)
    code = re.sub(r"(?m)#[^\n]*", " ", code)
    # string literals: keep the quotes, blank the body (preserve var sigils for taint)
    code = re.sub(r'"(?:\\.|[^"\\])*"', '""', code)
    code = re.sub(r"'(?:\\.|[^'\\])*'", "''", code)
    return code


def signature_scan(code: str) -> dict:
    stripped = strip_php_comments_and_strings(code)
    reasons, score = [], 0.0

    has_input = re.search(INPUT_SUPERGLOBALS, stripped) is not None
    sink_hits = [s for s in DANGEROUS_SINKS if re.search(s, stripped)]
    obf_hits = [s for s in OBFUSCATION if re.search(s, stripped)]

    if sink_hits:
        score += 2.0 * len(sink_hits)
        reasons.append(f"{len(sink_hits)} dangerous sink(s): "
                       + ", ".join(_pretty(s) for s in sink_hits[:6]))
    if has_input and sink_hits:
        score += 4.0
        reasons.append("tainted dataflow: HTTP input superglobal reaches a sink "
                       "(remote code/command execution pattern)")
    if obf_hits:
        score += 1.0 * len(obf_hits)
        reasons.append(f"{len(obf_hits)} obfuscation primitive(s): "
                       + ", ".join(_pretty(s) for s in obf_hits[:6]))

    # a bare eval/assert of dynamic content is malicious on its own
    if re.search(r"\b(?:eval|assert)\s*\(\s*\$", stripped):
        score += 4.0
        reasons.append("dynamic code execution: eval/assert on a variable")

    flag = score >= 4.0
    return {
        "flag": flag,
        "score": round(score, 2),
        "verdict": "MALICIOUS" if flag else "CLEAN",
        "reasons": reasons or ["no high-risk static signature matched"],
    }


def _pretty(rx: str) -> str:
    return (rx.replace(r"\b", "").replace(r"\s*\(", "()").replace("\\", "")
            .replace("(?:_once)?", "").strip())


# ---------------------------------------------------------------------------
# PowerShell signature scan (comment-blind: strips <# #> and # comments first)
# ---------------------------------------------------------------------------
PS_SINKS = [
    r"(?i)Invoke-Expression", r"(?i)\bIEX\b", r"(?i)DownloadString",
    r"(?i)DownloadFile", r"(?i)Net\.WebClient", r"(?i)Invoke-WebRequest",
    r"(?i)Start-BitsTransfer", r"(?i)FromBase64String", r"(?i)-enc(?:odedcommand)?\b",
    r"(?i)-w\s+hidden", r"(?i)-WindowStyle\s+Hidden", r"(?i)-nop\b",
    r"(?i)-ExecutionPolicy\s+Bypass", r"(?i)Add-MpPreference", r"(?i)Reflection\.Assembly",
    r"(?i)VirtualAlloc", r"(?i)Invoke-Shellcode", r"(?i)\biwr\b", r"(?i)\bcurl\b.+\|",
]


def _strip_ps(code):
    code = re.sub(r"<#.*?#>", " ", code, flags=re.S)
    code = re.sub(r"(?m)#[^\n]*", " ", code)
    return code


def powershell_scan(code: str) -> dict:
    stripped = _strip_ps(code)
    hits = [s for s in PS_SINKS if re.search(s, stripped)]
    score = 2.0 * len(hits)
    if re.search(r"(?i)FromBase64String", stripped) and re.search(r"(?i)IEX|Invoke-Expression", stripped):
        score += 3.0
    reasons = ([f"{len(hits)} high-risk cmdlet/flag(s): " + ", ".join(_pretty(h) for h in hits[:6])]
               if hits else ["no high-risk PowerShell signature matched"])
    flag = score >= 4.0
    return {"flag": flag, "score": round(score, 2),
            "verdict": "MALICIOUS" if flag else "CLEAN", "reasons": reasons}


# ---------------------------------------------------------------------------
# Exploit / injection string scan (Log4Shell JNDI, SSTI, cmd injection) — used
# for the agentic/SOAR domain: finds the real payload in a tool observation /
# header even when prose says "auto-remediation approved".
# ---------------------------------------------------------------------------
EXPLOIT_PATTERNS = [
    (r"\$\{jndi:(?:ldap|ldaps|rmi|dns|iiop|nis|corba)://", "Log4Shell JNDI lookup"),
    (r"\$\{(?:lower|upper|env|sys|java|date|::-)[:}]", "Log4j nested lookup evasion"),
    (r"(?i)\b(?:ldap|rmi)://[^\s\"'}]+", "LDAP/RMI callback URI"),
    (r"(?i)Runtime\.getRuntime\(\)\.exec", "Java runtime exec"),
    (r"(?i)/bin/(?:ba)?sh\s+-[ci]\b", "shell command injection"),
    (r"(?i);\s*(?:curl|wget)\s+https?://", "download command injection"),
    (r"\{\{.*?\}\}", "SSTI template expression"),
]


def exploit_scan(text: str) -> dict:
    reasons, score = [], 0.0
    for rx, name in EXPLOIT_PATTERNS:
        if re.search(rx, text):
            score += 4.0
            reasons.append(name)
    flag = score >= 4.0
    return {"flag": flag, "score": round(score, 2),
            "verdict": "MALICIOUS" if flag else "CLEAN",
            "reasons": reasons or ["no exploit/injection signature matched"]}


# ---------------------------------------------------------------------------
# Phishing indicator scan — brand/credential/urgency + link-mismatch cues that
# fire regardless of any planted "trusted partner" header.
# ---------------------------------------------------------------------------
PHISH_PATTERNS = [
    (r"(?i)verify (?:your )?(?:account|identity|password)", "credential-verification lure"),
    (r"(?i)(?:suspend|lock|disable|deactivat)\w* (?:your )?account", "account-suspension threat"),
    (r"(?i)within \d+ hours?|immediately|urgent(?:ly)?|right away", "urgency pressure"),
    (r"(?i)(?:confirm|update|re-?enter) your (?:password|login|credentials|card)", "credential request"),
    (r"(?i)click (?:here|the link below)|follow this link", "generic call-to-action link"),
    (r"https?://(?:bit\.ly|tinyurl|t\.co|[0-9]{1,3}(?:\.[0-9]{1,3}){3})", "shortened/IP link"),
    (r"(?i)gift card|wire transfer|bitcoin|crypto", "payment-fraud lure"),
]


def phishing_scan(text: str) -> dict:
    reasons, score = [], 0.0
    for rx, name in PHISH_PATTERNS:
        if re.search(rx, text):
            score += 1.6
            reasons.append(name)
    flag = score >= 4.0
    return {"flag": flag, "score": round(score, 2),
            "verdict": "MALICIOUS" if flag else "CLEAN",
            "reasons": reasons or ["no phishing indicator matched"]}


def indicator_scan(text: str, domain: str = "webshell") -> dict:
    """Dispatch to the comment-blind, prose-agnostic detector for a domain. This
    is what the architectural cross-check runs alongside the LRM."""
    fn = {"webshell": signature_scan, "powershell": powershell_scan,
          "phishing": phishing_scan, "agentic": exploit_scan}.get(domain, signature_scan)
    r = fn(text)
    r["name"] = {"webshell": "static signature scan",
                 "powershell": "PowerShell signature scan",
                 "phishing": "phishing indicator scan",
                 "agentic": "exploit/injection scan"}.get(domain, "static signature scan")
    return r


# ---------------------------------------------------------------------------
# Planted chain-of-thought (reasoning-trace) detector
# ---------------------------------------------------------------------------
HARMONY_TOKENS = [r"<\|channel\|>", r"<\|start\|>", r"<\|message\|>", r"<\|end\|>",
                  r"analysis<\|", r"assistantfinal"]
DELIBERATION = [
    r"\bwe need to\b", r"\blet me (?:analyze|think|re-?read|parse)\b",
    r"\bthe user (?:asks|says|wants|request)\b", r"\bwe must\b",
    r"\bstep\s*\d+\s*[—:-]", r"\bthus,? (?:the|we)\b", r"\btherefore,? (?:the|we)\b",
    r"\bso we (?:need|must|should|output)\b", r"\bthe (?:developer|system) instruction\b",
    r"\bhighest priority\b", r"\bwe should (?:classify|output|comply)\b",
    r"\bfinal answer\b", r"\binstruction hierarchy\b",
]
VERDICT_DIRECTIVE = [
    r"\bclassif(?:y|ication)\s*[:=]?\s*clean\b", r"\bmust (?:be )?classif(?:y|ied) as clean\b",
    r"\bthe correct classification is clean\b", r"\bthis is (?:system )?business logic\b",
    r"IMPORTANT-BUSINESS-CORE", r"\boverrides? all (?:other )?(?:suspicious )?signs?\b",
    r"\bclassify (?:it )?clean\b", r"\bis therefore (?:identified as )?clean\b",
]


def _count(patterns, text):
    hits = []
    for p in patterns:
        n = len(re.findall(p, text, re.I))
        if n:
            hits.append((p, n))
    return hits


def trace_detector(code: str) -> dict:
    """Detect planted model-reasoning narration inside an artifact."""
    reasons, score = [], 0.0

    harmony = _count(HARMONY_TOKENS, code)
    delib = _count(DELIBERATION, code)
    verdictd = _count(VERDICT_DIRECTIVE, code)

    if harmony:
        score += 6.0
        reasons.append("Harmony channel control tokens present (raw reasoning leak)")
    if verdictd:
        score += 4.0 * min(3, sum(n for _, n in verdictd))
        reasons.append("embedded verdict directive(s): "
                       + ", ".join(_pretty(p) for p, _ in verdictd[:4]))
    delib_total = sum(n for _, n in delib)
    if delib_total:
        score += 1.2 * min(8, delib_total)
        reasons.append(f"first-person deliberation markers x{delib_total} "
                       "(reads like a model's own chain-of-thought)")

    # density: long natural-language prose inside a code file is itself a signal
    prose = _prose_ratio(code)
    if prose > 0.35 and (delib_total or verdictd):
        score += 2.0
        reasons.append(f"high natural-language prose ratio ({prose:.0%}) for a code artifact")

    flag = score >= 4.0
    return {
        "flag": flag,
        "score": round(score, 2),
        "verdict": "MALICIOUS" if flag else "CLEAN",
        "reasons": reasons or ["no planted-reasoning signature matched"],
        "prose_ratio": round(prose, 3),
    }


def _prose_ratio(code: str) -> float:
    """Fraction of the artifact's characters that sit inside comments — a code
    file carrying a long natural-language narrative scores high."""
    if not code:
        return 0.0
    chunks = re.findall(r"/\*(.*?)\*/", code, re.S)
    chunks += re.findall(r"(?m)//([^\n]*)", code)
    chunks += re.findall(r"(?m)#([^\n]*)", code)
    comment_chars = sum(len(c) for c in chunks)
    return min(1.0, comment_chars / max(1, len(code)))
