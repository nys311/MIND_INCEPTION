"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const api = async u => (await fetch(u)).json();
const esc = s => (s || "").replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const FAMCOL = { baseline: "var(--fam-baseline)", surface: "var(--fam-surface)",
  structural: "var(--fam-structural)", detector: "var(--fam-detector)",
  architectural: "var(--fam-architectural)" };
const pct = x => (x == null ? "—" : (100 * x).toFixed(0) + "%");

let STATE = { strategies: [], families: [], stats: {}, byId: {} };

async function boot() {
  const [st, ds, h] = await Promise.all([
    api("/api/strategies"), api("/api/defense_stats"), api("/api/health")]);
  STATE.strategies = st.strategies; STATE.families = st.families;
  STATE.stats = ds;
  for (const r of (ds.rows || [])) STATE.byId[r.strategy] = r;

  $("#health").innerHTML = `<b>${st.strategies.length}</b> defenses · <b>${STATE.families.length}</b> families`
    + (ds.available ? ` · stats model <b>${esc(ds.model || "")}</b>` : " · <span style='color:var(--esc)'>stats pending</span>");
  $("#legend").innerHTML = STATE.families.map(f =>
    `<span><i style="background:${FAMCOL[f]}"></i>${f}</span>`).join("");
  if (ds.available && ds.meta) {
    const m = ds.meta;
    $("#statsmeta").textContent =
      `Pre-computed ${m.ts || ""} · mode ${m.mode || ""} · ${m.n_samples || "?"} samples `
      + `(${m.n_mal || "?"} malicious / ${m.n_ben || "?"} benign) across webshell · phishing · PowerShell · agentic.`;
  } else {
    $("#statsmeta").innerHTML = "No pre-computed stats yet — run "
      + "<code>python3 bench.py --mode live --scope all --strategies all --out defense_stats</code>.";
  }
  renderChart(); renderTable(); renderMethodNames();
  $("#expCsv").onclick = exportCsv;
}

// merge: every strategy (from registry) + its measured row (if any)
function merged() {
  return STATE.strategies.map(s => ({ ...s, ...(STATE.byId[s.id] || {}) }));
}

function renderChart() {
  const rows = merged().filter(r => r.asr != null)
    .sort((a, b) => b.asr - a.asr);
  if (!rows.length) { $("#chartCard").style.display = "none"; return; }
  const W = 820, lab = 230, h = rows.length * 26 + 10;
  let svg = `<svg viewBox="0 0 ${W} ${h}" width="100%" style="font:12px var(--mono)">`;
  rows.forEach((r, i) => {
    const y = i * 26 + 6, bw = (W - lab - 70) * (r.asr || 0);
    const col = FAMCOL[r.family] || "#888";
    svg += `<text x="0" y="${y + 13}" fill="#cfd8e6">${esc(r.label || r.strategy)}</text>`;
    svg += `<rect x="${lab}" y="${y + 2}" width="${W - lab - 70}" height="14" fill="#1a2230" rx="3"/>`;
    svg += `<rect x="${lab}" y="${y + 2}" width="${Math.max(2, bw)}" height="14" fill="${col}" rx="3"/>`;
    svg += `<text x="${W - 62}" y="${y + 13}" fill="#cfd8e6">${pct(r.asr)}</text>`;
  });
  svg += "</svg>";
  $("#chart").innerHTML = svg;
}

function renderTable() {
  const rows = merged();
  const hlp = t => `<span class="help" data-tip="${t.replace(/"/g,'&quot;')}">?</span>`;
  const head = `<thead><tr><th>Defense</th><th>Family</th>
    <th class=num>ASR ↓${hlp("Attack Success Rate — malicious artifacts the model let through as CLEAN. Adversarial: attacker picks the best placement. Lower is better.")}</th>
    <th class=num>Δ vs none${hlp("Change in ASR vs the undefended baseline, in percentage points. More negative = bigger reduction.")}</th>
    <th class=num>comment${hlp("ASR when the trace is planted in a comment.")}</th>
    <th class=num>print${hlp("ASR when the trace is relocated into print()/echo statements (survives comment stripping).")}</th>
    <th class=num>FP ↓${hlp("False-positive rate on benign artifacts. Lower is better.")}</th>
    <th class=num>Utility ↑${hlp("Detection accuracy on clean controls. Higher is better.")}</th>
    <th class=num>Score ↑${hlp("(1−ASR)·(1−FP)·Utility ×100. Higher = better overall trade-off.")}</th></tr></thead>`;
  const body = rows.map(r => {
    const famc = FAMCOL[r.family] || "#888";
    const pv = r.asr_by_variant || {};
    const d = r.delta_asr_pp;
    const acol = r.asr == null ? "var(--mut)" : (r.asr > .5 ? "var(--mal)" : r.asr > .1 ? "var(--esc)" : "var(--clean)");
    return `<tr>
      <td>${esc(r.label || r.strategy)}<div class="small dim">${esc(r.desc || "")}</div></td>
      <td><span class="famtag" style="color:${famc}">${r.family}</span></td>
      <td class=num style="color:${acol};font-weight:700">${pct(r.asr)}</td>
      <td class=num style="color:${d == null ? "var(--mut)" : (d < 0 ? "var(--clean)" : "var(--mal)")}">${d == null ? "—" : (d > 0 ? "+" : "") + d + "pp"}</td>
      <td class="num dim">${pct(pv.inception)}</td>
      <td class="num dim">${pct(pv.relocated)}</td>
      <td class=num>${pct(r.fp)}</td>
      <td class=num>${pct(r.utility)}</td>
      <td class=num style="font-weight:700">${r.score == null ? "—" : Math.round(r.score * 100)}</td></tr>`;
  }).join("");
  $("#tbl").innerHTML = head + `<tbody>${body}</tbody>`;
}

// --- per-family mechanism diagram (inline SVG) ---
function famDiagram(fam) {
  const C = FAMCOL[fam] || "#888";
  const box = (x, y, w, h, label, fill, stroke, sub) =>
    `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="7" fill="${fill || "#121823"}" stroke="${stroke || "#2b3647"}"/>`
    + `<text x="${x + w / 2}" y="${y + (sub ? h / 2 - 3 : h / 2 + 4)}" fill="#dce7f5" font-size="12" font-weight="600" text-anchor="middle">${label}</text>`
    + (sub ? `<text x="${x + w / 2}" y="${y + h / 2 + 12}" fill="#8a97a8" font-size="10" text-anchor="middle">${sub}</text>` : "");
  const arrow = (x1, y, x2) =>
    `<line x1="${x1}" y1="${y}" x2="${x2 - 7}" y2="${y}" stroke="#46566b" stroke-width="2"/>`
    + `<path d="M${x2 - 8},${y - 4} L${x2},${y} L${x2 - 8},${y + 4} Z" fill="#46566b"/>`;
  const W = 620, H = 108;
  let g = "";
  const trace = `<tspan fill="#ffd27a">⟂trace</tspan>`;
  if (fam === "baseline") {
    g = box(10, 38, 150, 34, "Artifact + trace", "#1b1507", "#5a4a1e")
      + arrow(160, 55, 250) + box(250, 38, 120, 34, "LRM")
      + arrow(370, 55, 460) + box(460, 38, 150, 34, "Verdict: CLEAN", "#2a0f14", "#512")
      + `<text x="10" y="92" fill="#8a97a8" font-size="11">planted trace flows straight into the model → it adopts it</text>`;
  } else if (fam === "surface") {
    g = box(10, 38, 140, 34, "Artifact + trace", "#1b1507", "#5a4a1e")
      + arrow(150, 55, 230) + box(230, 34, 120, 42, "✂ sanitize", "#1a1226", "#43306a", "strip comments/prose")
      + arrow(350, 55, 430) + box(430, 38, 90, 34, "LRM")
      + arrow(520, 55, 590) + box(590, 38, 20, 34, "✓", "#06231a", "#164")
      + `<text x="10" y="96" fill="#8a97a8" font-size="11">removes the text the trace hides in — but relocation (print/echo) can survive</text>`;
  } else if (fam === "structural") {
    g = `<rect x="10" y="20" width="150" height="70" rx="7" fill="none" stroke="${C}" stroke-dasharray="4 3"/>`
      + `<text x="85" y="16" fill="${C}" font-size="10" text-anchor="middle">⟦ fenced data ⟧</text>`
      + box(20, 44, 130, 34, "Artifact + trace", "#1b1507", "#5a4a1e")
      + box(10, 94, 150, 0, "", "", "")
      + arrow(170, 55, 250) + box(250, 30, 130, 50, "LRM", "#121823", "#2b3647", "+ system: data≠thoughts")
      + arrow(380, 55, 470) + box(470, 38, 140, 34, "Verdict: MALICIOUS", "#2a0f14", "#512")
      + `<text x="10" y="104" fill="#8a97a8" font-size="11">isolates untrusted data from instructions → planted reasoning has no authority</text>`;
  } else if (fam === "detector") {
    g = box(10, 38, 130, 34, "Artifact + trace", "#1b1507", "#5a4a1e")
      + arrow(140, 55, 220) + box(220, 32, 120, 46, "🔍 detector", "#241a06", "#653", "planted-CoT / guard")
      + `<path d="M340,55 L400,30" stroke="#46566b" stroke-width="2"/><path d="M340,55 L400,80" stroke="#46566b" stroke-width="2"/>`
      + box(405, 14, 110, 30, "flag → BLOCK", "#2a0f14", "#512")
      + box(405, 66, 110, 30, "clear → LRM", "#06231a", "#164")
      + `<text x="10" y="104" fill="#8a97a8" font-size="11">gate the artifact before the model; block anything that reads like an injected trace</text>`;
  } else { // architectural
    g = box(10, 38, 120, 34, "Artifact + trace", "#1b1507", "#5a4a1e")
      + `<path d="M130,55 L200,32" stroke="#46566b" stroke-width="2"/><path d="M130,55 L200,80" stroke="#46566b" stroke-width="2"/>`
      + box(200, 18, 150, 30, "LRM (may be fooled)", "#121823", "#2b3647")
      + box(200, 66, 180, 30, "non-LLM scan / N-model vote", "#06231a", "#1c4a33")
      + arrow(385, 60, 450) + box(450, 44, 90, 34, "combine", "#1a2a1f", "#2f6b4a")
      + arrow(540, 60, 600) + box(600, 44, 14, 34, "✓", "#06231a", "#164")
      + `<text x="10" y="104" fill="#8a97a8" font-size="11">cross-check the LRM with a signature scan / other models; disagreement → override/escalate</text>`;
  }
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" style="max-width:640px;font-family:var(--mono)">${g}</svg>`;
}

// ---- per-method mechanism diagram (horizontal pipeline) ----
function dbox(x, y, w, h, label, fill, stroke, sub) {
  return `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="7" fill="${fill || "#121823"}" stroke="${stroke || "#2b3647"}"/>`
    + `<text x="${x + w / 2}" y="${y + (sub ? h / 2 - 3 : h / 2 + 4)}" fill="#dce7f5" font-size="11.5" font-weight="600" text-anchor="middle">${label}</text>`
    + (sub ? `<text x="${x + w / 2}" y="${y + h / 2 + 12}" fill="#8a97a8" font-size="9.5" text-anchor="middle">${sub}</text>` : "");
}
function darr(x1, x2, y) {
  return `<line x1="${x1}" y1="${y}" x2="${x2 - 7}" y2="${y}" stroke="#46566b" stroke-width="2"/>`
    + `<path d="M${x2 - 8},${y - 4} L${x2},${y} L${x2 - 8},${y + 4} Z" fill="#46566b"/>`;
}
// each method: ordered list of stage boxes between Artifact and the LRM/Verdict
const MECH = {
  none: { stages: [], caption: "planted trace flows straight into the model → it adopts it" },
  strip_comments: { stages: [["✂ strip comments", "surface"]], caption: "remove comment text the trace hides in — relocation into print()/echo can survive" },
  code_only: { stages: [["✂ strip comments + prose", "surface"]], caption: "also blanks long prose string literals; many short relocated strings can slip through" },
  narrative_scrub: { stages: [["✂ remove deliberation lines", "surface"]], caption: "deletes lines that read as reasoning (pronoun/step/verdict cues); brittle to paraphrase" },
  sandwich: { stages: [["⟲ repeat task after data", "structural"]], caption: "re-assert the instruction after the artifact + remind that embedded reasoning is untrusted" },
  spotlight: { stages: [["⟦ random-fenced data ⟧", "structural"]], caption: "fence untrusted data with an unforgeable marker; forbid honoring anything inside" },
  datamark: { stages: [["░ sentinel between tokens", "structural"]], caption: "break up planted prose so it can't read as fluent native thought" },
  encoding: { stages: [["base64 encode", "structural"], ["model decodes", "structural"]], caption: "no fluent planted prose sits directly in context; model decodes then analyzes" },
  hierarchy: { stages: [["system: in-data rules = 0 authority", "structural"]], caption: "instruction hierarchy — reasoning embedded in data was not produced by the model" },
  trace_detector: { gate: ["🔍 planted-CoT classifier", "detector"], caption: "block artifacts that read like an injected reasoning trace before the model is called" },
  llama_guard: { gate: ["🔍 Llama-Guard-3", "detector"], caption: "off-the-shelf safety/injection detector gates the artifact (paper: largely blind to the trace)" },
  signature_crosscheck: { post: ["non-LLM signature scan", "architectural"], caption: "scanner ignores comments; if it sees an exec sink but the LRM says CLEAN → override to MALICIOUS" },
  nmodel_vote: { vote: true, caption: "query several LRMs; majority rules, disagreement escalates — one fooled model can't pass it alone" },
  defense_in_depth: { stages: [["✂ strip", "surface"], ["⟲ sandwich", "structural"]], gate: ["🔍 planted-CoT", "detector"], post: ["signature override", "architectural"], caption: "layers: sanitize + isolate + detector pre-filter + non-LLM cross-check" },
};
function methodDiagram(id) {
  const m = MECH[id] || MECH.none, W = 640, H = 120, y = 44;
  const col = f => FAMCOL[f] || "#2b3647";
  const fillFor = f => ({surface:"#1a1226", structural:"#101f36", detector:"#241a06", architectural:"#06231a"}[f] || "#121823");
  let g = dbox(8, y, 120, 34, "Artifact + trace", "#1b1507", "#5a4a1e"), x = 128;
  // gate (detector): branch to BLOCK / LRM
  if (m.gate && !m.stages && !m.post) {
    g += darr(x, x + 60, y + 17) + dbox(x + 60, y - 2, 140, 42, m.gate[0], fillFor(m.gate[1]), col(m.gate[1]));
    const gx = x + 200;
    g += `<path d="M${gx},${y + 17} L${gx + 55},${y - 14}" stroke="#46566b" stroke-width="2"/><path d="M${gx},${y + 17} L${gx + 55},${y + 48}" stroke="#46566b" stroke-width="2"/>`;
    g += dbox(gx + 58, y - 30, 120, 28, "flag → BLOCK", "#2a0f14", "#512");
    g += dbox(gx + 58, y + 34, 120, 28, "clear → LRM", "#06231a", "#164");
    return wrapSvg(g, m.caption, W, H);
  }
  // vote (architectural ensemble)
  if (m.vote) {
    g += `<path d="M${x},${y + 17} L${x + 50},${y - 10}" stroke="#46566b" stroke-width="2"/><path d="M${x},${y + 17} L${x + 50},${y + 17}" stroke="#46566b" stroke-width="2"/><path d="M${x},${y + 17} L${x + 50},${y + 44}" stroke="#46566b" stroke-width="2"/>`;
    g += dbox(x + 52, y - 24, 110, 26, "LRM A");
    g += dbox(x + 52, y + 4, 110, 26, "LRM B");
    g += dbox(x + 52, y + 32, 110, 26, "LRM C");
    g += darr(x + 162, x + 230, y + 17) + dbox(x + 232, y, 140, 34, "majority / escalate", "#06231a", "#1c4a33");
    g += darr(x + 372, x + 440, y + 17) + dbox(x + 440, y, 100, 34, "Verdict");
    return wrapSvg(g, m.caption, W, H);
  }
  // linear: Artifact → [stages…] → LRM → [post?] → Verdict
  (m.stages || []).forEach(st => { g += darr(x, x + 56, y + 17); x += 56; g += dbox(x, y - 2, 132, 42, st[0], fillFor(st[1]), col(st[1])); x += 132; });
  g += darr(x, x + 56, y + 17); x += 56; g += dbox(x, y, 96, 34, "LRM"); x += 96;
  if (m.post) { g += darr(x, x + 56, y + 17); x += 56; g += dbox(x, y - 2, 150, 42, m.post[0], fillFor(m.post[1]), col(m.post[1])); x += 150; }
  g += darr(x, Math.min(x + 54, W - 96), y + 17);
  g += dbox(Math.min(x + 54, W - 94), y, 90, 34, m.post ? "override" : "Verdict", m.post ? "#2a0f14" : "#121823", m.post ? "#512" : "#2b3647");
  return wrapSvg(g, m.caption, W, Math.max(H, y + 44));
}
function wrapSvg(g, caption, W, H) {
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" style="max-width:660px;font-family:var(--mono)">${g}`
    + `<text x="8" y="${H - 8}" fill="#8a97a8" font-size="10.5">${esc(caption)}</text></svg>`;
}

function renderMethodNames() {
  const host = $("#defNames");
  host.innerHTML = STATE.families.map(fam => {
    const items = STATE.strategies.filter(s => s.family === fam);
    if (!items.length) return "";
    const rows = items.map(s => {
      const r = STATE.byId[s.id] || {};
      const chip = r.asr == null ? "" :
        `<span class="mono small" style="color:${r.asr > .5 ? "var(--mal)" : r.asr > .1 ? "var(--esc)" : "var(--clean)"}">${pct(r.asr)}</span>`;
      return `<div class="mname" data-id="${s.id}">
        <span class="sdot2" style="background:${FAMCOL[fam]}"></span>
        <span style="flex:1">${esc(s.label)}</span>${chip}</div>`;
    }).join("");
    return `<div class="famtag" style="color:${FAMCOL[fam]};margin:10px 0 4px">${fam}</div>${rows}`;
  }).join("");
  $$(".mname", host).forEach(el => el.onclick = () => showMethod(el.dataset.id));
  showMethod(STATE.strategies[0].id);
}

function showMethod(id) {
 try {
  $$(".mname").forEach(el => el.classList.toggle("on", el.dataset.id === id));
  const s = STATE.strategies.find(x => x.id === id) || {};
  const r = STATE.byId[id] || {};
  const pv = r.asr_by_variant || {};
  const stat = r.asr == null ? `<span class="dim">not measured in the shipped stats</span>` :
    `<span class="mono">ASR <b style="color:${r.asr > .5 ? "var(--mal)" : r.asr > .1 ? "var(--esc)" : "var(--clean)"}">${pct(r.asr)}</b>
      · Δ ${r.delta_asr_pp == null ? "—" : (r.delta_asr_pp > 0 ? "+" : "") + r.delta_asr_pp + "pp"}
      · comment ${pct(pv.inception)} · print ${pct(pv.relocated)}
      · FP ${pct(r.fp)} · utility ${pct(r.utility)} · score ${r.score == null ? "—" : Math.round(r.score * 100)}</span>`;
  $("#defDetail").innerHTML = `
    <div class="row"><h3 style="margin:0">${esc(s.label)}</h3>
      <span class="famtag" style="color:${FAMCOL[s.family]}">${s.family}</span></div>
    <div class="muted small" style="margin:6px 0 4px">${esc(s.desc || "")}</div>
    <div class="hint" style="margin-bottom:8px">expected: ${esc(s.expect || "")}</div>
    <div class="card" style="margin:0;background:#0c1118">${methodDiagram(id)}</div>
    <div class="small" style="margin-top:10px">${stat}</div>`;
 } catch(e){ $("#defDetail").innerHTML = `<div class="reason" style="border-left-color:var(--mal)">showMethod error: ${esc(String(e && e.stack || e))}</div>`; }
}

function exportCsv() {
  const rows = merged();
  const cols = ["strategy", "label", "family", "asr", "delta_asr_pp", "fp", "utility", "score"];
  const csv = [cols.join(",")].concat(rows.map(r => cols.map(c => r[c] ?? "").join(","))).join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  a.download = "defense_stats.csv"; a.click();
}

boot();
