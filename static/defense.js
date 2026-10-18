"use strict";
const $ = (s, r = document) => r.querySelector(s);
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
  renderChart(); renderTable(); renderFamilies();
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

function renderFamilies() {
  const host = $("#families");
  host.innerHTML = STATE.families.map(fam => {
    const items = STATE.strategies.filter(s => s.family === fam);
    if (!items.length) return "";
    const cards = items.map(s => {
      const r = STATE.byId[s.id] || {};
      const num = r.asr == null ? "" :
        `<div class="small mono" style="margin-top:6px">measured ASR
          <b style="color:${r.asr > .5 ? "var(--mal)" : r.asr > .1 ? "var(--esc)" : "var(--clean)"}">${pct(r.asr)}</b>
          · FP ${pct(r.fp)} · utility ${pct(r.utility)}</div>`;
      return `<div class="card" style="margin:0">
        <div style="font-weight:700">${esc(s.label)}</div>
        <div class="small muted" style="margin:4px 0">${esc(s.desc)}</div>
        <div class="hint">expected: ${esc(s.expect || "")}</div>${num}</div>`;
    }).join("");
    return `<h3 style="color:${FAMCOL[fam]};margin:18px 0 8px;text-transform:capitalize">${fam} defenses</h3>
      <div class="card" style="margin-bottom:10px">${famDiagram(fam)}</div>
      <div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(300px,1fr))">${cards}</div>`;
  }).join("");
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
