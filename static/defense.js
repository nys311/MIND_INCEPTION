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
  renderChart(); renderTable(); DefMethods.renderMaster($("#defNames"), $("#defDetail"), STATE.strategies, STATE.families, STATE.byId);
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
    svg += `<text x="0" y="${y + 13}" fill="var(--svg-ink)">${esc(r.label || r.strategy)}</text>`;
    svg += `<rect x="${lab}" y="${y + 2}" width="${W - lab - 70}" height="14" fill="var(--track)" rx="3"/>`;
    svg += `<rect x="${lab}" y="${y + 2}" width="${Math.max(2, bw)}" height="14" fill="${col}" rx="3"/>`;
    svg += `<text x="${W - 62}" y="${y + 13}" fill="var(--svg-ink)">${pct(r.asr)}</text>`;
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


function exportCsv() {
  const rows = merged();
  const cols = ["strategy", "label", "family", "asr", "delta_asr_pp", "fp", "utility", "score"];
  const csv = [cols.join(",")].concat(rows.map(r => cols.map(c => r[c] ?? "").join(","))).join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  a.download = "defense_stats.csv"; a.click();
}

boot();
