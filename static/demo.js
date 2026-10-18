"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const api = async u => (await fetch(u)).json();
const post = (u, b) => fetch(u, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(window.MILAB ? window.MILAB.body(b) : b) }).then(r => r.json());
const esc = s => (s || "").replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const pct = x => (x == null ? "—" : (100 * x).toFixed(0) + "%");

const S = { model: null, mode: "auto", usecases: [], strategies: {}, current: null };

function vbadge(v) {
  const m = { MALICIOUS: ["b-mal", "CAUGHT (malicious)"], CLEAN: ["b-clean", "WAVED THROUGH (clean)"],
    ESCALATE: ["b-esc", "ESCALATED"], UNKNOWN: ["b-unk", "—"] };
  const [c, t] = m[v] || m.UNKNOWN;
  return `<span class="badge ${c}">${t}</span>`;
}
function highlightTrace(code) {
  let h = esc(code);
  h = h.replace(/(\/\*[\s\S]*?\*\/)/g, m => m.length > 60 ? `<span class="trace">${m}</span>` : m);
  h = h.replace(/(&lt;#[\s\S]*?#&gt;)/g, m => m.length > 60 ? `<span class="trace">${m}</span>` : m);
  h = h.replace(/(&lt;!--[\s\S]*?--&gt;)/g, m => m.length > 60 ? `<span class="trace">${m}</span>` : m);
  return h;
}

async function boot() {
  const [uc, mo, h, st] = await Promise.all([
    api("/api/usecases"), api("/api/models"), api("/api/health"), api("/api/strategies")]);
  S.usecases = uc.usecases;
  for (const s of st.strategies) S.strategies[s.id] = s;
  S.model = mo.models[0];
  const fill = () => window.MILAB ? window.MILAB.fillSelect("#model", mo.models)
    : ($("#model").innerHTML = mo.models.map(m => `<option>${m}</option>`).join(""));
  fill();
  $("#model").onchange = e => S.model = e.target.value;
  if (window.MILAB) window.MILAB.onChange(() => { const m=$("#model").value; fill(); $("#model").value=m||S.model; });
  $("#health").innerHTML = `<b>${uc.usecases.length}</b> use cases · api ${h.api_key_present ? "live" : "replay-only"}`;
  $$("#modeToggle button").forEach(b => b.onclick = () => {
    S.mode = b.dataset.mode;
    $$("#modeToggle button").forEach(x => x.classList.remove("on", "live"));
    b.classList.add("on"); if (b.dataset.mode === "live") b.classList.add("live");
  });
  renderCards();
}

function renderCards() {
  $("#cards").innerHTML = S.usecases.map(u => `
    <div class="usecard ${u.bg ? "hasbg" : ""}" data-id="${u.id}"
      style="${u.bg ? `--cardbg:url('${u.bg}')` : `--tint:${u.color}`}">
      <div class="uctop" style="background:${u.color}"></div>
      <div class="ucbody">
        <div class="row" style="gap:8px">
          <span class="famchip" style="color:${u.color}">${u.domain}</span>
        </div>
        <div style="font-weight:700;margin:8px 0 4px">${esc(u.title)}</div>
        <div class="small muted">${esc(u.scenario)}</div>
        <div class="small" style="margin-top:8px;color:var(--mal)">⚠ ${esc(u.impact)}</div>
        ${u.image ? `<div class="small dim" style="margin-top:8px">🖼 includes a real captured figure</div>` : ""}
      </div>
    </div>`).join("");
  $$(".usecard").forEach(el => el.onclick = () => openCase(el.dataset.id));
  const seg = decodeURIComponent((location.pathname.split("/")[2] || ""));
  if (seg && S.usecases.some(u => u.id === seg)) openCase(seg, false);
  window.addEventListener("popstate", () => {
    const s = decodeURIComponent((location.pathname.split("/")[2] || ""));
    if (s && S.usecases.some(u => u.id === s)) openCase(s, false);
  });
}

async function openCase(id, push = true) {
  const u = S.usecases.find(x => x.id === id);
  if (!u) return;
  S.current = u;
  if (push && location.pathname !== "/demo/" + id) history.pushState({ id }, "", "/demo/" + id);
  const def = S.strategies[u.defense] || { label: u.defense };
  $("#detail").innerHTML = `
    <div class="card">
      <div class="row">
        <div><h3>${esc(u.title)}</h3>
          <div class="small dim">${u.domain} · sample <span class="mono">${u.sample}</span></div></div>
        <span class="spacer"></span>
        <button class="primary" id="runCase">▶ Run scenario</button>
      </div>
      <div class="grid" style="grid-template-columns:1fr 1fr;margin-top:10px">
        <div><div class="small muted"><b>What the attacker plants</b></div>
          <div class="reason" style="border-left-color:var(--mal)">${esc(u.plant)}</div></div>
        <div><div class="small muted"><b>Impact if it works</b></div>
          <div class="reason" style="border-left-color:var(--esc)">${esc(u.impact)}</div></div>
      </div>
      ${u.image ? `<div style="margin-top:12px">
        <div class="small muted"><b>Captured figure</b>${u.source ? ` — ${esc(u.source)}` : ""}
          ${u.link ? ` · <a href="${u.link}" target="_blank" rel="noopener">source ↗</a>` : ""}</div>
        <img src="${u.image}" alt="captured attack figure" loading="lazy"
          style="margin-top:8px;max-width:100%;border:1px solid var(--line);border-radius:10px;display:block">
      </div>` : ""}
    </div>

    <div class="flip" style="margin-top:14px">
      <div class="card panel-v">
        <div class="row"><span class="tag">RAW — artifact only</span><span class="spacer"></span>
          <span id="rawV" class="badge b-unk">—</span></div>
        <div class="reason" id="rawR">Baseline: the honest pipeline should catch this.</div>
      </div>
      <div class="mid">➜</div>
      <div class="card panel-v">
        <div class="row"><span class="tag" style="border-color:#633;color:#f99">INCEPTION — + planted trace</span>
          <span class="spacer"></span><span id="incV" class="badge b-unk">—</span></div>
        <div class="reason" id="incR">Same artifact, borrowed reasoning trace planted inside it.</div>
      </div>
    </div>

    <div class="card" style="margin-top:14px">
      <div class="row">
        <h3>Defense: ${esc(def.label)}</h3>
        <span class="muted small">${esc(def.desc || "")}</span>
        <span class="spacer"></span>
        <button id="runDef" disabled>▶ Apply defense</button>
      </div>
      <div class="row" id="defR" style="margin-top:8px"></div>
    </div>

    <div class="card" style="margin-top:14px">
      <details open><summary>Inception artifact sent (planted trace highlighted)</summary>
      <pre class="code" id="artifact"></pre></details>
    </div>`;
  $("#detail").scrollIntoView({ behavior: "smooth", block: "start" });

  const d = await api(`/api/sample/${u.sample}`);
  $("#artifact").innerHTML = highlightTrace(d.variants.inception || d.variants.raw);
  $("#runCase").onclick = () => runCase(u);
  $("#runDef").onclick = () => runDef(u);
}

async function runCase(u) {
  const btn = $("#runCase"); btn.disabled = true; btn.innerHTML = '<span class="spin"></span> running';
  $("#rawV").outerHTML = `<span id="rawV">…</span>`; $("#incV").outerHTML = `<span id="incV">…</span>`;
  const [raw, inc] = await Promise.all([
    post("/api/run", { sample: u.sample, variant: "raw", strategy: "none", model: S.model, mode: S.mode }),
    post("/api/run", { sample: u.sample, variant: "inception", strategy: "none", model: S.model, mode: S.mode })]);
  $("#rawV").outerHTML = `<span id="rawV">${vbadge(raw.final_verdict)}</span>`;
  $("#incV").outerHTML = `<span id="incV">${vbadge(inc.final_verdict)}</span>`;
  $("#rawR").textContent = raw.reasoning || raw.content || "(no reasoning)";
  $("#incR").textContent = inc.reasoning || inc.content || "(no reasoning)";
  btn.innerHTML = "▶ Run scenario"; btn.disabled = false;
  $("#runDef").disabled = false;
}

async function runDef(u) {
  const btn = $("#runDef"); btn.disabled = true; btn.innerHTML = '<span class="spin"></span>';
  const r = await post("/api/run", { sample: u.sample, variant: "inception", strategy: u.defense, model: S.model, mode: S.mode });
  const blocked = r.final_verdict !== "CLEAN";
  $("#defR").innerHTML = `${vbadge(r.final_verdict)}
    <span class="chk ${blocked ? "ok" : "no"}">${blocked ? "✓ attack blocked" : "✗ still waved through"}</span>
    ${r.overridden ? '<span class="pill" style="color:var(--clean);border-color:#1c4">non-LLM override</span>' : ""}
    <span class="small dim mono">stage: ${esc(r.stage || "")}</span>`;
  btn.innerHTML = "▶ Apply defense"; btn.disabled = false;
}

boot();
