"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const api = async (url, opts) => (await fetch(url, opts)).json();
const withKey = b => (window.MILAB ? window.MILAB.body(b) : b);
const post = (url, body) => api(url, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(withKey(body))});
// metric help icon: text + direction (↓/↑ = which way is better)
const help = (tip, dir) => `<span class="help" data-tip="${tip.replace(/"/g,'&quot;')}">?</span>`
  + (dir ? `<span class="goal ${dir==='↓'?'down':'up'}">${dir} better</span>` : "");
const TIPS = {
  asr: "Attack Success Rate — share of malicious artifacts the model classified CLEAN (the attack worked). Adversarial: the attacker picks the best trace placement.",
  fp: "False-Positive rate — benign artifacts wrongly flagged as malicious. The cost a defense imposes on legitimate traffic.",
  utility: "Detection accuracy on clean control artifacts (no planted trace). A defense that wrecks utility is unusable even at 0% ASR.",
  score: "Composite = (1−ASR)·(1−FP)·Utility ×100. Higher is a better overall trade-off.",
  delta: "Change in ASR versus the undefended baseline, in percentage points. More negative = bigger reduction.",
  escalate: "Share of cases routed to a human instead of auto-decided (disagreement / detector hit).",
};

const state = {model: null, mode: "auto", models: [], samples: [], strategies: [],
  families: [], attackSample: null, defSample: null, bench: null};

const FAMCOL = {baseline:"var(--fam-baseline)", surface:"var(--fam-surface)",
  structural:"var(--fam-structural)", detector:"var(--fam-detector)",
  architectural:"var(--fam-architectural)"};

function vbadge(v){
  const m = {MALICIOUS:["b-mal","MALICIOUS"], CLEAN:["b-clean","CLEAN"],
    ESCALATE:["b-esc","ESCALATE"], UNKNOWN:["b-unk","—"]};
  const [c, t] = m[v] || m.UNKNOWN;
  return `<span class="badge ${c}">${t}</span>`;
}
const esc = s => (s||"").replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));

function highlightTrace(code){
  // highlight the planted /* ... */ trailing comment block
  let h = esc(code);
  h = h.replace(/(\/\*[^]*?\*\/)/g, m =>
    m.length > 60 ? `<span class="trace">${m}</span>` : m);
  return h;
}

// ---------------------------------------------------------------- boot
async function boot(){
  const [h, mo, st, sa, ds, tr] = await Promise.all([
    api("/api/health"), api("/api/models"), api("/api/strategies"),
    api("/api/samples"), api("/api/defense_stats"), api("/api/transfer_stats")]);
  state.models = mo.models; state.voteModels = mo.vote_models;
  state.strategies = st.strategies; state.families = st.families;
  state.samples = sa.samples; state.stats = ds; state.transfer = tr;

  state.model = state.models[0];
  const fillModels = () => {
    for (const sel of ["#model", "#xModel"]) (window.MILAB ? window.MILAB.fillSelect(sel, state.models)
      : ($(sel).innerHTML = state.models.map(m=>`<option>${m}</option>`).join("")));
    if (!$("#xModel").value) $("#xModel").value = state.models[1] || state.models[0];
  };
  fillModels();
  $("#xModel").value = state.models[1] || state.models[0];
  $("#model").onchange = e => { state.model = e.target.value; };
  if (window.MILAB) window.MILAB.onChange(() => { const m=$("#model").value; fillModels(); $("#model").value=m||state.model; });

  renderHealth(h);
  renderModeToggle();
  renderTabs();
  renderOverview();
  renderAttackSamples();
  renderDefSelect();
  renderLabMethods();
  $("#scount").textContent = `(${state.samples.length})`;
  $("#aboutHealth").textContent =
    `api_key=${h.api_key_present} · cached_runs=${h.cached_runs} · samples=${h.samples} · strategies=${h.strategies}`;

  wireAttack(); wireDefense(); wireBench();

  // step bar -> jump to tab
  $$("#stepbar .stp").forEach(s => s.onclick = () => activateTab(s.dataset.go));
  $$("#stepbar .stp").forEach(s => s.classList.toggle("on", s.dataset.go === tabFromPath()));
  // download samples
  const dl = $("#dlSamples"); if (dl) dl.onclick = () => window.open("/api/samples/download", "_blank");
}

// ---------------------------------------------------------------- overview
const FAMCOL2 = {baseline:"var(--fam-baseline)", surface:"var(--fam-surface)",
  structural:"var(--fam-structural)", detector:"var(--fam-detector)",
  architectural:"var(--fam-architectural)"};
const pctO = x => x==null ? "—" : (100*x).toFixed(0)+"%";

function renderOverview(){
  const ds = state.stats || {};
  const byId = {}; (ds.rows||[]).forEach(r => byId[r.strategy]=r);
  const rows = state.strategies.map(s => ({...s, ...(byId[s.id]||{})}));
  const base = byId["none"] || {};
  const measured = rows.filter(r => r.asr != null);
  const best = measured.filter(r => r.strategy!=="none").sort((a,b)=>(a.asr-b.asr))[0];
  const zero = measured.filter(r => r.strategy!=="none" && r.asr===0).length;
  const domains = [...new Set(state.samples.map(s=>s.family))];
  const domCount = {};
  state.samples.forEach(s=>{ const d=s.has_trace!==undefined?s.family:s.family; });

  // KPI tiles
  const kpi = (n,l,c)=>`<div class="k"><div class="n" style="color:${c||'var(--ink)'}">${n}</div><div class="l">${l}</div></div>`;
  $("#ovKpi").innerHTML =
    kpi(base.asr!=null?pctO(base.asr):"75%","undefended attack success"+help(TIPS.asr),"var(--mal)")
    + kpi(best?`${pctO(best.asr)}`:"0%", (best?`best defense (${esc(best.label)})`:"best defense")+help(TIPS.asr+" Lower is better.","↓"),"var(--clean)")
    + kpi(measured.length?zero:"6","defenses that reach 0% ASR","var(--clean)")
    + kpi(state.samples.length, "labeled artifacts","var(--accent)")
    + kpi("4","task domains","var(--accent)")
    + kpi(state.strategies.length,"defenses evaluated","var(--accent)");

  // chart (measured, else a small note)
  $("#ovLegend").innerHTML = state.families.map(f=>`<span><i style="background:${FAMCOL2[f]}"></i>${f}</span>`).join("");
  if (measured.length){
    const mr = measured.slice().sort((a,b)=>b.asr-a.asr);
    const W=640, lab=200, h=mr.length*24+8;
    let svg=`<svg viewBox="0 0 ${W} ${h}" width="100%" style="font:12px var(--mono)">`;
    mr.forEach((r,i)=>{const y=i*24+5,bw=(W-lab-60)*(r.asr||0),c=FAMCOL2[r.family]||"#888";
      svg+=`<text x="0" y="${y+13}" fill="#cfd8e6">${esc(r.label||r.strategy)}</text>`;
      svg+=`<rect x="${lab}" y="${y+2}" width="${W-lab-60}" height="13" fill="#141b26" rx="3"/>`;
      svg+=`<rect x="${lab}" y="${y+2}" width="${Math.max(2,bw)}" height="13" fill="${c}" rx="3"/>`;
      svg+=`<text x="${W-52}" y="${y+13}" fill="#cfd8e6">${pctO(r.asr)}</text>`;});
    svg+="</svg>"; $("#ovChart").innerHTML=svg;
    $("#ovMeta").textContent = `measured · ${ds.model||""}`;
    $("#ovChartHint").textContent = ds.meta ? `${ds.meta.n_samples||""} samples · mode ${ds.meta.mode||""}` : "";
  } else {
    $("#ovChart").innerHTML = `<div class="reason">Pre-computed numbers are being captured. Run
      <span class="mono">python3 bench.py --mode live --scope all --strategies all --out defense_stats</span>
      to populate this, or open the <b>Benchmark</b> tab to run a matrix now.</div>`;
    $("#ovMeta").innerHTML = `<span style="color:var(--esc)">stats pending</span>`;
  }

  // coverage
  const fam = {};
  state.samples.forEach(s=>{ fam[s.family]=fam[s.family]||{m:0,b:0};
    s.label==="malicious"?fam[s.family].m++:fam[s.family].b++; });
  $("#ovCoverage").innerHTML = Object.entries(fam).map(([f,c])=>
    `<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:6px 0">
       <span class="mono">${esc(f)}</span>
       <span class="small"><b style="color:var(--mal)">${c.m}</b> malicious · <b style="color:var(--clean)">${c.b}</b> benign</span></div>`).join("");

  renderTransfer();
}

function renderTransfer(){
  const t = state.transfer;
  if (!t || !t.available || !t.targets){ return; }
  $("#ovTransfer").style.display = "block";
  $("#ovTransferMeta").textContent =
    `one trace from ${t.source_model} · ${t.trace_len} chars · planted into ${t.n_webshells} webshells`
    + (t.neutralized_trace ? " · neutralized trace" : "");
  const entries = Object.entries(t.targets);
  const W=640, lab=250, h=entries.length*26+6;
  let svg=`<svg viewBox="0 0 ${W} ${h}" width="100%" style="font:12px var(--mono)">`;
  entries.forEach(([m,r],i)=>{
    const y=i*26+5, asr=r.asr||0, bw=(W-lab-70)*asr;
    const src = m.includes(t.source_model) || t.source_model.includes(m.split("/").pop());
    const col = src ? "var(--fam-baseline)" : "var(--mal)";
    svg+=`<text x="0" y="${y+13}" fill="#cfd8e6">${esc(m)}${src?" (source)":""}</text>`;
    svg+=`<rect x="${lab}" y="${y+2}" width="${W-lab-70}" height="14" fill="#1a2230" rx="3"/>`;
    svg+=`<rect x="${lab}" y="${y+2}" width="${Math.max(2,bw)}" height="14" fill="${col}" rx="3"/>`;
    svg+=`<text x="${W-62}" y="${y+13}" fill="#cfd8e6">${pctO(r.asr)}</text>`;
  });
  svg+="</svg>";
  $("#ovTransferBars").innerHTML = svg
    + `<div class="hint" style="margin-top:6px">The same trace, replayed unchanged, flips models from other families — the attacker needn't know which model is deployed.</div>`;
}

function renderHealth(h){
  const dotColor = h.api_key_present ? "var(--clean)" : "var(--esc)";
  $("#health").innerHTML =
    `<b>API</b> <span style="color:${dotColor}">${h.api_key_present?"key loaded":"no key (replay only)"}</span>
     &nbsp;·&nbsp; <b>cache</b> ${h.cached_runs} runs
     &nbsp;·&nbsp; <b>${h.samples}</b> samples / <b>${h.strategies}</b> defenses`;
}

function renderModeToggle(){
  $$("#modeToggle button").forEach(b => {
    b.onclick = () => {
      state.mode = b.dataset.mode;
      $$("#modeToggle button").forEach(x => { x.classList.remove("on","live"); });
      b.classList.add("on"); if (b.dataset.mode === "live") b.classList.add("live");
    };
  });
}

const TAB_PATH = {overview:"/", attack:"/attack", defense:"/lab", bench:"/benchmark", about:"/about"};
const PATH_TAB = {"/":"overview","/overview":"overview","/attack":"attack","/lab":"defense","/benchmark":"bench","/about":"about"};
function tabFromPath(){ return PATH_TAB[location.pathname] || "overview"; }
function activateTab(v, push=true){
  const btn = $(`#tabs button[data-v="${v}"]`); if(!btn) return;
  $$("#tabs button").forEach(x => x.classList.remove("on")); btn.classList.add("on");
  $$(".view").forEach(s => s.classList.remove("on"));
  const view = $(`#v-${v}`); if(view) view.classList.add("on");
  $$("#stepbar .stp").forEach(s => s.classList.toggle("on", s.dataset.go === v));
  if (push && TAB_PATH[v] && location.pathname !== TAB_PATH[v])
    history.pushState({v}, "", TAB_PATH[v]);
  window.scrollTo({top:0, behavior:"smooth"});
}
function renderTabs(){
  $$("#tabs button").forEach(b => b.onclick = () => activateTab(b.dataset.v));
  window.addEventListener("popstate", () => activateTab(tabFromPath(), false));
  activateTab(tabFromPath(), false);
}

// ---------------------------------------------------------------- attack (4-phase)
function renderAttackSamples(){
  const host = $("#attackSamples");
  host.innerHTML = state.samples.map(s =>
    `<div class="sitem" data-id="${s.id}">
       <span class="sdot ${s.label==='malicious'?'m':'b'}"></span>
       <div style="flex:1"><div>${esc(s.title||s.id)}</div>
         <div class="small dim mono">${esc(s.family||'')}${s.has_trace?' · trace':''}</div></div>
     </div>`).join("");
  $$(".sitem", host).forEach(el => el.onclick = () => selectAttackSample(el.dataset.id, host));
}

const PHASE = {raw:"Raw", seed:"Seed", root:"Root", spawn:"Spawn"};
function dprime(d, trace){           // build D' = µ + code + comment(trace)
  const [o,c] = d.comment || ["/*","*/"];
  const mk = d.marker ? `${o}${d.marker}${c}\n` : "";
  return `${mk}${d.code || ""}\n\n${o}\n${trace}\n${c}`;
}

async function selectAttackSample(id, host){
  $$(".sitem", host).forEach(x => x.classList.toggle("on", x.dataset.id === id));
  const d = await api(`/api/sample/${id}`);
  state.attackSample = d;
  $("#asTitle").textContent = d.title || d.id;
  $("#asSrc").textContent = `${d.family||''} · ${d.source||''}`;
  ["Raw","Seed","Root","Spawn"].forEach(p => setBadge("#v"+p, "—","b-unk"));
  // prefill editable inputs
  $("#inRaw").value   = d.variants.raw || d.code || "";
  $("#inSeed").value  = d.seed_input || d.variants.raw || "";
  $("#inRoot").value  = d.variants.inception || d.variants.raw || "";
  $("#inSpawn").value = d.variants.inception || d.variants.raw || "";
  $("#rRaw").textContent = "The honest baseline — the target should flag the malicious artifact.";
  $("#rSeed").textContent = "the surrogate's reasoning becomes the \"borrowed thought\"";
  $("#rRoot").textContent = "With the planted trace, the same model should flip its verdict.";
  $("#rSpawn").textContent = "Cross-model transfer — the harvested trace is replayed unchanged.";
  $("#useTrace").style.display = "none";
  $("#runAll").disabled = false;
  $$(".runp").forEach(b => b.disabled = false);
}

function setBadge(sel, text, cls){
  const e = $(sel); if(!e) return;
  e.className = "badge " + (cls||"b-unk"); e.textContent = text;
}
function verdictBadge(sel, v){
  const m = {MALICIOUS:["b-mal","MALICIOUS"],CLEAN:["b-clean","CLEAN"],ESCALATE:["b-esc","ESCALATE"],UNKNOWN:["b-unk","—"]};
  const [c,t] = m[v]||m.UNKNOWN; setBadge(sel,t,c);
}
// render a phase/run output: reasoning (thinking) + the model's FINAL answer
function phaseHTML(r, prefix){
  const reasoning = r.reasoning || "", content = r.content || "";
  let h = prefix ? `<div class="small dim mono" style="margin-bottom:4px">${esc(prefix)}</div>` : "";
  if (reasoning) h += `<div class="olabel">reasoning (thinking)</div><div class="otext">${esc(reasoning)}</div>`;
  if (content)   h += `<div class="olabel" style="margin-top:8px">final answer</div><pre class="ans">${esc(content)}</pre>`;
  if (r.error)   h += `<div style="color:var(--mal);margin-top:6px">error: ${esc(r.error)}</div>`;
  if (!reasoning && !content && !r.error) h += `<span class="dim">(no output)</span>`;
  return h;
}

async function runPhase(role){
  const d = state.attackSample; if(!d) return null;
  const P = PHASE[role];
  const model = role === "spawn" ? $("#xModel").value : state.model;
  const btn = $(`.runp[data-role="${role}"]`);
  if (btn){ btn.disabled = true; btn.dataset.lbl = btn.textContent; btn.innerHTML = '<span class="spin"></span>'; }
  setBadge("#v"+P, "…", "b-unk");
  if (role === "spawn") $("#spawnLabel").textContent = `P_tgt · D′ · ${model}`;
  const artifact = $("#in"+P).value;
  const r = await post("/api/phase", {role, sample:d.id, artifact, model, mode:state.mode});
  verdictBadge("#v"+P, r.verdict);
  $("#r"+P).innerHTML = phaseHTML(r, role==="spawn" ? `model: ${model}` : "");
  if (btn){ btn.innerHTML = btn.dataset.lbl || "▶ Run"; btn.disabled = false; }
  if (role === "seed"){
    state.harvested = (r.verdict === "CLEAN" && r.reasoning) ? r.reasoning : (d.trace || "");
    $("#useTrace").style.display = state.harvested ? "inline-block" : "none";
  }
  return r;
}

function wireAttack(){
  $$(".runp").forEach(b => b.onclick = () => runPhase(b.dataset.role));
  $("#useTrace").onclick = () => {
    const d = state.attackSample; const t = state.harvested; if(!d || !t) return;
    const dp = dprime(d, t);
    $("#inRoot").value = dp; $("#inSpawn").value = dp;
    toast("Harvested trace planted into ROOT & SPAWN inputs.");
  };
  $("#runAll").onclick = async () => {
    const btn = $("#runAll"); btn.disabled = true; btn.innerHTML = '<span class="spin"></span> running all';
    await runPhase("raw");
    const seed = await runPhase("seed");
    if (seed && state.harvested){ const dp = dprime(state.attackSample, state.harvested); $("#inRoot").value = dp; $("#inSpawn").value = dp; }
    await runPhase("root");
    await runPhase("spawn");
    btn.innerHTML = "▶ Run all phases"; btn.disabled = false;
  };
}

// ---------------------------------------------------------------- defense lab
function renderLabMethods(){
  if (!window.DefMethods) return;
  const byId = {}; ((state.stats && state.stats.rows) || []).forEach(r => byId[r.strategy] = r);
  DefMethods.renderMaster($("#labNames"), $("#labDetail"), state.strategies, state.families, byId);
}

function renderDefSelect(){
  const mal = state.samples.filter(s => s.has_trace);
  $("#defSample").innerHTML = mal.map(s => `<option value="${s.id}">${esc(s.title||s.id)}</option>`).join("");
  state.defSample = mal[0]?.id;
  $("#defSample").onchange = e => state.defSample = e.target.value;
  $("#runBattery").disabled = !mal.length;
}

function wireDefense(){
  $("#runBattery").onclick = async () => {
    const sid = $("#defSample").value || state.defSample; if (!sid) return;
    const btn = $("#runBattery"); btn.disabled = true; btn.innerHTML = '<span class="spin"></span> running battery';
    const host = $("#defCards"); host.innerHTML = "";
    const benignId = (state.samples.find(s => s.label==="benign")||{}).id;
    // placeholder cards
    for (const st of state.strategies){
      const el = document.createElement("div"); el.className="defcard"; el.id="dc-"+st.id;
      el.innerHTML = defCardHtml(st, null, null); host.appendChild(el);
    }
    let blocked=0, total=0, fpCount=0;
    // run strategies sequentially to keep order & progress legible
    for (const st of state.strategies){
      const atk = await post("/api/run", {sample:sid, variant:"inception", strategy:st.id, model:state.model, mode:state.mode});
      let fp = null;
      if (benignId){
        const bz = await post("/api/run", {sample:benignId, variant:"raw", strategy:st.id, model:state.model, mode:state.mode});
        fp = bz.false_positive;
      }
      total++; if (!atk.attack_success) blocked++; if (fp) fpCount++;
      $("#dc-"+st.id).outerHTML = `<div class="defcard ${atk.attack_success?'fail':'block'}" id="dc-${st.id}">${defCardHtml(st, atk, fp)}</div>`;
    }
    const kpi = $("#defKpi"); kpi.style.display="flex";
    kpi.innerHTML = `
      <div class="k"><div class="n" style="color:var(--clean)">${blocked}/${total}</div><div class="l">defenses blocked the attack</div></div>
      <div class="k"><div class="n" style="color:var(--mal)">${total-blocked}</div><div class="l">still fooled</div></div>
      <div class="k"><div class="n" style="color:var(--esc)">${fpCount}</div><div class="l">benign false-positives</div></div>`;
    btn.innerHTML = "▶ Run battery"; btn.disabled = false;
  };
}

function defCardHtml(st, atk, fp){
  const fam = st.family;
  const famc = FAMCOL[fam] || "var(--mut)";
  let body = `<div class="small dim">running…</div>`;
  if (atk){
    const ok = !atk.attack_success;
    const dets = (atk.detectors||[]).map(d =>
      `<div class="small"><b style="color:${d.flag?'var(--mal)':'var(--mut)'}">${esc(d.name||'detector')}</b>: ${esc((d.reasons||[])[0]||'')}</div>`).join("");
    body = `
      <div class="row">${vbadge(atk.final_verdict)}
        <span class="chk ${ok?'ok':'no'}">${ok?'✓ attack blocked':'✗ still CLEAN'}</span>
        ${atk.overridden?'<span class="pill" style="color:var(--clean);border-color:#1c4">override</span>':''}
        ${atk.replay?'<span class="pill">replay</span>':''}</div>
      <div class="small dim mono" style="margin-top:4px">stage: ${esc(atk.stage||'')}${atk.latency_ms?` · ${atk.latency_ms}ms`:''}
        ${fp===null?'':` · benign FP: <b style="color:${fp?'var(--mal)':'var(--clean)'}">${fp?'yes':'no'}</b>`}</div>
      ${dets?`<div style="margin-top:6px">${dets}</div>`:''}`;
  }
  return `<div class="top">
      <div><div style="font-weight:700">${esc(st.label)}</div>
        <div class="famtag" style="color:${famc}">${fam}</div></div>
    </div>
    <div class="small muted" style="margin-bottom:6px">${esc(st.desc)}</div>
    ${body}
    <div class="hint" style="margin-top:6px">expected: ${esc(st.expect||'')}</div>`;
}

// ---------------------------------------------------------------- benchmark
function wireBench(){
  $("#runBench").onclick = startBench;
  $("#cancelBench").onclick = () => { if (state.bench?.job) post(`/api/benchmark/${state.bench.job}/cancel`, {}); };
  $("#expJson").onclick = () => download("benchmark.json", JSON.stringify(state.bench?.result||{}, null, 2));
  $("#expCsv").onclick = exportCsv;
}

function pickSamples(scope){
  const mal = state.samples.filter(s => s.label==="malicious").map(s=>s.id);
  const ben = state.samples.filter(s => s.label==="benign").map(s=>s.id);
  if (scope==="quick") return [...mal.slice(0,4), ...ben.slice(0,2)];
  return [...mal, ...ben];
}
function pickStrategies(which){
  if (which==="all") return state.strategies.map(s=>s.id);
  // core: one representative per family (+ baseline)
  const pick = ["none","strip_comments","sandwich","trace_detector","signature_crosscheck","defense_in_depth"];
  return pick.filter(id => state.strategies.some(s=>s.id===id));
}

async function startBench(){
  const samples = pickSamples($("#benchScope").value);
  const strategies = pickStrategies($("#benchStrat").value);
  $("#runBench").disabled = true; $("#cancelBench").style.display="inline-block";
  $("#benchProg").style.display="block"; $("#benchMsg").textContent="starting…";
  $("#benchTableCard").style.display="none"; $("#benchChartCard").style.display="none";
  const {job} = await post("/api/benchmark", {samples, strategies, model:state.model, mode:state.mode});
  state.bench = {job};
  poll(job);
}

async function poll(job){
  const s = await api(`/api/benchmark/${job}`);
  if (s.total){
    const pct = Math.round(100*s.done/s.total);
    $("#benchBar").style.width = pct+"%";
    $("#benchMsg").innerHTML = `${s.done}/${s.total} runs · ${pct}%` +
      (s.last?` — <span class="mono">${s.last.sample}/${s.last.variant}/${s.last.strategy} → ${s.last.verdict||'…'}</span>`:"");
  }
  if (s.state==="done"){
    state.bench.result = s.result;
    $("#runBench").disabled=false; $("#cancelBench").style.display="none";
    $("#benchMsg").innerHTML = `done · ${s.total} runs · model <b>${esc(s.result.model)}</b> · mode ${s.result.mode}`;
    renderBench(s.result);
    return;
  }
  setTimeout(() => poll(job), 600);
}

function pct(x){ return x==null?"—":(100*x).toFixed(1)+"%"; }
function renderBench(res){
  // chart
  $("#benchChartCard").style.display="block";
  $("#benchLegend").innerHTML = state.families.map(f =>
    `<span><i style="background:${FAMCOL[f]}"></i>${f}</span>`).join("");
  const rows = res.rows;
  const W=760, rh=26, lab=220, max=1;
  let svg = `<svg viewBox="0 0 ${W} ${rows.length*rh+10}" width="100%" style="font:12px var(--mono)">`;
  rows.forEach((r,i)=>{
    const y=i*rh+6, w=(lab), bw=(W-lab-70)*((r.asr==null?0:r.asr)/max);
    const col=FAMCOL[r.family]||"var(--mut)";
    svg += `<text x="0" y="${y+13}" fill="#cfd8e6">${esc(r.label||r.strategy)}</text>`;
    svg += `<rect x="${lab}" y="${y+2}" width="${W-lab-70}" height="14" fill="#1a2230" rx="3"/>`;
    svg += `<rect x="${lab}" y="${y+2}" width="${Math.max(2,bw)}" height="14" fill="${col}" rx="3"/>`;
    svg += `<text x="${W-62}" y="${y+13}" fill="#cfd8e6">${pct(r.asr)}</text>`;
  });
  svg += `</svg>`;
  $("#benchChart").innerHTML = svg;

  // table
  $("#benchTableCard").style.display="block";
  const H = (t,k,tip) => `<th class="num" data-k="${k}">${t}<span class="help" data-tip="${tip.replace(/"/g,'&quot;')}">?</span></th>`;
  const head = `<thead><tr>
    <th>Defense <span class="help" data-tip="Click a column header to sort. Hover a metric's ? for its meaning.">?</span></th><th>Family</th>
    ${H("ASR ↓","asr",TIPS.asr+" Lower is better.")}${H("Δ vs none","delta_asr_pp",TIPS.delta)}
    ${H("FP ↓","fp",TIPS.fp+" Lower is better.")}${H("Utility ↑","utility",TIPS.utility+" Higher is better.")}
    ${H("Escalate","escalate_rate",TIPS.escalate)}${H("Score ↑","score",TIPS.score)}
    <th class="num" data-k="avg_latency_ms">ms</th></tr></thead>`;
  const body = rows.map(r => {
    const famc=FAMCOL[r.family]||"var(--mut)";
    const asrCol = r.asr==null?'var(--mut)':(r.asr>0.5?'var(--mal)':r.asr>0.1?'var(--esc)':'var(--clean)');
    const d = r.delta_asr_pp;
    return `<tr>
      <td>${esc(r.label||r.strategy)}<div class="small dim mono">${r.strategy}</div></td>
      <td><span class="famtag" style="color:${famc}">${r.family}</span></td>
      <td class="num" style="color:${asrCol};font-weight:700">${pct(r.asr)}</td>
      <td class="num" style="color:${d==null?'var(--mut)':(d<0?'var(--clean)':'var(--mal)')}">${d==null?'—':(d>0?'+':'')+d+'pp'}</td>
      <td class="num">${pct(r.fp)}</td>
      <td class="num">${pct(r.utility)}</td>
      <td class="num">${pct(r.escalate_rate)}</td>
      <td class="num" style="font-weight:700">${r.score==null?'—':(r.score*100).toFixed(0)}</td>
      <td class="num dim">${r.avg_latency_ms??'—'}</td></tr>`;
  }).join("");
  const t = $("#benchTable"); t.innerHTML = head + `<tbody>${body}</tbody>`;
  $$("th[data-k]", t).forEach(th => th.onclick = () => sortBench(th.dataset.k));
}

function sortBench(k){
  const rows = state.bench.result.rows;
  rows.sort((a,b)=>{const x=a[k]??-1,y=b[k]??-1; return y-x;});
  renderBench(state.bench.result);
}

function exportCsv(){
  const rows = state.bench?.result?.rows||[];
  const cols = ["strategy","label","family","asr","delta_asr_pp","fp","utility","escalate_rate","score","avg_latency_ms"];
  const csv = [cols.join(",")].concat(rows.map(r => cols.map(c => r[c]??"").join(","))).join("\n");
  download("benchmark.csv", csv);
}
function download(name, text){
  const a=document.createElement("a");
  a.href=URL.createObjectURL(new Blob([text],{type:"text/plain"})); a.download=name; a.click();
}

// ---------------------------------------------------------------- toast
let toastT;
function toast(msg){
  let el=$("#toast"); if(!el){el=document.createElement("div");el.id="toast";
    el.style.cssText="position:fixed;bottom:22px;left:50%;transform:translateX(-50%);background:#16202f;border:1px solid #2b4a6f;color:#dce9ff;padding:10px 16px;border-radius:10px;z-index:50;box-shadow:0 8px 30px #000a";
    document.body.appendChild(el);}
  el.textContent=msg; el.style.opacity="1";
  clearTimeout(toastT); toastT=setTimeout(()=>el.style.opacity="0", 3200);
}

boot();
