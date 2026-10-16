"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const api = async (url, opts) => (await fetch(url, opts)).json();
const post = (url, body) => api(url, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});

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
  const [h, mo, st, sa] = await Promise.all([
    api("/api/health"), api("/api/models"), api("/api/strategies"), api("/api/samples")]);
  state.models = mo.models; state.voteModels = mo.vote_models;
  state.strategies = st.strategies; state.families = st.families;
  state.samples = sa.samples;
  state.model = state.models[0];

  // model selectors
  for (const sel of ["#model", "#xModel"]){
    const el = $(sel); el.innerHTML = state.models.map(m => `<option>${m}</option>`).join("");
  }
  $("#xModel").value = state.models[1] || state.models[0];
  $("#model").onchange = e => { state.model = e.target.value; };

  renderHealth(h);
  renderModeToggle();
  renderTabs();
  renderAttackSamples();
  renderDefSelect();
  $("#scount").textContent = `(${state.samples.length})`;
  $("#aboutHealth").textContent =
    `api_key=${h.api_key_present} · cached_runs=${h.cached_runs} · samples=${h.samples} · strategies=${h.strategies}`;

  wireAttack(); wireDefense(); wireBench();
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

function renderTabs(){
  $$("#tabs button").forEach(b => b.onclick = () => {
    $$("#tabs button").forEach(x => x.classList.remove("on")); b.classList.add("on");
    $$(".view").forEach(v => v.classList.remove("on"));
    $(`#v-${b.dataset.v}`).classList.add("on");
  });
}

// ---------------------------------------------------------------- attack
function renderAttackSamples(){
  const host = $("#attackSamples");
  host.innerHTML = state.samples.map(s =>
    `<div class="sitem" data-id="${s.id}">
       <span class="sdot ${s.label==='malicious'?'m':'b'}"></span>
       <div style="flex:1"><div>${esc(s.title||s.id)}</div>
         <div class="small dim mono">${s.id} · ${s.chars}b${s.has_trace?' · trace':''}</div></div>
     </div>`).join("");
  $$(".sitem", host).forEach(el => el.onclick = () => selectAttackSample(el.dataset.id, host));
}

async function selectAttackSample(id, host){
  $$(".sitem", host).forEach(x => x.classList.toggle("on", x.dataset.id === id));
  const d = await api(`/api/sample/${id}`);
  state.attackSample = d;
  $("#asTitle").textContent = d.title || d.id;
  $("#asSrc").textContent = d.source || "";
  $("#rawCode").textContent = d.variants.raw;
  $("#incCode").innerHTML = highlightTrace(d.variants.inception);
  $("#rawVerdict").outerHTML = `<span id="rawVerdict" class="badge b-unk">—</span>`;
  $("#incVerdict").outerHTML = `<span id="incVerdict" class="badge b-unk">—</span>`;
  $("#rawReason").textContent = d.label==='malicious'
    ? "The honest baseline. The target should flag this webshell as MALICIOUS."
    : "A benign file — the target should return CLEAN.";
  $("#incReason").textContent = d.trace
    ? "The same code, with a borrowed reasoning trace planted in a trailing comment."
    : "This sample carries no planted trace.";
  $("#runAttack").disabled = false;
  $("#runTransfer").disabled = !d.trace;
  $("#xResult").innerHTML = "";
}

function wireAttack(){
  $("#runAttack").onclick = async () => {
    const d = state.attackSample; if (!d) return;
    const btn = $("#runAttack"); btn.disabled = true; btn.innerHTML = '<span class="spin"></span> running';
    setV("#rawVerdict", "…"); setV("#incVerdict", "…");
    $("#rawReason").textContent = "…"; $("#incReason").textContent = "…";
    const [raw, inc] = await Promise.all([
      post("/api/run", {sample:d.id, variant:"raw", strategy:"none", model:state.model, mode:state.mode}),
      post("/api/run", {sample:d.id, variant: d.trace?"inception":"raw", strategy:"none", model:state.model, mode:state.mode})]);
    $("#rawVerdict").outerHTML = `<span id="rawVerdict">${vbadge(raw.final_verdict)}</span>`;
    $("#incVerdict").outerHTML = `<span id="incVerdict">${vbadge(inc.final_verdict)}</span>`;
    $("#rawReason").textContent = raw.reasoning || raw.content || "(no reasoning returned)";
    $("#incReason").textContent = inc.reasoning || inc.content || "(no reasoning returned)";
    const flipped = raw.final_verdict==="MALICIOUS" && inc.final_verdict==="CLEAN";
    btn.innerHTML = "▶ Run attack"; btn.disabled = false;
    if (flipped) toast("Verdict flipped: MALICIOUS ➜ CLEAN — the webshell slipped through.");
  };
  $("#runTransfer").onclick = async () => {
    const d = state.attackSample; if (!d || !d.trace) return;
    const m = $("#xModel").value; const btn = $("#runTransfer");
    btn.disabled = true; btn.innerHTML = '<span class="spin"></span>';
    const r = await post("/api/run", {sample:d.id, variant:"inception", strategy:"none", model:m, mode:state.mode});
    $("#xResult").innerHTML =
      `<span class="pill mono">${m}</span> ${vbadge(r.final_verdict)}
       <span class="small ${r.attack_success?'':'dim'}" style="color:${r.attack_success?'var(--mal)':'var(--mut)'}">
       ${r.attack_success? 'trace transferred — classified CLEAN' : 'held — not fooled'}</span>
       ${r.replay?'<span class="pill">replay</span>':''}`;
    btn.innerHTML = "▶ Transfer"; btn.disabled = false;
  };
}
function setV(sel, t){ const e=$(sel); if(e) e.textContent=t; }

// ---------------------------------------------------------------- defense lab
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
  const head = `<thead><tr>
    <th>Defense</th><th>Family</th>
    <th class="num" data-k="asr">ASR ↓</th><th class="num" data-k="delta_asr_pp">Δ vs none</th>
    <th class="num" data-k="fp">FP ↓</th><th class="num" data-k="utility">Utility ↑</th>
    <th class="num" data-k="escalate_rate">Escalate</th><th class="num" data-k="score">Score ↑</th>
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
