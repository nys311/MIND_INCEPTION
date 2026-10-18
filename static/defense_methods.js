"use strict";
/* Shared "how each defense works" explorer: a clickable method list + per-method
   mechanism diagram. Used by both the Defenses page and the dashboard's Defense Lab. */
(function () {
  const FAMCOL = { baseline: "var(--fam-baseline)", surface: "var(--fam-surface)",
    structural: "var(--fam-structural)", detector: "var(--fam-detector)",
    architectural: "var(--fam-architectural)" };
  const esc = s => (s || "").replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
  const pct = x => (x == null ? "—" : (100 * x).toFixed(0) + "%");

  function dbox(x, y, w, h, label, fill, stroke, sub) {
    return `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="7" fill="${fill || "#121823"}" stroke="${stroke || "#2b3647"}"/>`
      + `<text x="${x + w / 2}" y="${y + (sub ? h / 2 - 3 : h / 2 + 4)}" fill="#dce7f5" font-size="11.5" font-weight="600" text-anchor="middle">${label}</text>`
      + (sub ? `<text x="${x + w / 2}" y="${y + h / 2 + 12}" fill="#8a97a8" font-size="9.5" text-anchor="middle">${sub}</text>` : "");
  }
  function darr(x1, x2, y) {
    return `<line x1="${x1}" y1="${y}" x2="${x2 - 7}" y2="${y}" stroke="#46566b" stroke-width="2"/>`
      + `<path d="M${x2 - 8},${y - 4} L${x2},${y} L${x2 - 8},${y + 4} Z" fill="#46566b"/>`;
  }
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
  function wrapSvg(g, caption, W, H) {
    return `<svg viewBox="0 0 ${W} ${H}" width="100%" style="max-width:660px;font-family:var(--mono)">${g}`
      + `<text x="8" y="${H - 8}" fill="#8a97a8" font-size="10.5">${esc(caption)}</text></svg>`;
  }
  function methodDiagram(id) {
    const m = MECH[id] || MECH.none, W = 640, H = 120, y = 44;
    const col = f => FAMCOL[f] || "#2b3647";
    const fillFor = f => ({ surface: "#1a1226", structural: "#101f36", detector: "#241a06", architectural: "#06231a" }[f] || "#121823");
    let g = dbox(8, y, 120, 34, "Artifact + trace", "#1b1507", "#5a4a1e"), x = 128;
    if (m.gate && !m.stages && !m.post) {
      g += darr(x, x + 60, y + 17) + dbox(x + 60, y - 2, 140, 42, m.gate[0], fillFor(m.gate[1]), col(m.gate[1]));
      const gx = x + 200;
      g += `<path d="M${gx},${y + 17} L${gx + 55},${y - 14}" stroke="#46566b" stroke-width="2"/><path d="M${gx},${y + 17} L${gx + 55},${y + 48}" stroke="#46566b" stroke-width="2"/>`;
      g += dbox(gx + 58, y - 30, 120, 28, "flag → BLOCK", "#2a0f14", "#512");
      g += dbox(gx + 58, y + 34, 120, 28, "clear → LRM", "#06231a", "#164");
      return wrapSvg(g, m.caption, W, H);
    }
    if (m.vote) {
      g += `<path d="M${x},${y + 17} L${x + 50},${y - 10}" stroke="#46566b" stroke-width="2"/><path d="M${x},${y + 17} L${x + 50},${y + 17}" stroke="#46566b" stroke-width="2"/><path d="M${x},${y + 17} L${x + 50},${y + 44}" stroke="#46566b" stroke-width="2"/>`;
      g += dbox(x + 52, y - 24, 110, 26, "LRM A") + dbox(x + 52, y + 4, 110, 26, "LRM B") + dbox(x + 52, y + 32, 110, 26, "LRM C");
      g += darr(x + 162, x + 230, y + 17) + dbox(x + 232, y, 140, 34, "majority / escalate", "#06231a", "#1c4a33");
      g += darr(x + 372, x + 440, y + 17) + dbox(x + 440, y, 100, 34, "Verdict");
      return wrapSvg(g, m.caption, W, H);
    }
    (m.stages || []).forEach(st => { g += darr(x, x + 56, y + 17); x += 56; g += dbox(x, y - 2, 132, 42, st[0], fillFor(st[1]), col(st[1])); x += 132; });
    g += darr(x, x + 56, y + 17); x += 56; g += dbox(x, y, 96, 34, "LRM"); x += 96;
    if (m.post) { g += darr(x, x + 56, y + 17); x += 56; g += dbox(x, y - 2, 150, 42, m.post[0], fillFor(m.post[1]), col(m.post[1])); x += 150; }
    g += darr(x, Math.min(x + 54, W - 96), y + 17);
    g += dbox(Math.min(x + 54, W - 94), y, 90, 34, m.post ? "override" : "Verdict", m.post ? "#2a0f14" : "#121823", m.post ? "#512" : "#2b3647");
    return wrapSvg(g, m.caption, W, Math.max(H, y + 44));
  }

  // Render the name list + detail panel into the given elements.
  function renderMaster(namesEl, detailEl, strategies, families, byId) {
    const $$ = (s, r) => [...(r || document).querySelectorAll(s)];
    namesEl.innerHTML = families.map(fam => {
      const items = strategies.filter(s => s.family === fam);
      if (!items.length) return "";
      const rows = items.map(s => {
        const r = byId[s.id] || {};
        const chip = r.asr == null ? "" :
          `<span class="mono small" style="color:${r.asr > .5 ? "var(--mal)" : r.asr > .1 ? "var(--esc)" : "var(--clean)"}">${pct(r.asr)}</span>`;
        return `<div class="mname" data-id="${s.id}"><span class="sdot2" style="background:${FAMCOL[fam]}"></span><span style="flex:1">${esc(s.label)}</span>${chip}</div>`;
      }).join("");
      return `<div class="famtag" style="color:${FAMCOL[fam]};margin:10px 0 4px">${fam}</div>${rows}`;
    }).join("");

    function show(id) {
      $$(".mname", namesEl).forEach(el => el.classList.toggle("on", el.dataset.id === id));
      const s = strategies.find(x => x.id === id) || {};
      const r = byId[id] || {}, pv = r.asr_by_variant || {};
      const stat = r.asr == null ? `<span class="dim">not measured in the shipped stats</span>` :
        `<span class="mono">ASR <b style="color:${r.asr > .5 ? "var(--mal)" : r.asr > .1 ? "var(--esc)" : "var(--clean)"}">${pct(r.asr)}</b>
          · Δ ${r.delta_asr_pp == null ? "—" : (r.delta_asr_pp > 0 ? "+" : "") + r.delta_asr_pp + "pp"}
          · comment ${pct(pv.inception)} · print ${pct(pv.relocated)}
          · FP ${pct(r.fp)} · utility ${pct(r.utility)} · score ${r.score == null ? "—" : Math.round(r.score * 100)}</span>`;
      detailEl.innerHTML = `
        <div class="row"><h3 style="margin:0">${esc(s.label)}</h3>
          <span class="famtag" style="color:${FAMCOL[s.family]}">${s.family}</span></div>
        <div class="muted small" style="margin:6px 0 4px">${esc(s.desc || "")}</div>
        <div class="hint" style="margin-bottom:8px">expected: ${esc(s.expect || "")}</div>
        <div class="card" style="margin:0;background:#0c1118">${methodDiagram(id)}</div>
        <div class="small" style="margin-top:10px">${stat}</div>`;
    }
    $$(".mname", namesEl).forEach(el => el.onclick = () => show(el.dataset.id));
    if (strategies[0]) show(strategies[0].id);
  }

  window.DefMethods = { methodDiagram, renderMaster };
})();
