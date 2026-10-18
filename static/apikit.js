"use strict";
/* Shared across all pages: a browser-side OpenRouter API key + custom model list.
   The key is stored only in this browser (localStorage) and is sent to the local
   mi_lab server solely to make live model calls. It is never cached to disk. */
(function () {
  const LS_KEY = "milab_api_key", LS_MODELS = "milab_models";
  const get = (k, d) => { try { return localStorage.getItem(k) ?? d; } catch { return d; } };
  const set = (k, v) => { try { localStorage.setItem(k, v); } catch {} };

  const state = {
    key: get(LS_KEY, "") || "",
    models: (get(LS_MODELS, "") || "").split(",").map(s => s.trim()).filter(Boolean),
    listeners: [],
  };

  const MILAB = {
    key: () => state.key,
    models: () => state.models.slice(),
    onChange: (cb) => state.listeners.push(cb),
    body: (obj) => state.key ? { ...obj, api_key: state.key } : obj,
    // merge built-in + custom models into a <select>, preserving current value
    fillSelect: (sel, builtins) => {
      const el = typeof sel === "string" ? document.querySelector(sel) : sel;
      if (!el) return;
      const cur = el.value;
      const all = [...builtins, ...state.models.filter(m => !builtins.includes(m))];
      el.innerHTML = all.map(m => `<option>${m}</option>`).join("");
      if (all.includes(cur)) el.value = cur;
    },
  };
  window.MILAB = MILAB;

  function emit() { state.listeners.forEach(cb => { try { cb(); } catch {} }); }

  function render() {
    const slot = document.getElementById("apiSlot");
    if (!slot) return;
    const isSet = !!state.key;
    slot.className = "apiwrap";
    slot.innerHTML = `
      <button class="apibtn ${isSet ? "set" : ""}" id="apiToggle">⚙ ${isSet ? "API ●" : "API key / models"}</button>
      <div class="apipanel" id="apiPanel">
        <h4>Test other models</h4>
        <label>OpenRouter API key (optional)</label>
        <input type="password" id="apiKeyInput" placeholder="sk-or-... (uses server key if blank)" value="${state.key ? "" : ""}">
        <label>Add a model id</label>
        <div class="row" style="gap:6px">
          <input id="apiModelInput" placeholder="e.g. anthropic/claude-3.7-sonnet" style="flex:1">
          <button id="apiAddModel">Add</button>
        </div>
        <div class="mchips" id="apiModelChips"></div>
        <div class="note">Stored in this browser only; sent to the local lab server
          just to make live calls. Clear to remove.</div>
        <div class="row" style="margin-top:12px">
          <button class="primary" id="apiSave">Save</button>
          <button id="apiClear">Clear key</button>
          <span class="spacer"></span>
          <span class="small dim" id="apiStatus"></span>
        </div>
      </div>`;
    const panel = slot.querySelector("#apiPanel");
    slot.querySelector("#apiToggle").onclick = () => panel.classList.toggle("on");
    document.addEventListener("click", e => { if (!slot.contains(e.target)) panel.classList.remove("on"); });

    const keyInput = slot.querySelector("#apiKeyInput");
    keyInput.placeholder = state.key ? "•••• saved (type to replace)" : "sk-or-... (uses server key if blank)";
    renderChips(slot);

    slot.querySelector("#apiAddModel").onclick = () => {
      const v = slot.querySelector("#apiModelInput").value.trim();
      if (v && !state.models.includes(v)) { state.models.push(v); slot.querySelector("#apiModelInput").value = ""; renderChips(slot); }
    };
    slot.querySelector("#apiModelInput").addEventListener("keydown", e => { if (e.key === "Enter") slot.querySelector("#apiAddModel").click(); });
    slot.querySelector("#apiSave").onclick = () => {
      if (keyInput.value.trim()) state.key = keyInput.value.trim();
      set(LS_KEY, state.key); set(LS_MODELS, state.models.join(","));
      slot.querySelector("#apiStatus").textContent = "saved";
      emit(); render(); // re-render to reflect set state
      document.getElementById("apiPanel")?.classList.add("on");
    };
    slot.querySelector("#apiClear").onclick = () => {
      state.key = ""; set(LS_KEY, ""); keyInput.value = ""; emit(); render();
      document.getElementById("apiPanel")?.classList.add("on");
    };
  }

  function renderChips(slot) {
    const host = slot.querySelector("#apiModelChips");
    host.innerHTML = state.models.length
      ? state.models.map((m, i) => `<span class="mchip">${m}<b data-i="${i}">✕</b></span>`).join("")
      : `<span class="small dim">no custom models yet</span>`;
    host.querySelectorAll("b[data-i]").forEach(b => b.onclick = () => {
      state.models.splice(+b.dataset.i, 1); renderChips(slot);
    });
  }

  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", render);
  else render();
})();
