"use strict";
/* Shared across pages: read the browser-stored OpenRouter key + custom models and
   expose helpers. Editing lives on the dedicated /models page. The key is stored
   only in this browser and sent to the local server solely to make live calls. */
(function () {
  const LS_KEY = "milab_api_key", LS_MODELS = "milab_models";
  const get = (k, d) => { try { return localStorage.getItem(k) ?? d; } catch { return d; } };

  const state = {
    key: get(LS_KEY, "") || "",
    models: (get(LS_MODELS, "") || "").split(",").map(s => s.trim()).filter(Boolean),
    listeners: [],
  };

  window.MILAB = {
    key: () => state.key,
    models: () => state.models.slice(),
    onChange: (cb) => state.listeners.push(cb),
    body: (obj) => state.key ? { ...obj, api_key: state.key } : obj,
    fillSelect: (sel, builtins) => {
      const el = typeof sel === "string" ? document.querySelector(sel) : sel;
      if (!el) return;
      const cur = el.value;
      const all = [...builtins, ...state.models.filter(m => !builtins.includes(m))];
      el.innerHTML = all.map(m => `<option>${m}</option>`).join("");
      if (all.includes(cur)) el.value = cur;
    },
  };

  function render() {
    const slot = document.getElementById("apiSlot");
    if (!slot) return;
    const isSet = !!state.key, n = state.models.length;
    slot.className = "apiwrap";
    slot.innerHTML =
      `<a href="/models" class="apibtn ${isSet ? "set" : ""}" title="Set your API key and custom models">`
      + `⚙ Models${isSet ? " ●" : ""}${n ? ` <span class="small dim">(+${n})</span>` : ""}</a>`;
  }

  if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", render);
  else render();
})();
