// BareMetalBind — reactive Proxy state and rv-* directive binder
// Directives: rv-value, rv-text, rv-if, rv-on-click, rv-on-submit
// API: reactive(initial) → { state, watch, data },  bind(root, state, watch)
const BareMetalBind = (() => {
  'use strict';

  function reactive(initial) {
    const L = new Map();
    const notify = k => (L.get(k) || []).forEach(fn => fn());
    const watch  = (k, fn) => { L.has(k) || L.set(k, []); L.get(k).push(fn); };
    const data   = { ...initial };
    const state  = new Proxy(data, {
      set(t, k, v) { t[k] = v; notify(k); return true; }
    });
    return { state, watch, data };
  }

  function bind(root, state, watch) {
    root.querySelectorAll('[rv-value]').forEach(n => {
      const k = n.getAttribute('rv-value'), chk = n.type === 'checkbox';
      const isDate = n.type === 'date', isDtLocal = n.type === 'datetime-local';
      const fmt = v => {
        if (v == null || v === '') return '';
        if (isDate) return String(v).slice(0, 10);          // YYYY-MM-DD
        if (isDtLocal) return String(v).slice(0, 16);        // YYYY-MM-DDTHH:MM
        return String(v);
      };
      const sync = () => {
        if (chk) { n.checked = !!state[k]; }
        else { const v = fmt(state[k]); if (n.value !== v) n.value = v; }
      };
      sync(); watch(k, sync);
      n.addEventListener(chk ? 'change' : 'input', () => state[k] = chk ? n.checked : n.value);
    });
    root.querySelectorAll('[rv-text]').forEach(n => {
      const k = n.getAttribute('rv-text'), sync = () => n.textContent = state[k] ?? '';
      sync(); watch(k, sync);
    });
    root.querySelectorAll('[rv-if]').forEach(n => {
      const k = n.getAttribute('rv-if'), sync = () => n.style.display = state[k] ? '' : 'none';
      sync(); watch(k, sync);
    });
    root.querySelectorAll('[rv-on-click],[rv-on-submit]').forEach(n => {
      const sub = n.hasAttribute('rv-on-submit');
      const fn  = n.getAttribute(sub ? 'rv-on-submit' : 'rv-on-click');
      n.addEventListener(sub ? 'submit' : 'click', e => {
        e.preventDefault();
        typeof state[fn] === 'function' && state[fn](e);
      });
    });
  }

  return { reactive, bind };
})();
