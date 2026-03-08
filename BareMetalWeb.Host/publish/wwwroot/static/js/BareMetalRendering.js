// BareMetalRendering — entity lifecycle orchestrator
// Depends on: BareMetalRest, BareMetalBind, BareMetalTemplate (load in order)
// API: createEntity(slug), listEntities()
// Also exposes window.minibind for the declarative usage pattern:
//   minibind.setRoot('/api/');
//   const e = await minibind.createNewEntity('customer');
//   e.renderUI('app');
const BareMetalRendering = (() => {
  'use strict';

  let _cache = null;  // entity list cache (populated by listEntities)

  async function createEntity(slug) {
    const api  = BareMetalRest.entity(slug);
    const meta = await api.metadata();

    // Hydrate lookup options for select fields before rendering
    const schemaFields = meta.schema?.fields || {};
    await Promise.all(
      Object.entries(schemaFields).map(async ([, f]) => {
        if (f && f.lookupUrl) {
          try {
            const items = await BareMetalRest.call('GET', f.lookupUrl);
            const _lst = Array.isArray(items) ? items : (items?.data || []);
            f.options = _lst.map(i => ({
              value: String(i[f.lookupValueField] ?? i.Id ?? i.id ?? ''),
              label: String(i[f.lookupDisplayField] ?? i.Name ?? i.name ?? '')
            }));
          } catch { f.options = []; }
        }
      })
    );

    const { state, watch, data } = BareMetalBind.reactive(meta.initialData || {});

    const save = async (formEl) => {
      const id = data.id || data.Id;
      // Use FormData when the form contains file inputs with selected files
      const hasFiles = formEl && formEl.querySelector('input[type="file"]') &&
        Array.from(formEl.querySelectorAll('input[type="file"]')).some(i => i.files.length > 0);
      let payload;
      if (hasFiles) {
        payload = new FormData();
        Object.entries(data).forEach(([k, v]) => { if (v != null) payload.append(k, v); });
        formEl.querySelectorAll('input[type="file"]').forEach(i => {
          if (i.files.length > 0) payload.append(i.getAttribute('rv-value') || i.name, i.files[0]);
        });
      } else {
        payload = { ...data };
      }
      const saved = id
        ? await api.update(id, payload)
        : await api.create(payload);
      if (saved) Object.assign(state, saved);
    };

    const load = async id => {
      const loaded = await api.get(id);
      if (loaded) Object.assign(state, loaded);
    };

    const renderUI = el => {
      const c = typeof el === 'string' ? document.getElementById(el) : el;
      if (!c) return;
      c.replaceChildren();
      const layout = meta.layout || { fields: Object.keys(schemaFields) };
      const form = BareMetalTemplate.buildForm(layout, schemaFields);
      state.save = () => save(form);
      c.appendChild(form);
      BareMetalBind.bind(c, state, watch);
    };

    // Build a lookup resolver: fieldName → (rawValue → displayLabel)
    const _lookupMaps = {};
    Object.entries(schemaFields).forEach(([name, f]) => {
      if (f && f.options && f.options.length) {
        const m = new Map();
        f.options.forEach(o => m.set(String(o.value), String(o.label)));
        _lookupMaps[name] = v => m.get(String(v ?? '')) ?? String(v ?? '');
      }
    });
    const resolve = (fieldName, rawValue) =>
      _lookupMaps[fieldName] ? _lookupMaps[fieldName](rawValue) : String(rawValue ?? '');

    return { state, save, load, renderUI, meta, api, resolve };
  }

  async function listEntities() {
    if (!_cache) _cache = await BareMetalRest.call('GET', BareMetalRest.getRoot() + '_meta');
    return _cache;
  }

  // Expose minibind-compatible surface as window.minibind
  window.minibind = {
    setRoot:         r => BareMetalRest.setRoot(r),
    createNewEntity: n => createEntity(n),
    listEntities,
    bind:            BareMetalBind.bind
  };

  return { createEntity, listEntities };
})();
