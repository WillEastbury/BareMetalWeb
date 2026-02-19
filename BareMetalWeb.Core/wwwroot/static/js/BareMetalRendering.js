// BareMetalRendering — entity lifecycle orchestrator
// Depends on: BareMetalRest, BareMetalBind, BareMetalTemplate (load in order)
// API: createEntity(slug), listEntities()
// Also exposes window.minibind for the declarative usage pattern:
//   minibind.setRoot('/api/');
//   const e = await minibind.createNewEntity('customer');
//   e.renderUI('app');
const BareMetalRendering = (() => {
  'use strict';

  async function createEntity(slug) {
    const api  = BareMetalRest.entity(slug);
    const meta = await api.metadata();
    const { state, watch, data } = BareMetalBind.reactive(meta.initialData || {});

    const save = async () => {
      const id    = data.id || data.Id;
      const saved = id
        ? await api.update(id, { ...data })
        : await api.create({ ...data });
      Object.assign(state, saved);
    };

    const load = async id => Object.assign(state, await api.get(id));

    const renderUI = el => {
      const c = typeof el === 'string' ? document.getElementById(el) : el;
      if (!c) return;
      c.innerHTML = '';
      state.save = save;
      const schemaFields = meta.schema?.fields || {};
      const layout = meta.layout || { fields: Object.keys(schemaFields) };
      c.appendChild(BareMetalTemplate.buildForm(layout, schemaFields));
      BareMetalBind.bind(c, state, watch);
    };

    return { state, save, load, renderUI, meta, api };
  }

  async function listEntities() {
    return BareMetalRest.call('GET', BareMetalRest.getRoot() + '_meta');
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
