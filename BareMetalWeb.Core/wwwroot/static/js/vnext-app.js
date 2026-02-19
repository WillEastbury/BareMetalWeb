// VNext Router — thin SPA router powered by BareMetalRendering
// Parses /vnext[/admin/data]/[{slug}[/{id}|/create]]
// Depends on: BareMetalRest, BareMetalBind, BareMetalTemplate, BareMetalRendering
(async function () {
  'use strict';
  BareMetalRest.setRoot('/api/');

  const R   = document.getElementById('vnext-root');
  const esc = s => String(s ?? '').replace(/[&<>"]/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
  const go  = url => { history.pushState({}, '', url); route(); };
  window.addEventListener('popstate', route);

  function wire() {
    R.querySelectorAll('[data-go]').forEach(a =>
      a.addEventListener('click', e => { e.preventDefault(); go(a.getAttribute('href')); })
    );
  }

  function navbar(activeSlug) {
    const all = BareMetalRendering._cache || [];
    return '<nav class="navbar navbar-expand navbar-dark bg-dark mb-3 px-3">' +
      '<a class="navbar-brand" href="/vnext" data-go>\u26A1 VNext</a>' +
      '<ul class="navbar-nav me-auto">' +
      all.filter(e => e.showOnNav).map(e =>
        `<li class="nav-item"><a class="nav-link${e.slug === activeSlug ? ' active' : ''}" href="/vnext/${esc(e.slug)}" data-go>${esc(e.name)}</a></li>`
      ).join('') +
      '</ul>' +
      '<a class="btn btn-sm btn-outline-light" href="/admin/data">Classic UI</a></nav>';
  }

  async function route() {
    const p      = location.pathname.replace(/^\/vnext\/?/, '').replace(/^admin\/data\/?/, '').split('/').filter(Boolean);
    const slug   = p[0], rawId = p[1], action = p[2];
    // rawId is 'create' → new form; otherwise it's an entity id (or undefined for list)
    const id     = (rawId && rawId !== 'create') ? rawId : null;

    R.innerHTML = '<div class="d-flex justify-content-center mt-5"><div class="spinner-border" role="status"><span class="visually-hidden">Loading\u2026</span></div></div>';

    try {
      if (!BareMetalRendering._cache)
        BareMetalRendering._cache = await BareMetalRendering.listEntities();

      // Home: entity cards
      if (!slug) {
        R.innerHTML = navbar() +
          '<div class="container"><div class="row g-3 mt-1">' +
          (BareMetalRendering._cache || []).filter(e => e.showOnNav).map(e =>
            `<div class="col-sm-6 col-md-3"><a class="card card-body text-decoration-none" href="/vnext/${esc(e.slug)}" data-go>` +
            `<strong>${esc(e.name)}</strong><p class="text-muted small mb-0">${esc(e.navGroup || '')}</p></a></div>`
          ).join('') +
          '</div></div>';
        wire(); return;
      }

      const entity = await BareMetalRendering.createEntity(slug);
      R.innerHTML = navbar(slug);
      const main = document.createElement('div');
      main.className = 'container';
      R.appendChild(main);

      if (!rawId) {
        // List view
        const items = await BareMetalRest.entity(slug).list();
        const hdr   = document.createElement('div');
        hdr.className = 'd-flex justify-content-between align-items-center mb-3';
        hdr.innerHTML  = `<h2>${esc(entity.meta.name || slug)}</h2>`;
        const addBtn   = document.createElement('a');
        addBtn.href    = `/vnext/${esc(slug)}/create`;
        addBtn.className = 'btn btn-success btn-sm';
        addBtn.textContent = '+ Add';
        addBtn.setAttribute('data-go', '');
        hdr.appendChild(addBtn);
        main.appendChild(hdr);
        main.appendChild(BareMetalTemplate.buildTable(
          entity.meta.schema?.fields || {},
          Array.isArray(items) ? items : [],
          // onView loads the record read-only; onEdit opens the same edit form
          { onView: i => go(`/vnext/${slug}/${i}`), onEdit: i => go(`/vnext/${slug}/${i}/edit`) }
        ));

      } else {
        // Create / Edit form
        if (id) await entity.load(id);
        const hdr = document.createElement('div');
        hdr.className = 'd-flex justify-content-between align-items-center mb-3';
        hdr.innerHTML  = `<h2>${esc(id ? 'Edit ' : 'New ')}${esc(entity.meta.name || slug)}</h2>`;
        const back = document.createElement('a');
        back.href   = `/vnext/${esc(slug)}`;
        back.className = 'btn btn-secondary btn-sm';
        back.textContent = '\u2190 Back';
        back.setAttribute('data-go', '');
        hdr.appendChild(back);
        main.appendChild(hdr);
        entity.renderUI(main);
      }

      wire();
    } catch (e) {
      R.innerHTML = `<div class="container mt-3"><div class="alert alert-danger">${esc(e.message)}</div></div>`;
    }
  }

  route();
})();
