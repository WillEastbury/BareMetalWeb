// VNext Router — thin SPA router powered by BareMetalRendering
// Parses /vnext[/admin/data]/[{slug}[/{id}[/edit]|/create]]
// Depends on: BareMetalRest, BareMetalBind, BareMetalTemplate, BareMetalRendering
(async function () {
  'use strict';
  BareMetalRest.setRoot('/api/');

  const R   = document.getElementById('vnext-root');
  const esc = s => String(s ?? '').replace(/[&<>"]/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
  const go  = url => { history.pushState({}, '', url); route(); };
  window.addEventListener('popstate', route);

  // Module-local entity list cache (separate from BareMetalRendering's internal cache)
  let _entityList = null;

  function wire() {
    R.querySelectorAll('[data-go]').forEach(a =>
      a.addEventListener('click', e => { e.preventDefault(); go(a.getAttribute('href')); })
    );
  }

  function navbar(activeSlug) {
    const all = _entityList || [];
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
    // rawId is 'create' → new form; a real id + action='edit' → edit; id alone → view
    const id     = (rawId && rawId !== 'create') ? rawId : null;

    R.innerHTML = '<div class="d-flex justify-content-center mt-5"><div class="spinner-border" role="status"><span class="visually-hidden">Loading\u2026</span></div></div>';

    try {
      if (!_entityList) _entityList = await BareMetalRendering.listEntities();

      // ── Home: entity cards ───────────────────────────────────────────────
      if (!slug) {
        R.innerHTML = navbar() +
          '<div class="container"><div class="row g-3 mt-1">' +
          (_entityList || []).filter(e => e.showOnNav).map(e =>
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
        // ── List view ───────────────────────────────────────────────────────
        const items  = await BareMetalRest.entity(slug).list();
        const hdr    = document.createElement('div');
        hdr.className = 'd-flex justify-content-between align-items-center mb-3';
        hdr.innerHTML = `<h2>${esc(entity.meta.name || slug)}</h2>`;
        const addBtn  = document.createElement('a');
        addBtn.href   = `/vnext/${esc(slug)}/create`;
        addBtn.className = 'btn btn-success btn-sm';
        addBtn.textContent = '+ Add';
        addBtn.setAttribute('data-go', '');
        hdr.appendChild(addBtn);
        main.appendChild(hdr);
        main.appendChild(BareMetalTemplate.buildTable(
          entity.meta.schema?.fields || {},
          Array.isArray(items) ? items : [],
          {
            onView:   i => go(`/vnext/${slug}/${i}`),
            onEdit:   i => go(`/vnext/${slug}/${i}/edit`),
            onDelete: async i => {
              if (!confirm('Delete this record? This cannot be undone.')) return;
              try {
                await BareMetalRest.entity(slug).remove(i);
                go(`/vnext/${slug}`);
              } catch (err) { alert('Delete failed: ' + err.message); }
            }
          }
        ));

      } else {
        // ── Create / Edit / View ─────────────────────────────────────────────
        const isCreate = rawId === 'create';
        const isEdit   = !isCreate && action === 'edit';
        const isView   = !isCreate && !isEdit;

        if (id) await entity.load(id);

        const hdr = document.createElement('div');
        hdr.className = 'd-flex justify-content-between align-items-center mb-3 gap-2 flex-wrap';
        hdr.innerHTML = `<h2>${esc(isCreate ? 'New' : isEdit ? 'Edit' : '')} ${esc(entity.meta.name || slug)}</h2>`;

        const back = document.createElement('a');
        back.href  = isView
          ? `/vnext/${esc(slug)}`
          : id ? `/vnext/${esc(slug)}/${esc(id)}` : `/vnext/${esc(slug)}`;
        back.className = 'btn btn-secondary btn-sm';
        back.textContent = '\u2190 Back';
        back.setAttribute('data-go', '');
        hdr.appendChild(back);

        if (isView && id) {
          const editBtn = document.createElement('a');
          editBtn.href = `/vnext/${esc(slug)}/${esc(id)}/edit`;
          editBtn.className = 'btn btn-primary btn-sm';
          editBtn.textContent = '\u270F Edit';
          editBtn.setAttribute('data-go', '');
          hdr.appendChild(editBtn);
        }

        main.appendChild(hdr);

        if (isView) {
          // Readonly view: definition list of all schema fields
          const dl = document.createElement('dl');
          dl.className = 'row';
          Object.entries(entity.meta.schema?.fields || {}).forEach(([name, f]) => {
            if (!f || f.type === 'hidden') return;
            const dt = document.createElement('dt'); dt.className = 'col-sm-3 fw-semibold';
            dt.textContent = f.label || name;
            const dd = document.createElement('dd'); dd.className = 'col-sm-9';
            const v  = entity.state[name];
            dd.textContent = (v == null || v === '') ? '\u2014' : String(v);
            dl.append(dt, dd);
          });
          main.appendChild(dl);

        } else {
          // Edit / Create: render form and override save with navigation + feedback
          entity.renderUI(main);
          entity.state.save = async () => {
            try {
              await entity.save();
              const savedId = entity.state.id || entity.state.Id;
              go(savedId ? `/vnext/${slug}/${savedId}` : `/vnext/${slug}`);
            } catch (err) {
              const a = document.createElement('div');
              a.className = 'alert alert-danger mt-2';
              a.textContent = err.message;
              main.prepend(a);
            }
          };
        }
      }

      wire();
    } catch (e) {
      R.innerHTML = `<div class="container mt-3"><div class="alert alert-danger">${esc(e.message)}</div></div>`;
    }
  }

  route();
})();
