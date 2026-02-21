// VNext Router — thin SPA router powered by BareMetalRendering
// Parses /vnext[/admin/data]/[{slug}[/{id}[/edit]|/create]]
// Depends on: BareMetalRest, BareMetalBind, BareMetalTemplate, BareMetalRendering
(async function () {
  'use strict';
  BareMetalRest.setRoot('/api/');

  const R   = document.getElementById('vnext-root');
  const esc = s => String(s ?? '').replace(/[&<>"]/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
  const el  = (tag, props, children) => {
    const e = Object.assign(document.createElement(tag), props);
    (children || []).forEach(c => typeof c === 'string' ? e.append(c) : e.appendChild(c));
    return e;
  };
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
    const nav = el('nav', { className: 'navbar navbar-expand navbar-dark bg-dark mb-3 px-3' });
    const brand = el('a', { className: 'navbar-brand', href: '/vnext', textContent: '\u26A1 VNext' });
    brand.setAttribute('data-go', '');
    nav.appendChild(brand);
    const ul = el('ul', { className: 'navbar-nav me-auto' });

    // Group entities by navGroup for dropdown menus
    const groups = new Map();
    all.filter(e => e.showOnNav).forEach(e => {
      const g = e.navGroup || '';
      if (!groups.has(g)) groups.set(g, []);
      groups.get(g).push(e);
    });

    groups.forEach((entities, groupName) => {
      if (!groupName || entities.length === 1) {
        // No group or single item — render as flat nav links
        entities.forEach(e => {
          const li = el('li', { className: 'nav-item' });
          const a  = el('a', { className: 'nav-link' + (e.slug === activeSlug ? ' active' : ''), href: '/vnext/' + e.slug, textContent: e.name });
          a.setAttribute('data-go', '');
          li.appendChild(a);
          ul.appendChild(li);
        });
      } else {
        // Multiple items in a group — Bootstrap dropdown
        const li = el('li', { className: 'nav-item dropdown' });
        const toggle = el('a', {
          className: 'nav-link dropdown-toggle' + (entities.some(e => e.slug === activeSlug) ? ' active' : ''),
          href: '#', textContent: groupName, role: 'button'
        });
        toggle.setAttribute('data-bs-toggle', 'dropdown');
        toggle.setAttribute('aria-expanded', 'false');
        li.appendChild(toggle);
        const menu = el('ul', { className: 'dropdown-menu' });
        entities.forEach(e => {
          const mli = el('li');
          const a = el('a', { className: 'dropdown-item' + (e.slug === activeSlug ? ' active' : ''), href: '/vnext/' + e.slug, textContent: e.name });
          a.setAttribute('data-go', '');
          mli.appendChild(a);
          menu.appendChild(mli);
        });
        li.appendChild(menu);
        ul.appendChild(li);
      }
    });

    nav.appendChild(ul);
    nav.appendChild(el('a', { className: 'btn btn-sm btn-outline-light', href: '/admin/data', textContent: 'Classic UI' }));
    return nav;
  }

  async function route() {
    const p      = location.pathname.replace(/^\/vnext\/?/, '').replace(/^admin\/data\/?/, '').split('/').filter(Boolean);
    const slug   = p[0], rawId = p[1], action = p[2];
    const id     = (rawId && rawId !== 'create') ? rawId : null;

    R.replaceChildren(
      el('div', { className: 'd-flex justify-content-center mt-5' }, [
        el('div', { className: 'spinner-border', role: 'status' }, [
          el('span', { className: 'visually-hidden', textContent: 'Loading\u2026' })
        ])
      ])
    );

    try {
      if (!_entityList) _entityList = await BareMetalRendering.listEntities();

      // ── Home: entity cards ───────────────────────────────────────────────
      if (!slug) {
        R.replaceChildren(navbar());
        const container = el('div', { className: 'container' });
        const row = el('div', { className: 'row g-3 mt-1' });
        (_entityList || []).filter(e => e.showOnNav).forEach(e => {
          const card = el('a', { className: 'card card-body text-decoration-none', href: '/vnext/' + e.slug });
          card.setAttribute('data-go', '');
          card.appendChild(el('strong', { textContent: e.name }));
          card.appendChild(el('p', { className: 'text-muted small mb-0', textContent: e.navGroup || '' }));
          row.appendChild(el('div', { className: 'col-sm-6 col-md-3' }, [card]));
        });
        container.appendChild(row);
        R.appendChild(container);
        wire(); return;
      }

      const entity = await BareMetalRendering.createEntity(slug);
      R.replaceChildren(navbar(slug));
      const main = el('div', { className: 'container' });
      R.appendChild(main);

      if (!rawId) {
        // ── List view ───────────────────────────────────────────────────────
        const items  = await BareMetalRest.entity(slug).list();
        const hdr    = el('div', { className: 'd-flex justify-content-between align-items-center mb-3' });
        hdr.appendChild(el('h2', { textContent: entity.meta.name || slug }));
        const addBtn  = el('a', { href: '/vnext/' + slug + '/create', className: 'btn btn-success btn-sm', textContent: '+ Add' });
        addBtn.setAttribute('data-go', '');
        hdr.appendChild(addBtn);
        main.appendChild(hdr);
        main.appendChild(BareMetalTemplate.buildTable(
          entity.meta.schema?.fields || {},
          Array.isArray(items) ? items : [],
          {
            resolve:  (name, v) => entity.resolve(name, v),
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

        const hdr = el('div', { className: 'd-flex justify-content-between align-items-center mb-3 gap-2 flex-wrap' });
        const title = isCreate ? 'New' : isEdit ? 'Edit' : '';
        hdr.appendChild(el('h2', { textContent: (title ? title + ' ' : '') + (entity.meta.name || slug) }));

        const back = el('a', {
          href: isView ? `/vnext/${slug}` : id ? `/vnext/${slug}/${id}` : `/vnext/${slug}`,
          className: 'btn btn-secondary btn-sm',
          textContent: '\u2190 Back'
        });
        back.setAttribute('data-go', '');
        hdr.appendChild(back);

        if (isView && id) {
          const editBtn = el('a', { href: `/vnext/${slug}/${id}/edit`, className: 'btn btn-primary btn-sm', textContent: '\u270F Edit' });
          editBtn.setAttribute('data-go', '');
          hdr.appendChild(editBtn);
        }

        main.appendChild(hdr);

        if (isView) {
          const dl = el('dl', { className: 'row' });
          Object.entries(entity.meta.schema?.fields || {}).forEach(([name, f]) => {
            if (!f || f.type === 'hidden') return;
            const dt = el('dt', { className: 'col-sm-3 fw-semibold', textContent: f.label || name });
            const v  = entity.state[name];
            const display = entity.resolve(name, v);
            const dd = el('dd', { className: 'col-sm-9', textContent: (v == null || v === '') ? '\u2014' : display });
            dl.append(dt, dd);
          });
          main.appendChild(dl);

        } else {
          entity.renderUI(main);
          entity.state.save = async () => {
            try {
              await entity.save();
              const savedId = entity.state.id || entity.state.Id;
              go(savedId ? `/vnext/${slug}/${savedId}` : `/vnext/${slug}`);
            } catch (err) {
              main.prepend(el('div', { className: 'alert alert-danger mt-2', textContent: err.message }));
            }
          };
        }
      }

      wire();
    } catch (e) {
      R.replaceChildren(
        el('div', { className: 'container mt-3' }, [
          el('div', { className: 'alert alert-danger', textContent: e.message })
        ])
      );
    }
  }

  route();
})();
