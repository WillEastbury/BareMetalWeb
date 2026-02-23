// BareMetalTemplate — DOM builder from schema/layout metadata
// Builds Bootstrap-compatible forms and list tables from server-driven structure.
// API: buildForm(layout, fields) → HTMLElement,  buildTable(fields, items, callbacks) → HTMLElement
const BareMetalTemplate = (() => {
  'use strict';

  const INPUT_TYPES = {
    number: 'number', email: 'email', date: 'date',
    'datetime-local': 'datetime-local', time: 'time', password: 'password'
  };
  const mk = (tag, props) => Object.assign(document.createElement(tag), props);

  function buildForm(layout, fields) {
    const form = mk('form', { className: 'mb-3' });
    form.setAttribute('rv-on-submit', 'save');
    const cols = layout.columns || 1;
    const row  = mk('div', { className: 'row g-3' });

    (layout.fields || Object.keys(fields)).forEach(name => {
      const f = fields[name] || {};

      // Hidden fields: carry the value without a visible widget
      if (f.type === 'hidden') {
        const inp = mk('input', { type: 'hidden' });
        inp.setAttribute('rv-value', name);
        row.appendChild(inp);
        return;
      }

      const col = mk('div', { className: 'col-md-' + Math.floor(12 / cols) });
      const lbl = mk('label', {
        className: 'form-label fw-semibold',
        textContent: f.label || name.replace(/([A-Z])/g, ' $1').trim()
      });

      let inp;
      if (f.type === 'boolean') {
        // Use Bootstrap form-check: checkbox then label (avoids label-then-checkbox odd layout)
        const wrap = mk('div', { className: 'form-check mt-2' });
        const chkId = 'f_' + name;
        inp = mk('input', { type: 'checkbox', className: 'form-check-input', id: chkId });
        inp.setAttribute('rv-value', name);
        if (f.required) inp.required = true;
        const chkLabel = mk('label', { className: 'form-check-label', htmlFor: chkId,
          textContent: f.label || name.replace(/([A-Z])/g, ' $1').trim() });
        wrap.append(inp, chkLabel);
        col.appendChild(wrap);
        row.appendChild(col);
        return; // skip standard append below
      } else if (f.type === 'textarea') {
        inp = mk('textarea', { className: 'form-control', rows: f.rows || 3 });
      } else if (f.type === 'select') {
        inp = mk('select', { className: 'form-select' });
        [{ value: '', label: '— select —' }, ...(f.options || [])].forEach(o => {
          const isObj = o !== null && typeof o === 'object';
          inp.appendChild(mk('option', {
            value: isObj ? String(o.value ?? '') : String(o),
            textContent: isObj ? String(o.label ?? o.value ?? o) : String(o)
          }));
        });
      } else if (f.type === 'file') {
        inp = mk('input', { type: 'file', className: 'form-control' });
        if (f.accept) inp.accept = f.accept;
      } else {
        inp = mk('input', { className: 'form-control', type: INPUT_TYPES[f.type] || 'text' });
      }

      inp.setAttribute('rv-value', name);
      if (f.required) inp.required = true;
      if (f.placeholder) inp.placeholder = f.placeholder;
      // Readonly/computed fields are shown with their value but cannot be edited
      if (f.readonly) { inp.disabled = true; inp.className += ' bg-light'; }

      // For lookup selects: wrap in input-group and add Add/Refresh buttons
      if (f.type === 'select' && f.lookupUrl) {
        const grp = mk('div', { className: 'input-group input-group-sm' });
        grp.appendChild(inp);
        const targetSlug = f.lookupUrl.replace(/[?#].*$/, '').replace(/\/$/, '').split('/').pop();
        const addBtn = mk('a', {
          href: '/vnext/' + targetSlug + '/create',
          className: 'btn btn-outline-secondary', title: 'Add new', target: '_blank'
        });
        addBtn.innerHTML = '<i class="bi bi-plus"></i>';
        const refBtn = mk('button', { type: 'button', className: 'btn btn-outline-secondary', title: 'Refresh' });
        refBtn.innerHTML = '<i class="bi bi-arrow-clockwise"></i>';
        refBtn.dataset.lookupRefresh = name;
        refBtn.dataset.lookupUrl = f.lookupUrl;
        refBtn.dataset.lookupValueField = f.lookupValueField || 'id';
        refBtn.dataset.lookupDisplayField = f.lookupDisplayField || 'name';
        grp.append(addBtn, refBtn);
        col.append(lbl, grp);
      } else {
        col.append(lbl, inp);
      }
      row.appendChild(col);
    });

    const foot = mk('div', { className: 'col-12 mt-2 d-flex gap-2' });
    foot.appendChild(mk('button', { type: 'submit', className: 'btn btn-primary', textContent: 'Save' }));
    row.appendChild(foot);
    form.appendChild(row);
    return form;
  }

  function buildTable(fields, items, callbacks) {
    const cb    = callbacks || {};
    const resolve = cb.resolve || ((name, v) => String(v ?? ''));
    const names = Object.keys(fields).filter(n => !fields[n].readonly).slice(0, 6);
    const wrap  = mk('div', { className: 'table-responsive' });
    const tbl   = mk('table', { className: 'table table-hover table-sm align-middle' });
    const hrow  = tbl.createTHead().insertRow();
    names.forEach(n => hrow.appendChild(mk('th', { textContent: fields[n]?.label || n })));
    hrow.appendChild(mk('th', { className: 'text-end' }));
    const tbody = tbl.createTBody();
    items.forEach(item => {
      const tr = tbody.insertRow();
      names.forEach(n => {
        const td = tr.insertCell();
        if (fields[n]?.type === 'boolean') {
          const v = item[n];
          td.innerHTML = (v === true || v === 'true' || v === 1)
            ? '<span class="badge bg-success"><i class="bi bi-check-lg"></i></span>'
            : '<span class="badge bg-secondary"><i class="bi bi-x-lg"></i></span>';
        } else {
          td.textContent = resolve(n, item[n]);
        }
      });
      const td = tr.insertCell(); td.className = 'text-end';
      const id = item.id || item.Id || '';
      if (cb.onView) {
        const b = mk('button', { className: 'btn btn-sm btn-outline-primary me-1', textContent: '\uD83D\uDC41' });
        b.onclick = () => cb.onView(id, item); td.appendChild(b);
      }
      if (cb.onEdit) {
        const b = mk('button', { className: 'btn btn-sm btn-outline-secondary me-1', textContent: '\u270F' });
        b.onclick = () => cb.onEdit(id, item); td.appendChild(b);
      }
      if (cb.onDelete) {
        const b = mk('button', { className: 'btn btn-sm btn-outline-danger', textContent: '\uD83D\uDDD1' });
        b.onclick = () => cb.onDelete(id, item); td.appendChild(b);
      }
    });
    wrap.appendChild(tbl);
    return wrap;
  }

  return { buildForm, buildTable };
})();
