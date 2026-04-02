// BareMetalTemplate — DOM builder from schema/layout metadata
// Builds Bootstrap-compatible forms and list tables from server-driven structure.
// API: buildForm(layout, fields) → HTMLElement,  buildTable(fields, items, callbacks) → HTMLElement
const BareMetalTemplate = (() => {
  'use strict';

  const INPUT_TYPES = {
    number: 'number', email: 'email', date: 'date',
    'datetime-local': 'datetime-local', time: 'time', password: 'password',
    Integer: 'number', Decimal: 'number', Money: 'number',
    Email: 'email', DateTime: 'datetime-local', Date: 'date', Time: 'time',
    Password: 'password', Url: 'text', Phone: 'tel'
  };
  const COUNTRY_OPTIONS = [
    ['','— Select —'],['AF','Afghanistan'],['AL','Albania'],['DZ','Algeria'],['AR','Argentina'],['AU','Australia'],
    ['AT','Austria'],['BE','Belgium'],['BR','Brazil'],['CA','Canada'],['CN','China'],
    ['CO','Colombia'],['HR','Croatia'],['CZ','Czech Republic'],['DK','Denmark'],['EG','Egypt'],
    ['FI','Finland'],['FR','France'],['DE','Germany'],['GR','Greece'],['HK','Hong Kong'],
    ['HU','Hungary'],['IN','India'],['ID','Indonesia'],['IE','Ireland'],['IL','Israel'],
    ['IT','Italy'],['JP','Japan'],['MX','Mexico'],['NL','Netherlands'],['NZ','New Zealand'],
    ['NG','Nigeria'],['NO','Norway'],['PK','Pakistan'],['PH','Philippines'],['PL','Poland'],
    ['PT','Portugal'],['RO','Romania'],['RU','Russia'],['SA','Saudi Arabia'],['SG','Singapore'],
    ['ZA','South Africa'],['KR','South Korea'],['ES','Spain'],['SE','Sweden'],['CH','Switzerland'],
    ['TW','Taiwan'],['TH','Thailand'],['TR','Turkey'],['UA','Ukraine'],['AE','United Arab Emirates'],
    ['GB','United Kingdom'],['US','United States'],['VN','Vietnam']
  ];
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
      } else if (f.type === 'Country') {
        inp = mk('select', { className: 'form-select' });
        COUNTRY_OPTIONS.forEach(c => {
          inp.appendChild(mk('option', { value: c[0], textContent: c[1] }));
        });
      } else if (f.type === 'file') {
        inp = mk('input', { type: 'file', className: 'form-control' });
        if (f.accept) inp.accept = f.accept;
      } else {
        inp = mk('input', { className: 'form-control', type: INPUT_TYPES[f.type] || 'text' });
        if (f.type === 'Integer') inp.step = '1';
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
          href: '/' + targetSlug + '/create',
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

  // ── BMW Layout Grammar helpers ──
  // Build lightweight custom element DOM: ds=stack dr=row dc=column db=box dn=nav ta=table
  const ds = (children) => { const e = document.createElement('ds'); (children||[]).forEach(c => e.appendChild(c)); return e; };
  const dr = (children, attrs) => { const e = document.createElement('dr'); if (attrs) Object.entries(attrs).forEach(([k,v]) => e.setAttribute(k,v)); (children||[]).forEach(c => e.appendChild(c)); return e; };
  const dc = (children) => { const e = document.createElement('dc'); (children||[]).forEach(c => e.appendChild(c)); return e; };
  const db = (children, title) => {
    const e = document.createElement('db');
    if (title) { const h = mk('strong', { textContent: title }); e.appendChild(h); }
    (children||[]).forEach(c => e.appendChild(c));
    return e;
  };
  const dn = (text, children) => {
    const e = document.createElement('dn');
    if (text) e.appendChild(mk('span', { textContent: text }));
    (children||[]).forEach(c => e.appendChild(c));
    return e;
  };
  const ta = (tableEl) => { const e = document.createElement('ta'); if (tableEl) e.appendChild(tableEl); return e; };
  const ch = () => document.createElement('ch');
  const gt = () => document.createElement('gt');
  const cl = () => document.createElement('cl');

  // Build a BMW grammar form — uses ds/dr/dc instead of Bootstrap grid
  function buildBmwForm(layout, fields) {
    const form = mk('form', {});
    form.setAttribute('rv-on-submit', 'save');
    const stack = document.createElement('ds');
    const cols = layout.columns || 2;
    let currentRow = null;
    let colCount = 0;

    (layout.fields || Object.keys(fields)).forEach(name => {
      const f = fields[name] || {};
      if (f.type === 'hidden') {
        const inp = mk('input', { type: 'hidden' });
        inp.setAttribute('rv-value', name);
        form.appendChild(inp);
        return;
      }

      if (!currentRow || colCount >= cols) {
        currentRow = document.createElement('dr');
        stack.appendChild(currentRow);
        colCount = 0;
      }

      const col = document.createElement('dc');
      const lbl = mk('label', {
        textContent: f.label || name.replace(/([A-Z])/g, ' $1').trim()
      });
      lbl.style.fontWeight = '600';
      lbl.style.fontSize = '0.85rem';

      let inp;
      if (f.type === 'boolean') {
        inp = mk('input', { type: 'checkbox' });
      } else if (f.type === 'textarea') {
        inp = mk('textarea', { rows: f.rows || 3 });
        inp.style.width = '100%';
      } else if (f.type === 'select') {
        inp = mk('select', {});
        inp.style.width = '100%';
        [{ value: '', label: '— select —' }, ...(f.options || [])].forEach(o => {
          const isObj = o !== null && typeof o === 'object';
          inp.appendChild(mk('option', {
            value: isObj ? String(o.value ?? '') : String(o),
            textContent: isObj ? String(o.label ?? o.value ?? o) : String(o)
          }));
        });
      } else if (f.type === 'Country') {
        inp = mk('select', {});
        inp.style.width = '100%';
        COUNTRY_OPTIONS.forEach(c => {
          inp.appendChild(mk('option', { value: c[0], textContent: c[1] }));
        });
      } else if (f.type === 'file') {
        inp = mk('input', { type: 'file' });
        if (f.accept) inp.accept = f.accept;
      } else {
        inp = mk('input', { type: INPUT_TYPES[f.type] || 'text' });
        inp.style.width = '100%';
        if (f.type === 'Integer') inp.step = '1';
      }

      inp.setAttribute('rv-value', name);
      if (f.required) inp.required = true;
      if (f.placeholder) inp.placeholder = f.placeholder;
      if (f.readonly) inp.disabled = true;

      col.append(lbl, inp);
      currentRow.appendChild(col);
      colCount++;
    });

    const foot = document.createElement('dr');
    const saveBtn = mk('button', { type: 'submit', textContent: 'Save' });
    saveBtn.style.cssText = 'padding:6px 16px;font-weight:600;cursor:pointer';
    foot.appendChild(saveBtn);
    stack.appendChild(foot);
    form.appendChild(stack);
    return form;
  }

  // Build a BMW grammar table — uses <ta> wrapper with plain <table>
  function buildBmwTable(fields, items, callbacks) {
    const cb = callbacks || {};
    const resolve = cb.resolve || ((name, v) => String(v ?? ''));
    const names = Object.keys(fields).filter(n => !fields[n].readonly).slice(0, 6);
    const tbl = mk('table', {});
    const hrow = tbl.createTHead().insertRow();
    names.forEach(n => hrow.appendChild(mk('th', { textContent: fields[n]?.label || n })));
    hrow.appendChild(mk('th', {}));
    const tbody = tbl.createTBody();
    items.forEach(item => {
      const tr = tbody.insertRow();
      names.forEach(n => {
        const td = tr.insertCell();
        if (fields[n]?.type === 'boolean') {
          td.textContent = (item[n] === true || item[n] === 'true' || item[n] === 1) ? '✓' : '✗';
        } else {
          td.textContent = resolve(n, item[n]);
        }
      });
      const td = tr.insertCell(); td.style.textAlign = 'right';
      const id = item.id || item.Id || '';
      if (cb.onView) { const b = mk('button', { textContent: '👁' }); b.onclick = () => cb.onView(id, item); td.appendChild(b); }
      if (cb.onEdit) { const b = mk('button', { textContent: '✏' }); b.onclick = () => cb.onEdit(id, item); td.appendChild(b); }
      if (cb.onDelete) { const b = mk('button', { textContent: '🗑' }); b.onclick = () => cb.onDelete(id, item); td.appendChild(b); }
    });
    return ta(tbl);
  }

  return { buildForm, buildTable, buildBmwForm, buildBmwTable, ds, dr, dc, db, dn, ta, ch, gt, cl };
})();
