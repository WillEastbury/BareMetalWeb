/**
 * @jest-environment jest-environment-jsdom
 */
'use strict';

const path = require('path');
const fs   = require('fs');

const SRC = path.resolve(
  __dirname, '../../../BareMetalWeb.Core/wwwroot/static/js/BareMetalTemplate.js'
);

function loadTemplate() {
  const code = fs.readFileSync(SRC, 'utf8');
  const iife = code.replace(/const BareMetalTemplate\s*=\s*/, '').replace(/;\s*$/, '');
  const factory = new Function('document', `return (${iife});`);
  return factory(global.document);
}

// ── buildForm ──────────────────────────────────────────────────────────────

describe('BareMetalTemplate – buildForm()', () => {
  let tmpl;
  beforeEach(() => { tmpl = loadTemplate(); });

  test('returns a form element', () => {
    const form = tmpl.buildForm({ fields: ['name'] }, { name: { type: 'text', label: 'Name' } });
    expect(form.tagName).toBe('FORM');
  });

  test('form has rv-on-submit attribute set to "save"', () => {
    const form = tmpl.buildForm({ fields: ['x'] }, { x: {} });
    expect(form.getAttribute('rv-on-submit')).toBe('save');
  });

  test('renders a text input with rv-value', () => {
    const form = tmpl.buildForm({ fields: ['email'] }, { email: { type: 'email', label: 'Email' } });
    const inp = form.querySelector('input[type="email"]');
    expect(inp).not.toBeNull();
    expect(inp.getAttribute('rv-value')).toBe('email');
  });

  test('renders a hidden input without a visible column', () => {
    const form = tmpl.buildForm({ fields: ['id'] }, { id: { type: 'hidden' } });
    const inp = form.querySelector('input[type="hidden"]');
    expect(inp).not.toBeNull();
    // Hidden fields should not be wrapped in a col div
    expect(inp.closest('.col-md-12')).toBeNull();
  });

  test('renders a textarea for type "textarea"', () => {
    const form = tmpl.buildForm({ fields: ['notes'] }, { notes: { type: 'textarea', rows: 5 } });
    const ta = form.querySelector('textarea');
    expect(ta).not.toBeNull();
    expect(ta.rows).toBe(5);
  });

  test('renders a select element with options for type "select"', () => {
    const fields = {
      status: {
        type: 'select',
        label: 'Status',
        options: [
          { value: 'active', label: 'Active' },
          { value: 'inactive', label: 'Inactive' }
        ]
      }
    };
    const form = tmpl.buildForm({ fields: ['status'] }, fields);
    const sel = form.querySelector('select');
    expect(sel).not.toBeNull();
    // Includes the blank "— select —" option + 2 real options
    expect(sel.options.length).toBe(3);
    expect(sel.options[0].value).toBe('');
    expect(sel.options[1].value).toBe('active');
  });

  test('renders a checkbox for type "boolean"', () => {
    const form = tmpl.buildForm({ fields: ['active'] }, { active: { type: 'boolean', label: 'Active' } });
    const chk = form.querySelector('input[type="checkbox"]');
    expect(chk).not.toBeNull();
    expect(chk.className).toContain('form-check-input');
  });

  test('renders a file input for type "file"', () => {
    const form = tmpl.buildForm({ fields: ['avatar'] }, { avatar: { type: 'file', accept: 'image/*' } });
    const inp = form.querySelector('input[type="file"]');
    expect(inp).not.toBeNull();
    expect(inp.accept).toBe('image/*');
  });

  test('sets required attribute when field has required: true', () => {
    const form = tmpl.buildForm({ fields: ['name'] }, { name: { required: true } });
    const inp = form.querySelector('input');
    expect(inp.required).toBe(true);
  });

  test('sets placeholder when field has placeholder', () => {
    const form = tmpl.buildForm({ fields: ['search'] }, { search: { placeholder: 'Type here…' } });
    const inp = form.querySelector('input');
    expect(inp.placeholder).toBe('Type here…');
  });

  test('disables input and adds bg-light class for readonly fields', () => {
    const form = tmpl.buildForm({ fields: ['code'] }, { code: { readonly: true } });
    const inp = form.querySelector('input');
    expect(inp.disabled).toBe(true);
    expect(inp.className).toContain('bg-light');
  });

  test('renders a Save submit button', () => {
    const form = tmpl.buildForm({ fields: ['x'] }, { x: {} });
    const btn = form.querySelector('button[type="submit"]');
    expect(btn).not.toBeNull();
    expect(btn.textContent).toBe('Save');
  });

  test('uses layout.fields order when provided', () => {
    const fields = { a: {}, b: {}, c: {} };
    const form = tmpl.buildForm({ fields: ['c', 'a'] }, fields);
    const inputs = form.querySelectorAll('input:not([type="submit"])');
    // First rendered is 'c', second is 'a'
    expect(inputs[0].getAttribute('rv-value')).toBe('c');
    expect(inputs[1].getAttribute('rv-value')).toBe('a');
  });

  test('adds input-group wrapper and Add/Refresh buttons for lookup select', () => {
    const fields = {
      customerId: {
        type: 'select',
        label: 'Customer',
        lookupUrl: '/api/customers',
        options: []
      }
    };
    const form = tmpl.buildForm({ fields: ['customerId'] }, fields);
    const grp = form.querySelector('.input-group');
    expect(grp).not.toBeNull();
    // Refresh button
    const refBtn = form.querySelector('[data-lookup-refresh]');
    expect(refBtn).not.toBeNull();
    expect(refBtn.dataset.lookupUrl).toBe('/api/customers');
  });

  test('auto-generates label from camelCase field name when label is absent', () => {
    const form = tmpl.buildForm({ fields: ['firstName'] }, { firstName: {} });
    const label = form.querySelector('label');
    // firstName → 'first Name' (space before each capital letter, trimmed)
    expect(label.textContent).toBe('first Name');
  });
});

// ── buildTable ─────────────────────────────────────────────────────────────

describe('BareMetalTemplate – buildTable()', () => {
  let tmpl;
  beforeEach(() => { tmpl = loadTemplate(); });

  const sampleFields = {
    name:  { label: 'Name' },
    email: { label: 'Email' },
  };

  const sampleItems = [
    { id: '1', name: 'Alice', email: 'alice@example.com' },
    { id: '2', name: 'Bob',   email: 'bob@example.com'   },
  ];

  test('returns a div.table-responsive wrapping a table', () => {
    const wrap = tmpl.buildTable(sampleFields, sampleItems, {});
    expect(wrap.className).toContain('table-responsive');
    expect(wrap.querySelector('table')).not.toBeNull();
  });

  test('renders a header row with field labels', () => {
    const wrap = tmpl.buildTable(sampleFields, sampleItems, {});
    const ths = wrap.querySelectorAll('th');
    const labels = Array.from(ths).map(th => th.textContent);
    expect(labels).toContain('Name');
    expect(labels).toContain('Email');
  });

  test('renders one body row per item', () => {
    const wrap = tmpl.buildTable(sampleFields, sampleItems, {});
    const rows = wrap.querySelectorAll('tbody tr');
    expect(rows.length).toBe(2);
  });

  test('renders cell text using default resolver (String(value))', () => {
    const wrap = tmpl.buildTable(sampleFields, sampleItems, {});
    const firstRow = wrap.querySelectorAll('tbody tr')[0];
    const cells = firstRow.querySelectorAll('td');
    expect(cells[0].textContent).toBe('Alice');
    expect(cells[1].textContent).toBe('alice@example.com');
  });

  test('uses custom resolve callback for cell display', () => {
    const resolve = jest.fn((name, v) => name === 'name' ? v.toUpperCase() : v);
    const wrap = tmpl.buildTable(sampleFields, sampleItems, { resolve });
    const firstCell = wrap.querySelector('tbody tr td');
    expect(firstCell.textContent).toBe('ALICE');
  });

  test('renders onEdit button when onEdit callback is provided', () => {
    const onEdit = jest.fn();
    const wrap = tmpl.buildTable(sampleFields, sampleItems, { onEdit });
    const editBtns = wrap.querySelectorAll('button');
    expect(editBtns.length).toBeGreaterThan(0);
    editBtns[0].click();
    expect(onEdit).toHaveBeenCalledWith('1', sampleItems[0]);
  });

  test('renders onDelete button when onDelete callback is provided', () => {
    const onDelete = jest.fn();
    const wrap = tmpl.buildTable(sampleFields, sampleItems, { onDelete });
    // The delete button for the first row is the last button in that row's action cell
    const firstRow = wrap.querySelectorAll('tbody tr')[0];
    const delBtn = Array.from(firstRow.querySelectorAll('button')).pop();
    delBtn.click();
    expect(onDelete).toHaveBeenCalledWith('1', sampleItems[0]);
  });

  test('renders onView button when onView callback is provided', () => {
    const onView = jest.fn();
    const wrap = tmpl.buildTable(sampleFields, sampleItems, { onView });
    const btn = wrap.querySelector('button');
    btn.click();
    expect(onView).toHaveBeenCalledWith('1', sampleItems[0]);
  });

  test('renders boolean fields as badge icons', () => {
    const fields = { active: { label: 'Active', type: 'boolean' } };
    const items  = [{ id: '1', active: true }, { id: '2', active: false }];
    const wrap = tmpl.buildTable(fields, items, {});
    const cells = wrap.querySelectorAll('tbody td:first-child');
    // true → success badge
    expect(cells[0].innerHTML).toContain('bg-success');
    // false → secondary badge
    expect(cells[1].innerHTML).toContain('bg-secondary');
  });

  test('empty items list renders an empty tbody', () => {
    const wrap = tmpl.buildTable(sampleFields, [], {});
    const rows = wrap.querySelectorAll('tbody tr');
    expect(rows.length).toBe(0);
  });
});

// ── BMW Grammar helpers ────────────────────────────────────────────────────

describe('BareMetalTemplate – BMW Grammar helpers', () => {
  let tmpl;
  beforeEach(() => { tmpl = loadTemplate(); });

  test('ds() creates a stack element', () => {
    const el = tmpl.ds([]);
    expect(el.tagName).toBe('DS');
  });

  test('dr() creates a row element with optional attributes', () => {
    const el = tmpl.dr([], { cols: '3' });
    expect(el.tagName).toBe('DR');
    expect(el.getAttribute('cols')).toBe('3');
  });

  test('dc() creates a column element', () => {
    const el = tmpl.dc([]);
    expect(el.tagName).toBe('DC');
  });

  test('db() creates a box element with optional title', () => {
    const el = tmpl.db([], 'Panel Title');
    expect(el.tagName).toBe('DB');
    expect(el.querySelector('strong').textContent).toBe('Panel Title');
  });

  test('dn() creates a nav element with text', () => {
    const el = tmpl.dn('Navigation');
    expect(el.tagName).toBe('DN');
    expect(el.querySelector('span').textContent).toBe('Navigation');
  });

  test('ta() wraps a table element', () => {
    const tbl = document.createElement('table');
    const el = tmpl.ta(tbl);
    expect(el.tagName).toBe('TA');
    expect(el.querySelector('table')).toBe(tbl);
  });

  test('ch(), gt(), cl() create chart, gantt, calendar elements', () => {
    expect(tmpl.ch().tagName).toBe('CH');
    expect(tmpl.gt().tagName).toBe('GT');
    expect(tmpl.cl().tagName).toBe('CL');
  });

  test('nested composition: ds > dr > dc > db', () => {
    const layout = tmpl.ds([
      tmpl.dr([
        tmpl.dc([tmpl.db([], 'A')]),
        tmpl.dc([tmpl.db([], 'B')])
      ], { cols: '2' })
    ]);
    expect(layout.tagName).toBe('DS');
    expect(layout.querySelector('dr').getAttribute('cols')).toBe('2');
    expect(layout.querySelectorAll('dc').length).toBe(2);
    expect(layout.querySelectorAll('db').length).toBe(2);
    expect(layout.querySelectorAll('db')[0].querySelector('strong').textContent).toBe('A');
    expect(layout.querySelectorAll('db')[1].querySelector('strong').textContent).toBe('B');
  });
});

// ── buildBmwForm ───────────────────────────────────────────────────────────

describe('BareMetalTemplate – buildBmwForm()', () => {
  let tmpl;
  beforeEach(() => { tmpl = loadTemplate(); });

  test('returns a form element containing ds/dr/dc tags', () => {
    const form = tmpl.buildBmwForm({ fields: ['name'] }, { name: { type: 'text', label: 'Name' } });
    expect(form.tagName).toBe('FORM');
    expect(form.querySelector('ds')).not.toBeNull();
    expect(form.querySelector('dr')).not.toBeNull();
    expect(form.querySelector('dc')).not.toBeNull();
  });

  test('form has rv-on-submit attribute', () => {
    const form = tmpl.buildBmwForm({ fields: ['x'] }, { x: {} });
    expect(form.getAttribute('rv-on-submit')).toBe('save');
  });

  test('renders input with rv-value', () => {
    const form = tmpl.buildBmwForm({ fields: ['email'] }, { email: { type: 'email' } });
    const inp = form.querySelector('input[type="email"]');
    expect(inp).not.toBeNull();
    expect(inp.getAttribute('rv-value')).toBe('email');
  });

  test('renders hidden inputs outside grid', () => {
    const form = tmpl.buildBmwForm({ fields: ['id', 'name'] }, { id: { type: 'hidden' }, name: {} });
    const hidden = form.querySelector('input[type="hidden"]');
    expect(hidden).not.toBeNull();
    expect(hidden.closest('dc')).toBeNull();
  });

  test('renders a Save submit button', () => {
    const form = tmpl.buildBmwForm({ fields: ['x'] }, { x: {} });
    const btn = form.querySelector('button[type="submit"]');
    expect(btn).not.toBeNull();
    expect(btn.textContent).toBe('Save');
  });

  test('distributes fields across rows based on column count', () => {
    const form = tmpl.buildBmwForm(
      { columns: 2, fields: ['a', 'b', 'c'] },
      { a: {}, b: {}, c: {} }
    );
    const rows = form.querySelectorAll('dr');
    // 3 fields / 2 cols = 2 rows (2 in first, 1 in second) + 1 footer row
    expect(rows.length).toBe(3);
  });

  test('renders select with options', () => {
    const form = tmpl.buildBmwForm({ fields: ['status'] }, {
      status: { type: 'select', options: [{ value: 'a', label: 'A' }] }
    });
    const sel = form.querySelector('select');
    expect(sel).not.toBeNull();
    expect(sel.options.length).toBe(2); // blank + A
  });

  test('renders checkbox for boolean', () => {
    const form = tmpl.buildBmwForm({ fields: ['active'] }, { active: { type: 'boolean' } });
    const chk = form.querySelector('input[type="checkbox"]');
    expect(chk).not.toBeNull();
  });

  test('renders textarea', () => {
    const form = tmpl.buildBmwForm({ fields: ['notes'] }, { notes: { type: 'textarea', rows: 4 } });
    const ta = form.querySelector('textarea');
    expect(ta).not.toBeNull();
    expect(ta.rows).toBe(4);
  });
});

// ── buildBmwTable ──────────────────────────────────────────────────────────

describe('BareMetalTemplate – buildBmwTable()', () => {
  let tmpl;
  beforeEach(() => { tmpl = loadTemplate(); });

  const sampleFields = { name: { label: 'Name' }, email: { label: 'Email' } };
  const sampleItems = [
    { id: '1', name: 'Alice', email: 'alice@example.com' },
    { id: '2', name: 'Bob',   email: 'bob@example.com' }
  ];

  test('returns a ta element wrapping a table', () => {
    const el = tmpl.buildBmwTable(sampleFields, sampleItems, {});
    expect(el.tagName).toBe('TA');
    expect(el.querySelector('table')).not.toBeNull();
  });

  test('renders header with field labels', () => {
    const el = tmpl.buildBmwTable(sampleFields, sampleItems, {});
    const ths = el.querySelectorAll('th');
    const labels = Array.from(ths).map(th => th.textContent);
    expect(labels).toContain('Name');
    expect(labels).toContain('Email');
  });

  test('renders one row per item', () => {
    const el = tmpl.buildBmwTable(sampleFields, sampleItems, {});
    const rows = el.querySelectorAll('tbody tr');
    expect(rows.length).toBe(2);
  });

  test('renders action buttons', () => {
    const onView = jest.fn();
    const el = tmpl.buildBmwTable(sampleFields, sampleItems, { onView });
    const btn = el.querySelector('button');
    btn.click();
    expect(onView).toHaveBeenCalledWith('1', sampleItems[0]);
  });

  test('boolean fields render as check/cross text', () => {
    const fields = { active: { label: 'Active', type: 'boolean' } };
    const items = [{ id: '1', active: true }, { id: '2', active: false }];
    const el = tmpl.buildBmwTable(fields, items, {});
    const cells = el.querySelectorAll('tbody td:first-child');
    expect(cells[0].textContent).toBe('✓');
    expect(cells[1].textContent).toBe('✗');
  });
});
