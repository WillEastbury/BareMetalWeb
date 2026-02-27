/**
 * @jest-environment jest-environment-jsdom
 */
'use strict';

const path = require('path');
const fs   = require('fs');

const SRC = path.resolve(
  __dirname, '../../../BareMetalWeb.Core/wwwroot/static/js/BareMetalBind.js'
);

// Helper: load BareMetalBind into the current jsdom context each time.
// Uses new Function so each test suite starts from a fresh module instance.
function loadBind() {
  const code = fs.readFileSync(SRC, 'utf8');
  const iife = code.replace(/const BareMetalBind\s*=\s*/, '').replace(/;\s*$/, '');
  const factory = new Function(
    'document',
    `return (${iife});`
  );
  return factory(global.document);
}

// ── reactive() ────────────────────────────────────────────────────────────

describe('BareMetalBind – reactive()', () => {
  let bind;
  beforeEach(() => { bind = loadBind(); });

  test('returns state, watch, and data properties', () => {
    const r = bind.reactive({ x: 1 });
    expect(r).toHaveProperty('state');
    expect(r).toHaveProperty('watch');
    expect(r).toHaveProperty('data');
  });

  test('state reads initial values', () => {
    const { state } = bind.reactive({ name: 'Alice', age: 30 });
    expect(state.name).toBe('Alice');
    expect(state.age).toBe(30);
  });

  test('setting state property notifies registered watcher', () => {
    const { state, watch } = bind.reactive({ count: 0 });
    const spy = jest.fn();
    watch('count', spy);
    state.count = 5;
    expect(spy).toHaveBeenCalledTimes(1);
  });

  test('setting state property updates data object', () => {
    const { state, data } = bind.reactive({ val: 'old' });
    state.val = 'new';
    expect(data.val).toBe('new');
  });

  test('multiple watchers on the same key are all called', () => {
    const { state, watch } = bind.reactive({ x: 0 });
    const spy1 = jest.fn();
    const spy2 = jest.fn();
    watch('x', spy1);
    watch('x', spy2);
    state.x = 42;
    expect(spy1).toHaveBeenCalledTimes(1);
    expect(spy2).toHaveBeenCalledTimes(1);
  });

  test('watcher for a different key is NOT called', () => {
    const { state, watch } = bind.reactive({ a: 1, b: 2 });
    const spyA = jest.fn();
    watch('a', spyA);
    state.b = 99;
    expect(spyA).not.toHaveBeenCalled();
  });
});

// ── bind() – rv-text ──────────────────────────────────────────────────────

describe('BareMetalBind – bind() rv-text directive', () => {
  let bind;
  beforeEach(() => { bind = loadBind(); });

  test('sets textContent from state on initial bind', () => {
    const root = document.createElement('div');
    root.innerHTML = '<span rv-text="greeting"></span>';
    const { state, watch } = bind.reactive({ greeting: 'Hello' });
    bind.bind(root, state, watch);
    expect(root.querySelector('span').textContent).toBe('Hello');
  });

  test('updates textContent when state changes', () => {
    const root = document.createElement('div');
    root.innerHTML = '<span rv-text="msg"></span>';
    const { state, watch } = bind.reactive({ msg: 'before' });
    bind.bind(root, state, watch);
    state.msg = 'after';
    expect(root.querySelector('span').textContent).toBe('after');
  });

  test('textContent is empty string when state value is undefined', () => {
    const root = document.createElement('div');
    root.innerHTML = '<span rv-text="missing"></span>';
    const { state, watch } = bind.reactive({});
    bind.bind(root, state, watch);
    expect(root.querySelector('span').textContent).toBe('');
  });
});

// ── bind() – rv-value ─────────────────────────────────────────────────────

describe('BareMetalBind – bind() rv-value directive', () => {
  let bind;
  beforeEach(() => { bind = loadBind(); });

  test('sets input value from state on initial bind', () => {
    const root = document.createElement('div');
    root.innerHTML = '<input rv-value="name">';
    const { state, watch } = bind.reactive({ name: 'Bob' });
    bind.bind(root, state, watch);
    expect(root.querySelector('input').value).toBe('Bob');
  });

  test('updates input value when state changes', () => {
    const root = document.createElement('div');
    root.innerHTML = '<input rv-value="city">';
    const { state, watch } = bind.reactive({ city: 'London' });
    bind.bind(root, state, watch);
    state.city = 'Paris';
    expect(root.querySelector('input').value).toBe('Paris');
  });

  test('input event updates state', () => {
    const root = document.createElement('div');
    root.innerHTML = '<input rv-value="val">';
    const { state, watch } = bind.reactive({ val: '' });
    bind.bind(root, state, watch);
    const inp = root.querySelector('input');
    inp.value = 'typed';
    inp.dispatchEvent(new Event('input'));
    expect(state.val).toBe('typed');
  });

  test('checkbox reflects boolean state', () => {
    const root = document.createElement('div');
    root.innerHTML = '<input type="checkbox" rv-value="active">';
    const { state, watch } = bind.reactive({ active: true });
    bind.bind(root, state, watch);
    expect(root.querySelector('input').checked).toBe(true);
  });

  test('checkbox change event updates boolean state', () => {
    const root = document.createElement('div');
    root.innerHTML = '<input type="checkbox" rv-value="flag">';
    const { state, watch } = bind.reactive({ flag: false });
    bind.bind(root, state, watch);
    const chk = root.querySelector('input');
    chk.checked = true;
    chk.dispatchEvent(new Event('change'));
    expect(state.flag).toBe(true);
  });

  test('date input formats value to YYYY-MM-DD', () => {
    const root = document.createElement('div');
    root.innerHTML = '<input type="date" rv-value="dob">';
    const { state, watch } = bind.reactive({ dob: '2000-06-15T00:00:00Z' });
    bind.bind(root, state, watch);
    expect(root.querySelector('input').value).toBe('2000-06-15');
  });
});

// ── bind() – rv-if ────────────────────────────────────────────────────────

describe('BareMetalBind – bind() rv-if directive', () => {
  let bind;
  beforeEach(() => { bind = loadBind(); });

  test('shows element when state value is truthy', () => {
    const root = document.createElement('div');
    root.innerHTML = '<div rv-if="visible">content</div>';
    const { state, watch } = bind.reactive({ visible: true });
    bind.bind(root, state, watch);
    expect(root.querySelector('div').style.display).toBe('');
  });

  test('hides element when state value is falsy', () => {
    const root = document.createElement('div');
    root.innerHTML = '<div rv-if="visible">content</div>';
    const { state, watch } = bind.reactive({ visible: false });
    bind.bind(root, state, watch);
    expect(root.querySelector('div').style.display).toBe('none');
  });

  test('toggles display when state changes', () => {
    const root = document.createElement('div');
    root.innerHTML = '<div rv-if="show">x</div>';
    const { state, watch } = bind.reactive({ show: true });
    bind.bind(root, state, watch);
    state.show = false;
    expect(root.querySelector('div').style.display).toBe('none');
    state.show = true;
    expect(root.querySelector('div').style.display).toBe('');
  });
});

// ── bind() – rv-on-click ──────────────────────────────────────────────────

describe('BareMetalBind – bind() rv-on-click directive', () => {
  let bind;
  beforeEach(() => { bind = loadBind(); });

  test('calls state function when button is clicked', () => {
    const root = document.createElement('div');
    root.innerHTML = '<button rv-on-click="handleClick">click me</button>';
    const handler = jest.fn();
    const { state, watch } = bind.reactive({ handleClick: handler });
    bind.bind(root, state, watch);
    root.querySelector('button').click();
    expect(handler).toHaveBeenCalledTimes(1);
  });

  test('does not throw when rv-on-click references a non-function state key', () => {
    const root = document.createElement('div');
    root.innerHTML = '<button rv-on-click="notAFn">x</button>';
    const { state, watch } = bind.reactive({ notAFn: 'oops' });
    bind.bind(root, state, watch);
    expect(() => root.querySelector('button').click()).not.toThrow();
  });
});

// ── bind() – rv-on-submit ─────────────────────────────────────────────────

describe('BareMetalBind – bind() rv-on-submit directive', () => {
  let bind;
  beforeEach(() => { bind = loadBind(); });

  test('calls state function on form submit', () => {
    const root = document.createElement('div');
    root.innerHTML = '<form rv-on-submit="save"><button type="submit">go</button></form>';
    const saveHandler = jest.fn();
    const { state, watch } = bind.reactive({ save: saveHandler });
    bind.bind(root, state, watch);
    const form = root.querySelector('form');
    form.dispatchEvent(new Event('submit'));
    expect(saveHandler).toHaveBeenCalledTimes(1);
  });
});
