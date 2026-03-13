/**
 * @jest-environment jest-environment-jsdom
 */
'use strict';

const path = require('path');
const fs   = require('fs');

const SRC = path.resolve(
  __dirname, '../../../BareMetalWeb.Core/wwwroot/static/js/theme-switcher.js'
);

// ── Helpers ────────────────────────────────────────────────────────────────

const THEME_STORAGE_KEY  = 'bm-selected-theme';
const LAYOUT_STORAGE_KEY = 'bm-selected-layout';
const DEFAULT_THEME      = 'light';
const THEME_PREFIX       = '/static/css/themes/';
const THEME_SUFFIX       = '.min.css';

// Allowed BMW theme names (must match the set in theme-switcher.js)
const VALID_THEMES = ['light', 'dark', 'colourful', 'muted', 'highviz'];

// Load the theme-switcher IIFE into the current jsdom window.
function loadSwitcher() {
  const code = fs.readFileSync(SRC, 'utf8');
  const fn = new Function('document', 'window', code);
  fn(global.document, global.window);
}

function getThemeLinkHref() {
  const link = document.getElementById('bm-theme');
  return link ? link.href : null;
}

function setCookieTheme(name) {
  document.cookie = `${THEME_STORAGE_KEY}=${encodeURIComponent(name)}; path=/`;
}

function clearCookieTheme() {
  document.cookie = `${THEME_STORAGE_KEY}=; path=/; max-age=0`;
}

function clearCookieLayout() {
  document.cookie = `${LAYOUT_STORAGE_KEY}=; path=/; max-age=0`;
}

// Create a theme select element with all valid theme options and append to body.
function createThemeSelect(id) {
  const sel = document.createElement('select');
  sel.id = id || 'bm-theme-select';
  VALID_THEMES.forEach(t => {
    const opt = document.createElement('option');
    opt.value = t; opt.textContent = t;
    sel.appendChild(opt);
  });
  document.body.appendChild(sel);
  return sel;
}

// Create a layout select element and append to body.
function createLayoutSelect() {
  const sel = document.createElement('select');
  sel.id = 'bm-layout-select';
  ['top', 'sidebar'].forEach(v => {
    const opt = document.createElement('option');
    opt.value = v; opt.textContent = v;
    sel.appendChild(opt);
  });
  document.body.appendChild(sel);
  return sel;
}

// Shared beforeEach: full DOM reset to prevent cross-test contamination.
function sharedCleanup() {
  clearCookieTheme();
  clearCookieLayout();
  document.querySelectorAll('#bm-theme-select').forEach(el => el.remove());
  document.querySelectorAll('#bm-layout-select').forEach(el => el.remove());
  const link = document.getElementById('bm-theme');
  if (link) link.remove();
  // Reset body attributes — JS will re-apply on next loadSwitcher() call
  document.body.removeAttribute('data-bm-layout');
  document.body.removeAttribute('data-bm-skin');
}

// ── BMW skin always-on ──────────────────────────────────────────────────────

describe('theme-switcher – BMW skin always active', () => {
  afterEach(sharedCleanup);

  test('loads with data-bm-skin="bmw" set on body', () => {
    createThemeSelect();
    loadSwitcher();
    expect(document.body.getAttribute('data-bm-skin')).toBe('bmw');
  });
});

// ── getStoredTheme / setStoredTheme ────────────────────────────────────────

describe('theme-switcher – cookie storage', () => {
  beforeEach(sharedCleanup);
  afterEach(sharedCleanup);

  test('default theme is "light" when no cookie is set', () => {
    const sel = createThemeSelect();
    loadSwitcher();
    const href = getThemeLinkHref();
    expect(href).toContain(DEFAULT_THEME);
  });

  test('stored cookie theme is applied on load', () => {
    setCookieTheme('dark');
    const sel = createThemeSelect();
    loadSwitcher();
    const href = getThemeLinkHref();
    expect(href).toContain('dark');
  });

  test('theme select value is set to stored cookie value on load', () => {
    setCookieTheme('muted');
    const sel = createThemeSelect();
    loadSwitcher();
    expect(sel.value).toBe('muted');
  });
});

// ── applyTheme ─────────────────────────────────────────────────────────────

describe('theme-switcher – applyTheme()', () => {
  beforeEach(sharedCleanup);
  afterEach(sharedCleanup);

  test('creates the bm-theme link element when absent', () => {
    createThemeSelect();
    loadSwitcher();
    expect(document.getElementById('bm-theme')).not.toBeNull();
  });

  test('link href reflects the selected theme', () => {
    createThemeSelect();
    loadSwitcher();
    const href = getThemeLinkHref();
    expect(href).toContain(THEME_PREFIX.replace('/', ''));
    expect(href).toContain(THEME_SUFFIX);
  });

  test('changing the select triggers a theme change', () => {
    const sel = createThemeSelect();
    loadSwitcher();

    sel.value = 'dark';
    sel.dispatchEvent(new Event('change'));

    const href = getThemeLinkHref();
    expect(href).toContain('dark');
  });

  test('unknown theme is clamped to the default', () => {
    setCookieTheme('invalid-theme-xyz');
    createThemeSelect();
    loadSwitcher();
    const href = getThemeLinkHref();
    expect(href).toContain(DEFAULT_THEME);
  });

  test('no select element present → init() exits gracefully without errors', () => {
    expect(() => loadSwitcher()).not.toThrow();
  });
});

// ── applyLayout ─────────────────────────────────────────────────────────────

describe('theme-switcher – applyLayout()', () => {
  beforeEach(sharedCleanup);
  afterEach(sharedCleanup);

  test('default layout sets data-bm-layout="top" on body', () => {
    createThemeSelect();
    createLayoutSelect();
    loadSwitcher();
    expect(document.body.getAttribute('data-bm-layout')).toBe('top');
  });

  test('selecting sidebar sets data-bm-layout="sidebar" on body', () => {
    const sel = createThemeSelect();
    const layoutSel = createLayoutSelect();
    loadSwitcher();

    layoutSel.value = 'sidebar';
    layoutSel.dispatchEvent(new Event('change'));

    expect(document.body.getAttribute('data-bm-layout')).toBe('sidebar');
  });

  test('switching back to top sets data-bm-layout="top"', () => {
    document.cookie = `${LAYOUT_STORAGE_KEY}=sidebar; path=/`;
    const sel = createThemeSelect();
    const layoutSel = createLayoutSelect();
    loadSwitcher();

    layoutSel.value = 'top';
    layoutSel.dispatchEvent(new Event('change'));

    expect(document.body.getAttribute('data-bm-layout')).toBe('top');
  });
});
