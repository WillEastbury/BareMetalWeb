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

const STORAGE_KEY    = 'bm-selected-theme';
const DEFAULT_THEME  = 'vapor';
const THEME_PREFIX   = '/static/css/themes/';
const THEME_SUFFIX   = '.min.css';

// Allowed theme names (must match the set in theme-switcher.js)
const VALID_THEMES = ['cerulean', 'cosmo', 'cyborg', 'darkly', 'flatly', 'vapor'];

// Load the theme-switcher IIFE into the current jsdom window.
function loadSwitcher() {
  const code = fs.readFileSync(SRC, 'utf8');
  const fn = new Function('document', 'window', code);
  fn(global.document, global.window);
}

function getThemeLinkHref() {
  const link = document.getElementById('bootswatch-theme');
  return link ? link.href : null;
}

function setCookieTheme(name) {
  document.cookie = `${STORAGE_KEY}=${encodeURIComponent(name)}; path=/`;
}

function clearCookieTheme() {
  document.cookie = `${STORAGE_KEY}=; path=/; max-age=0`;
}

// Create a select element with all valid theme options and append to body.
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

// Shared beforeEach: full DOM reset to prevent cross-test contamination.
function sharedCleanup() {
  clearCookieTheme();
  // Remove all bm-theme-select and bootswatch-theme elements
  document.querySelectorAll('#bm-theme-select').forEach(el => el.remove());
  const link = document.getElementById('bootswatch-theme');
  if (link) link.remove();
}

// ── getStoredTheme / setStoredTheme ────────────────────────────────────────

describe('theme-switcher – cookie storage', () => {
  beforeEach(sharedCleanup);
  afterEach(sharedCleanup);

  test('default theme is "vapor" when no cookie is set', () => {
    const sel = createThemeSelect();
    loadSwitcher();
    const href = getThemeLinkHref();
    expect(href).toContain(DEFAULT_THEME);
  });

  test('stored cookie theme is applied on load', () => {
    setCookieTheme('darkly');
    const sel = createThemeSelect();
    loadSwitcher();
    const href = getThemeLinkHref();
    expect(href).toContain('darkly');
  });

  test('theme select value is set to stored cookie value on load', () => {
    setCookieTheme('cosmo');
    const sel = createThemeSelect();
    loadSwitcher();
    expect(sel.value).toBe('cosmo');
  });
});

// ── applyTheme ─────────────────────────────────────────────────────────────

describe('theme-switcher – applyTheme()', () => {
  beforeEach(sharedCleanup);
  afterEach(sharedCleanup);

  test('creates the bootswatch-theme link element when absent', () => {
    createThemeSelect();
    loadSwitcher();
    expect(document.getElementById('bootswatch-theme')).not.toBeNull();
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

    sel.value = 'cosmo';
    sel.dispatchEvent(new Event('change'));

    const href = getThemeLinkHref();
    expect(href).toContain('cosmo');
  });

  test('unknown theme is clamped to the default', () => {
    setCookieTheme('invalid-theme-xyz');
    createThemeSelect();
    loadSwitcher();
    const href = getThemeLinkHref();
    expect(href).toContain(DEFAULT_THEME);
  });

  test('does not set data-bs-theme attribute (removed on apply)', () => {
    document.body.setAttribute('data-bs-theme', 'dark');
    createThemeSelect();
    loadSwitcher();
    expect(document.body.hasAttribute('data-bs-theme')).toBe(false);
  });

  test('no select element present → init() exits gracefully without errors', () => {
    expect(() => loadSwitcher()).not.toThrow();
  });
});
