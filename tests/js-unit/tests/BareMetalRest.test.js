/**
 * @jest-environment jest-environment-jsdom
 */
'use strict';

const path = require('path');
const fs   = require('fs');

const SRC = path.resolve(
  __dirname, '../../../BareMetalWeb.Core/wwwroot/static/js/BareMetalRest.js'
);

// Helper: load the module so its `fetch` references global.fetch at call time.
// We extract the IIFE by removing the `const BareMetalRest = ` assignment and
// wrapping it in a factory function that receives explicit globals, allowing
// `fetch` to be lazily delegated so per-test mocks work at call time.
function loadRest() {
  const code = fs.readFileSync(SRC, 'utf8');
  // Remove the outer `const BareMetalRest = ` assignment (note: no ^ so it finds it after comments)
  const iife = code.replace(/const BareMetalRest\s*=\s*/, '').replace(/;\s*$/, '');
  // Build a factory that injects globals; fetch is wrapped so tests can swap global.fetch
  const factory = new Function(
    'fetchFn', 'document', 'location', 'FormData', 'URLSearchParams',
    // Shadow bare `fetch` with our injectable wrapper inside the IIFE body
    'var fetch = fetchFn;\n' +
    `return (${iife});`
  );
  return factory(
    (...args) => global.fetch(...args),  // lazy delegate — test mocks work at call time
    global.document,
    global.location,
    global.FormData,
    global.URLSearchParams
  );
}

// ── Shared fetch response builders ────────────────────────────────────────

function jsonResponse(data, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => 'application/json' },
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  };
}

function noContentResponse() {
  return { ok: true, status: 204, headers: { get: () => '' } };
}

function errorResponse(statusText, bodyText, status = 500) {
  return {
    ok: false, status, statusText,
    headers: { get: () => 'text/plain' },
    text: () => Promise.resolve(bodyText),
  };
}

// ── setRoot / getRoot ──────────────────────────────────────────────────────

describe('BareMetalRest – root URL management', () => {
  let rest;
  beforeEach(() => { rest = loadRest(); });

  test('default root is /api/', () => {
    expect(rest.getRoot()).toBe('/api/');
  });

  test('setRoot appends trailing slash when missing', () => {
    rest.setRoot('/v2/api');
    expect(rest.getRoot()).toBe('/v2/api/');
  });

  test('setRoot keeps trailing slash when already present', () => {
    rest.setRoot('/v3/api/');
    expect(rest.getRoot()).toBe('/v3/api/');
  });

  test('entity() is accessible after setRoot', () => {
    rest.setRoot('/custom/');
    expect(typeof rest.entity('items').list).toBe('function');
  });
});

// ── entity() – URL construction ────────────────────────────────────────────

describe('BareMetalRest – entity() helper', () => {
  let rest;

  beforeEach(() => {
    global.fetch = jest.fn().mockResolvedValue(jsonResponse([]));
    rest = loadRest();
    rest.setRoot('/api/');
  });

  afterEach(() => { delete global.fetch; });

  test('entity().list() calls GET /api/{slug}', async () => {
    await rest.entity('orders').list();
    expect(global.fetch).toHaveBeenCalledWith('/api/orders', expect.objectContaining({ method: 'GET' }));
  });

  test('entity().list(params) appends query string', async () => {
    await rest.entity('orders').list({ status: 'open' });
    const url = global.fetch.mock.calls[0][0];
    expect(url).toContain('status=open');
  });

  test('entity().get(id) calls GET /api/{slug}/{id}', async () => {
    global.fetch.mockResolvedValue(jsonResponse({ id: '7' }));
    await rest.entity('products').get('7');
    expect(global.fetch).toHaveBeenCalledWith('/api/products/7', expect.objectContaining({ method: 'GET' }));
  });

  test('entity().create(data) calls POST with JSON body', async () => {
    global.fetch.mockResolvedValue(jsonResponse({ id: '1' }));
    await rest.entity('customers').create({ name: 'Alice' });
    const [url, opts] = global.fetch.mock.calls[0];
    expect(url).toBe('/api/customers');
    expect(opts.method).toBe('POST');
    expect(opts.body).toBe(JSON.stringify({ name: 'Alice' }));
    expect(opts.headers['Content-Type']).toBe('application/json');
  });

  test('entity().update(id, data) calls PUT /api/{slug}/{id}', async () => {
    global.fetch.mockResolvedValue(jsonResponse({ id: '3' }));
    await rest.entity('customers').update('3', { name: 'Bob' });
    const [url, opts] = global.fetch.mock.calls[0];
    expect(url).toBe('/api/customers/3');
    expect(opts.method).toBe('PUT');
  });

  test('entity().remove(id) calls DELETE /api/{slug}/{id}', async () => {
    global.fetch.mockResolvedValue(noContentResponse());
    await rest.entity('customers').remove('5');
    const [url, opts] = global.fetch.mock.calls[0];
    expect(url).toBe('/api/customers/5');
    expect(opts.method).toBe('DELETE');
  });

  test('entity().metadata() calls GET /api/metadata/{slug}', async () => {
    global.fetch.mockResolvedValue(jsonResponse({}));
    await rest.entity('products').metadata();
    const [url] = global.fetch.mock.calls[0];
    expect(url).toBe('/api/metadata/products');
  });
});

// ── call() – HTTP semantics ────────────────────────────────────────────────

describe('BareMetalRest – call() HTTP semantics', () => {
  let rest;

  beforeEach(() => {
    global.fetch = jest.fn();
    rest = loadRest();
  });

  afterEach(() => { delete global.fetch; });

  test('throws when response is not ok', async () => {
    global.fetch.mockResolvedValue(errorResponse('Internal Server Error', 'Server blew up'));
    await expect(rest.call('GET', '/api/bad')).rejects.toThrow('Server blew up');
  });

  test('returns null for 204 No Content', async () => {
    global.fetch.mockResolvedValue(noContentResponse());
    const result = await rest.call('DELETE', '/api/items/1');
    expect(result).toBeNull();
  });

  test('returns null when content-type is not application/json', async () => {
    global.fetch.mockResolvedValue({ ok: true, status: 200, headers: { get: () => 'text/html' } });
    const result = await rest.call('GET', '/api/items');
    expect(result).toBeNull();
  });

  test('sets X-Requested-With header on POST', async () => {
    global.fetch.mockResolvedValue(jsonResponse({}));
    await rest.call('POST', '/api/items', { name: 'test' });
    const opts = global.fetch.mock.calls[0][1];
    expect(opts.headers['X-Requested-With']).toBe('BareMetalWeb');
  });

  test('does NOT set X-Requested-With on GET', async () => {
    global.fetch.mockResolvedValue(jsonResponse([]));
    await rest.call('GET', '/api/items');
    const opts = global.fetch.mock.calls[0][1];
    expect(opts.headers['X-Requested-With']).toBeUndefined();
  });

  test('reads CSRF token from meta tag', async () => {
    const meta = document.createElement('meta');
    meta.setAttribute('name', 'csrf-token');
    meta.setAttribute('content', 'test-csrf-123');
    document.head.appendChild(meta);

    global.fetch.mockResolvedValue(jsonResponse({}));
    await rest.call('POST', '/api/items', {});
    const opts = global.fetch.mock.calls[0][1];
    expect(opts.headers['X-CSRF-Token']).toBe('test-csrf-123');

    document.head.removeChild(meta);
  });

  test('sends FormData body without Content-Type header', async () => {
    global.fetch.mockResolvedValue(jsonResponse({}));
    const fd = new FormData();
    fd.append('name', 'test');
    await rest.call('POST', '/api/upload', fd);
    const opts = global.fetch.mock.calls[0][1];
    expect(opts.body).toBeInstanceOf(FormData);
    // Browser must set Content-Type with boundary — must NOT be set manually
    expect(opts.headers['Content-Type']).toBeUndefined();
  });
});
