// BareMetalRest — lean REST client for BareMetalWeb
// Handles CRUD, metadata fetch and 401 redirect.
// Uses binary wire format (BSO1) for entity operations when BareMetalBinary is available.
// API: setRoot(url), getRoot(), entity(slug), call(method, url, body)
const BareMetalRest = (() => {
  'use strict';
  let root = '/api/';
  let _binaryReady = false;

  // ── Numeric route ID dispatch ──
  // verb+path → routeId lookup map, populated from /bmw/routes at init().
  let _routeTable = null; // Map<string, number> e.g. "GET /api/users" → 42
  let _routeTableReady = false;

  const setRoot = r => { root = r.endsWith('/') ? r : r + '/'; };
  const getRoot = () => root;

  /// Fetch route table from /bmw/routes and build verb+path → routeId map.
  async function init() {
    if (_routeTableReady) return;
    try {
      const r = await fetch('/bmw/routes');
      if (!r.ok) return;
      const routes = await r.json();
      _routeTable = new Map();
      for (const rt of routes) {
        _routeTable.set(rt.verb + ' ' + rt.path, rt.id);
      }
      _routeTableReady = true;
    } catch { /* graceful fallback to string URLs */ }
  }

  /// Look up numeric route ID for a verb+path pair.
  function resolveRouteId(verb, path) {
    if (!_routeTable) return null;
    return _routeTable.get(verb + ' ' + path) || null;
  }

  /// Rewrite a URL to use numeric route ID dispatch when available.
  /// e.g. GET /api/users → GET /42?type=users
  function rewriteUrl(verb, url) {
    if (!_routeTableReady) return url;
    const id = resolveRouteId(verb, url);
    if (id) return '/' + id;
    return url;
  }

  /// Explicit O(1) dispatch by route ID.
  function byId(routeId, opts) {
    return call(opts && opts.method || 'GET', '/' + routeId, opts && opts.body);
  }

  // ── Binary bootstrap ──
  // Fetches signing key and initialises BareMetalBinary.
  // Called lazily on first entity() operation.
  async function ensureBinary() {
    if (_binaryReady || typeof BareMetalBinary === 'undefined') return;
    try {
      const r = await fetch(root + '_binary/_key');
      if (r.ok) {
        const key = await r.text();
        await BareMetalBinary.setSigningKey(key.trim());
        _binaryReady = true;
      }
    } catch { /* fall back to JSON */ }
  }

  function isBinaryAvailable() {
    return _binaryReady && typeof BareMetalBinary !== 'undefined';
  }

  // ── JSON fallback call (unchanged) ──
  async function call(method, url, body) {
    const opts = { method, headers: {} };
    if (body !== undefined) {
      if (body instanceof FormData) {
        opts.body = body;
      } else {
        opts.body = JSON.stringify(body);
        opts.headers['Content-Type'] = 'application/json';
      }
    }
    if (method !== 'GET' && method !== 'HEAD') {
      opts.headers['X-Requested-With'] = 'BareMetalWeb';
      const csrfMeta = document.querySelector('meta[name="csrf-token"]');
      if (csrfMeta) opts.headers['X-CSRF-Token'] = csrfMeta.content;
    }
    const r = await fetch(url, opts);
    if (r.status === 401) {
      location.href = '/login?returnUrl=' + encodeURIComponent(location.href);
      throw new Error('Unauthorized');
    }
    if (!r.ok) throw new Error((await r.text()) || r.statusText);
    if (r.status === 204) return null;
    const ct = r.headers.get('content-type') || '';
    if (!ct.includes('application/json')) return null;
    return r.json();
  }

  // ── Binary API call ──
  async function binaryCall(method, url, body) {
    const opts = { method, headers: {} };
    if (body instanceof ArrayBuffer || body instanceof Uint8Array) {
      opts.body = body;
      opts.headers['Content-Type'] = 'application/x-bmw-binary';
    }
    if (method !== 'GET' && method !== 'HEAD') {
      opts.headers['X-Requested-With'] = 'BareMetalWeb';
      const csrfMeta = document.querySelector('meta[name="csrf-token"]');
      if (csrfMeta) opts.headers['X-CSRF-Token'] = csrfMeta.content;
    }
    const r = await fetch(url, opts);
    if (r.status === 401) {
      location.href = '/login?returnUrl=' + encodeURIComponent(location.href);
      throw new Error('Unauthorized');
    }
    if (!r.ok) throw new Error((await r.text()) || r.statusText);
    if (r.status === 204) return null;
    return r.arrayBuffer();
  }

  function entity(slug) {
    const jsonBase = root + slug;
    const binBase = root + '_binary/' + slug;

    // Build numeric dispatch URLs for entity CRUD operations.
    // Routes with params are stored as e.g. "/api/orders/{id}".
    // Returns /{routeId}?type={slug}[&id={id}] when route table loaded,
    // otherwise falls back to the original path-based URL.
    function numUrl(verb, id) {
      if (!_routeTableReady) return null;
      // For id-bearing routes, look up the parameterized pattern
      const path = id
        ? '/api/' + slug + '/{id}'
        : '/api/' + slug;
      const routeId = resolveRouteId(verb, path);
      if (!routeId) return null;
      let url = '/' + routeId + '?type=' + encodeURIComponent(slug);
      if (id) url += '&id=' + encodeURIComponent(id);
      return url;
    }

    return {
      list: async (q) => {
        await ensureBinary();
        if (isBinaryAvailable()) {
          try {
            const schema = await BareMetalBinary.fetchSchema(slug, root);
            const url = binBase + (q ? '?' + new URLSearchParams(q) : '');
            const buf = await binaryCall('GET', url);
            return { data: await BareMetalBinary.deserializeList(buf, schema), count: -1 };
          } catch { /* fall back */ }
        }
        const nurl = numUrl('GET', null);
        const base = nurl || jsonBase;
        return call('GET', base + (q ? (nurl ? '&' : '?') + new URLSearchParams(q) : ''));
      },
      get: async (id) => {
        await ensureBinary();
        if (isBinaryAvailable()) {
          try {
            const schema = await BareMetalBinary.fetchSchema(slug, root);
            const buf = await binaryCall('GET', `${binBase}/${id}`);
            return BareMetalBinary.deserialize(buf, schema);
          } catch { /* fall back */ }
        }
        return call('GET', numUrl('GET', id) || `${jsonBase}/${id}`);
      },
      create: async (data) => {
        await ensureBinary();
        if (isBinaryAvailable()) {
          try {
            const schema = await BareMetalBinary.fetchSchema(slug, root);
            const payload = await BareMetalBinary.serialize(data, schema);
            const buf = await binaryCall('POST', binBase, payload);
            return BareMetalBinary.deserialize(buf, schema);
          } catch { /* fall back */ }
        }
        return call('POST', numUrl('POST', null) || jsonBase, data);
      },
      update: async (id, data) => {
        await ensureBinary();
        if (isBinaryAvailable()) {
          try {
            const schema = await BareMetalBinary.fetchSchema(slug, root);
            const payload = await BareMetalBinary.serialize(data, schema);
            const buf = await binaryCall('PUT', `${binBase}/${id}`, payload);
            return BareMetalBinary.deserialize(buf, schema);
          } catch { /* fall back */ }
        }
        return call('PUT', numUrl('PUT', id) || `${jsonBase}/${id}`, data);
      },
      remove: async (id) => {
        await ensureBinary();
        if (isBinaryAvailable()) {
          try {
            await binaryCall('DELETE', `${binBase}/${id}`);
            return null;
          } catch { /* fall back */ }
        }
        return call('DELETE', numUrl('DELETE', id) || `${jsonBase}/${id}`);
      },
      /** Apply a field-level delta mutation (JSON). Only sends changed fields. */
      delta: async (id, changes, expectedVersion = 0) => {
        await ensureBinary();
        if (isBinaryAvailable()) {
          try {
            return await BareMetalBinary.applyDeltaJson(slug, id, changes, expectedVersion);
          } catch { /* fall back to full update */ }
        }
        return call('PUT', numUrl('PUT', id) || `${jsonBase}/${id}`, changes);
      },
      /** Apply a binary delta mutation from a change tracker. */
      deltaFromTracker: async (tracker) => {
        await ensureBinary();
        if (!isBinaryAvailable()) throw new Error('Binary API not available');
        const layout = await BareMetalBinary.fetchLayout(slug);
        const buf = BareMetalBinary.buildDelta(tracker, layout);
        if (!buf) return tracker.entity; // no changes
        const id = tracker.entity.Key;
        return BareMetalBinary.applyDelta(slug, id, buf);
      },
      metadata: () => call('GET', `${root}metadata/${slug}`)
    };
  }

  return { setRoot, getRoot, entity, call, ensureBinary, isBinaryAvailable, init, byId, resolveRouteId };
})();
