// BareMetalRest — lean REST client for BareMetalWeb
// Handles CRUD, metadata fetch and 401 redirect.
// Uses binary wire format (BSO1) for entity operations when BareMetalBinary is available.
// Supports numeric route ID dispatch for O(1) server-side routing when route table is loaded.
// API: setRoot(url), getRoot(), entity(slug), call(method, url, body), byId(routeId, opts), init()
const BareMetalRest = (() => {
  'use strict';
  let root = '/api/';
  let _binaryReady = false;

  // ── Route ID acceleration ──
  // Map of "VERB /path/template" → numeric route ID (ushort)
  let _routeLookup = null;
  let _initPromise = null;

  const setRoot = r => { root = r.endsWith('/') ? r : r + '/'; };
  const getRoot = () => root;

  // ── Route table bootstrap ──
  // Fetches /bmw/routes and builds a lookup map for transparent URL rewriting.
  // Safe to call multiple times — deduplicates via _initPromise.
  async function init() {
    if (_routeLookup) return true;
    if (_initPromise) return _initPromise;
    _initPromise = (async () => {
      try {
        const r = await fetch('/bmw/routes');
        if (!r.ok) return false;
        const table = await r.json();
        _routeLookup = new Map();
        for (let i = 0; i < table.length; i++) {
          const e = table[i];
          _routeLookup.set(e.verb + ' ' + e.path, e.id);
        }
        return true;
      } catch { return false; }
    })();
    return _initPromise;
  }

  /** Returns true if the route ID table has been loaded. */
  function isRouteIdReady() { return _routeLookup !== null; }

  /**
   * Resolve a verb + path template to a numeric route ID.
   * Returns 0 if the route table is not loaded or the key is not found.
   */
  function resolveRouteId(verb, pathTemplate) {
    if (!_routeLookup) return 0;
    return _routeLookup.get(verb + ' ' + pathTemplate) || 0;
  }

  /**
   * Build a numeric dispatch URL: /{routeId}?key=val&...
   * @param {number} routeId Numeric route ID
   * @param {object} [params] Query parameters to append
   * @returns {string} URL like "/42?type=users&id=abc"
   */
  function numericUrl(routeId, params) {
    let url = '/' + routeId;
    if (params) {
      const keys = Object.keys(params);
      if (keys.length > 0) {
        url += '?' + new URLSearchParams(params).toString();
      }
    }
    return url;
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

    // Resolve route IDs for this entity's CRUD operations (if table loaded).
    // Template patterns match the server's route registration keys.
    function rid(verb, pathTmpl) { return resolveRouteId(verb, pathTmpl); }

    /** Build the URL for a JSON entity call, using numeric route ID when available. */
    function jsonUrl(verb, pathTmpl, params, qs) {
      const id = rid(verb, pathTmpl);
      if (id) {
        const merged = params ? Object.assign({}, params, qs || {}) : qs;
        return numericUrl(id, merged);
      }
      // Fallback: traditional string URL
      let url = jsonBase;
      if (params && params.id) url += '/' + encodeURIComponent(params.id);
      if (qs) url += '?' + new URLSearchParams(qs).toString();
      return url;
    }

    /** Build the URL for a binary entity call, using numeric route ID when available. */
    function binUrl(verb, pathTmpl, params, qs) {
      const id = rid(verb, pathTmpl);
      if (id) {
        const merged = params ? Object.assign({}, params, qs || {}) : qs;
        return numericUrl(id, merged);
      }
      let url = binBase;
      if (params && params.id) url += '/' + encodeURIComponent(params.id);
      if (qs) url += '?' + new URLSearchParams(qs).toString();
      return url;
    }

    const tp = { type: slug }; // common type param

    return {
      list: async (q) => {
        await ensureBinary();
        if (isBinaryAvailable()) {
          try {
            const schema = await BareMetalBinary.fetchSchema(slug, root);
            const url = binUrl('GET', '/api/_binary/{type}', tp, q);
            const buf = await binaryCall('GET', url);
            return { data: await BareMetalBinary.deserializeList(buf, schema), count: -1 };
          } catch { /* fall back */ }
        }
        return call('GET', jsonUrl('GET', '/api/{type}', tp, q));
      },
      get: async (id) => {
        await ensureBinary();
        const p = { type: slug, id };
        if (isBinaryAvailable()) {
          try {
            const schema = await BareMetalBinary.fetchSchema(slug, root);
            const buf = await binaryCall('GET', binUrl('GET', '/api/_binary/{type}/{id}', p));
            return BareMetalBinary.deserialize(buf, schema);
          } catch { /* fall back */ }
        }
        return call('GET', jsonUrl('GET', '/api/{type}/{id}', p));
      },
      create: async (data) => {
        await ensureBinary();
        if (isBinaryAvailable()) {
          try {
            const schema = await BareMetalBinary.fetchSchema(slug, root);
            const payload = await BareMetalBinary.serialize(data, schema);
            const buf = await binaryCall('POST', binUrl('POST', '/api/_binary/{type}', tp), payload);
            return BareMetalBinary.deserialize(buf, schema);
          } catch { /* fall back */ }
        }
        return call('POST', jsonUrl('POST', '/api/{type}', tp), data);
      },
      update: async (id, data) => {
        await ensureBinary();
        const p = { type: slug, id };
        if (isBinaryAvailable()) {
          try {
            const schema = await BareMetalBinary.fetchSchema(slug, root);
            const payload = await BareMetalBinary.serialize(data, schema);
            const buf = await binaryCall('PUT', binUrl('PUT', '/api/_binary/{type}/{id}', p), payload);
            return BareMetalBinary.deserialize(buf, schema);
          } catch { /* fall back */ }
        }
        return call('PUT', jsonUrl('PUT', '/api/{type}/{id}', p), data);
      },
      remove: async (id) => {
        await ensureBinary();
        const p = { type: slug, id };
        if (isBinaryAvailable()) {
          try {
            await binaryCall('DELETE', binUrl('DELETE', '/api/_binary/{type}/{id}', p));
            return null;
          } catch { /* fall back */ }
        }
        return call('DELETE', jsonUrl('DELETE', '/api/{type}/{id}', p));
      },
      /** Apply a field-level delta mutation (JSON). Only sends changed fields. */
      delta: async (id, changes, expectedVersion = 0) => {
        await ensureBinary();
        if (isBinaryAvailable()) {
          try {
            return await BareMetalBinary.applyDeltaJson(slug, id, changes, expectedVersion);
          } catch { /* fall back to full update */ }
        }
        return call('PUT', jsonUrl('PUT', '/api/{type}/{id}', { type: slug, id }), changes);
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
      metadata: () => call('GET', jsonUrl('GET', '/api/metadata/{entity}', { entity: slug }))
    };
  }

  /**
   * Direct numeric route dispatch — bypasses lookup, sends /{routeId} directly.
   * @param {number} routeId The server-assigned numeric route ID
   * @param {object} [opts] Options: { method, params, body }
   * @returns {Promise} Parsed JSON response
   */
  async function byId(routeId, opts) {
    const { method = 'GET', params, body } = opts || {};
    return call(method, numericUrl(routeId, params), body);
  }

  return { setRoot, getRoot, entity, call, byId, init, isRouteIdReady, resolveRouteId, ensureBinary, isBinaryAvailable };
})();
