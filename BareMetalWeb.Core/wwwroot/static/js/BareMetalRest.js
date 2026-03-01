// BareMetalRest — lean REST client for BareMetalWeb
// Handles CRUD, metadata fetch and 401 redirect.
// Uses binary wire format (BSO1) for entity operations when BareMetalBinary is available.
// API: setRoot(url), getRoot(), entity(slug), call(method, url, body)
const BareMetalRest = (() => {
  'use strict';
  let root = '/api/';
  let _binaryReady = false;

  const setRoot = r => { root = r.endsWith('/') ? r : r + '/'; };
  const getRoot = () => root;

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
        return call('GET', jsonBase + (q ? '?' + new URLSearchParams(q) : ''));
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
        return call('GET', `${jsonBase}/${id}`);
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
        return call('POST', jsonBase, data);
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
        return call('PUT', `${jsonBase}/${id}`, data);
      },
      remove: async (id) => {
        await ensureBinary();
        if (isBinaryAvailable()) {
          try {
            await binaryCall('DELETE', `${binBase}/${id}`);
            return null;
          } catch { /* fall back */ }
        }
        return call('DELETE', `${jsonBase}/${id}`);
      },
      metadata: () => call('GET', `${root}metadata/${slug}`)
    };
  }

  return { setRoot, getRoot, entity, call, ensureBinary, isBinaryAvailable };
})();
