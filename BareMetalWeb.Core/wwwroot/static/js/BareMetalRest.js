// BareMetalRest — lean REST client for BareMetalWeb
// Handles CRUD, metadata fetch and 401 redirect.
// Uses BMW WebSocket binary transport when connected, BSO1 when available, JSON as fallback.
// API: setRoot(url), getRoot(), entity(slug), call(method, url, body), connectWs()
const BareMetalRest = (() => {
  'use strict';
  let root = '/api/';
  let _binaryReady = false;

  // ── BMW WebSocket transport ──
  let _ws = null;
  let _wsReady = false;
  let _wsPending = new Map();
  let _wsNextId = 1;
  let _wsConnecting = null; // Promise while connecting
  const FRAME_SIZE = 6;
  const PAYLOAD_HDR = 3;
  const ROUTE_BITS = 11;

  function _encodeFrame(opcode, entityId) {
    const b = new Uint8Array(FRAME_SIZE);
    const v = new DataView(b.buffer);
    v.setUint16(0, opcode << 2);
    v.setUint32(2, entityId, true);
    return b;
  }

  function _encodePayload(frame, data) {
    const json = JSON.stringify(data);
    const enc = new TextEncoder().encode(json);
    const len = enc.length;
    const buf = new Uint8Array(FRAME_SIZE + PAYLOAD_HDR + len);
    buf.set(frame);
    buf[6] = len & 0xFF;
    buf[7] = (len >> 8) & 0xFF;
    buf[8] = (len >> 16) & 0xFF;
    buf.set(enc, FRAME_SIZE + PAYLOAD_HDR);
    return buf;
  }

  function _decodeResponse(buf) {
    if (buf.byteLength <= FRAME_SIZE) return null;
    return JSON.parse(new TextDecoder().decode(
      new Uint8Array(buf, FRAME_SIZE + PAYLOAD_HDR)));
  }

  /// Connect BMW WebSocket transport. Returns a promise that resolves when connected.
  async function connectWs(url) {
    if (_wsReady && _ws && _ws.readyState === 1) return;
    if (_wsConnecting) return _wsConnecting;
    _wsConnecting = new Promise((resolve, reject) => {
      const wsUrl = url ||
        ((typeof location !== 'undefined')
          ? `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/bmw/ws`
          : 'ws://localhost/bmw/ws');
      _ws = new WebSocket(wsUrl);
      _ws.binaryType = 'arraybuffer';
      _ws.onopen = () => { _wsReady = true; _wsConnecting = null; resolve(); };
      _ws.onerror = () => { _wsConnecting = null; reject(new Error('WebSocket connection failed')); };
      _ws.onclose = () => {
        _wsReady = false;
        _wsConnecting = null;
        for (const [, cb] of _wsPending) cb(null, new Error('Connection closed'));
        _wsPending.clear();
      };
      _ws.onmessage = (e) => {
        const v = new DataView(e.data);
        const id = v.getUint32(2, true);
        const cb = _wsPending.get(id);
        if (cb) { _wsPending.delete(id); cb(e.data); }
      };
    });
    return _wsConnecting;
  }

  /// Send a binary frame via WebSocket. Returns decoded response.
  function wsSend(opcode, entityId, data) {
    return new Promise((resolve, reject) => {
      if (!_ws || _ws.readyState !== 1) return reject(new Error('Not connected'));
      const reqId = entityId || (_wsNextId++);
      _wsPending.set(reqId, (buf, err) => {
        if (err) return reject(err);
        try { resolve(_decodeResponse(buf)); }
        catch (e) { reject(e); }
      });
      const frame = _encodeFrame(opcode, reqId);
      if (data !== undefined) {
        _ws.send(_encodePayload(frame, data));
      } else {
        _ws.send(frame);
      }
    });
  }

  function isWsReady() { return _wsReady; }

  // ── Numeric route ID dispatch ──
  let _routeTable = null;
  let _routeTableReady = false;
  // BMW protocol descriptor — maps SDK method names to opcodes
  let _protocol = null;
  let _opcodeMap = null; // Map<string, number>: "listOrders" → opcode

  const setRoot = r => { root = r.endsWith('/') ? r : r + '/'; };
  const getRoot = () => root;

  /// Fetch route table and protocol descriptor, connect WebSocket.
  async function init() {
    // Fetch route table for numeric HTTP dispatch
    if (!_routeTableReady) {
      try {
        const r = await fetch('/bmw/routes');
        if (r.ok) {
          const routes = await r.json();
          _routeTable = new Map();
          for (const rt of routes) {
            _routeTable.set(rt.verb + ' ' + rt.path, rt.id);
          }
          _routeTableReady = true;
        }
      } catch { /* graceful fallback */ }
    }

    // Fetch BMW protocol descriptor for WebSocket opcode dispatch
    if (!_protocol) {
      try {
        const r = await fetch('/bmw/protocol');
        if (r.ok) {
          _protocol = await r.json();
          _opcodeMap = new Map();
          for (const route of _protocol.routes) {
            _opcodeMap.set(route.name, route.opcode);
          }
        }
      } catch { /* graceful fallback */ }
    }

    // Auto-connect WebSocket transport
    try { await connectWs(); } catch { /* WebSocket optional */ }
  }

  function resolveRouteId(verb, path) {
    if (!_routeTable) return null;
    return _routeTable.get(verb + ' ' + path) || null;
  }

  function byId(routeId, opts) {
    return call(opts && opts.method || 'GET', '/' + routeId, opts && opts.body);
  }

  // ── Binary bootstrap (BSO1) ──
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

  // ── JSON fetch call ──
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

  // ── Binary API call (BSO1) ──
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

  /// Resolve BMW SDK method name for an entity CRUD operation.
  function _sdkName(verb, slug, hasId) {
    const cap = slug.charAt(0).toUpperCase() + slug.slice(1);
    switch (verb) {
      case 'GET':    return hasId ? 'get' + cap : 'list' + cap;
      case 'POST':   return 'create' + cap;
      case 'PUT':    return 'update' + cap;
      case 'PATCH':  return 'patch' + cap;
      case 'DELETE': return 'delete' + cap;
      case 'HEAD':   return 'head' + cap;
      default:       return verb.toLowerCase() + cap;
    }
  }

  /// Try to execute an entity operation via BMW WebSocket transport.
  /// Returns null if WS unavailable or opcode not found.
  function _tryWs(verb, slug, id, data) {
    if (!_wsReady || !_opcodeMap) return null;
    const name = _sdkName(verb, slug, !!id);
    const opcode = _opcodeMap.get(name);
    if (opcode === undefined) return null;
    return wsSend(opcode, id ? (typeof id === 'number' ? id : parseInt(id, 10) || 0) : 0, data);
  }

  function entity(slug) {
    const jsonBase = root + slug;
    const binBase = root + '_binary/' + slug;

    function numUrl(verb, id) {
      if (!_routeTableReady) return null;
      const path = id ? '/api/' + slug + '/{id}' : '/api/' + slug;
      const routeId = resolveRouteId(verb, path);
      if (!routeId) return null;
      let url = '/' + routeId + '?type=' + encodeURIComponent(slug);
      if (id) url += '&id=' + encodeURIComponent(id);
      return url;
    }

    return {
      list: async (q) => {
        // Try WebSocket first (no query param support yet — skip for filtered queries)
        if (!q || Object.keys(q).length === 0) {
          const ws = _tryWs('GET', slug, null);
          if (ws) try { return await ws; } catch { /* fall back */ }
        }
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
        const ws = _tryWs('GET', slug, id);
        if (ws) try { return await ws; } catch { /* fall back */ }
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
        const ws = _tryWs('POST', slug, null, data);
        if (ws) try { return await ws; } catch { /* fall back */ }
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
        const ws = _tryWs('PUT', slug, id, data);
        if (ws) try { return await ws; } catch { /* fall back */ }
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
        const ws = _tryWs('DELETE', slug, id);
        if (ws) try { return await ws; } catch { /* fall back */ }
        await ensureBinary();
        if (isBinaryAvailable()) {
          try {
            await binaryCall('DELETE', `${binBase}/${id}`);
            return null;
          } catch { /* fall back */ }
        }
        return call('DELETE', numUrl('DELETE', id) || `${jsonBase}/${id}`);
      },
      delta: async (id, changes, expectedVersion = 0) => {
        await ensureBinary();
        if (isBinaryAvailable()) {
          try {
            return await BareMetalBinary.applyDeltaJson(slug, id, changes, expectedVersion);
          } catch { /* fall back to full update */ }
        }
        return call('PUT', numUrl('PUT', id) || `${jsonBase}/${id}`, changes);
      },
      deltaFromTracker: async (tracker) => {
        await ensureBinary();
        if (!isBinaryAvailable()) throw new Error('Binary API not available');
        const layout = await BareMetalBinary.fetchLayout(slug);
        const buf = BareMetalBinary.buildDelta(tracker, layout);
        if (!buf) return tracker.entity;
        const id = tracker.entity.Key;
        return BareMetalBinary.applyDelta(slug, id, buf);
      },
      metadata: () => call('GET', `${root}metadata/${slug}`)
    };
  }

  return { setRoot, getRoot, entity, call, ensureBinary, isBinaryAvailable, init, byId, resolveRouteId, connectWs, isWsReady };
})();
