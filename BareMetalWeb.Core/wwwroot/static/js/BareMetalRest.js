// BareMetalRest — lean REST client for BareMetalWeb
// Handles CRUD, metadata fetch and 401 redirect.
// API: setRoot(url), getRoot(), entity(slug), call(method, url, body)
const BareMetalRest = (() => {
  'use strict';
  let root = '/api/';

  const setRoot = r => { root = r.endsWith('/') ? r : r + '/'; };
  const getRoot = () => root;

  async function call(method, url, body) {
    const opts = { method, headers: {} };
    if (body !== undefined) {
      opts.body = JSON.stringify(body);
      opts.headers['Content-Type'] = 'application/json';
    }
    // Custom header on mutating requests — CSRF mitigation for cookie-auth APIs.
    // Cross-origin requests with custom headers trigger CORS preflight, which the
    // server's CORS policy blocks, preventing cross-site request forgery.
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
    // Only parse as JSON when the server confirms it — avoids opaque errors on HTML error pages
    const ct = r.headers.get('content-type') || '';
    if (!ct.includes('application/json')) return null;
    return r.json();
  }

  function entity(slug) {
    const b = root + slug;
    return {
      list:     q          => call('GET',    b + (q ? '?' + new URLSearchParams(q) : '')),
      get:      id         => call('GET',    `${b}/${id}`),
      create:   data       => call('POST',   b, data),
      update:   (id, data) => call('PUT',    `${b}/${id}`, data),
      remove:   id         => call('DELETE', `${b}/${id}`),
      metadata: ()         => call('GET',    `${root}metadata/${slug}`)
    };
  }

  return { setRoot, getRoot, entity, call };
})();
