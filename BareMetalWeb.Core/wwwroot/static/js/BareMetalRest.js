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
    const r = await fetch(url, opts);
    if (r.status === 401) {
      location.href = '/login?returnUrl=' + encodeURIComponent(location.href);
      throw new Error('Unauthorized');
    }
    if (!r.ok) throw new Error((await r.text()) || r.statusText);
    if (r.status === 204) return null;
    return r.json().catch(() => null);
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
