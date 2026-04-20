// BareMetal.Auth — OIDC/OAuth2 client for SPAs
var BareMetal = (typeof BareMetal !== 'undefined') ? BareMetal : {};
BareMetal.Auth = (() => {
  'use strict';

  // ── Redirect helper (testable) ──
  var _redirect = function (url) { window.location.assign(url); };

  // ── Config & state ──
  let _cfg = null;
  let _discovery = null;
  let _tokens = null;
  let _listeners = [];
  let _refreshPromise = null;

  // ── Storage helpers ──
  function _store() {
    return _cfg && _cfg.storage === 'session' ? sessionStorage : null;
  }

  function _saveTokens(t) {
    _tokens = t;
    var s = _store();
    if (s) s.setItem('bm_auth_tokens', JSON.stringify(t));
    _notify();
  }

  function _loadTokens() {
    var s = _store();
    if (s) {
      var raw = s.getItem('bm_auth_tokens');
      if (raw) { try { _tokens = JSON.parse(raw); } catch (e) { _tokens = null; } }
    }
    return _tokens;
  }

  function _clearTokens() {
    _tokens = null;
    var s = _store();
    if (s) s.removeItem('bm_auth_tokens');
    _notify();
  }

  function _saveTx(state, tx) {
    var s = _store();
    if (s) { s.setItem('bm_auth_tx_' + state, JSON.stringify(tx)); return; }
    _saveTx._mem = _saveTx._mem || {};
    _saveTx._mem[state] = tx;
  }

  function _loadTx(state) {
    var s = _store();
    if (s) {
      var raw = s.getItem('bm_auth_tx_' + state);
      if (s) s.removeItem('bm_auth_tx_' + state);
      if (raw) { try { return JSON.parse(raw); } catch (e) { return null; } }
      return null;
    }
    var mem = (_saveTx._mem || {});
    var tx = mem[state] || null;
    delete mem[state];
    return tx;
  }

  function _notify() {
    var authed = isAuthenticated();
    for (var i = 0; i < _listeners.length; i++) {
      try { _listeners[i](authed); } catch (e) { /* ignore */ }
    }
  }

  // ── PKCE helpers (inline, no BareMetal.Crypto dependency) ──
  function randomString(len) {
    var arr = new Uint8Array(len);
    crypto.getRandomValues(arr);
    return base64url(arr);
  }

  function base64url(buffer) {
    var bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    var str = '';
    for (var i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  async function sha256(str) {
    var buf = new TextEncoder().encode(str);
    return crypto.subtle.digest('SHA-256', buf);
  }

  async function createPkce() {
    var verifier = randomString(32);
    var challenge = base64url(new Uint8Array(await sha256(verifier)));
    return { verifier: verifier, challenge: challenge };
  }

  // ── JWT parsing (no signature verification) ──
  function parseJwt(token) {
    if (!token) return null;
    var parts = token.split('.');
    if (parts.length < 2) return null;
    try {
      var b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      while (b64.length % 4) b64 += '=';
      return JSON.parse(atob(b64));
    } catch (e) { return null; }
  }

  // ── DOM helper ──
  function h(tag, attrs, children) {
    var el = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (k === 'style' && typeof attrs[k] === 'object') {
          Object.assign(el.style, attrs[k]);
        } else if (k.indexOf('on') === 0) {
          el.addEventListener(k.slice(2).toLowerCase(), attrs[k]);
        } else if (k === 'className') {
          el.className = attrs[k];
        } else if (k === 'innerHTML') {
          el.innerHTML = attrs[k];
        } else {
          el.setAttribute(k, attrs[k]);
        }
      });
    }
    if (children) {
      (Array.isArray(children) ? children : [children]).forEach(function (c) {
        if (c == null) return;
        el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
      });
    }
    return el;
  }

  function resolveContainer(container) {
    if (typeof container === 'string') return document.querySelector(container);
    return container;
  }

  // ── Provider presets ──
  var PROVIDER_PRESETS = {
    google: {
      name: 'Google', color: '#333', bgColor: '#fff',
      icon: '<svg viewBox="0 0 16 16" width="16" height="16"><path fill="#4285F4" d="M15.68 8.18c0-.57-.05-1.12-.15-1.64H8v3.1h4.3a3.68 3.68 0 0 1-1.6 2.41v2h2.6c1.52-1.4 2.38-3.46 2.38-5.87z"/><path fill="#34A853" d="M8 16c2.16 0 3.97-.72 5.3-1.94l-2.6-2a5.07 5.07 0 0 1-7.56-2.66H.54v2.06A8 8 0 0 0 8 16z"/><path fill="#FBBC05" d="M3.14 9.4a4.82 4.82 0 0 1 0-2.8V4.54H.54a8 8 0 0 0 0 6.92l2.6-2.06z"/><path fill="#EA4335" d="M8 3.18a4.33 4.33 0 0 1 3.07 1.2l2.3-2.3A7.72 7.72 0 0 0 8 0 8 8 0 0 0 .54 4.54l2.6 2.06A4.77 4.77 0 0 1 8 3.18z"/></svg>'
    },
    microsoft: {
      name: 'Microsoft', color: '#fff', bgColor: '#2f2f2f',
      icon: '<svg viewBox="0 0 16 16" width="16" height="16"><rect fill="#F25022" x="0" y="0" width="7.5" height="7.5"/><rect fill="#7FBA00" x="8.5" y="0" width="7.5" height="7.5"/><rect fill="#00A4EF" x="0" y="8.5" width="7.5" height="7.5"/><rect fill="#FFB900" x="8.5" y="8.5" width="7.5" height="7.5"/></svg>'
    },
    github: {
      name: 'GitHub', color: '#fff', bgColor: '#333',
      icon: '<svg viewBox="0 0 16 16" width="16" height="16"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.64 7.64 0 0 1 4 0c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>'
    },
    apple: {
      name: 'Apple', color: '#fff', bgColor: '#000',
      icon: '<svg viewBox="0 0 16 16" width="16" height="16"><path fill="currentColor" d="M12.15 8.54c-.02-1.95 1.6-2.9 1.67-2.94a3.64 3.64 0 0 0-2.87-1.46c-1.21-.13-2.39.72-3 .72-.63 0-1.57-.7-2.59-.68a3.82 3.82 0 0 0-3.22 1.96c-1.38 2.39-.35 5.9.98 7.84.66.95 1.44 2 2.46 1.96.99-.04 1.37-.64 2.57-.64 1.19 0 1.53.64 2.57.62 1.07-.02 1.74-.95 2.38-1.9a8.5 8.5 0 0 0 1.08-2.22 3.47 3.47 0 0 1-2.1-3.26zM10.23 2.9A3.54 3.54 0 0 0 11.04 0a3.6 3.6 0 0 0-2.33 1.21 3.37 3.37 0 0 0-.84 2.44c.88.07 1.78-.42 2.36-1.15z"/></svg>'
    },
    facebook: {
      name: 'Facebook', color: '#fff', bgColor: '#1877F2',
      icon: '<svg viewBox="0 0 16 16" width="16" height="16"><path fill="currentColor" d="M16 8a8 8 0 1 0-9.25 7.9v-5.59H4.72V8h2.03V6.24c0-2 1.19-3.11 3.02-3.11.87 0 1.79.16 1.79.16v1.97h-1.01c-.99 0-1.3.62-1.3 1.25V8h2.22l-.35 2.31H9.25v5.59A8 8 0 0 0 16 8z"/></svg>'
    }
  };

  // ── JWT decode helper for UI ──
  function decodeJwtParts(token) {
    if (!token) return null;
    var parts = token.split('.');
    if (parts.length < 2) return null;
    function decode(s) {
      var b64 = s.replace(/-/g, '+').replace(/_/g, '/');
      while (b64.length % 4) b64 += '=';
      try { return JSON.parse(atob(b64)); } catch (e) { return null; }
    }
    return { header: decode(parts[0]), payload: decode(parts[1]) };
  }

  // ── UI Render Methods ──
  var _uiSubscriptions = [];

  function _autoUpdate(renderFn) {
    var unsub = onAuthChange(function () { renderFn(); });
    _uiSubscriptions.push(unsub);
    return unsub;
  }

  function renderLogin(container, opts) {
    opts = opts || {};
    var el = resolveContainer(container);
    if (!el) return null;
    el.innerHTML = '';

    var title = opts.title || 'Sign In';
    var theme = opts.theme || 'light';
    var providers = opts.providers || [];
    var compact = !!opts.compact;

    function makeProviderBtn(p) {
      var preset = PROVIDER_PRESETS[p.id] || {};
      var name = p.name || preset.name || p.id;
      var color = p.color || preset.color || '#333';
      var bgColor = p.bgColor || preset.bgColor || '#fff';
      var iconHtml = p.icon || preset.icon || '';

      var iconEl = null;
      if (iconHtml) {
        iconEl = h('span', { innerHTML: iconHtml, style: { display: 'inline-flex', alignItems: 'center' } });
      }

      var btn = h('button', {
        className: 'bt fx al-c ju-c',
        style: { width: '100%', padding: '10px 16px', border: '1px solid #ddd', borderRadius: '6px', background: bgColor, color: color, fontSize: '14px', cursor: 'pointer', gap: '8px' },
        onClick: function () {
          login({ provider: p.id }).then(function () {
            if (opts.onLogin) {
              var user = getUser();
              if (user) opts.onLogin(user);
            }
          }).catch(function () { /* redirect happens */ });
        }
      }, iconEl ? [iconEl, h('span', null, ['Sign in with ' + name])] : ['Sign in with ' + name]);

      return btn;
    }

    var buttons;
    if (providers.length === 0) {
      var singleBtn = h('button', {
        className: 'bt bt-p',
        style: { width: '100%', padding: '10px 16px', cursor: 'pointer' },
        onClick: function () {
          login().catch(function () { });
        }
      }, ['Sign In']);
      buttons = [singleBtn];
    } else {
      buttons = providers.map(makeProviderBtn);
    }

    var btnContainer = h('div', { className: 'fx fx-c', style: { gap: '8px' } }, buttons);

    var root;
    if (compact) {
      root = h('div', { className: opts.className || '' }, [btnContainer]);
    } else {
      var children = [];
      if (opts.logo) {
        var logoEl = opts.logo.indexOf('<') === 0
          ? h('div', { innerHTML: opts.logo, className: 'tx-c m2' })
          : h('div', { className: 'tx-c m2' }, [h('img', { src: opts.logo, style: { maxHeight: '48px' } })]);
        children.push(logoEl);
      }
      children.push(h('h3', { className: 'tx-c m2' }, [title]));
      if (opts.subtitle) {
        children.push(h('p', { className: 'tx-c', style: { color: '#666', margin: '0 0 12px' } }, [opts.subtitle]));
      }
      children.push(btnContainer);

      var body = h('div', { className: 'cd-b p3' }, children);
      root = h('div', {
        className: 'cd sh rn' + (opts.className ? ' ' + opts.className : ''),
        style: { maxWidth: '400px', margin: 'auto' }
      }, [body]);
    }

    if (theme === 'dark') {
      root.style.background = '#1e1e1e';
      root.style.color = '#eee';
    }

    el.appendChild(root);
    return root;
  }

  function renderLogout(container, opts) {
    opts = opts || {};
    var el = resolveContainer(container);
    if (!el) return null;
    el.innerHTML = '';

    var label = opts.label || 'Sign Out';
    var className = opts.className || 'bt bt-er';

    var btn = h('button', {
      className: className,
      style: { cursor: 'pointer' },
      onClick: function () {
        if (opts.confirm && !window.confirm('Are you sure?')) return;
        logout();
        if (opts.onLogout) opts.onLogout();
      }
    }, [label]);

    el.appendChild(btn);
    return btn;
  }

  function renderWhoami(container, opts) {
    opts = opts || {};
    var el = resolveContainer(container);
    if (!el) return null;

    function render() {
      el.innerHTML = '';
      var user = getUser();
      if (!user) return null;

      var theme = opts.theme || 'light';
      var fields = opts.fields || ['name', 'email', 'picture'];
      var showAvatar = opts.showAvatar !== false;
      var showLogout = opts.showLogout !== false;
      var compact = !!opts.compact;

      if (compact) {
        var parts = [];
        if (showAvatar && user.picture) {
          parts.push(h('img', { src: user.picture, style: { width: '24px', height: '24px', borderRadius: '50%', verticalAlign: 'middle', marginRight: '6px' } }));
        }
        parts.push(h('span', null, [user.name || 'User']));
        if (showLogout) {
          parts.push(h('a', {
            href: '#', style: { marginLeft: '8px', fontSize: '12px' },
            onClick: function (e) { e.preventDefault(); logout(); if (opts.onLogout) opts.onLogout(); }
          }, ['Logout']));
        }
        var span = h('span', { className: opts.className || '' }, parts);
        el.appendChild(span);
        return span;
      }

      var children = [];
      if (showAvatar && user.picture) {
        children.push(h('img', { src: user.picture, style: { width: '64px', height: '64px', borderRadius: '50%' } }));
      }
      children.push(h('h5', null, [user.name || 'User']));
      if (user.email) {
        children.push(h('small', { className: 'tx-mu' }, [user.email]));
      }
      fields.forEach(function (f) {
        if (f === 'name' || f === 'email' || f === 'picture') return;
        if (user[f]) children.push(h('small', null, [f + ': ' + user[f]]));
      });
      if (showLogout) {
        children.push(h('button', {
          className: 'bt bt-er', style: { marginTop: '12px', cursor: 'pointer' },
          onClick: function () { logout(); if (opts.onLogout) opts.onLogout(); }
        }, ['Sign Out']));
      }

      var body = h('div', { className: 'cd-b p3 fx fx-c al-c' }, children);
      var card = h('div', { className: 'cd sh rn' }, [body]);
      if (theme === 'dark') { card.style.background = '#1e1e1e'; card.style.color = '#eee'; }
      el.appendChild(card);
      return card;
    }

    var root = render();
    _autoUpdate(render);
    return root;
  }

  function renderTokenInspector(container, opts) {
    opts = opts || {};
    var el = resolveContainer(container);
    if (!el) return null;
    el.innerHTML = '';

    var showIdToken = opts.showIdToken !== false;
    var showAccessToken = opts.showAccessToken !== false;
    var showRefreshToken = !!opts.showRefreshToken;
    var showExpiry = opts.showExpiry !== false;
    var theme = opts.theme || 'light';

    var tokens = _tokens || {};
    var sections = [];

    function tokenSection(label, token) {
      if (!token) return h('details', null, [h('summary', null, [label + ' (none)'])]);
      var decoded = decodeJwtParts(token);
      var expiryBadge = '';
      if (showExpiry && decoded && decoded.payload && decoded.payload.exp) {
        var remaining = decoded.payload.exp * 1000 - Date.now();
        expiryBadge = remaining > 0
          ? ' [expires in ' + Math.round(remaining / 60000) + 'm]'
          : ' [expired]';
      }
      var content = decoded
        ? 'Header:\n' + JSON.stringify(decoded.header, null, 2) + '\n\nPayload:\n' + JSON.stringify(decoded.payload, null, 2)
        : token;
      return h('details', null, [
        h('summary', null, [label + expiryBadge]),
        h('pre', { style: { fontSize: '11px', overflow: 'auto', maxHeight: '300px' } }, [content])
      ]);
    }

    if (showIdToken) sections.push(tokenSection('ID Token', tokens.id_token));
    if (showAccessToken) sections.push(tokenSection('Access Token', tokens.access_token));
    if (showRefreshToken) sections.push(tokenSection('Refresh Token', tokens.refresh_token));

    var header = h('div', { className: 'cd-h p2' }, [h('strong', null, ['Token Inspector'])]);
    var body = h('div', { className: 'cd-b p2' }, sections);
    var card = h('div', { className: 'cd sh rn' }, [header, body]);
    if (theme === 'dark') { card.style.background = '#1e1e1e'; card.style.color = '#eee'; }

    el.appendChild(card);
    return card;
  }

  function renderUserTiles(container, opts) {
    opts = opts || {};
    var el = resolveContainer(container);
    if (!el) return null;
    el.innerHTML = '';

    var columns = opts.columns || 2;
    var theme = opts.theme || 'light';
    var tiles = opts.tiles || [
      { id: 'profile', title: 'Profile', icon: '👤', description: 'Manage your profile information' },
      { id: 'security', title: 'Security', icon: '🔒', description: 'Password and authentication settings' },
      { id: 'sessions', title: 'Sessions', icon: '📱', description: 'View active sessions' },
      { id: 'linked', title: 'Linked Accounts', icon: '🔗', description: 'Manage connected accounts' }
    ];

    var tileEls = tiles.map(function (t) {
      var card = h('div', {
        className: 'cd sh rn p3 tx-c',
        style: { cursor: 'pointer' },
        onClick: t.onClick || function () {}
      }, [
        h('div', { style: { fontSize: '24px', marginBottom: '8px' } }, [t.icon || '']),
        h('h5', null, [t.title]),
        t.description ? h('small', { style: { color: '#666' } }, [t.description]) : null
      ].filter(Boolean));
      if (theme === 'dark') { card.style.background = '#1e1e1e'; card.style.color = '#eee'; }
      return card;
    });

    var grid = h('div', {
      style: { display: 'grid', gridTemplateColumns: 'repeat(' + columns + ', 1fr)', gap: '12px' }
    }, tileEls);

    el.appendChild(grid);
    return grid;
  }

  function renderAuthGate(container, opts) {
    opts = opts || {};
    var el = resolveContainer(container);
    if (!el) return null;

    function render() {
      el.innerHTML = '';
      if (isAuthenticated()) {
        return renderWhoami(el, opts.whoamiOpts || opts);
      } else {
        return renderLogin(el, opts.loginOpts || opts);
      }
    }

    var root = render();
    _autoUpdate(render);
    return root;
  }

  // ── Public API ──
  function configure(opts) {
    _cfg = {
      authority: (opts.authority || '').replace(/\/+$/, ''),
      clientId: opts.clientId,
      redirectUri: opts.redirectUri,
      scopes: opts.scopes || 'openid profile',
      silentRedirectUri: opts.silentRedirectUri || null,
      storage: opts.storage || 'memory',
      postLogoutRedirectUri: opts.postLogoutRedirectUri || null
    };
    _tokens = null;
    _discovery = null;
    _saveTx._mem = {};
    _loadTokens();
  }

  async function initialize() {
    if (!_cfg) throw new Error('Auth: call configure() first');
    var url = _cfg.authority + '/.well-known/openid-configuration';
    var res = await fetch(url);
    if (!res.ok) throw new Error('Auth: discovery fetch failed (' + res.status + ')');
    _discovery = await res.json();
  }

  async function login(extraParams) {
    if (!_discovery) throw new Error('Auth: call initialize() first');
    var pkce = await createPkce();
    var state = randomString(16);
    var nonce = randomString(16);

    _saveTx(state, { nonce: nonce, codeVerifier: pkce.verifier, redirectUri: _cfg.redirectUri });

    var params = new URLSearchParams({
      response_type: 'code',
      client_id: _cfg.clientId,
      redirect_uri: _cfg.redirectUri,
      scope: _cfg.scopes,
      state: state,
      nonce: nonce,
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256'
    });
    if (extraParams) {
      Object.keys(extraParams).forEach(function (k) { params.set(k, extraParams[k]); });
    }

    _redirect(_discovery.authorization_endpoint + '?' + params.toString());
  }

  async function handleCallback(url) {
    var loc = url || window.location.href;
    var parsed = new URL(loc);
    var params = parsed.searchParams;
    var code = params.get('code');
    var state = params.get('state');
    var error = params.get('error');

    if (error) throw new Error('Auth callback error: ' + error);
    if (!code || !state) throw new Error('Auth: missing code or state in callback');

    var tx = _loadTx(state);
    if (!tx) throw new Error('Auth: no pending transaction for state');

    var body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: _cfg.clientId,
      redirect_uri: tx.redirectUri || _cfg.redirectUri,
      code: code,
      code_verifier: tx.codeVerifier
    });

    var res = await fetch(_discovery.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    });
    if (!res.ok) throw new Error('Auth: token exchange failed (' + res.status + ')');
    var data = await res.json();

    // Validate nonce
    var claims = parseJwt(data.id_token);
    if (claims && tx.nonce && claims.nonce !== tx.nonce) {
      throw new Error('Auth: nonce mismatch');
    }

    var tokens = {
      access_token: data.access_token,
      id_token: data.id_token,
      refresh_token: data.refresh_token || null,
      expires_at: data.expires_in ? Date.now() + data.expires_in * 1000 : null
    };
    _saveTokens(tokens);

    // Clean URL
    if (typeof history !== 'undefined' && history.replaceState) {
      try {
        var clean = parsed.origin + parsed.pathname;
        history.replaceState(null, '', clean);
      } catch (e) { /* cross-origin or security restriction — ignore */ }
    }

    return { user: claims, accessToken: tokens.access_token, idToken: tokens.id_token };
  }

  function logout() {
    var idToken = _tokens ? _tokens.id_token : null;
    _clearTokens();
    if (_discovery && _discovery.end_session_endpoint) {
      var params = new URLSearchParams();
      if (idToken) params.set('id_token_hint', idToken);
      if (_cfg.postLogoutRedirectUri) params.set('post_logout_redirect_uri', _cfg.postLogoutRedirectUri);
      _redirect(_discovery.end_session_endpoint + '?' + params.toString());
    }
  }

  function clearSession() {
    _clearTokens();
  }

  async function getToken() {
    if (!_tokens) return null;
    if (_tokens.expires_at && Date.now() >= _tokens.expires_at) {
      if (_tokens.refresh_token) {
        try { await _refreshWithToken(_tokens.refresh_token); } catch (e) { _clearTokens(); return null; }
      } else {
        return null;
      }
    }
    return _tokens ? _tokens.access_token : null;
  }

  async function _refreshWithToken(refreshToken) {
    var body = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: _cfg.clientId,
      refresh_token: refreshToken
    });
    var res = await fetch(_discovery.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    });
    if (!res.ok) throw new Error('Auth: refresh failed');
    var data = await res.json();
    _saveTokens({
      access_token: data.access_token,
      id_token: data.id_token || (_tokens && _tokens.id_token),
      refresh_token: data.refresh_token || refreshToken,
      expires_at: data.expires_in ? Date.now() + data.expires_in * 1000 : null
    });
  }

  function getIdToken() {
    return _tokens ? _tokens.id_token : null;
  }

  async function silentRefresh() {
    if (_refreshPromise) return _refreshPromise;
    _refreshPromise = _doSilentRefresh().finally(function () { _refreshPromise = null; });
    return _refreshPromise;
  }

  async function _doSilentRefresh() {
    if (!_cfg || !_cfg.silentRedirectUri || !_discovery) { _clearTokens(); return; }
    try {
      var pkce = await createPkce();
      var state = randomString(16);
      var nonce = randomString(16);
      _saveTx(state, { nonce: nonce, codeVerifier: pkce.verifier, redirectUri: _cfg.silentRedirectUri });

      var params = new URLSearchParams({
        response_type: 'code',
        client_id: _cfg.clientId,
        redirect_uri: _cfg.silentRedirectUri,
        scope: _cfg.scopes,
        state: state,
        nonce: nonce,
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256',
        prompt: 'none'
      });

      var iframe = document.createElement('iframe');
      iframe.style.display = 'none';
      iframe.src = _discovery.authorization_endpoint + '?' + params.toString();

      var result = await new Promise(function (resolve, reject) {
        var timer = setTimeout(function () {
          cleanup();
          reject(new Error('Auth: silent refresh timeout'));
        }, 10000);

        function onMessage(ev) {
          if (ev.origin !== _cfg.authority) return;
          cleanup();
          resolve(ev.data);
        }

        function cleanup() {
          clearTimeout(timer);
          window.removeEventListener('message', onMessage);
          if (iframe.parentNode) iframe.parentNode.removeChild(iframe);
        }

        window.addEventListener('message', onMessage);
        document.body.appendChild(iframe);
      });

      if (result && result.code && result.state) {
        var callbackUrl = _cfg.silentRedirectUri + '?code=' + result.code + '&state=' + result.state;
        await handleCallback(callbackUrl);
      } else {
        _clearTokens();
      }
    } catch (e) {
      _clearTokens();
    }
  }

  function handleSilentCallback() {
    if (window.parent && window.parent !== window) {
      var params = new URLSearchParams(window.location.search);
      window.parent.postMessage({
        code: params.get('code'),
        state: params.get('state'),
        error: params.get('error')
      }, '*');
    }
  }

  function getUser() {
    if (!_tokens || !_tokens.id_token) return null;
    return parseJwt(_tokens.id_token);
  }

  async function getUserInfo() {
    if (!_discovery || !_discovery.userinfo_endpoint) throw new Error('Auth: no userinfo_endpoint');
    var token = await getToken();
    if (!token) throw new Error('Auth: not authenticated');
    var res = await fetch(_discovery.userinfo_endpoint, {
      headers: { Authorization: 'Bearer ' + token }
    });
    if (!res.ok) throw new Error('Auth: userinfo failed (' + res.status + ')');
    return res.json();
  }

  function isAuthenticated() {
    return !!_tokens && !!_tokens.access_token;
  }

  function onAuthChange(callback) {
    _listeners.push(callback);
    return function () {
      _listeners = _listeners.filter(function (cb) { return cb !== callback; });
    };
  }

  function attachToRest() {
    var Rest = (typeof BareMetal !== 'undefined') && BareMetal.Communications;
    if (!Rest || !Rest.call) return;

    var originalCall = Rest.call;
    Rest.call = async function (method, url, body, headers) {
      var h = Object.assign({}, headers || {});
      var token = await getToken();
      if (token) h['Authorization'] = 'Bearer ' + token;

      var res = await originalCall.call(Rest, method, url, body, h);

      // 401 retry: silent refresh then retry once
      if (res && res.status === 401) {
        try {
          await silentRefresh();
          var newToken = await getToken();
          if (newToken) {
            h['Authorization'] = 'Bearer ' + newToken;
            return originalCall.call(Rest, method, url, body, h);
          }
        } catch (e) { /* fall through */ }
      }
      return res;
    };
  }

  return {
    configure: configure,
    initialize: initialize,
    login: login,
    handleCallback: handleCallback,
    logout: logout,
    clearSession: clearSession,
    getToken: getToken,
    getIdToken: getIdToken,
    silentRefresh: silentRefresh,
    handleSilentCallback: handleSilentCallback,
    getUser: getUser,
    getUserInfo: getUserInfo,
    isAuthenticated: isAuthenticated,
    onAuthChange: onAuthChange,
    attachToRest: attachToRest,
    _setRedirect: function (fn) { _redirect = fn; },
    renderLogin: renderLogin,
    renderLogout: renderLogout,
    renderWhoami: renderWhoami,
    renderTokenInspector: renderTokenInspector,
    renderUserTiles: renderUserTiles,
    renderAuthGate: renderAuthGate
  };
})();
