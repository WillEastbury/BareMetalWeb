// BareMetal.Progressive — PWA helper and service worker manager
var BareMetal = (typeof BareMetal !== 'undefined') ? BareMetal : {};
BareMetal.Progressive = (() => {
  'use strict';

  let _registration = null;
  let _installPromptEvent = null;
  let _installPromptCallbacks = [];
  let _connectivityCallbacks = [];
  let _messageCallbacks = [];
  let _offlineQueue = [];
  const SW_DEFAULT = '/BareMetal.ServiceWorker.js';

  // --- Offline queue persistence helpers ---
  function _getStore() {
    if (typeof BareMetal !== 'undefined' && BareMetal.LocalKVStore) return BareMetal.LocalKVStore;
    return null;
  }

  function _loadQueue() {
    var store = _getStore();
    if (store) {
      var data = store.get('bm_offline_queue');
      _offlineQueue = data ? JSON.parse(data) : [];
    } else if (typeof localStorage !== 'undefined') {
      try { _offlineQueue = JSON.parse(localStorage.getItem('bm_offline_queue') || '[]'); } catch (e) { _offlineQueue = []; }
    }
  }

  function _saveQueue() {
    var json = JSON.stringify(_offlineQueue);
    var store = _getStore();
    if (store) { store.set('bm_offline_queue', json); }
    else if (typeof localStorage !== 'undefined') { localStorage.setItem('bm_offline_queue', json); }
  }

  function _replayQueue() {
    if (!_offlineQueue.length) return;
    var queue = _offlineQueue.splice(0);
    _saveQueue();
    if (typeof BareMetal !== 'undefined' && BareMetal.Rest) {
      queue.forEach(function(entry) {
        BareMetal.Rest.fetch ? BareMetal.Rest.fetch(entry.url, entry.options) : fetch(entry.url, entry.options);
      });
    }
  }

  // --- Install prompt capture ---
  if (typeof window !== 'undefined') {
    window.addEventListener('beforeinstallprompt', function(e) {
      e.preventDefault();
      _installPromptEvent = e;
      _installPromptCallbacks.forEach(function(cb) {
        cb({ prompt: function() { return _installPromptEvent.prompt().then(function(r) { _installPromptEvent = null; return r; }); } });
      });
    });

    window.addEventListener('online', function() { _connectivityCallbacks.forEach(function(cb) { cb(true); }); _replayQueue(); });
    window.addEventListener('offline', function() { _connectivityCallbacks.forEach(function(cb) { cb(false); }); });
  }

  // --- REST integration: monkey-patch if available ---
  function _hookRest() {
    if (typeof BareMetal === 'undefined' || !BareMetal.Rest || BareMetal.Rest._bmProgPatched) return;
    var origFetch = BareMetal.Rest.fetch;
    if (!origFetch) return;
    BareMetal.Rest._bmProgPatched = true;
    BareMetal.Rest.fetch = function(url, options) {
      if (navigator.onLine) return origFetch.call(BareMetal.Rest, url, options);
      _offlineQueue.push({ url: url, options: options });
      _saveQueue();
      return Promise.reject(new Error('Offline — request queued'));
    };
  }

  // --- SW communication ---
  function _getActiveSW() {
    if (_registration && _registration.active) return _registration.active;
    if (typeof navigator !== 'undefined' && navigator.serviceWorker && navigator.serviceWorker.controller) return navigator.serviceWorker.controller;
    return null;
  }

  function postMessage(msg) {
    return new Promise(function(resolve, reject) {
      var sw = _getActiveSW();
      if (!sw) return reject(new Error('No active service worker'));
      if (typeof MessageChannel !== 'undefined') {
        var ch = new MessageChannel();
        ch.port1.onmessage = function(e) { resolve(e.data); };
        sw.postMessage(msg, [ch.port2]);
      } else {
        sw.postMessage(msg);
        resolve();
      }
    });
  }

  // --- Public API ---
  function register(swUrl, opts) {
    swUrl = swUrl || SW_DEFAULT;
    opts = opts || {};
    if (typeof navigator === 'undefined' || !navigator.serviceWorker) return Promise.reject(new Error('Service workers not supported'));
    _loadQueue();
    _hookRest();

    return navigator.serviceWorker.register(swUrl, opts.scope ? { scope: opts.scope } : undefined)
      .then(function(reg) {
        _registration = reg;

        reg.addEventListener('updatefound', function() {
          var newWorker = reg.installing;
          if (!newWorker) return;
          newWorker.addEventListener('statechange', function() {
            if (newWorker.state === 'installed') {
              if (reg.active && opts.onUpdate) opts.onUpdate(reg);
              else if (opts.onInstalled) opts.onInstalled(reg);
            }
            if (newWorker.state === 'activated' && opts.onActivated) opts.onActivated(reg);
          });
        });

        if (typeof navigator !== 'undefined' && navigator.serviceWorker) {
          navigator.serviceWorker.addEventListener('message', function(e) {
            _messageCallbacks.forEach(function(cb) { cb(e.data); });
          });
        }

        return reg;
      })
      .catch(function(err) { if (opts.onError) opts.onError(err); throw err; });
  }

  function unregister() {
    if (!_registration) return (typeof navigator !== 'undefined' && navigator.serviceWorker)
      ? navigator.serviceWorker.getRegistration().then(function(r) { return r ? r.unregister() : false; })
      : Promise.resolve(false);
    return _registration.unregister().then(function(ok) { _registration = null; return ok; });
  }

  function getRegistration() {
    if (_registration) return Promise.resolve(_registration);
    if (typeof navigator !== 'undefined' && navigator.serviceWorker) return navigator.serviceWorker.getRegistration();
    return Promise.resolve(null);
  }

  function update() {
    if (_registration) return _registration.update();
    return getRegistration().then(function(r) { return r ? r.update() : undefined; });
  }

  function onInstallPrompt(callback) {
    _installPromptCallbacks.push(callback);
    if (_installPromptEvent) {
      callback({ prompt: function() { return _installPromptEvent.prompt().then(function(r) { _installPromptEvent = null; return r; }); } });
    }
    return function() { _installPromptCallbacks = _installPromptCallbacks.filter(function(c) { return c !== callback; }); };
  }

  function isInstalled() {
    if (typeof window !== 'undefined' && window.matchMedia) return window.matchMedia('(display-mode: standalone)').matches;
    return false;
  }

  function isInstallable() { return !!_installPromptEvent; }

  function precache(urls) { return postMessage({ type: 'BM_PRECACHE', urls: urls }); }
  function clearCache(cacheName) { return postMessage({ type: 'BM_CLEAR_CACHE', cacheName: cacheName || null }); }
  function getCacheStatus() { return postMessage({ type: 'BM_CACHE_STATUS' }); }

  function isOnline() { return typeof navigator !== 'undefined' ? !!navigator.onLine : true; }

  function onConnectivityChange(callback) {
    _connectivityCallbacks.push(callback);
    return function() { _connectivityCallbacks = _connectivityCallbacks.filter(function(c) { return c !== callback; }); };
  }

  function requestSync(tag) {
    return getRegistration().then(function(reg) {
      if (!reg || !reg.sync) return Promise.reject(new Error('Background sync not supported'));
      return reg.sync.register(tag);
    });
  }

  function subscribePush(vapidPublicKey) {
    if (typeof Notification !== 'undefined' && Notification.permission !== 'granted') {
      return Notification.requestPermission().then(function(perm) {
        if (perm !== 'granted') return Promise.reject(new Error('Notification permission denied'));
        return _subscribePush(vapidPublicKey);
      });
    }
    return _subscribePush(vapidPublicKey);
  }

  function _subscribePush(vapidPublicKey) {
    return getRegistration().then(function(reg) {
      if (!reg || !reg.pushManager) return Promise.reject(new Error('Push not supported'));
      var key = Uint8Array.from(atob(vapidPublicKey.replace(/-/g, '+').replace(/_/g, '/')), function(c) { return c.charCodeAt(0); });
      return reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
    });
  }

  function unsubscribePush() {
    return getPushSubscription().then(function(sub) { return sub ? sub.unsubscribe() : false; });
  }

  function getPushSubscription() {
    return getRegistration().then(function(reg) {
      return (reg && reg.pushManager) ? reg.pushManager.getSubscription() : null;
    });
  }

  function generateManifest(opts) {
    opts = opts || {};
    return {
      name: opts.name || 'App',
      short_name: opts.shortName || opts.name || 'App',
      start_url: opts.startUrl || '/',
      display: opts.display || 'standalone',
      theme_color: opts.themeColor || '#000000',
      background_color: opts.bgColor || '#ffffff',
      icons: opts.icons || []
    };
  }

  function injectManifest(opts) {
    var manifest = generateManifest(opts);
    var blob = new Blob([JSON.stringify(manifest)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var link = document.createElement('link');
    link.rel = 'manifest';
    link.href = url;
    document.head.appendChild(link);
    return manifest;
  }

  function onMessage(callback) {
    _messageCallbacks.push(callback);
    return function() { _messageCallbacks = _messageCallbacks.filter(function(c) { return c !== callback; }); };
  }

  return {
    register: register,
    unregister: unregister,
    getRegistration: getRegistration,
    update: update,
    onInstallPrompt: onInstallPrompt,
    isInstalled: isInstalled,
    isInstallable: isInstallable,
    precache: precache,
    clearCache: clearCache,
    getCacheStatus: getCacheStatus,
    isOnline: isOnline,
    onConnectivityChange: onConnectivityChange,
    requestSync: requestSync,
    subscribePush: subscribePush,
    unsubscribePush: unsubscribePush,
    getPushSubscription: getPushSubscription,
    generateManifest: generateManifest,
    injectManifest: injectManifest,
    postMessage: postMessage,
    onMessage: onMessage
  };
})();
