// BareMetal.ServiceWorker — service worker for BareMetal.Progressive
(function(sw) {
  'use strict';

  var CACHE_PREFIX = 'bm-';
  var routes = [
    { match: /\.(css|js|woff2?)$/, strategy: 'cacheFirst', cacheName: 'bm-static' },
    { match: /\/api\//, strategy: 'networkFirst', cacheName: 'bm-api' },
    { match: /\.(png|jpg|svg|gif|webp)$/, strategy: 'cacheFirst', cacheName: 'bm-images' },
    { match: /./, strategy: 'networkFirst', cacheName: 'bm-pages' }
  ];

  var offlinePage = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Offline</title></head>'
    + '<body style="font-family:sans-serif;text-align:center;padding:4rem">'
    + '<h1>You are offline</h1><p>Please check your connection and try again.</p></body></html>';

  var precacheUrls = [];

  // --- Caching strategies ---
  function cacheFirst(request, cacheName) {
    return sw.caches.open(cacheName).then(function(cache) {
      return cache.match(request).then(function(cached) {
        if (cached) return cached;
        return fetch(request).then(function(response) {
          if (response && response.ok) cache.put(request, response.clone());
          return response;
        });
      });
    });
  }

  function networkFirst(request, cacheName) {
    return fetch(request).then(function(response) {
      if (response && response.ok) {
        sw.caches.open(cacheName).then(function(cache) { cache.put(request, response.clone()); });
      }
      return response;
    }).catch(function() {
      return sw.caches.open(cacheName).then(function(cache) { return cache.match(request); });
    });
  }

  function staleWhileRevalidate(request, cacheName) {
    return sw.caches.open(cacheName).then(function(cache) {
      return cache.match(request).then(function(cached) {
        var fetchPromise = fetch(request).then(function(response) {
          if (response && response.ok) cache.put(request, response.clone());
          return response;
        });
        return cached || fetchPromise;
      });
    });
  }

  function networkOnly(request) { return fetch(request); }

  function cacheOnly(request, cacheName) {
    return sw.caches.open(cacheName).then(function(cache) { return cache.match(request); });
  }

  var strategies = {
    cacheFirst: cacheFirst,
    networkFirst: networkFirst,
    staleWhileRevalidate: staleWhileRevalidate,
    networkOnly: networkOnly,
    cacheOnly: cacheOnly
  };

  function matchRoute(url) {
    for (var i = 0; i < routes.length; i++) {
      var r = routes[i];
      var pattern = (typeof r.match === 'string') ? new RegExp(r.match) : r.match;
      if (pattern.test(url)) return r;
    }
    return null;
  }

  function serveOffline() {
    return new Response(offlinePage, { status: 503, headers: { 'Content-Type': 'text/html' } });
  }

  // --- Lifecycle ---
  sw.addEventListener('install', function(event) {
    event.waitUntil(
      (precacheUrls.length
        ? sw.caches.open('bm-precache').then(function(cache) { return cache.addAll(precacheUrls); })
        : Promise.resolve()
      ).then(function() { return sw.skipWaiting(); })
    );
  });

  sw.addEventListener('activate', function(event) {
    var validNames = {};
    routes.forEach(function(r) { validNames[r.cacheName] = true; });
    validNames['bm-precache'] = true;

    event.waitUntil(
      sw.caches.keys().then(function(names) {
        return Promise.all(names.map(function(name) {
          if (name.indexOf(CACHE_PREFIX) === 0 && !validNames[name]) return sw.caches.delete(name);
          return Promise.resolve();
        }));
      }).then(function() { return sw.clients.claim(); })
    );
  });

  sw.addEventListener('fetch', function(event) {
    var url = event.request.url;
    if (event.request.method !== 'GET') return;

    var route = matchRoute(url);
    if (!route) return;

    var handler = strategies[route.strategy];
    if (!handler) return;

    event.respondWith(
      handler(event.request, route.cacheName).then(function(response) {
        return response || serveOffline();
      }).catch(function() {
        return serveOffline();
      })
    );
  });

  // --- Message handling ---
  sw.addEventListener('message', function(event) {
    var data = event.data;
    if (!data || !data.type) return;

    if (data.type === 'BM_PRECACHE') {
      var urls = data.urls || [];
      sw.caches.open('bm-precache').then(function(cache) {
        return cache.addAll(urls);
      }).then(function() {
        if (event.ports && event.ports[0]) event.ports[0].postMessage({ ok: true });
      });
    }

    else if (data.type === 'BM_CLEAR_CACHE') {
      var target = data.cacheName;
      (target
        ? sw.caches.delete(target)
        : sw.caches.keys().then(function(names) {
            return Promise.all(names.filter(function(n) { return n.indexOf(CACHE_PREFIX) === 0; }).map(function(n) { return sw.caches.delete(n); }));
          })
      ).then(function() {
        if (event.ports && event.ports[0]) event.ports[0].postMessage({ ok: true });
      });
    }

    else if (data.type === 'BM_CACHE_STATUS') {
      sw.caches.keys().then(function(names) {
        var bmCaches = names.filter(function(n) { return n.indexOf(CACHE_PREFIX) === 0; });
        if (event.ports && event.ports[0]) event.ports[0].postMessage({ caches: bmCaches, totalSize: 0 });
      });
    }

    else if (data.type === 'BM_SET_ROUTES') {
      if (Array.isArray(data.routes)) {
        routes = data.routes.map(function(r) {
          return { match: (typeof r.match === 'string') ? new RegExp(r.match) : r.match, strategy: r.strategy, cacheName: r.cacheName };
        });
      }
      if (event.ports && event.ports[0]) event.ports[0].postMessage({ ok: true });
    }

    else if (data.type === 'BM_SKIP_WAITING') {
      sw.skipWaiting();
      if (event.ports && event.ports[0]) event.ports[0].postMessage({ ok: true });
    }

    else if (data.type === 'BM_SET_OFFLINE_PAGE') {
      if (data.html) offlinePage = data.html;
      if (event.ports && event.ports[0]) event.ports[0].postMessage({ ok: true });
    }
  });

  // --- Background sync ---
  sw.addEventListener('sync', function(event) {
    event.waitUntil(
      sw.clients.matchAll().then(function(clients) {
        clients.forEach(function(client) {
          client.postMessage({ type: 'BM_SYNC', tag: event.tag });
        });
      })
    );
  });

  // --- Push notifications ---
  sw.addEventListener('push', function(event) {
    var payload = event.data ? event.data.json() : {};
    var title = payload.title || 'Notification';
    var options = { body: payload.body || '', icon: payload.icon, badge: payload.badge, data: payload.data };
    event.waitUntil(sw.registration.showNotification(title, options));
  });

  sw.addEventListener('notificationclick', function(event) {
    event.notification.close();
    event.waitUntil(
      sw.clients.matchAll({ type: 'window' }).then(function(clientList) {
        for (var i = 0; i < clientList.length; i++) {
          if (clientList[i].focus) return clientList[i].focus();
        }
        if (sw.clients.openWindow) return sw.clients.openWindow('/');
      })
    );
  });

})(self);
