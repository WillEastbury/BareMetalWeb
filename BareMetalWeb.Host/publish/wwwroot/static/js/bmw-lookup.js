// bmw.lookup() — client-side data query function
// Fetches entity data from the server on demand with caching and request deduplication.
(function() {
    'use strict';

    var bmw = window.bmw = window.bmw || {};
    var cache = {};
    var inflight = {};
    var DEFAULT_TTL = 30000; // 30 seconds

    function buildUrl(entityType, idOrFilter, options) {
        var opts = options || {};

        // Aggregate query
        if (opts.aggregate) {
            var url = '/api/_lookup/' + encodeURIComponent(entityType) + '/_aggregate?fn=' + encodeURIComponent(opts.aggregate);
            if (opts.field) {
                url += '&field=' + encodeURIComponent(opts.field);
            }
            if (typeof idOrFilter === 'object' && idOrFilter !== null) {
                var keys = Object.keys(idOrFilter);
                for (var i = 0; i < keys.length; i++) {
                    url += '&filter=' + encodeURIComponent(keys[i] + ':' + idOrFilter[keys[i]]);
                }
            }
            return url;
        }

        // Single entity by ID (string)
        if (typeof idOrFilter === 'string') {
            return '/api/_lookup/' + encodeURIComponent(entityType) + '/' + encodeURIComponent(idOrFilter);
        }

        // Query with filter object
        var base = '/api/_lookup/' + encodeURIComponent(entityType);
        var params = [];

        if (typeof idOrFilter === 'object' && idOrFilter !== null) {
            var filterKeys = Object.keys(idOrFilter);
            for (var j = 0; j < filterKeys.length; j++) {
                params.push('filter=' + encodeURIComponent(filterKeys[j] + ':' + idOrFilter[filterKeys[j]]));
            }
        }

        if (opts.sort) {
            params.push('sort=' + encodeURIComponent(opts.sort));
        }
        if (opts.dir) {
            params.push('dir=' + encodeURIComponent(opts.dir));
        }
        if (opts.skip) {
            params.push('skip=' + encodeURIComponent(opts.skip));
        }
        if (opts.top) {
            params.push('top=' + encodeURIComponent(opts.top));
        }

        return params.length > 0 ? base + '?' + params.join('&') : base;
    }

    function getCached(key) {
        var entry = cache[key];
        if (!entry) return null;
        if (Date.now() > entry.expires) {
            delete cache[key];
            return null;
        }
        return entry.data;
    }

    function setCache(key, data, ttl) {
        cache[key] = { data: data, expires: Date.now() + (ttl || DEFAULT_TTL) };
    }

    /**
     * Fetch entity data from the server.
     * @param {string} entityType - The entity type slug (e.g. "Product", "User")
     * @param {string|object} [idOrFilter] - Entity ID (string) or filter object (e.g. { IsActive: true })
     * @param {object} [options] - Options: { aggregate, field, sort, dir, skip, top, ttl, noCache }
     * @returns {Promise<object>} Parsed JSON response
     */
    bmw.lookup = function(entityType, idOrFilter, options) {
        var opts = options || {};
        var url = buildUrl(entityType, idOrFilter, opts);
        var ttl = opts.ttl != null ? opts.ttl : DEFAULT_TTL;

        // Check cache first
        if (!opts.noCache) {
            var cached = getCached(url);
            if (cached !== null) {
                return Promise.resolve(cached);
            }
        }

        // Deduplicate in-flight requests
        if (inflight[url]) {
            return inflight[url];
        }

        var promise = fetch(url, {
            method: 'GET',
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' }
        }).then(function(response) {
            if (!response.ok) {
                return response.json().then(function(err) {
                    var error = new Error(err.error || ('HTTP ' + response.status));
                    error.status = response.status;
                    error.detail = err;
                    throw error;
                });
            }
            return response.json();
        }).then(function(data) {
            delete inflight[url];
            if (!opts.noCache && ttl > 0) {
                setCache(url, data, ttl);
            }
            return data;
        }).catch(function(err) {
            delete inflight[url];
            throw err;
        });

        inflight[url] = promise;
        return promise;
    };

    /**
     * Fetch a single field value from an entity.
     * @param {string} entityType - The entity type slug
     * @param {string} id - The entity ID
     * @param {string} fieldName - The field name to retrieve
     * @param {object} [options] - Options: { ttl, noCache }
     * @returns {Promise<*>} The field value
     */
    bmw.lookupField = function(entityType, id, fieldName, options) {
        var opts = options || {};
        var url = '/api/_lookup/' + encodeURIComponent(entityType) + '/_field/' + encodeURIComponent(id) + '/' + encodeURIComponent(fieldName);
        var ttl = opts.ttl != null ? opts.ttl : DEFAULT_TTL;

        if (!opts.noCache) {
            var cached = getCached(url);
            if (cached !== null) {
                return Promise.resolve(cached);
            }
        }

        if (inflight[url]) {
            return inflight[url];
        }

        var promise = fetch(url, {
            method: 'GET',
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' }
        }).then(function(response) {
            if (!response.ok) {
                return response.json().then(function(err) {
                    var error = new Error(err.error || ('HTTP ' + response.status));
                    error.status = response.status;
                    error.detail = err;
                    throw error;
                });
            }
            return response.json();
        }).then(function(data) {
            delete inflight[url];
            var result = { field: data.field, value: data.value };
            if (!opts.noCache && ttl > 0) {
                setCache(url, result, ttl);
            }
            return result;
        }).catch(function(err) {
            delete inflight[url];
            throw err;
        });

        inflight[url] = promise;
        return promise;
    };

    /**
     * Invalidate cached lookup data.
     * @param {string} [entityType] - If provided, only invalidate entries for this entity type. If omitted, clears all.
     */
    bmw.lookupClearCache = function(entityType) {
        if (!entityType) {
            cache = {};
            return;
        }
        var prefix = '/api/_lookup/' + encodeURIComponent(entityType);
        var keys = Object.keys(cache);
        for (var i = 0; i < keys.length; i++) {
            if (keys[i].indexOf(prefix) === 0) {
                delete cache[keys[i]];
            }
        }
    };
})();
