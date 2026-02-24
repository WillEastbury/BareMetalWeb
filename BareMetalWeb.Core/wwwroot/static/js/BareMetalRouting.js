// BareMetalRouting.js — Client-side SPA router for BareMetalWeb VNext
// Provides declarative route registration, History API navigation, and
// URL-pattern matching for single-page application use. No external dependencies.
(function (global) {
    'use strict';

    /**
     * BMRouter — lightweight SPA router
     *
     * Usage:
     *   BMRouter.on('/admin/data/:entity',       handlers.listView);
     *   BMRouter.on('/admin/data/:entity/create', handlers.createView);
     *   BMRouter.on('/admin/data/:entity/:id',    handlers.detailView);
     *   BMRouter.on('/admin',                           handlers.homeView);
     *   BMRouter.start();                // match current URL and start listening
     *   BMRouter.navigate('/admin/...');  // programmatic navigation
     */
    var BMRouter = {
        _routes: [],
        _notFound: null,

        /**
         * Register a route handler.
         * Patterns support named segments (:param) and a catch-all (*).
         * Routes are matched in registration order; register more-specific routes first.
         * @param {string}   pattern  URL pattern, e.g. '/admin/data/:entity/:id/edit'
         * @param {function} handler  Called with (params, query, state) when matched.
         */
        on: function (pattern, handler) {
            this._routes.push({ pattern: pattern, handler: handler, re: patternToRegex(pattern), keys: extractKeys(pattern) });
            return this;
        },

        /**
         * Register a fallback handler invoked when no route matches.
         * @param {function} handler Called with (path) when no route matches.
         */
        notFound: function (handler) {
            this._notFound = handler;
            return this;
        },

        /**
         * Start the router: listen for popstate events and dispatch the current URL.
         */
        start: function () {
            var self = this;
            window.addEventListener('popstate', function (e) {
                self._dispatch(window.location.pathname, window.location.search, e.state);
            });
            // Intercept clicks on vnext-internal anchor tags
            document.addEventListener('click', function (e) {
                var anchor = e.target.closest('a[href]');
                if (!anchor) return;
                var href = anchor.getAttribute('href');
                if (!href || href.startsWith('#') || anchor.target === '_blank') return;
                if (isVNextPath(href)) {
                    e.preventDefault();
                    self.navigate(href, null, anchor.dataset.replace === 'true');
                }
            });
            this._dispatch(window.location.pathname, window.location.search, window.history.state);
        },

        /**
         * Navigate to a new path without a full page reload.
         * @param {string}  path     Absolute path, e.g. '/admin/data/customers'
         * @param {object}  [state]  Optional state object for history entry
         * @param {boolean} [replace] When true uses replaceState instead of pushState
         */
        navigate: function (path, state, replace) {
            var url = path;
            if (replace) {
                window.history.replaceState(state || null, '', url);
            } else {
                window.history.pushState(state || null, '', url);
            }
            var qIdx = path.indexOf('?');
            var pathname = qIdx >= 0 ? path.substring(0, qIdx) : path;
            var search   = qIdx >= 0 ? path.substring(qIdx) : '';
            this._dispatch(pathname, search, state || null);
        },

        /** @private */
        _dispatch: function (pathname, search, state) {
            var query = parseQuery(search);
            for (var i = 0; i < this._routes.length; i++) {
                var route = this._routes[i];
                var match = route.re.exec(pathname);
                if (match) {
                    var params = {};
                    for (var k = 0; k < route.keys.length; k++) {
                        params[route.keys[k]] = match[k + 1] !== undefined
                            ? decodeURIComponent(match[k + 1])
                            : undefined;
                    }
                    route.handler(params, query, state);
                    return;
                }
            }
            if (this._notFound) {
                this._notFound(pathname, query);
            }
        }
    };

    // ── Helpers ──────────────────────────────────────────────────────────────────

    /**
     * Convert a route pattern string to a RegExp.
     * Processing order matters:
     *  1. Replace :name params and * wildcards with safe placeholders.
     *  2. Escape all remaining regex special characters.
     *  3. Restore placeholders as capturing groups.
     */
    function patternToRegex(pattern) {
        // Step 1: tokenise named params and wildcards
        var tokenized = pattern
            .replace(/:([a-zA-Z_][a-zA-Z0-9_]*)/g, '\x01param\x01')
            .replace(/\*/g, '\x01wild\x01');

        // Step 2: escape regex metacharacters in the remaining literal segments
        var escaped = tokenized.replace(/[.+?^${}()|[\]\\]/g, '\\$&');

        // Step 3: restore placeholders as capturing groups
        escaped = escaped
            .replace(/\x01param\x01/g, '([^/]+)')
            .replace(/\x01wild\x01/g,  '(.*)');

        return new RegExp('^' + escaped + '/?$');
    }

    /** Extract parameter names from a route pattern (in order). */
    function extractKeys(pattern) {
        var keys = [];
        var re = /:([a-zA-Z_][a-zA-Z0-9_]*)/g;
        var m;
        while ((m = re.exec(pattern)) !== null) {
            keys.push(m[1]);
        }
        if (pattern.indexOf('*') >= 0) {
            keys.push('*');
        }
        return keys;
    }

    /** Parse a query string (with or without leading '?') into an object. */
    function parseQuery(search) {
        var q = {};
        if (!search || search.length <= 1) return q;
        var str = search.charAt(0) === '?' ? search.substring(1) : search;
        var pairs = str.split('&');
        for (var i = 0; i < pairs.length; i++) {
            var idx = pairs[i].indexOf('=');
            if (idx < 0) {
                q[decodeURIComponent(pairs[i])] = '';
            } else {
                var key = decodeURIComponent(pairs[i].substring(0, idx));
                var val = decodeURIComponent(pairs[i].substring(idx + 1).replace(/\+/g, ' '));
                if (q[key] !== undefined) {
                    if (!Array.isArray(q[key])) q[key] = [q[key]];
                    q[key].push(val);
                } else {
                    q[key] = val;
                }
            }
        }
        return q;
    }

    /** Returns true if the given href should be handled by the SPA router. */
    function isVNextPath(href) {
        if (href.startsWith('http://') || href.startsWith('https://')) {
            try {
                var u = new URL(href);
                if (u.host !== window.location.host) return false;
                href = u.pathname + u.search;
            } catch (e) {
                return false;
            }
        }
        return href === '/admin' ||
               href.indexOf('/admin/data') === 0 ||
               href.indexOf('/meta/') === 0;
    }

    global.BMRouter = BMRouter;
})(window);
