// vnext-app.js — BareMetalWeb VNext client-side rendering engine
// Consumes /meta/* and /api/* to render full CRUD UI without any server-side HTML templating.
// Requires BareMetalRouting.js and Bootstrap 5 to be loaded first.
(function (global) {
    'use strict';

    // ── Configuration ─────────────────────────────────────────────────────────
    var BASE = '';
    var API  = '/api';
    var META = '/meta';
    var LOOKUP_CARDINALITY_THRESHOLD = 20; // above this count, show a search dialog

    // ── CSRF support ──────────────────────────────────────────────────────────
    function getCsrfToken() {
        var el = document.querySelector('meta[name="csrf-token"]');
        return el ? el.getAttribute('content') : '';
    }

    // ── Background job tracking ───────────────────────────────────────────────
    var _trackedJobs  = {};   // jobId → latest JobStatusSnapshot (only jobs started this session)
    var _jobPollTimer = null; // setInterval handle while there are active tracked jobs
    var _jobsPageRefreshCallback = null; // set by renderJobsPage when the jobs page is open

    // ── Metadata cache ────────────────────────────────────────────────────────
    var _metaObjects = null;
    var _metaCache   = {};
    var META_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes — keep in sync with Cache-Control max-age on /meta/* server endpoints
    var META_STORE_KEY    = 'bmw_meta_objects';
    var META_STORE_PFX    = 'bmw_meta_';

    function _loadFromSession(key) {
        try {
            var raw = sessionStorage.getItem(key);
            if (!raw) return null;
            var entry = JSON.parse(raw);
            if (entry && entry.ts && (Date.now() - entry.ts) < META_CACHE_TTL_MS) return entry.data;
            sessionStorage.removeItem(key);
        } catch (e) {}
        return null;
    }

    function _saveToSession(key, data) {
        try { sessionStorage.setItem(key, JSON.stringify({ ts: Date.now(), data: data })); } catch (e) { console.warn('bmw: sessionStorage write failed', e); }
    }

    function fetchMetaObjects() {
        // Consume server-inlined meta objects (always takes priority — refreshes cache on every shell load)
        var inlined = window.__BMW_META_OBJECTS__;
        if (inlined) {
            window.__BMW_META_OBJECTS__ = null;
            _metaObjects = inlined;
            _saveToSession(META_STORE_KEY, inlined);
            return Promise.resolve(_metaObjects);
        }
        if (_metaObjects) return Promise.resolve(_metaObjects);
        // Consume server-inlined meta objects — eliminates the /meta/objects round-trip on first load
        if (window.__BMW_META_OBJECTS__ != null) {
            _metaObjects = window.__BMW_META_OBJECTS__;
            window.__BMW_META_OBJECTS__ = null;
            _saveToSession(META_STORE_KEY, _metaObjects);
            return Promise.resolve(_metaObjects);
        }
        var cached = _loadFromSession(META_STORE_KEY);
        if (cached) { _metaObjects = cached; return Promise.resolve(_metaObjects); }
        return apiFetch(META + '/objects').then(function (data) {
            _metaObjects = data;
            _saveToSession(META_STORE_KEY, data);
            return data;
        });
    }

    function fetchMeta(slug) {
        // Consume server-inlined entity schema (takes priority — refreshes cache for the current entity)
        var inlinedSlug = window.__BMW_META_SLUG__ && window.__BMW_META_SLUG__[slug];
        if (inlinedSlug) {
            delete window.__BMW_META_SLUG__[slug];
            _metaCache[slug] = inlinedSlug;
            _saveToSession(META_STORE_PFX + slug, inlinedSlug);
            return Promise.resolve(_metaCache[slug]);
        }
        if (_metaCache[slug]) return Promise.resolve(_metaCache[slug]);
        // Consume server-inlined entity schema — eliminates the /meta/{slug} round-trip on first load
        if (window.__BMW_META__ && window.__BMW_META__[slug] != null) {
            _metaCache[slug] = window.__BMW_META__[slug];
            _saveToSession(META_STORE_PFX + slug, _metaCache[slug]);
            delete window.__BMW_META__[slug];
            return Promise.resolve(_metaCache[slug]);
        }
        var cached = _loadFromSession(META_STORE_PFX + slug);
        if (cached) { _metaCache[slug] = cached; return Promise.resolve(cached); }
        return apiFetch(META + '/' + encodeURIComponent(slug)).then(function (data) {
            _metaCache[slug] = data;
            _saveToSession(META_STORE_PFX + slug, data);
            return data;
        });
    }

    // ── Lookup cache (bounded) ──────────────────────────────────────────────
    var _lookupCache = {};
    var _lookupCacheKeys = [];
    var LOOKUP_CACHE_MAX = 100;

    function fetchLookupOptions(targetSlug, queryField, queryValue, sortField, sortDir, queryOperator) {
        var key = targetSlug + '|' + (queryField || '') + '|' + (queryOperator || '') + '|' + (queryValue || '') + '|' + (sortField || '') + '|' + (sortDir || '');
        if (_lookupCache[key]) return Promise.resolve(_lookupCache[key]);

        var params = [];
        if (queryField && queryValue) {
            params.push('f_' + encodeURIComponent(queryField) + '=' + encodeURIComponent(queryValue));
            if (queryOperator && queryOperator !== 'Equals') {
                var opMap = { NotEquals: 'ne', Contains: 'contains', StartsWith: 'startswith', GreaterThan: 'gt', LessThan: 'lt' };
                var opKey = opMap[queryOperator];
                if (opKey) params.push('op_' + encodeURIComponent(queryField) + '=' + encodeURIComponent(opKey));
            }
        }
        if (sortField) { params.push('sort=' + encodeURIComponent(sortField)); }
        if (sortDir)   { params.push('dir='  + encodeURIComponent(sortDir)); }
        params.push('top=500');

        var url = API + '/' + encodeURIComponent(targetSlug) + (params.length ? '?' + params.join('&') : '');
        return apiFetch(url).then(function (items) {
            // Evict oldest entry if cache is full
            if (_lookupCacheKeys.length >= LOOKUP_CACHE_MAX) {
                var evict = _lookupCacheKeys.shift();
                delete _lookupCache[evict];
            }
            _lookupCache[key] = Array.isArray(items) ? items : (items.items || []);
            _lookupCacheKeys.push(key);
            return _lookupCache[key];
        }).catch(function (err) {
            console.warn('Lookup fetch failed for ' + targetSlug + ':', err);
            return [];
        });
    }

    function clearLookupCache(slug) {
        Object.keys(_lookupCache).forEach(function (k) {
            if (k.indexOf(slug + '|') === 0) {
                delete _lookupCache[k];
                var idx = _lookupCacheKeys.indexOf(k);
                if (idx >= 0) _lookupCacheKeys.splice(idx, 1);
            }
        });
    }

    // ── Abort controller for in-flight navigation requests ─────────────────
    var _navAbortController = null;

    function cancelNavigation() {
        if (_navAbortController) {
            _navAbortController.abort();
            _navAbortController = null;
        }
    }

    function getNavSignal() {
        cancelNavigation();
        _navAbortController = new AbortController();
        return _navAbortController.signal;
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────
    function apiFetch(url, options) {
        var opts = Object.assign({ credentials: 'same-origin', headers: {} }, options || {});
        opts.headers['Accept'] = 'application/json';
        if (opts.method && opts.method !== 'GET') {
            opts.headers['X-Requested-With'] = 'BareMetalWeb';
            opts.headers['X-CSRF-Token'] = getCsrfToken();
        }
        return fetch(url, opts).then(function (r) {
            if (r.status === 401) { window.location.href = '/login'; throw new Error('Unauthorized'); }
            if (!r.ok) {
                return r.text().then(function (t) {
                    var msg = t;
                    try { msg = JSON.parse(t).error || t; } catch (e) {}
                    throw new Error(msg || ('HTTP ' + r.status));
                });
            }
            if (r.status === 204) return null;
            var httpStatus = r.status;
            return r.json().then(function (data) {
                if (httpStatus === 202 && data && data.jobId)
                    trackJob(data.jobId, data.operationName || 'Background Job');
                return data;
            });
        });
    }

    function apiPost(url, body)   { return apiFetch(url, { method: 'POST',   headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); }
    function apiPut(url, body)    { return apiFetch(url, { method: 'PUT',    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); }
    function apiDelete(url)       { return apiFetch(url, { method: 'DELETE' }); }
    function apiGet(url)          { return apiFetch(url); }

    // Raw ordinal fetch — decompresses Brotli on the client and parses ordinal array
    function apiRawFetch(slug) {
        return fetch('/api/_binary/' + encodeURIComponent(slug) + '/_raw')
            .then(function (res) {
                if (!res.ok) throw new Error('Raw fetch failed: ' + res.status);
                var fieldsHeader = res.headers.get('X-BMW-Fields') || '';
                var fieldNames = fieldsHeader.split(',');
                return res.arrayBuffer().then(function (compressed) {
                    // Use DecompressionStream if available (modern browsers)
                    if (typeof DecompressionStream !== 'undefined') {
                        var ds = new DecompressionStream('deflate-raw');
                        var blob = new Blob([compressed]);
                        return new Response(blob.stream().pipeThrough(ds)).arrayBuffer()
                            .then(function (raw) { return parseOrdinalData(new DataView(raw), fieldNames); });
                    }
                    // Fallback: assume server sent uncompressed if no DecompressionStream
                    return parseOrdinalData(new DataView(compressed), fieldNames);
                });
            });
    }

    // Shared Uint8Array view reused across all parseOrdinalData calls to avoid per-cell allocation.
    var _ordinalBuf = null;
    var _ordinalDecoder = new TextDecoder('utf-8');

    function parseOrdinalData(view, fieldNames) {
        var offset = 0;
        var byteLen = view.byteLength;
        if (byteLen < 6) throw new Error('Ordinal data too short');
        var rowCount = view.getUint32(offset, true); offset += 4;
        var fieldCount = view.getUint16(offset, true); offset += 2;
        if (rowCount > 1000000 || fieldCount > 10000) throw new Error('Ordinal data exceeds safe bounds');
        var rows = new Array(rowCount);
        // Reuse or create a Uint8Array view over the DataView's buffer.
        if (!_ordinalBuf || _ordinalBuf.buffer !== view.buffer) {
            _ordinalBuf = new Uint8Array(view.buffer);
        }
        var fieldNameCount = fieldNames.length;
        for (var r = 0; r < rowCount; r++) {
            var row = {};
            for (var f = 0; f < fieldCount; f++) {
                if (offset + 2 > byteLen) throw new Error('Ordinal data truncated at field length');
                var len = view.getUint16(offset, true); offset += 2;
                if (offset + len > byteLen) throw new Error('Ordinal data truncated at field value');
                // Decode by slicing a view (subarray) — no copy; TextDecoder reads in-place.
                if (f < fieldNameCount) row[fieldNames[f]] = len > 0 ? _ordinalDecoder.decode(_ordinalBuf.subarray(offset, offset + len)) : '';
                offset += len;
            }
            rows[r] = row;
        }
        return { rows: rows, fieldNames: fieldNames, rowCount: rowCount };
    }

    // ── UI helpers ────────────────────────────────────────────────────────────
    var content = null;

    function getContent() {
        return content || (content = document.getElementById('vnext-content'));
    }

    function setContent(html) {
        getContent().innerHTML = html;
    }

    function showLoading() {
        setContent('<div class="text-center py-5"><div class="spinner-border" role="status"><span class="visually-hidden">Loading\u2026</span></div></div>');
    }

    function showError(msg) {
        setContent('<div class="alert alert-danger m-3"><i class="bi bi-exclamation-triangle-fill me-2"></i>' + escHtml(msg) + '</div>');
    }

    function showToast(message, type) {
        var container = document.getElementById('vnext-toast-container');
        if (!container) return;
        var id = 'toast-' + Date.now();
        var cls = type === 'error' ? 'bg-danger text-white' : type === 'warning' ? 'bg-warning' : type === 'info' ? 'bg-info text-dark' : 'bg-success text-white';
        container.insertAdjacentHTML('beforeend',
            '<div id="' + id + '" class="toast align-items-center ' + cls + ' border-0" role="alert" aria-live="assertive">' +
            '<div class="d-flex"><div class="toast-body">' + escHtml(message) + '</div>' +
            '<button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>' +
            '</div></div>');
        var el = document.getElementById(id);
        if (el && global.bootstrap) {
            var toast = new bootstrap.Toast(el, { delay: 4000 });
            toast.show();
            el.addEventListener('hidden.bs.toast', function () { el.remove(); });
        }
    }

    // ── Background job tracking ───────────────────────────────────────────────

    function trackJob(jobId, operationName) {
        _trackedJobs[jobId] = { jobId: jobId, operationName: operationName, status: 'queued', percentComplete: 0, description: '' };
        showToast('\u23F3 Job queued: ' + operationName, 'info');
        _startJobPolling();
        _updateJobBadge();
        if (_jobsPageRefreshCallback) _jobsPageRefreshCallback(); // refresh jobs page if open
    }

    function _startJobPolling() {
        if (_jobPollTimer) return;
        _jobPollTimer = setInterval(_pollJobs, 3000);
    }

    function _stopJobPolling() {
        if (_jobPollTimer) { clearInterval(_jobPollTimer); _jobPollTimer = null; }
    }

    function _pollJobs() {
        apiFetch(API + '/jobs').then(function (jobs) {
            if (!Array.isArray(jobs)) return;
            jobs.forEach(function (j) {
                var prev = _trackedJobs[j.jobId];
                if (!prev) return; // not a job we started this session
                var wasActive = prev.status === 'queued' || prev.status === 'running';
                _trackedJobs[j.jobId] = j;
                if (wasActive && j.status === 'succeeded')
                    showToast('\u2705 ' + j.operationName + ': completed successfully.', 'success');
                else if (wasActive && j.status === 'failed')
                    showToast('\u274C ' + j.operationName + ': failed. ' + (j.error || ''), 'error');
            });
            _updateJobBadge();
            if (_jobsPageRefreshCallback) _jobsPageRefreshCallback();
            var hasActive = Object.keys(_trackedJobs).some(function (id) {
                var s = _trackedJobs[id].status;
                return s === 'queued' || s === 'running';
            });
            if (!hasActive) _stopJobPolling();
        }).catch(function () {}); // silent — don't disrupt the user
    }

    function _updateJobBadge() {
        var badge = document.getElementById('vnext-jobs-badge');
        if (!badge) return;
        var active = Object.keys(_trackedJobs).filter(function (id) {
            var s = _trackedJobs[id].status;
            return s === 'queued' || s === 'running';
        }).length;
        badge.textContent = String(active);
        badge.classList.toggle('d-none', active === 0);
    }

    function _updateInboxBadge() {
        fetch(BASE + '/api/inbox/unread-count', { credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) {
                if (!data) return;
                var badge = document.getElementById('vnext-inbox-badge');
                if (!badge) return;
                var count = data.count || 0;
                badge.textContent = count > 99 ? '99+' : String(count);
                badge.classList.toggle('d-none', count === 0);
            })
            .catch(function () {});
    }

    // Single-pass HTML escaper: one scan instead of 5 chained regex replace calls.
    function escHtml(str) {
        if (str == null) return '';
        var s = String(str);
        // Single-pass scan replaces 4× regex passes with one loop.
        // Avoids 4 intermediate string allocations per call.
        var out = '';
        var last = 0;
        for (var i = 0; i < s.length; i++) {
            var ent;
            switch (s.charCodeAt(i)) {
                case 38: ent = '&amp;'; break;  // &
                case 60: ent = '&lt;'; break;   // <
                case 62: ent = '&gt;'; break;   // >
                case 34: ent = '&quot;'; break; // "
                case 39: ent = '&#39;'; break;  // '
                default: continue;
            }
            if (i > last) out += s.substring(last, i);
            out += ent;
            last = i + 1;
        }
        return last === 0 ? s : out + s.substring(last);
    }

    function syncTagHidden(container) {
        var fieldName = container.dataset.field;
        var hidden = container.parentElement.querySelector('input[name="' + fieldName + '"]');
        var tags = [];
        container.querySelectorAll('.vnext-tag-pill').forEach(function (pill) {
            tags.push(pill.firstChild.textContent.trim());
        });
        if (hidden) hidden.value = JSON.stringify(tags);
    }

    // ── Lightweight Markdown → HTML ─────────────────────────────────────────
    // Allowlist of tags produced by renderMarkdownToHtml — strip anything else.
    var _mdAllowedTags = /^(p|br|h[1-6]|strong|em|code|pre|a|ul|ol|li|hr|div|span|blockquote|table|thead|tbody|tr|th|td|img)$/i;

    function sanitizeHtml(html) {
        // Strip any HTML tag not in the allowlist, and remove dangerous attributes
        // (on*, style with expressions, src/href with javascript:)
        return html
            .replace(/<\/?([a-zA-Z][a-zA-Z0-9]*)\b[^>]*>/g, function (match, tag) {
                if (!_mdAllowedTags.test(tag)) return '';
                // Remove event handler attributes (onclick, onerror, etc.)
                return match.replace(/\s+on\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]*)/gi, '');
            });
    }

    function renderMarkdownToHtml(md) {
        if (!md) return '';
        var html = escHtml(md);
        // Code blocks (``` ... ```)
        html = html.replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>');
        // Inline code
        html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
        // Headers
        html = html.replace(/^### (.+)$/gm, '<h5>$1</h5>');
        html = html.replace(/^## (.+)$/gm, '<h4>$1</h4>');
        html = html.replace(/^# (.+)$/gm, '<h3>$1</h3>');
        // Bold + italic
        html = html.replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>');
        html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
        html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');
        // Links (only http/https/mailto — block javascript: URIs)
        html = html.replace(/\[([^\]]+)\]\(((?:https?:\/\/|mailto:)[^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
        // Unordered lists
        html = html.replace(/^\- (.+)$/gm, '<li>$1</li>');
        html = html.replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>');
        // Horizontal rules
        html = html.replace(/^---$/gm, '<hr>');
        // Paragraphs (double newline)
        html = html.replace(/\n\n/g, '</p><p>');
        html = '<p>' + html + '</p>';
        // Single newlines → <br>
        html = html.replace(/\n/g, '<br>');
        return sanitizeHtml(html);
    }

    function fmtValue(val, fieldType) {
        if (val == null || val === '') return '<span class="text-muted">—</span>';
        if (fieldType === 'YesNo' || fieldType === 'Boolean') {
            return val === true || val === 'true' || val === 1
                ? '<span class="badge bg-success">Yes</span>'
                : '<span class="badge bg-secondary">No</span>';
        }
        if (fieldType === 'Password') return '<span class="text-muted">••••••••</span>';
        if (fieldType === 'Markdown') return '<div class="bm-markdown-rendered">' + renderMarkdownToHtml(String(val)) + '</div>';
        if (fieldType === 'Tags' && Array.isArray(val)) {
            return val.map(function (t) { return '<span class="badge bg-info text-dark me-1">' + escHtml(t) + '</span>'; }).join('');
        }
        if (fieldType === 'Image') {
            if (typeof val === 'object' && val.url) return '<img src="' + escHtml(val.url) + '" class="img-thumbnail bm-img-thumb" alt="">';
            return escHtml(String(val));
        }
        if (typeof val === 'object') return '<code>' + escHtml(JSON.stringify(val)) + '</code>';
        return escHtml(String(val));
    }

    function nestedGet(obj, path) {
        if (!obj || !path) return undefined;
        // Fast path: simple field name with no dot (covers the vast majority of calls)
        if (path.indexOf('.') === -1) {
            if (path in obj) return obj[path];
            var alt = path.charAt(0) === path.charAt(0).toLowerCase()
                ? path.charAt(0).toUpperCase() + path.slice(1)
                : path.charAt(0).toLowerCase() + path.slice(1);
            if (alt in obj) return obj[alt];
            var lp = path.toLowerCase();
            for (var k in obj) { if (k.toLowerCase() === lp) return obj[k]; }
            return undefined;
        }
        var parts = path.split('.');
        var cur = obj;
        for (var i = 0; i < parts.length; i++) {
            if (cur == null) return undefined;
            var p = parts[i];
            if (p in cur) { cur = cur[p]; continue; }
            // Case-insensitive fallback: try camelCase/PascalCase variants
            var alt2 = p.charAt(0) === p.charAt(0).toLowerCase()
                ? p.charAt(0).toUpperCase() + p.slice(1)
                : p.charAt(0).toLowerCase() + p.slice(1);
            if (alt2 in cur) { cur = cur[alt2]; continue; }
            // Full case-insensitive search as last resort
            var lp2 = p.toLowerCase();
            var found = false;
            for (var k in cur) {
                if (k.toLowerCase() === lp2) { cur = cur[k]; found = true; break; }
            }
            if (!found) return undefined;
        }
        return cur;
    }

    function findCellCaseInsensitive(row, fieldName) {
        var cell = row.querySelector('td[data-field="' + fieldName + '"]');
        if (cell) return cell;
        var lower = fieldName.toLowerCase();
        var cells = row.querySelectorAll('td[data-field]');
        for (var i = 0; i < cells.length; i++) {
            if (cells[i].getAttribute('data-field').toLowerCase() === lower) return cells[i];
        }
        return null;
    }

    // ── Navigation builder ────────────────────────────────────────────────────
    function buildNav(entities) {
        var navEl = document.getElementById('vnext-nav-items');
        if (!navEl) return;

        var groups = {};
        entities.forEach(function (e) {
            if (!e.showOnNav) return;
            if (e.rightAligned) return; // already rendered in the right-hand system menu
            var g = e.navGroup || 'Other';
            if (!groups[g]) groups[g] = [];
            groups[g].push(e);
        });

        var html = '';
        Object.keys(groups).sort().forEach(function (groupName) {
            var items = groups[groupName];
            if (items.length === 1) {
                html += '<li class="nav-item"><a class="nav-link" href="' + BASE + '/' + escHtml(items[0].slug) + '">' + escHtml(items[0].name) + '</a></li>';
            } else {
                html += '<li class="nav-item dropdown">';
                html += '<a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">' + escHtml(groupName) + '</a>';
                html += '<ul class="dropdown-menu dropdown-menu-dark">';
                items.sort(function (a, b) { return (a.navOrder || 0) - (b.navOrder || 0) || a.name.localeCompare(b.name); })
                     .forEach(function (e) {
                        html += '<li><a class="dropdown-item" href="' + BASE + '/' + escHtml(e.slug) + '">' + escHtml(e.name) + '</a></li>';
                     });
                html += '</ul></li>';
            }
        });
        navEl.innerHTML = html;

        // Elevation toggle for users with elevated permissions
        if (window.__BMW_HAS_ELEVATED__) {
            var rightNav = document.querySelector('.navbar-nav.ms-auto');
            if (rightNav) {
                var elevLi = document.createElement('li');
                elevLi.className = 'nav-item ms-2';
                var elevBtn = document.createElement('button');
                elevBtn.className = 'btn btn-sm btn-outline-warning';
                elevBtn.id = 'bm-elevation-toggle';
                var isElevated = sessionStorage.getItem('bm-elevated') === 'true';
                elevBtn.innerHTML = isElevated
                    ? '<i class="bi bi-shield-fill-check"></i> Elevated'
                    : '<i class="bi bi-shield-lock"></i> Elevate';
                if (isElevated) elevBtn.classList.replace('btn-outline-warning', 'btn-warning');
                elevBtn.onclick = function () {
                    var nowElevated = sessionStorage.getItem('bm-elevated') !== 'true';
                    sessionStorage.setItem('bm-elevated', nowElevated ? 'true' : 'false');
                    elevBtn.innerHTML = nowElevated
                        ? '<i class="bi bi-shield-fill-check"></i> Elevated'
                        : '<i class="bi bi-shield-lock"></i> Elevate';
                    if (nowElevated) elevBtn.classList.replace('btn-outline-warning', 'btn-warning');
                    else elevBtn.classList.replace('btn-warning', 'btn-outline-warning');
                };
                elevLi.appendChild(elevBtn);
                rightNav.insertBefore(elevLi, rightNav.firstChild);
            }
        }
    }

    // ── Home view ─────────────────────────────────────────────────────────────
    function renderHome() {
        fetchMetaObjects().then(function (entities) {
            var groups = {};
            entities.filter(function (e) { return e.showOnNav; })
                    .sort(function (a, b) { return (a.navOrder || 0) - (b.navOrder || 0) || a.name.localeCompare(b.name); })
                    .forEach(function (e) {
                        var g = e.navGroup || 'Other';
                        if (!groups[g]) groups[g] = [];
                        groups[g].push(e);
                    });
            var html = '<ds pad><dn>' + escHtml('Data Objects') + '</dn>';
            Object.keys(groups).sort().forEach(function (groupName) {
                html += '<strong style="margin-top:0.5rem">' + escHtml(groupName) + '</strong>';
                html += '<dr cols="3">';
                groups[groupName].forEach(function (e) {
                    html += '<dc><db>' +
                        '<strong>' + escHtml(e.name) + '</strong>' +
                        '<a href="' + BASE + '/' + escHtml(e.slug) + '">Open</a>' +
                        '</db></dc>';
                });
                html += '</dr>';
            });
            html += '</ds>';
            setContent(html);
        }).catch(function (err) { showError('Could not load entities: ' + err.message); });
    }

    // ── Table / List view ─────────────────────────────────────────────────────
    function renderList(slug, query) {
        showLoading();
        var skip  = parseInt(query.skip  || '0',  10);
        var top   = parseInt(query.top   || '25', 10);
        var sort  = query.sort  || '';
        var dir   = query.dir   || 'asc';
        var search = query.q    || '';

        // Consume server-inlined initial data immediately (prevents stale use on SPA back-nav)
        var _bmwInline = window.__BMW_INITIAL_DATA__;
        window.__BMW_INITIAL_DATA__ = null;

        fetchMeta(slug).then(function (meta) {
            // Apply default sort from metadata when no explicit sort is in the URL
            if (!sort && meta.defaultSortField) {
                sort = meta.defaultSortField;
                dir  = (meta.defaultSortDirection || 'Asc').toLowerCase();
            }

            // Hierarchy/calendar views need all items (no pagination)
            var vt = meta.viewType || '';
            var activeView = query.view || '';
            var isHierarchyView = (vt === 'TreeView' || vt === 'OrgChart' || vt === 'Timeline' || vt === 'Sankey' || vt === 'Kanban' || vt === 'Calendar' || activeView === 'TreeView' || activeView === 'OrgChart' || activeView === 'Timeline' || activeView === 'Timetable' || activeView === 'Sankey' || activeView === 'Workflow' || activeView === 'Kanban' || activeView === 'Calendar');

            var effectiveSkip = isHierarchyView ? 0 : skip;
            var effectiveTop  = isHierarchyView ? 10000 : top;

            // Build API query
            var params = ['skip=' + effectiveSkip, 'top=' + effectiveTop];
            if (search)  params.push('q=' + encodeURIComponent(search));
            if (sort)    params.push('sort=' + encodeURIComponent(sort), 'dir=' + encodeURIComponent(dir));
            // Per-field filters from query string
            meta.fields.filter(function (f) { return f.list; }).forEach(function (f) {
                var v = query['f_' + f.name];
                if (v) params.push('f_' + encodeURIComponent(f.name) + '=' + encodeURIComponent(v));
            });

            // Use server-inlined initial data when available and the request matches the default first-load params
            // (slug must match, effectiveTop must match, and no custom pagination / search / sort / field-filters in the URL)
            var hasFieldFilters = meta.fields.some(function (f) { return !!query['f_' + f.name]; });
            var useInline = _bmwInline && _bmwInline.slug === slug &&
                _bmwInline.top === effectiveTop &&
                effectiveSkip === 0 && !query.top && !query.q && !query.sort && !hasFieldFilters;

            var dataPromise = useInline
                ? Promise.resolve(_bmwInline)
                : apiFetch(API + '/' + encodeURIComponent(slug) + '?' + params.join('&'), { signal: getNavSignal() });

            return dataPromise
                .then(function (result) { renderListResult(meta, result, slug, query, skip, top, search, sort, dir); });
        }).catch(function (err) { showError(err.message); });
    }

    function renderListResult(meta, result, slug, query, skip, top, search, sort, dir) {
        var items = Array.isArray(result) ? result : (result.items || []);
        var total = (result && result.total != null) ? result.total : items.length;
        var listFields = meta.fields.filter(function (f) { return f.list; }).sort(function (a, b) { return a.order - b.order; });
        var commands   = meta.commands || [];

        var baseUrl = BASE + '/' + encodeURIComponent(slug);

        function buildSortUrl(fieldName) {
            var newDir = (sort === fieldName && dir === 'asc') ? 'desc' : 'asc';
            return buildUrl(baseUrl, Object.assign({}, query, { sort: fieldName, dir: newDir, skip: 0 }));
        }

        var filterFields = listFields.filter(function (f) { return f.indexed; });

        function buildFilterInput(f, currentVal, cssClass) {
            var n = 'f_' + f.name;
            var ariaLabel = 'aria-label="Filter by ' + escHtml(f.label) + '"';
            if (f.type === 'Bool' || f.type === 'Boolean') {
                return '<select class="' + escHtml(cssClass) + '" name="' + escHtml(n) + '" ' + ariaLabel + '>' +
                    '<option value="">All</option>' +
                    '<option value="true"' + (currentVal === 'true' ? ' selected' : '') + '>Yes</option>' +
                    '<option value="false"' + (currentVal === 'false' ? ' selected' : '') + '>No</option>' +
                    '</select>';
            }
            if (f.type === 'Enum' && f.enumValues && f.enumValues.length) {
                var sel = '<select class="' + escHtml(cssClass) + '" name="' + escHtml(n) + '" ' + ariaLabel + '><option value="">All</option>';
                f.enumValues.forEach(function (ev) {
                    sel += '<option value="' + escHtml(String(ev.value)) + '"' + (currentVal === String(ev.value) ? ' selected' : '') + '>' + escHtml(ev.label) + '</option>';
                });
                return sel + '</select>';
            }
            if (f.type === 'Int32' || f.type === 'Int64' || f.type === 'Decimal' || f.type === 'Money' || f.type === 'Double' || f.type === 'Float') {
                return '<input type="number" class="' + escHtml(cssClass) + '" name="' + escHtml(n) + '" value="' + escHtml(currentVal) + '" placeholder="' + escHtml(f.label) + '\u2026" ' + ariaLabel + '>';
            }
            if (f.type === 'DateOnly' || f.type === 'Date') {
                return '<input type="date" class="' + escHtml(cssClass) + '" name="' + escHtml(n) + '" value="' + escHtml(currentVal) + '" ' + ariaLabel + '>';
            }
            if (f.type === 'DateTime') {
                return '<input type="date" class="' + escHtml(cssClass) + '" name="' + escHtml(n) + '" value="' + escHtml(currentVal ? currentVal.substring(0, 10) : '') + '" ' + ariaLabel + '>';
            }
            return '<input type="text" class="' + escHtml(cssClass) + '" name="' + escHtml(n) + '" value="' + escHtml(currentVal) + '" placeholder="' + escHtml(f.label) + '\u2026" ' + ariaLabel + '>';
        }

        var viewType = meta.viewType || 'Table';
        var activeView = query.view || viewType;

        var html = '<ds pad>';
        // Breadcrumb
        html += '<nav aria-label="breadcrumb"><ol class="breadcrumb"><li class="breadcrumb-item"><a href="' + BASE + '">Home</a></li>';
        html += '<li class="breadcrumb-item active">' + escHtml(meta.name) + '</li></ol></nav>';

        // Title + action bar
        html += '<dr>';
        html += '<h2 style="margin:0">' + escHtml(meta.name) + '</h2>';
        html += '<span class="badge bg-secondary" title="Total records" aria-label="' + total + ' total records">' + total + ' records</span>';
        html += '<a class="btn btn-primary btn-sm" href="' + baseUrl + '/create"><i class="bi bi-plus-lg"></i> New</a>';
        html += '<a class="btn btn-outline-secondary btn-sm" href="' + API + '/' + encodeURIComponent(slug) + '?format=csv" download><i class="bi bi-filetype-csv"></i> Export CSV</a>';
        html += '<a class="btn btn-outline-secondary btn-sm" href="' + API + '/' + encodeURIComponent(slug) + '?format=json" download><i class="bi bi-filetype-json"></i> Export JSON</a>';
        html += '<button class="btn btn-outline-secondary btn-sm" id="vnext-import-btn" data-slug="' + escHtml(slug) + '"><i class="bi bi-upload"></i> Import CSV</button>';
        // View type switcher (when entity supports alternate views or has a parent field for hierarchy)
        if (viewType !== 'Table' || meta.parentField || meta.canShowTimetable || meta.canShowTimeline || meta.canShowSankey || meta.canShowCalendar || meta.canShowWorkflow) {
            html += '<div class="btn-group btn-group-sm ms-2">';
            html += '<a class="btn btn-outline-secondary' + (activeView === 'Table' ? ' active' : '') + '" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'Table' })) + '" title="Table View"><i class="bi bi-table"></i></a>';
            if (viewType === 'TreeView' || (viewType === 'OrgChart' && meta.parentField)) html += '<a class="btn btn-outline-secondary' + (activeView === 'TreeView' ? ' active' : '') + '" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'TreeView' })) + '" title="Tree View"><i class="bi bi-diagram-3"></i></a>';
            if (viewType === 'OrgChart' || (viewType === 'TreeView' && meta.parentField)) html += '<a class="btn btn-outline-secondary' + (activeView === 'OrgChart' ? ' active' : '') + '" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'OrgChart' })) + '" title="Org Chart"><i class="bi bi-people"></i></a>';
            if (viewType === 'Timeline' || meta.canShowTimeline) html += '<a class="btn btn-outline-secondary' + (activeView === 'Timeline' ? ' active' : '') + '" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'Timeline' })) + '" title="Timeline"><i class="bi bi-calendar-range"></i></a>';
            if (meta.canShowTimetable) html += '<a class="btn btn-outline-secondary' + (activeView === 'Timetable' ? ' active' : '') + '" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'Timetable' })) + '" title="Timetable"><i class="bi bi-calendar3"></i></a>';
            if (viewType === 'Sankey' || meta.canShowSankey) html += '<a class="btn btn-outline-secondary' + (activeView === 'Sankey' ? ' active' : '') + '" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'Sankey' })) + '" title="Document Chain (Sankey)"><i class="bi bi-diagram-2-fill"></i></a>';
            if (viewType === 'Calendar' || meta.canShowCalendar) html += '<a class="btn btn-outline-secondary' + (activeView === 'Calendar' ? ' active' : '') + '" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'Calendar' })) + '" title="Calendar"><i class="bi bi-calendar-month"></i></a>';
            if (viewType === 'Kanban' || meta.canShowWorkflow) html += '<a class="btn btn-outline-secondary' + (activeView === 'Workflow' || activeView === 'Kanban' ? ' active' : '') + '" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'Workflow' })) + '" title="Kanban Board"><i class="bi bi-kanban"></i></a>';
            html += '<a class="btn btn-outline-secondary' + (activeView === 'Aggregation' ? ' active' : '') + '" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'Aggregation' })) + '" title="Aggregations"><i class="bi bi-bar-chart-line"></i></a>';
            html += '<a class="btn btn-outline-secondary' + (activeView === 'Chart' ? ' active' : '') + '" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'Chart' })) + '" title="Charts"><i class="bi bi-graph-up"></i></a>';
            html += '</div>';
        }
        html += '</dr>';

        if (activeView === 'TreeView' || (activeView === '' && viewType === 'TreeView')) {
            html += renderTreeView(meta, items, slug, baseUrl, query);
        } else if (activeView === 'OrgChart' || (activeView === '' && viewType === 'OrgChart')) {
            html += renderOrgChart(meta, items, slug, baseUrl);
        } else if ((activeView === 'Timeline' || (activeView === '' && viewType === 'Timeline')) && items.length > 0) {
            html += renderTimeline(meta, items, slug, baseUrl, query);
        } else if ((activeView === 'Timetable' || (activeView === '' && viewType === 'Timetable')) && items.length > 0) {
            html += renderTimetable(meta, items, slug, baseUrl);
        } else if (activeView === 'Sankey' || (activeView === '' && viewType === 'Sankey')) {
            html += renderSankeyView(meta, items, slug, baseUrl);
        } else if (activeView === 'Calendar' || (activeView === '' && viewType === 'Calendar')) {
            html += renderCalendarView(meta, items, slug, baseUrl, query);
        } else if (activeView === 'Aggregation') {
            html += renderAggregationView(meta, items, slug, baseUrl, query);
        } else if (activeView === 'Workflow' || activeView === 'Kanban' || (activeView === '' && viewType === 'Kanban')) {
            html += renderWorkflowView(meta, items, slug, baseUrl, query);
        } else if (activeView === 'Chart') {
            html += renderChartView(meta, items, slug, baseUrl, query);
        } else {
            // Search bar
            html += '<form class="d-flex gap-2 mb-3" id="vnext-search-form">';
            html += '<input class="form-control form-control-sm w-auto" type="search" name="q" placeholder="Search\u2026" value="' + escHtml(search) + '">';
            html += '<button class="btn btn-sm btn-outline-primary" type="submit"><i class="bi bi-search"></i></button>';
            html += '</form>';

            // Bulk actions bar
            html += '<div id="vnext-bulk-bar" class="d-none mb-2">' +
                '<button class="btn btn-sm btn-danger me-2" id="vnext-bulk-delete"><i class="bi bi-trash"></i> Delete Selected</button>' +
                '<button class="btn btn-sm btn-secondary" id="vnext-bulk-export-csv"><i class="bi bi-filetype-csv"></i> Export Selected</button>' +
                '</div>';

            // Table
            // Mobile filter card (shown above cards on narrow viewports)
            var hasActiveFilters = filterFields.some(function (f) { return !!query['f_' + f.name]; });
            if (filterFields.length > 0) {
                html += '<div class="d-md-none mb-3">';
                html += '<div class="card">';
                html += '<div class="card-header p-2 d-flex justify-content-between align-items-center">';
                html += '<span class="fw-semibold small"><i class="bi bi-funnel' + (hasActiveFilters ? '-fill text-primary' : '') + ' me-1"></i>Filters</span>';
                html += '<button class="btn btn-sm btn-outline-secondary py-0" type="button" data-bs-toggle="collapse" data-bs-target="#vnext-mobile-filters" aria-expanded="' + (hasActiveFilters ? 'true' : 'false') + '" aria-label="Toggle filters"><i class="bi bi-chevron-down"></i></button>';
                html += '</div>';
                html += '<div class="collapse' + (hasActiveFilters ? ' show' : '') + '" id="vnext-mobile-filters">';
                html += '<div class="card-body p-2">';
                html += '<form id="vnext-filter-form-mobile">';
                if (sort) html += '<input type="hidden" name="sort" value="' + escHtml(sort) + '">';
                if (dir) html += '<input type="hidden" name="dir" value="' + escHtml(dir) + '">';
                html += '<input type="hidden" name="top" value="' + escHtml(String(top)) + '">';
                if (search) html += '<input type="hidden" name="q" value="' + escHtml(search) + '">';
                if (query.view) html += '<input type="hidden" name="view" value="' + escHtml(query.view) + '">';
                filterFields.forEach(function (f) {
                    var currentVal = query['f_' + f.name] || '';
                    html += '<div class="mb-2"><label class="form-label form-label-sm mb-1 fw-semibold">' + escHtml(f.label) + '</label>';
                    html += buildFilterInput(f, currentVal, 'form-control form-control-sm');
                    html += '</div>';
                });
                html += '<button class="btn btn-sm btn-primary" type="submit"><i class="bi bi-funnel"></i> Apply</button>';
                if (hasActiveFilters) {
                    var clearQuery = Object.assign({}, query);
                    filterFields.forEach(function (f) { delete clearQuery['f_' + f.name]; });
                    html += ' <a class="btn btn-sm btn-outline-secondary" href="' + escHtml(buildUrl(baseUrl, Object.assign(clearQuery, { skip: 0 }))) + '"><i class="bi bi-x-lg"></i> Clear</a>';
                }
                html += '</form></div></div></div></div>';
            }

            // Card layout for narrow viewports
            html += '<div class="d-md-none vnext-card-list">';
            if (items.length === 0) {
                html += '<div class="bm-empty-state"><i class="bi bi-inbox"></i><p>No records found</p><small>Create one to get started</small></div>';
            } else {
                var cparts = new Array(items.length);
                for (var ci2 = 0; ci2 < items.length; ci2++) {
                    var item = items[ci2];
                    var id = item.id || item.Id || '';
                    var encId = encodeURIComponent(id);
                    var cp = '<div class="card mb-2"><div class="card-body p-2">';
                    for (var fi2 = 0; fi2 < listFields.length; fi2++) {
                        var f = listFields[fi2];
                        var val = nestedGet(item, f.name);
                        var cellHtml;
                        if (f.type === 'CustomHtml' && Array.isArray(val)) {
                            cellHtml = '<span class="badge bg-secondary">' + val.length + ' item' + (val.length !== 1 ? 's' : '') + '</span>';
                        } else if (f.lookup && f.lookup.targetSlug && val) {
                            cellHtml = '<span data-lookup-field="' + escHtml(f.name) + '" data-target-slug="' + escHtml(f.lookup.targetSlug) + '" data-display-field="' + escHtml(f.lookup.displayField) + '" data-value="' + escHtml(String(val)) + '">' + escHtml(String(val)) + '</span>';
                        } else {
                            cellHtml = '<span>' + fmtValue(val, f.type) + '</span>';
                        }
                        cp += '<div class="d-flex justify-content-between"><small class="text-muted">' + escHtml(f.label) + '</small>' + cellHtml + '</div>';
                    }
                    cp += '<div class="mt-2 d-flex gap-1">';
                    cp += '<a class="btn btn-xs btn-outline-info btn-sm" href="' + baseUrl + '/' + encId + '"><i class="bi bi-eye"></i></a>';
                    cp += '<a class="btn btn-xs btn-outline-warning btn-sm" href="' + baseUrl + '/' + encId + '/edit"><i class="bi bi-pencil"></i></a>';
                    cp += '<button class="btn btn-xs btn-outline-primary btn-sm vnext-row-clone" data-id="' + escHtml(id) + '" data-slug="' + escHtml(slug) + '"><i class="bi bi-files"></i></button>';
                    cp += '<button class="btn btn-xs btn-outline-danger btn-sm vnext-row-delete" data-id="' + escHtml(id) + '" data-slug="' + escHtml(slug) + '"><i class="bi bi-trash"></i></button>';
                    for (var cmdI = 0; cmdI < commands.length; cmdI++) {
                        var cmd = commands[cmdI];
                        var cls = cmd.destructive ? 'btn-outline-danger' : 'btn-outline-secondary';
                        cp += '<button class="btn btn-xs btn-sm ' + cls + ' vnext-row-cmd" data-id="' + escHtml(id) + '" data-cmd="' + escHtml(cmd.name) + '" data-confirm="' + escHtml(cmd.confirmMessage || '') + '" title="' + escHtml(cmd.label) + '">' +
                            (cmd.icon ? '<i class="bi ' + escHtml(cmd.icon) + '"></i>' : escHtml(cmd.label)) + '</button>';
                    }
                    cparts[ci2] = cp + '</div></div></div>';
                }
                html += cparts.join('');
            }
            html += '</div>';

            // Table layout for wider viewports
            html += '<ta class="d-none d-md-block"><table class="table bm-table table-hover table-striped table-sm align-middle">';
            html += '<thead><tr>';
            html += '<th scope="col"><input type="checkbox" class="form-check-input" id="vnext-select-all" title="Select all"></th>';
            listFields.forEach(function (f) {
                var sortIcon;
                if (sort === f.name) {
                    sortIcon = dir === 'asc'
                        ? ' <i class="bi bi-arrow-up" aria-hidden="true"></i>'
                        : ' <i class="bi bi-arrow-down" aria-hidden="true"></i>';
                } else {
                    sortIcon = ' <i class="bi bi-arrow-down-up text-muted bm-sort-icon-dim" aria-hidden="true"></i>';
                }
                html += '<th scope="col"><a class="text-decoration-none text-reset" href="' + escHtml(buildSortUrl(f.name)) + '" title="Sort by ' + escHtml(f.label) + '">' + escHtml(f.label) + sortIcon + '</a></th>';
            });
            html += '<th scope="col">Actions</th></tr>';
            // Filter row for indexed columns
            if (filterFields.length > 0) {
                html += '<tr id="vnext-filter-row">';
                html += '<th></th>';
                listFields.forEach(function (f) {
                    if (f.indexed) {
                        var currentVal = query['f_' + f.name] || '';
                        var activeClass = currentVal ? ' table-warning' : '';
                        html += '<th class="p-1' + activeClass + '">' + buildFilterInput(f, currentVal, 'form-control form-control-sm bm-col-filter') + '</th>';
                    } else {
                        html += '<th></th>';
                    }
                });
                html += '<th></th>';
                html += '</tr>';
            }
            html += '</thead>';
            html += '<tbody>';

            if (items.length === 0) {
                html += '<tr><td colspan="' + (listFields.length + 2) + '"><div class="bm-empty-state"><i class="bi bi-inbox"></i><p>No records found</p><small>Create one to get started</small></div></td></tr>';
            } else {
                var tparts = new Array(items.length);
                for (var ri = 0; ri < items.length; ri++) {
                    var item = items[ri];
                    var id = item.id || item.Id || '';
                    var encId = encodeURIComponent(id);
                    var rp = '<tr data-id="' + escHtml(id) + '"><td><input type="checkbox" class="form-check-input vnext-row-select" value="' + escHtml(id) + '"></td>';
                    for (var fi = 0; fi < listFields.length; fi++) {
                        var f = listFields[fi];
                        var val = nestedGet(item, f.name);
                        if (f.type === 'CustomHtml' && Array.isArray(val)) {
                            rp += '<td data-label="' + escHtml(f.label) + '"><span class="badge bg-secondary">' + val.length + ' item' + (val.length !== 1 ? 's' : '') + '</span></td>';
                        } else if (f.lookup && f.lookup.targetSlug && val) {
                            rp += '<td data-label="' + escHtml(f.label) + '" data-lookup-field="' + escHtml(f.name) + '" data-target-slug="' + escHtml(f.lookup.targetSlug) + '" data-display-field="' + escHtml(f.lookup.displayField) + '" data-value="' + escHtml(String(val)) + '">' +
                                '<a href="' + BASE + '/' + escHtml(f.lookup.targetSlug) + '/' + encodeURIComponent(val) + '">' + escHtml(String(val)) + '</a></td>';
                        } else {
                            rp += '<td data-label="' + escHtml(f.label) + '">' + fmtValue(val, f.type) + '</td>';
                        }
                    }
                    rp += '<td data-label="Actions" class="text-nowrap">';
                    rp += '<a class="btn btn-xs btn-outline-info btn-sm me-1" href="' + baseUrl + '/' + encId + '" title="View"><i class="bi bi-eye"></i></a>';
                    rp += '<a class="btn btn-xs btn-outline-warning btn-sm me-1" href="' + baseUrl + '/' + encId + '/edit" title="Edit"><i class="bi bi-pencil"></i></a>';
                    rp += '<button class="btn btn-xs btn-outline-primary btn-sm me-1 vnext-row-clone" data-id="' + escHtml(id) + '" data-slug="' + escHtml(slug) + '" title="Clone"><i class="bi bi-files"></i></button>';
                    rp += '<button class="btn btn-xs btn-outline-danger btn-sm vnext-row-delete" data-id="' + escHtml(id) + '" data-slug="' + escHtml(slug) + '" title="Delete"><i class="bi bi-trash"></i></button>';
                    for (var ci = 0; ci < commands.length; ci++) {
                        var cmd = commands[ci];
                        var cls = cmd.destructive ? 'btn-outline-danger' : 'btn-outline-secondary';
                        rp += '<button class="btn btn-xs btn-sm ms-1 ' + cls + ' vnext-row-cmd" data-id="' + escHtml(id) + '" data-cmd="' + escHtml(cmd.name) + '" data-confirm="' + escHtml(cmd.confirmMessage || '') + '" title="' + escHtml(cmd.label) + '">' +
                            (cmd.icon ? '<i class="bi ' + escHtml(cmd.icon) + '"></i>' : escHtml(cmd.label)) + '</button>';
                    }
                    tparts[ri] = rp + '</td></tr>';
                }
                html += tparts.join('');
            }

            html += '</tbody></table></ta>';

            // Pagination
            html += renderPagination(total, skip, top, baseUrl, query);
        }

        html += '</ds>';
        setContent(html);

        // Resolve lookup display values in background
        resolveViewLookups(slug);

        // Wire up events
        var form = document.getElementById('vnext-search-form');
        if (form) form.addEventListener('submit', function (e) {
            e.preventDefault();
            var q = form.querySelector('input[name=q]').value;
            BMRouter.navigate(buildUrl(baseUrl, { q: q, skip: 0, top: top, sort: sort, dir: dir }));
        });

        // Wire import button
        var importBtn = document.getElementById('vnext-import-btn');
        if (importBtn) importBtn.addEventListener('click', function () { openImportModal(slug, baseUrl, query); });

        // Wire column filter inputs (desktop table)
        if (filterFields.length > 0) {
            function applyColFilters() {
                var params = Object.assign({}, query, { skip: 0 });
                document.querySelectorAll('.bm-col-filter').forEach(function (inp) {
                    if (inp.value) { params[inp.name] = inp.value; }
                    else { delete params[inp.name]; }
                });
                BMRouter.navigate(buildUrl(baseUrl, params));
            }
            document.querySelectorAll('.bm-col-filter').forEach(function (inp) {
                if (inp.tagName === 'SELECT') {
                    inp.addEventListener('change', applyColFilters);
                } else {
                    inp.addEventListener('keydown', function (e) {
                        if (e.key === 'Enter') { e.preventDefault(); applyColFilters(); }
                    });
                }
            });

            // Wire mobile filter form
            var mobileFilterForm = document.getElementById('vnext-filter-form-mobile');
            if (mobileFilterForm) {
                mobileFilterForm.addEventListener('submit', function (e) {
                    e.preventDefault();
                    var params = Object.assign({}, query, { skip: 0 });
                    mobileFilterForm.querySelectorAll('[name^="f_"]').forEach(function (inp) {
                        if (inp.value) { params[inp.name] = inp.value; }
                        else { delete params[inp.name]; }
                    });
                    BMRouter.navigate(buildUrl(baseUrl, params));
                });
            }
        }

        wireListEvents(slug, baseUrl, query, top, sort, dir);

        // Wire page-size selector
        var pageSizeSel = document.getElementById('vnext-page-size');
        if (pageSizeSel) pageSizeSel.addEventListener('change', function () {
            var newTop = parseInt(pageSizeSel.value, 10) || 25;
            BMRouter.navigate(buildUrl(baseUrl, Object.assign({}, query, { skip: 0, top: newTop })));
        });

        // Wire row command buttons
        document.querySelectorAll('.vnext-row-cmd').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var id = btn.dataset.id;
                var cmdName = btn.dataset.cmd;
                var confirm = btn.dataset.confirm;
                var doRun = function () {
                    apiPost(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id) + '/_command/' + encodeURIComponent(cmdName), {})
                        .then(function () {
                            showToast('Command executed.', 'success');
                            clearLookupCache(slug);
                            BMRouter.navigate(buildUrl(baseUrl, query));
                        })
                        .catch(function (err) { showToast('Command failed: ' + err.message, 'error'); });
                };
                if (confirm) showConfirm('Run command?', confirm, doRun);
                else doRun();
            });
        });
    }

    // ── Alternate view renderers ──────────────────────────────────────────────

    function renderTreeView(meta, items, slug, baseUrl, query) {
        var parentField = meta.parentField ? meta.parentField.name : null;
        var labelField = meta.fields.filter(function (f) { return f.list; }).sort(function (a, b) { return a.order - b.order; })[0];
        var viewFields = meta.fields.filter(function (f) { return f.view; }).sort(function (a, b) { return a.order - b.order; });
        var selectedId = (query && query.selected) ? query.selected : '';

        if (items.length === 0) {
            return '<p class="text-center text-muted py-4"><i class="bi bi-diagram-3 me-2"></i>No records found.</p>';
        }

        // Build node map
        var nodeMap = {};
        items.forEach(function (item) {
            var id = item.id || item.Id || '';
            nodeMap[id] = { item: item, children: [] };
        });

        // Determine ancestors of selected item so their branches stay expanded
        var ancestorIds = {};
        if (selectedId && parentField && nodeMap[selectedId]) {
            var cur = nodeMap[selectedId].item;
            var visited = {};
            while (cur) {
                var curId = cur.id || cur.Id || '';
                if (visited[curId]) break;
                visited[curId] = true;
                var pid = nestedGet(cur, parentField) || '';
                if (!pid || !nodeMap[pid]) break;
                ancestorIds[pid] = true;
                cur = nodeMap[pid].item;
            }
        }

        function getLabel(item) {
            var id = item.id || item.Id || '';
            return labelField ? (nestedGet(item, labelField.name) || id) : id;
        }

        function buildNodeHtml(node) {
            var id = node.item.id || node.item.Id || '';
            var label = getLabel(node.item);
            var isActive = (id === selectedId);
            var isExpanded = isActive || ancestorIds[id] || false;
            var activeClass = isActive ? ' bm-data-tree-active' : '';
            var viewUrl = buildUrl(baseUrl, Object.assign({}, query, { view: 'TreeView', selected: id }));

            var row = '<li class="bm-tree-item"><div class="bm-tree-node">';
            if (node.children.length > 0) {
                var icon = isExpanded ? '<i class="bi bi-chevron-down"></i>' : '<i class="bi bi-chevron-right"></i>';
                var expCls = isExpanded ? 'bm-tree-expanded' : 'bm-tree-collapsed';
                row += '<span class="bm-tree-toggle ' + expCls + '" onclick="(function(t){' +
                    'var li=t.closest(\'.bm-tree-item\');' +
                    'var ul=li&&li.querySelector(\':scope > ul\');' +
                    'if(!ul)return;' +
                    'var ic=t.querySelector(\'i\');if(!ic)return;' +
                    'var exp=!ul.classList.contains(\'d-none\');' +
                    'ul.classList.toggle(\'d-none\',exp);' +
                    'ic.className=exp?\'bi bi-chevron-right\':\'bi bi-chevron-down\';' +
                    't.classList.toggle(\'bm-tree-expanded\',!exp);' +
                    't.classList.toggle(\'bm-tree-collapsed\',exp);' +
                    '})(this)">' + icon + '</span>';
            } else {
                row += '<span class="bm-tree-toggle bm-tree-spacer"></span>';
            }
            row += '<a class="bm-data-tree-link' + activeClass + '" href="' + viewUrl + '">' + escHtml(String(label)) + '</a>';
            row += '</div>';
            if (node.children.length > 0) {
                var hiddenClass = isExpanded ? '' : ' d-none';
                row += '<ul class="bm-data-tree-list' + hiddenClass + '">';
                node.children.forEach(function (child) { row += buildNodeHtml(child); });
                row += '</ul>';
            }
            row += '</li>';
            return row;
        }

        // Build hierarchy
        var roots = [];
        if (parentField) {
            items.forEach(function (item) {
                var id = item.id || item.Id || '';
                var parentId = nestedGet(item, parentField) || '';
                if (parentId && nodeMap[parentId] && parentId !== id) nodeMap[parentId].children.push(nodeMap[id]);
                else roots.push(nodeMap[id]);
            });
            if (roots.length === 0) {
                items.forEach(function (item) { roots.push(nodeMap[item.id || item.Id || '']); });
            }
        } else {
            items.forEach(function (item) { roots.push(nodeMap[item.id || item.Id || '']); });
        }

        // Split-panel layout (mirrors log viewer / VNext tree view)
        var html = '<div class="bm-data-tree-layout">';

        // Left: tree sidebar
        html += '<div class="bm-data-tree-panel bm-data-tree-sidebar">';
        html += '<div class="bm-data-tree-header">' + escHtml(meta.name) + '</div>';
        html += '<ul class="bm-data-tree-list ps-0">';
        roots.forEach(function (root) { html += buildNodeHtml(root); });
        html += '</ul>';
        html += '</div>';

        // Right: detail panel
        html += '<div class="bm-data-tree-panel bm-data-tree-content">';
        var selectedItem = selectedId && nodeMap[selectedId] ? nodeMap[selectedId].item : null;
        if (selectedItem) {
            html += '<div class="bm-data-tree-header">Details</div>';
            html += '<dl class="row">';
            viewFields.forEach(function (f) {
                var val = nestedGet(selectedItem, f.name);
                html += '<dt class="col-sm-3">' + escHtml(f.label) + '</dt>';
                if (f.type === 'CustomHtml' && Array.isArray(val)) {
                    html += '<dd class="col-sm-9">' + renderSubListReadonly(val, f) + '</dd>';
                } else if (f.lookup && f.lookup.targetSlug && val) {
                    html += '<dd class="col-sm-9" data-lookup-field="' + escHtml(f.name) + '" data-target-slug="' + escHtml(f.lookup.targetSlug) + '" data-display-field="' + escHtml(f.lookup.displayField) + '" data-value="' + escHtml(String(val)) + '">' +
                        '<a href="' + BASE + '/' + escHtml(f.lookup.targetSlug) + '/' + encodeURIComponent(val) + '">' + escHtml(String(val)) + '</a></dd>';
                } else {
                    html += '<dd class="col-sm-9">' + fmtValue(val, f.type) + '</dd>';
                }
            });
            html += '</dl>';
            var safeId = encodeURIComponent(selectedId);
            html += '<div class="mt-3">';
            html += '<a class="btn btn-warning btn-sm me-2" href="' + baseUrl + '/' + safeId + '/edit"><i class="bi bi-pencil"></i> Edit</a>';
            html += '<a class="btn btn-outline-danger btn-sm" href="' + baseUrl + '/' + safeId + '/delete"><i class="bi bi-x-lg"></i> Delete</a>';
            html += '</div>';

            // Document chain mini-panel (async)
            var relFields = meta.documentRelationFields || [];
            if (relFields.length > 0) {
                html += '<div class="mt-3 bm-doc-chain-tree-panel" id="bm-tree-chain-body">';
                html += '<div class="bm-doc-chain-label text-muted small fw-semibold mb-1"><i class="bi bi-diagram-3 me-1"></i>Document Chain</div>';
                html += '<div class="text-muted small"><i class="bi bi-hourglass-split me-1"></i>Loading\u2026</div>';
                html += '</div>';
            }
        } else {
            html += '<p class="text-muted mb-0">Select an item to view details.</p>';
        }
        html += '</div>';

        html += '</div>';

        // Async chain load for the selected tree item
        if (selectedItem && (meta.documentRelationFields || []).length > 0) {
            setTimeout(function () {
                apiFetch(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(selectedId) + '/_related-chain')
                    .then(function (chain) { renderDocumentChainPanel(chain, 'bm-tree-chain-body'); })
                    .catch(function () {
                        var el = document.getElementById('bm-tree-chain-body');
                        if (el) el.innerHTML = '<span class="text-warning small">Chain unavailable</span>';
                    });
            }, 50);
        }

        return html;
    }

    function renderOrgChart(meta, items, slug, baseUrl) {
        var parentField = meta.parentField ? meta.parentField.name : null;
        var labelField = meta.fields.filter(function (f) { return f.list; }).sort(function (a, b) { return a.order - b.order; })[0];
        var subtitleField = meta.fields.filter(function (f) { return f.list && f !== labelField; }).sort(function (a, b) { return a.order - b.order; })[0];
        // Look for a title/role field like the list view does
        var titleField = meta.fields.find(function (f) {
            var n = f.name.toLowerCase();
            return n.indexOf('title') >= 0 || n.indexOf('role') >= 0 || n.indexOf('position') >= 0;
        });

        function buildCardHtml(item) {
            var id = item.id || item.Id || '';
            var label = labelField ? (nestedGet(item, labelField.name) || id) : id;
            var subtitle = '';
            if (titleField) {
                subtitle = nestedGet(item, titleField.name) || '';
            } else if (subtitleField) {
                subtitle = nestedGet(item, subtitleField.name) || '';
            }
            return '<div class="bm-orgchart-card">' +
                '<div class="bm-orgchart-name">' + escHtml(String(label)) + '</div>' +
                (subtitle ? '<div class="bm-orgchart-title">' + escHtml(String(subtitle)) + '</div>' : '') +
                '<div class="bm-orgchart-actions">' +
                '<a class="btn btn-sm btn-outline-info me-1" href="' + baseUrl + '/' + encodeURIComponent(id) + '" title="View"><i class="bi bi-search"></i></a>' +
                '<a class="btn btn-sm btn-outline-warning me-1" href="' + baseUrl + '/' + encodeURIComponent(id) + '/edit" title="Edit"><i class="bi bi-pencil"></i></a>' +
                '</div></div>';
        }

        var html = '<div class="bm-orgchart-container">';

        if (items.length === 0) {
            html += '<p class="text-center text-muted py-4"><i class="bi bi-diagram-2 me-2"></i>No records found.</p>';
            html += '</div>';
            return html;
        }

        if (parentField) {
            var nodeMap = {}, roots = [];
            items.forEach(function (item) {
                var id = item.id || item.Id || '';
                nodeMap[id] = { item: item, children: [] };
            });
            items.forEach(function (item) {
                var id = item.id || item.Id || '';
                var parentId = nestedGet(item, parentField) || '';
                if (parentId && nodeMap[parentId] && parentId !== id) nodeMap[parentId].children.push(nodeMap[id]);
                else roots.push(nodeMap[id]);
            });
            if (roots.length === 0) {
                items.forEach(function (item) { var k = item.id || item.Id || ''; if (k && nodeMap[k]) roots.push(nodeMap[k]); });
            }

            function renderNode(node, depth) {
                if (depth > 5) return '';
                var out = '<div class="bm-orgchart-node">';
                out += buildCardHtml(node.item);
                if (node.children.length > 0) {
                    out += '<div class="bm-orgchart-connector"></div>';
                    out += '<div class="bm-orgchart-level">';
                    node.children.forEach(function (c) { out += renderNode(c, depth + 1); });
                    out += '</div>';
                }
                out += '</div>';
                return out;
            }

            roots.forEach(function (r) { html += renderNode(r, 0); });
        } else {
            html += '<div class="bm-orgchart-level">';
            items.forEach(function (item) {
                html += '<div class="bm-orgchart-node">' + buildCardHtml(item) + '</div>';
            });
            html += '</div>';
        }
        html += '</div>';
        return html;
    }

    function renderTimeline(meta, items, slug, baseUrl, query) {
        // Find first two DateOnly/DateTime fields: start date, optional end date
        var dateFields = meta.fields.filter(function (f) { return f.type === 'DateTime' || f.type === 'DateOnly'; });
        if (!dateFields.length) return '<p class="text-warning">Timeline view requires a DateOnly or DateTime field.</p>';

        var startField = dateFields[0];
        var endField = dateFields.length > 1 ? dateFields[1] : null;
        var labelField = meta.fields.filter(function (f) { return f.list; }).sort(function (a, b) { return a.order - b.order; })[0];

        // Pivot/group-by support: non-date list fields the user can pivot on
        var pivotOptions = meta.fields.filter(function (f) {
            return f.list && f.type !== 'DateTime' && f.type !== 'DateOnly' && f.type !== 'TimeOnly';
        }).sort(function (a, b) { return a.order - b.order; });
        var pivotBy = (query && query.pivotBy) || '';
        var pivotField = pivotBy ? pivotOptions.find(function (f) { return f.name === pivotBy; }) : null;

        // Build gantt items with parsed start/end dates
        var barColors = ['#4472c4', '#c0504d', '#9bbb59', '#f79646', '#8064a2'];
        var ganttItems = [];
        items.forEach(function (item) {
            var sv = nestedGet(item, startField.name);
            if (!sv) return;
            var sd = new Date(sv);
            if (isNaN(sd.getTime())) return;
            var startDate = { y: sd.getFullYear(), m: sd.getMonth(), d: sd.getDate() };

            var endDate = startDate;
            if (endField) {
                var ev = nestedGet(item, endField.name);
                if (ev) {
                    var ed = new Date(ev);
                    if (!isNaN(ed.getTime())) {
                        endDate = { y: ed.getFullYear(), m: ed.getMonth(), d: ed.getDate() };
                        if (new Date(endDate.y, endDate.m, endDate.d) < new Date(startDate.y, startDate.m, startDate.d))
                            endDate = startDate;
                    }
                }
            }

            var id = item.id || item.Id || '';
            var label = labelField ? (nestedGet(item, labelField.name) || id) : id;
            ganttItems.push({ item: item, id: id, label: String(label), start: startDate, end: endDate });
        });

        if (!ganttItems.length) return '<p class="text-muted">No items with valid dates found.</p>';

        // Compute chart date range (expand to full month boundaries)
        var allStarts = ganttItems.map(function (g) { return new Date(g.start.y, g.start.m, g.start.d); });
        var allEnds = ganttItems.map(function (g) { return new Date(g.end.y, g.end.m, g.end.d); });
        var minDate = new Date(Math.min.apply(null, allStarts));
        var maxDate = new Date(Math.max.apply(null, allEnds));
        var chartStart = new Date(minDate.getFullYear(), minDate.getMonth(), 1);
        var chartEndM = maxDate.getMonth() + 1;
        var chartEndY = maxDate.getFullYear();
        if (chartEndM > 11) { chartEndM = 0; chartEndY++; }
        var chartEnd = new Date(chartEndY, chartEndM, 1);
        var totalDays = Math.max((chartEnd - chartStart) / 86400000, 1);

        // Build month columns
        var months = [];
        var cur = new Date(chartStart);
        var runLeft = 0;
        var monthNames = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
        while (cur < chartEnd) {
            var dim = new Date(cur.getFullYear(), cur.getMonth() + 1, 0).getDate();
            var wpct = dim / totalDays * 100;
            months.push({ left: runLeft, width: wpct, label: monthNames[cur.getMonth()], year: cur.getFullYear() });
            runLeft += wpct;
            cur = new Date(cur.getFullYear(), cur.getMonth() + 1, 1);
        }

        // Build year groups from months
        var years = [];
        months.forEach(function (mo) {
            var last = years.length ? years[years.length - 1] : null;
            if (last && last.year === mo.year) {
                last.width += mo.width;
            } else {
                years.push({ year: mo.year, left: mo.left, width: mo.width });
            }
        });

        // Helper: build label HTML for a field value, using data-lookup-field for async resolution
        function makeLabelHtml(field, rawVal, itemId) {
            if (!field) return escHtml(rawVal || itemId);
            if (field.lookup && field.lookup.targetSlug && rawVal) {
                return '<span data-lookup-field="' + escHtml(field.name) +
                    '" data-target-slug="' + escHtml(field.lookup.targetSlug) +
                    '" data-display-field="' + escHtml(field.lookup.displayField || 'Name') +
                    '" data-value="' + escHtml(String(rawVal)) + '">' + escHtml(String(rawVal)) + '</span>';
            }
            return escHtml(String(rawVal || itemId));
        }

        // Build rows: group by pivotField when specified, otherwise one row per item
        var rows; // each row: { labelHtml, titleAttr, bars: [{g, color}] }
        if (pivotField) {
            var groups = {};
            var groupOrder = [];
            ganttItems.forEach(function (g) {
                var pivotVal = String(nestedGet(g.item, pivotField.name) || '');
                if (!groups[pivotVal]) { groups[pivotVal] = []; groupOrder.push(pivotVal); }
                groups[pivotVal].push(g);
            });
            rows = groupOrder.map(function (pivotVal, gi) {
                var color = barColors[gi % barColors.length];
                return {
                    labelHtml: makeLabelHtml(pivotField, pivotVal, pivotVal),
                    titleAttr: escHtml(pivotVal || '(blank)'),
                    bars: groups[pivotVal].map(function (g) { return { g: g, color: color }; })
                };
            });
        } else {
            rows = ganttItems.map(function (g, i) {
                var rawVal = nestedGet(g.item, labelField ? labelField.name : '') || g.id;
                return {
                    labelHtml: '<a href="' + baseUrl + '/' + encodeURIComponent(g.id) + '">' +
                        makeLabelHtml(labelField, rawVal, g.id) + '</a>',
                    titleAttr: escHtml(g.label),
                    bars: [{ g: g, color: barColors[i % barColors.length] }]
                };
            });
        }

        // "View by" pivot selector
        var html = '';
        if (pivotOptions.length > 0) {
            html += '<div class="mb-2 d-flex align-items-center gap-2 flex-wrap">';
            html += '<span class="text-muted small fw-semibold">View by:</span>';
            var itemUrl = buildUrl(baseUrl, Object.assign({}, query, { view: 'Timeline', pivotBy: '' }));
            html += '<a class="btn btn-sm' + (!pivotField ? ' btn-secondary' : ' btn-outline-secondary') +
                '" href="' + itemUrl + '">Item</a>';
            pivotOptions.forEach(function (f) {
                var active = pivotField && pivotField.name === f.name;
                var url = buildUrl(baseUrl, Object.assign({}, query, { view: 'Timeline', pivotBy: f.name }));
                html += '<a class="btn btn-sm' + (active ? ' btn-secondary' : ' btn-outline-secondary') +
                    '" href="' + url + '">' + escHtml(f.label) + '</a>';
            });
            html += '</div>';
        }

        // Render Gantt chart HTML (matches bm-gantt-* classes)
        html += '<div class="bm-gantt-container"><div class="bm-gantt-inner">';

        // Year header row
        html += '<div class="bm-gantt-header-row"><div class="bm-gantt-label-col"></div>';
        html += '<div class="bm-gantt-years-hdr">';
        years.forEach(function (yr) {
            html += '<div class="bm-gantt-year-lbl" data-gantt-left="' + yr.left.toFixed(2) + '%" data-gantt-width="' + yr.width.toFixed(2) + '%">' + yr.year + '</div>';
        });
        html += '</div></div>';

        // Month header row
        html += '<div class="bm-gantt-header-row"><div class="bm-gantt-label-col"></div>';
        html += '<div class="bm-gantt-months-hdr">';
        months.forEach(function (mo) {
            html += '<div class="bm-gantt-month-lbl" data-gantt-left="' + mo.left.toFixed(2) + '%" data-gantt-width="' + mo.width.toFixed(2) + '%">' + escHtml(mo.label) + '</div>';
        });
        html += '</div></div>';

        // Rows
        rows.forEach(function (row) {
            html += '<div class="bm-gantt-row">';
            html += '<div class="bm-gantt-lbl" title="' + row.titleAttr + '">' + row.labelHtml + '</div>';
            html += '<div class="bm-gantt-bar-area">';
            months.forEach(function (mo) {
                html += '<div class="bm-gantt-sep" data-gantt-left="' + mo.left.toFixed(2) + '%"></div>';
            });
            row.bars.forEach(function (b) {
                var g = b.g;
                var sd = new Date(g.start.y, g.start.m, g.start.d);
                var ed = new Date(g.end.y, g.end.m, g.end.d);
                var startDays = (sd - chartStart) / 86400000;
                var endDays = (ed - chartStart) / 86400000 + 1;
                var barLeft = startDays / totalDays * 100;
                var barWidth = Math.max((endDays - startDays) / totalDays * 100, 0.5);
                var tooltip = endField
                    ? escHtml(g.label) + ': ' + sd.toISOString().slice(0,10) + ' \u2013 ' + ed.toISOString().slice(0,10)
                    : escHtml(g.label) + ': ' + sd.toISOString().slice(0,10);
                html += '<a href="' + baseUrl + '/' + encodeURIComponent(g.id) + '/edit" class="bm-gantt-bar" data-gantt-left="' + barLeft.toFixed(2) + '%" data-gantt-width="' + barWidth.toFixed(2) + '%" data-gantt-bg="' + escHtml(b.color) + '" title="' + tooltip + '">';
                html += '<span class="bm-gantt-bar-text">' + escHtml(g.label) + '</span>';
                html += '</a>';
            });
            html += '</div></div>';
        });

        html += '</div></div>';

        // Apply dynamic styles (same as gantt-view.js)
        setTimeout(function () {
            var els = document.querySelectorAll('[data-gantt-left],[data-gantt-width],[data-gantt-bg]');
            for (var j = 0; j < els.length; j++) {
                var el = els[j];
                if (el.dataset.ganttLeft) el.style.left = el.dataset.ganttLeft;
                if (el.dataset.ganttWidth) el.style.width = el.dataset.ganttWidth;
                if (el.dataset.ganttBg) el.style.background = el.dataset.ganttBg;
            }
        }, 0);

        return html;
    }

    function renderTimetable(meta, items, slug, baseUrl) {
        // Find the day enum field (prefer one whose name contains 'day')
        var dayField = meta.fields.find(function (f) {
            return f.type === 'Enum' && f.name.toLowerCase().indexOf('day') >= 0;
        }) || meta.fields.find(function (f) { return f.type === 'Enum'; });

        // Find the time field
        var timeField = meta.fields.find(function (f) {
            return f.type === 'TimeOnly' || f.type === 'DateTime';
        });

        if (!dayField || !timeField) {
            return '<p class="text-warning">Timetable view requires a Day (enum) field and a Time field.</p>';
        }

        // Get list columns in display order
        var listFields = meta.fields.filter(function (f) { return f.list; })
            .sort(function (a, b) { return a.order - b.order; });

        // Ordered day names from enumValues (or DayOfWeek fallback)
        var dayOrder = (dayField.enumValues && dayField.enumValues.length)
            ? dayField.enumValues.map(function (ev) { return ev.value; })
            : ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
        var dayLabels = {};
        if (dayField.enumValues && dayField.enumValues.length) {
            dayField.enumValues.forEach(function (ev) { dayLabels[ev.value] = ev.label; });
        } else {
            dayOrder.forEach(function (d) { dayLabels[d] = d; });
        }

        // Group items by day value (enum serialises to its name string)
        var byDay = {};
        items.forEach(function (item) {
            var dayVal = String(nestedGet(item, dayField.name) != null ? nestedGet(item, dayField.name) : '');
            if (!byDay[dayVal]) byDay[dayVal] = [];
            byDay[dayVal].push(item);
        });

        // Sort items within each day by time field value
        function parseTimeSortKey(val) {
            if (val == null) return -1;
            var s = String(val);
            var d = new Date('1970-01-01 ' + s);
            if (!isNaN(d.getTime())) return d.getTime();
            d = new Date('1970-01-01T' + s);
            if (!isNaN(d.getTime())) return d.getTime();
            return 0;
        }
        Object.keys(byDay).forEach(function (key) {
            byDay[key].sort(function (a, b) {
                return parseTimeSortKey(nestedGet(a, timeField.name)) - parseTimeSortKey(nestedGet(b, timeField.name));
            });
        });

        // Render a vertical section per day (only non-empty days, in enum order)
        var html = '';
        dayOrder.forEach(function (dayVal) {
            var dayItems = byDay[dayVal];
            if (!dayItems || !dayItems.length) return;
            var dayName = dayLabels[dayVal] || dayVal;
            html += '<div class="bm-timetable-day-section mb-4">';
            html += '<h3 class="bm-timetable-day-header">' + escHtml(dayName) + '</h3>';
            html += '<div class="table-responsive"><table class="table table-striped table-hover">';
            html += '<thead><tr><th>Actions</th>';
            listFields.forEach(function (f) { html += '<th>' + escHtml(f.label) + '</th>'; });
            html += '</tr></thead><tbody>';
            dayItems.forEach(function (item) {
                var id = item.id || item.Id || '';
                html += '<tr><td class="text-nowrap">' +
                    '<a class="btn btn-outline-info btn-sm me-1" href="' + baseUrl + '/' + encodeURIComponent(id) + '" title="View"><i class="bi bi-eye"></i></a>' +
                    '<a class="btn btn-outline-warning btn-sm me-1" href="' + baseUrl + '/' + encodeURIComponent(id) + '/edit" title="Edit"><i class="bi bi-pencil"></i></a>' +
                    '<a class="btn btn-outline-secondary btn-sm me-1" href="' + baseUrl + '/create?cloneFrom=' + encodeURIComponent(id) + '" title="Clone"><i class="bi bi-copy"></i></a>' +
                    '<button class="btn btn-outline-danger btn-sm" data-delete-id="' + escHtml(id) + '" title="Delete"><i class="bi bi-trash"></i></button>' +
                    '</td>';
                listFields.forEach(function (f) {
                    var val = nestedGet(item, f.name);
                    if (f.lookup && f.lookup.targetSlug && val) {
                        html += '<td data-lookup-field="' + escHtml(f.name) + '" data-target-slug="' + escHtml(f.lookup.targetSlug) + '" data-display-field="' + escHtml(f.lookup.displayField) + '" data-value="' + escHtml(String(val)) + '">' +
                            '<a href="' + BASE + '/' + escHtml(f.lookup.targetSlug) + '/' + encodeURIComponent(val) + '">' + escHtml(String(val)) + '</a></td>';
                    } else {
                        html += '<td>' + fmtValue(val, f.type) + '</td>';
                    }
                });
                html += '</tr>';
            });
            html += '</tbody></table></div></div>';
        });

        if (!html) return '<p class="text-muted">No timetable items found.</p>';
        return html;
    }

    // ── Document chain / Sankey view ─────────────────────────────────────────

    /**
     * renderSankeyView — shows a document-pipeline (Sankey-style) visualisation.
     *
     * The view has two sections:
     * 1. A "pipeline summary" card that fetches aggregate counts from
     *    GET /api/_document-chain-graph and renders stage → stage flow nodes.
     * 2. A per-record table showing each item's upstream document link(s).
     */
    function renderSankeyView(meta, items, slug, baseUrl) {
        var relFields = meta.documentRelationFields || [];
        var labelField = meta.fields.filter(function (f) { return f.list; }).sort(function (a, b) { return a.order - b.order; })[0];

        // Render the per-record table first (synchronous)
        var html = '';

        // Pipeline graph card — populated async after render
        html += '<div class="card shadow-sm mb-4 bm-page-card" id="bm-sankey-graph-card">';
        html += '<div class="card-header"><h6 class="mb-0"><i class="bi bi-diagram-2-fill me-2"></i>Document Pipeline</h6></div>';
        html += '<div class="card-body" id="bm-sankey-graph-body">';
        html += '<div class="text-muted small"><i class="bi bi-hourglass-split me-1"></i>Loading pipeline graph\u2026</div>';
        html += '</div></div>';

        // Per-record chain table
        if (items.length === 0) {
            html += '<p class="text-center text-muted py-4"><i class="bi bi-diagram-2-fill me-2"></i>No records found.</p>';
        } else {
            html += '<div class="table-responsive"><table class="table table-sm table-hover table-bordered align-middle">';
            html += '<thead class="table-light"><tr>';
            html += '<th>' + escHtml(labelField ? labelField.label : 'Record') + '</th>';
            relFields.forEach(function (rf) {
                html += '<th><i class="bi bi-arrow-up-circle me-1 text-primary"></i>' + escHtml(rf.label) + ' (' + escHtml(rf.targetName || rf.targetSlug) + ')</th>';
            });
            html += '<th></th>';
            html += '</tr></thead><tbody>';

            items.forEach(function (item) {
                var id = item.id || item.Id || '';
                var label = labelField ? (nestedGet(item, labelField.name) || id) : id;
                html += '<tr>';
                html += '<td><a href="' + baseUrl + '/' + encodeURIComponent(id) + '">' + escHtml(String(label)) + '</a></td>';
                relFields.forEach(function (rf) {
                    var fkVal = nestedGet(item, rf.name);
                    if (fkVal && rf.targetSlug) {
                        var href = BASE + '/' + encodeURIComponent(rf.targetSlug) + '/' + encodeURIComponent(String(fkVal));
                        html += '<td><a href="' + href + '" class="badge bg-primary text-decoration-none">' + escHtml(String(fkVal)) + '</a></td>';
                    } else {
                        html += '<td><span class="text-muted small">—</span></td>';
                    }
                });
                html += '<td class="text-nowrap">';
                html += '<a class="btn btn-sm btn-outline-info me-1" href="' + baseUrl + '/' + encodeURIComponent(id) + '?view=chain" title="View chain"><i class="bi bi-diagram-3"></i></a>';
                html += '</td>';
                html += '</tr>';
            });
            html += '</tbody></table></div>';
        }

        // Kick off async graph load after the DOM settles
        setTimeout(function () {
            apiFetch(API + '/_document-chain-graph')
                .then(function (graph) { renderSankeyGraph(graph, 'bm-sankey-graph-body'); })
                .catch(function (err) {
                    var el = document.getElementById('bm-sankey-graph-body');
                    if (el) el.innerHTML = '<span class="text-warning small">Pipeline graph unavailable: ' + escHtml(err.message) + '</span>';
                });
        }, 50);

        return html;
    }

    // ── Calendar View (Day / Week / Month) ─────────────────────────────────
    function renderCalendarView(meta, items, slug, baseUrl, query) {
        var dateField = meta.fields.find(function (f) {
            return f.type === 'DateOnly' || f.type === 'DateTime';
        });
        if (!dateField) return '<p class="text-warning">Calendar view requires a Date field.</p>';

        var labelField = meta.fields.find(function (f) { return f.list && f.type === 'Text'; }) || meta.fields[0];
        var calMode = query.calMode || 'month'; // 'month' | 'week' | 'day'
        var now = new Date();

        // Helper: format Date as YYYY-MM-DD
        function fmtDate(d) {
            var mm = d.getMonth() + 1, dd = d.getDate();
            return d.getFullYear() + '-' + (mm < 10 ? '0' : '') + mm + '-' + (dd < 10 ? '0' : '') + dd;
        }

        // Helper: build items for a given YYYY-MM-DD string key
        var dateMap = {};
        items.forEach(function (item) {
            var raw = nestedGet(item, dateField.name);
            if (!raw) return;
            var d = new Date(raw);
            if (isNaN(d.getTime())) return;
            var key = fmtDate(d);
            if (!dateMap[key]) dateMap[key] = [];
            dateMap[key].push(item);
        });

        // Helper: render a single event badge (draggable)
        function renderEventBadge(it, dateKey) {
            var lbl = nestedGet(it, labelField.name) || '(untitled)';
            var itemId = it.id || it.Id || it.key || it.Key || '';
            return '<a href="' + baseUrl + '/' + encodeURIComponent(itemId) + '" ' +
                'class="d-block small text-truncate badge bg-primary-subtle text-primary mb-1 bm-cal-event" ' +
                'draggable="true" ' +
                'data-item-id="' + escHtml(itemId) + '" ' +
                'data-date-field="' + escHtml(dateField.name) + '" ' +
                'data-src-date="' + escHtml(dateKey) + '" ' +
                'title="' + escHtml(lbl) + '">' + escHtml(lbl) + '</a>';
        }

        // Helper: render a droppable day cell with click-to-create
        function renderDayCell(dateKey, cellClass, showDayNum, dayNum, isToday, minHeight) {
            var createUrl = baseUrl + '/create?' + encodeURIComponent(dateField.name) + '=' + encodeURIComponent(dateKey);
            var h = '<td class="bm-cal-cell' + (isToday ? ' table-primary' : '') + (cellClass ? ' ' + cellClass : '') + '" ' +
                'style="min-height:' + (minHeight || 80) + 'px;vertical-align:top" ' +
                'data-cal-date="' + escHtml(dateKey) + '">';
            if (showDayNum) {
                h += '<div class="d-flex justify-content-between align-items-start">';
                h += '<span class="fw-bold small ' + (isToday ? 'text-primary' : 'text-muted') + '">' + dayNum + '</span>';
                h += '<a href="' + createUrl + '" class="bm-cal-add-btn text-muted text-decoration-none small" title="New item on this day" tabindex="-1">+</a>';
                h += '</div>';
            }
            var dayItems = dateMap[dateKey] || [];
            dayItems.forEach(function (it) { h += renderEventBadge(it, dateKey); });
            h += '</td>';
            return h;
        }

        var monthNames = ['January','February','March','April','May','June','July','August','September','October','November','December'];
        var dayAbbr    = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];

        // ── Sub-view toggle bar ──────────────────────────────────────────────
        function modeUrl(m) { return buildUrl(baseUrl, Object.assign({}, query, { view: 'Calendar', calMode: m })); }
        var html = '';
        html += '<div class="btn-group btn-group-sm mb-3" role="group" aria-label="Calendar mode">';
        ['day','week','month'].forEach(function (m) {
            var label = m.charAt(0).toUpperCase() + m.slice(1);
            html += '<a class="btn btn-outline-secondary' + (calMode === m ? ' active' : '') + '" href="' + modeUrl(m) + '">' + label + '</a>';
        });
        html += '</div>';

        // ─────────────────────────────────────────────────────────────────────
        if (calMode === 'month') {
            var calYear  = parseInt(query.calYear)  || now.getFullYear();
            var calMonth = parseInt(query.calMonth);
            if (isNaN(calMonth)) calMonth = now.getMonth();

            var firstDay   = new Date(calYear, calMonth, 1);
            var daysInMonth = new Date(calYear, calMonth + 1, 0).getDate();
            var startDow   = firstDay.getDay();

            var prevMonth = calMonth - 1, prevYear = calYear;
            if (prevMonth < 0) { prevMonth = 11; prevYear--; }
            var nextMonth = calMonth + 1, nextYear = calYear;
            if (nextMonth > 11) { nextMonth = 0; nextYear++; }

            html += '<div class="d-flex justify-content-between align-items-center mb-2">';
            html += '<a class="btn btn-outline-secondary btn-sm" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'Calendar', calMode: 'month', calYear: prevYear, calMonth: prevMonth })) + '"><i class="bi bi-chevron-left"></i></a>';
            html += '<h5 class="mb-0">' + monthNames[calMonth] + ' ' + calYear + '</h5>';
            html += '<a class="btn btn-outline-secondary btn-sm" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'Calendar', calMode: 'month', calYear: nextYear, calMonth: nextMonth })) + '"><i class="bi bi-chevron-right"></i></a>';
            html += '</div>';

            html += '<table class="table table-bordered bm-calendar-table"><thead><tr>';
            dayAbbr.forEach(function (d) { html += '<th class="text-center small text-muted" style="width:14.28%">' + d + '</th>'; });
            html += '</tr></thead><tbody>';

            var day = 1;
            var isCurrentMonth = (calYear === now.getFullYear() && calMonth === now.getMonth());
            for (var week = 0; day <= daysInMonth; week++) {
                html += '<tr>';
                for (var dow = 0; dow < 7; dow++) {
                    if ((week === 0 && dow < startDow) || day > daysInMonth) {
                        html += '<td class="bg-light bm-cal-cell" style="min-height:80px;vertical-align:top">&nbsp;</td>';
                    } else {
                        var dateKey = fmtDate(new Date(calYear, calMonth, day));
                        var isToday = isCurrentMonth && day === now.getDate();
                        html += renderDayCell(dateKey, '', true, day, isToday, 80);
                        day++;
                    }
                }
                html += '</tr>';
            }
            html += '</tbody></table>';

        } else if (calMode === 'week') {
            // Determine the week start (Sunday) from calWeekStart or today
            var weekStartStr = query.calWeekStart;
            var weekStart;
            if (weekStartStr) {
                weekStart = new Date(weekStartStr);
                if (isNaN(weekStart.getTime())) weekStart = null;
            }
            if (!weekStart) {
                weekStart = new Date(now);
                weekStart.setDate(now.getDate() - now.getDay()); // snap to Sunday
            }
            weekStart.setHours(0, 0, 0, 0);

            var prevWeekStart = new Date(weekStart); prevWeekStart.setDate(weekStart.getDate() - 7);
            var nextWeekStart = new Date(weekStart); nextWeekStart.setDate(weekStart.getDate() + 7);
            var weekEnd   = new Date(weekStart); weekEnd.setDate(weekStart.getDate() + 6);

            var wLabel = monthNames[weekStart.getMonth()] + ' ' + weekStart.getDate() + ' – ' +
                (weekStart.getMonth() !== weekEnd.getMonth() ? monthNames[weekEnd.getMonth()] + ' ' : '') +
                weekEnd.getDate() + ', ' + weekEnd.getFullYear();

            html += '<div class="d-flex justify-content-between align-items-center mb-2">';
            html += '<a class="btn btn-outline-secondary btn-sm" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'Calendar', calMode: 'week', calWeekStart: fmtDate(prevWeekStart) })) + '"><i class="bi bi-chevron-left"></i></a>';
            html += '<h5 class="mb-0">' + wLabel + '</h5>';
            html += '<a class="btn btn-outline-secondary btn-sm" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'Calendar', calMode: 'week', calWeekStart: fmtDate(nextWeekStart) })) + '"><i class="bi bi-chevron-right"></i></a>';
            html += '</div>';

            html += '<table class="table table-bordered bm-calendar-table"><thead><tr>';
            for (var wi = 0; wi < 7; wi++) {
                var wDay = new Date(weekStart); wDay.setDate(weekStart.getDate() + wi);
                var isWToday = fmtDate(wDay) === fmtDate(now);
                html += '<th class="text-center small' + (isWToday ? ' text-primary fw-bold' : ' text-muted') + '" style="width:14.28%">' +
                    dayAbbr[wDay.getDay()] + '<br><span class="fs-6">' + wDay.getDate() + '</span></th>';
            }
            html += '</tr></thead><tbody><tr>';
            for (var wi2 = 0; wi2 < 7; wi2++) {
                var wDay2 = new Date(weekStart); wDay2.setDate(weekStart.getDate() + wi2);
                var wDateKey = fmtDate(wDay2);
                var isWDay2Today = wDateKey === fmtDate(now);
                html += renderDayCell(wDateKey, '', false, wDay2.getDate(), isWDay2Today, 160);
            }
            html += '</tr></tbody></table>';

        } else { // day
            var calDayStr = query.calDay || fmtDate(now);
            var calDayDate = new Date(calDayStr);
            if (isNaN(calDayDate.getTime())) calDayDate = new Date(now);
            calDayDate.setHours(0, 0, 0, 0);

            var prevDay = new Date(calDayDate); prevDay.setDate(calDayDate.getDate() - 1);
            var nextDay = new Date(calDayDate); nextDay.setDate(calDayDate.getDate() + 1);
            var dayDateKey = fmtDate(calDayDate);
            var isDayToday = dayDateKey === fmtDate(now);
            var createUrl = baseUrl + '/create?' + encodeURIComponent(dateField.name) + '=' + encodeURIComponent(dayDateKey);

            html += '<div class="d-flex justify-content-between align-items-center mb-2">';
            html += '<a class="btn btn-outline-secondary btn-sm" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'Calendar', calMode: 'day', calDay: fmtDate(prevDay) })) + '"><i class="bi bi-chevron-left"></i></a>';
            html += '<h5 class="mb-0' + (isDayToday ? ' text-primary' : '') + '">' + dayAbbr[calDayDate.getDay()] + ', ' + monthNames[calDayDate.getMonth()] + ' ' + calDayDate.getDate() + ', ' + calDayDate.getFullYear() + '</h5>';
            html += '<a class="btn btn-outline-secondary btn-sm" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'Calendar', calMode: 'day', calDay: fmtDate(nextDay) })) + '"><i class="bi bi-chevron-right"></i></a>';
            html += '</div>';

            var dayEvents = dateMap[dayDateKey] || [];
            html += '<div class="card bm-cal-cell' + (isDayToday ? ' border-primary' : '') + '" data-cal-date="' + escHtml(dayDateKey) + '" style="min-height:200px">';
            html += '<div class="card-body">';
            if (dayEvents.length === 0) {
                html += '<div class="text-center text-muted py-4"><i class="bi bi-calendar-x fs-2"></i><br>No events</div>';
            } else {
                dayEvents.forEach(function (it) { html += renderEventBadge(it, dayDateKey); });
            }
            html += '<div class="mt-3"><a href="' + createUrl + '" class="btn btn-outline-primary btn-sm"><i class="bi bi-plus-lg"></i> New item on this day</a></div>';
            html += '</div></div>';
        }

        // Wire drag-and-drop after HTML is injected
        setTimeout(function () {
            // dragstart — store item id, field name, and source date
            document.querySelectorAll('.bm-cal-event').forEach(function (el) {
                el.addEventListener('dragstart', function (ev) {
                    ev.dataTransfer.effectAllowed = 'move';
                    ev.dataTransfer.setData('text/plain', JSON.stringify({
                        itemId:    el.dataset.itemId,
                        dateField: el.dataset.dateField,
                        srcDate:   el.dataset.srcDate
                    }));
                    el.classList.add('opacity-50');
                });
                el.addEventListener('dragend', function () { el.classList.remove('opacity-50'); });
            });

            // dragover — allow drop on table cells
            document.querySelectorAll('.bm-cal-cell').forEach(function (cell) {
                cell.addEventListener('dragover', function (ev) {
                    ev.preventDefault();
                    ev.dataTransfer.dropEffect = 'move';
                    cell.classList.add('table-warning');
                });
                cell.addEventListener('dragleave', function () { cell.classList.remove('table-warning'); });
                cell.addEventListener('drop', function (ev) {
                    ev.preventDefault();
                    cell.classList.remove('table-warning');
                    var targetDate = cell.dataset.calDate;
                    if (!targetDate) return;
                    var payload;
                    try { payload = JSON.parse(ev.dataTransfer.getData('text/plain')); } catch (e) { return; }
                    if (!payload.itemId || payload.srcDate === targetDate) return;
                    // Patch the record's date field
                    var patch = {};
                    patch[payload.dateField] = targetDate;
                    apiPut(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(payload.itemId), patch)
                        .then(function () {
                            showToast('Moved to ' + targetDate, 'success');
                            // Refresh the calendar view
                            BMRouter.navigate(window.location.pathname + window.location.search);
                        })
                        .catch(function (err) { showToast('Move failed: ' + err.message, 'error'); });
                });
            });
        }, 0);

        return html;
    }

    // ── Workflow / Kanban Board View ─────────────────────────────────────────
    function renderWorkflowView(meta, items, slug, baseUrl, query) {
        // Find the flow field (enum) - from query.flowField or auto-detect
        var flowField = query.flowField
            ? meta.fields.find(function (f) { return f.name === query.flowField; })
            : null;
        if (!flowField) {
            flowField = meta.fields.find(function (f) {
                return f.type === 'Enum' && f.enumValues && f.enumValues.length > 0;
            });
        }
        if (!flowField || !flowField.enumValues) {
            return '<div class="bm-empty-state"><i class="bi bi-kanban"></i><p>No enum field found for Kanban view.</p><small>Add at least one Enum field to use Kanban view.</small></div>';
        }

        var labelField = meta.fields.find(function (f) { return f.list && f.type === 'Text'; }) || meta.fields[0];
        var stages = flowField.enumValues;

        // Parse WIP limits from query: wipLimit_StageName=N
        var wipLimits = {};
        Object.keys(query).forEach(function (k) {
            if (k.indexOf('wipLimit_') === 0) {
                var stageName = k.slice('wipLimit_'.length);
                var lim = parseInt(query[k], 10);
                if (!isNaN(lim) && lim > 0) wipLimits[stageName] = lim;
            }
        });

        // Parse automation hooks from query: hook_StageName=commandName
        var hooks = {};
        Object.keys(query).forEach(function (k) {
            if (k.indexOf('hook_') === 0) {
                var stageName = k.slice('hook_'.length);
                if (query[k]) hooks[stageName] = query[k];
            }
        });

        // Collect available enum fields for the flow field picker
        var enumFields = meta.fields.filter(function (f) {
            return f.type === 'Enum' && f.enumValues && f.enumValues.length > 0;
        });

        // Collect available commands for automation hook selection
        var commands = meta.commands || [];

        // Group items by stage
        var stageMap = {};
        stages.forEach(function (s) { stageMap[s] = []; });
        items.forEach(function (item) {
            var val = (nestedGet(item, flowField.name) || '').toString();
            if (!stageMap[val]) stageMap[val] = [];
            stageMap[val].push(item);
        });

        var colors = ['primary', 'info', 'warning', 'success', 'secondary', 'danger'];
        var uniqueId = 'bm-kb-' + slug;

        // Toolbar: flow field picker + WIP config + hook config
        var html = '<div class="mb-3 d-flex flex-wrap gap-2 align-items-center">';
        // Flow field selector (only shown when multiple enum fields exist)
        if (enumFields.length > 1) {
            html += '<div class="d-flex align-items-center gap-1">';
            html += '<label class="form-label mb-0 small fw-semibold">Column field:</label>';
            html += '<select class="form-select form-select-sm" style="width:auto" onchange="(function(v){var u=new URL(location.href);u.searchParams.set(\'view\',\'Workflow\');u.searchParams.set(\'flowField\',v);location.href=u.toString();})(this.value)">';
            enumFields.forEach(function (f) {
                html += '<option value="' + escHtml(f.name) + '"' + (f.name === flowField.name ? ' selected' : '') + '>' + escHtml(f.label || f.name) + '</option>';
            });
            html += '</select>';
            html += '</div>';
        }
        // WIP limits toggle button
        html += '<button type="button" class="btn btn-outline-secondary btn-sm" onclick="document.getElementById(\'bm-kb-settings-' + slug + '\').classList.toggle(\'d-none\')">';
        html += '<i class="bi bi-sliders"></i> Board settings</button>';
        html += '</div>';

        // Board settings panel (collapsed by default)
        html += '<div id="bm-kb-settings-' + slug + '" class="card mb-3 d-none">';
        html += '<div class="card-header fw-semibold"><i class="bi bi-sliders me-2"></i>Board Settings</div>';
        html += '<div class="card-body">';
        html += '<p class="small text-muted mb-2">Settings are stored in the URL and preserved per bookmark/link.</p>';
        html += '<div class="row g-3">';
        stages.forEach(function (stage, idx) {
            var color = colors[idx % colors.length];
            html += '<div class="col-md-4">';
            html += '<div class="card border-' + color + '-subtle">';
            html += '<div class="card-header bg-' + color + '-subtle text-' + color + '-emphasis small fw-semibold">' + escHtml(stage) + '</div>';
            html += '<div class="card-body p-2">';
            // WIP limit input
            html += '<div class="mb-2">';
            html += '<label class="form-label small mb-1">WIP limit <span class="text-muted">(0 = unlimited)</span></label>';
            html += '<input type="number" min="0" class="form-control form-control-sm bm-kb-wip" data-stage="' + escHtml(stage) + '" value="' + (wipLimits[stage] || 0) + '">';
            html += '</div>';
            // Automation hook select
            if (commands.length > 0) {
                html += '<div>';
                html += '<label class="form-label small mb-1">Automation hook <span class="text-muted">(run on move)</span></label>';
                html += '<select class="form-select form-select-sm bm-kb-hook" data-stage="' + escHtml(stage) + '">';
                html += '<option value="">(none)</option>';
                commands.forEach(function (cmd) {
                    var cmdName = cmd.name || cmd;
                    html += '<option value="' + escHtml(cmdName) + '"' + (hooks[stage] === cmdName ? ' selected' : '') + '>' + escHtml(cmd.label || cmdName) + '</option>';
                });
                html += '</select>';
                html += '</div>';
            }
            html += '</div></div></div>';
        });
        html += '</div>';
        html += '<div class="mt-3">';
        html += '<button type="button" class="btn btn-primary btn-sm" onclick="bmKanbanApplySettings(\'' + escHtml(slug) + '\')">';
        html += '<i class="bi bi-check-lg"></i> Apply</button>';
        html += '</div>';
        html += '</div></div>';

        // Kanban board
        html += '<div class="d-flex gap-3 overflow-auto pb-3" id="' + uniqueId + '" style="min-height:400px">';
        stages.forEach(function (stage, idx) {
            var stageItems = stageMap[stage] || [];
            var color = colors[idx % colors.length];
            var wipLimit = wipLimits[stage] || 0;
            var wipExceeded = wipLimit > 0 && stageItems.length > wipLimit;

            html += '<div class="card flex-shrink-0 bm-kb-col" data-stage="' + escHtml(stage) + '" data-slug="' + escHtml(slug) + '" data-field="' + escHtml(flowField.name) + '" style="min-width:260px;max-width:320px;flex:1">';
            html += '<div class="card-header bg-' + color + '-subtle text-' + color + '-emphasis d-flex justify-content-between align-items-center">';
            html += '<span class="fw-semibold"><i class="bi bi-kanban me-1"></i>' + escHtml(stage) + '</span>';
            html += '<span>';
            html += '<span class="badge bg-' + color + (wipExceeded ? ' border border-danger' : '') + '" title="' + stageItems.length + ' items' + (wipLimit > 0 ? ' (WIP limit: ' + wipLimit + ')' : '') + '">' + stageItems.length + (wipLimit > 0 ? '/' + wipLimit : '') + '</span>';
            if (wipExceeded) html += ' <span class="badge bg-danger" title="WIP limit exceeded!"><i class="bi bi-exclamation-triangle-fill"></i></span>';
            html += '</span>';
            html += '</div>';
            // Drop zone
            html += '<div class="card-body p-2 bm-kb-dropzone" data-stage="' + escHtml(stage) + '" style="min-height:80px;max-height:60vh;overflow-y:auto">';
            if (stageItems.length === 0) {
                html += '<div class="text-center text-muted small py-3 bm-kb-empty"><i class="bi bi-inbox"></i><br>Drop cards here</div>';
            }
            stageItems.forEach(function (item) {
                var id = item.id || item.Id || item.key || item.Key || '';
                var label = nestedGet(item, labelField.name) || '(untitled)';
                html += '<div class="card mb-2 bm-kb-card" draggable="true" data-id="' + escHtml(id) + '" data-stage="' + escHtml(stage) + '" data-label="' + escHtml(label) + '">';
                html += '<div class="card-body p-2 d-flex justify-content-between align-items-start">';
                html += '<div style="flex:1;min-width:0">';
                html += '<div class="fw-semibold small text-truncate">' + escHtml(label) + '</div>';
                // Show a secondary field if available
                var secondaryField = meta.fields.find(function (f) {
                    return f.list && f.name !== labelField.name && f.name !== flowField.name && f.type !== 'YesNo';
                });
                if (secondaryField) {
                    var secVal = nestedGet(item, secondaryField.name);
                    if (secVal) html += '<div class="text-muted small text-truncate">' + escHtml(secVal.toString()) + '</div>';
                }
                html += '</div>';
                html += '<a href="' + baseUrl + '/' + encodeURIComponent(id) + '" class="btn btn-sm btn-link p-0 ms-1 text-muted" title="Open record" onclick="event.stopPropagation()"><i class="bi bi-box-arrow-up-right"></i></a>';
                html += '</div></div>';
            });
            html += '</div></div>';
        });
        html += '</div>';

        // Inline script for drag/drop, WIP limits, automation hooks
        html += '<script>(function() {\n';
        // Store hooks config so the JS can access it
        html += 'var _bmKbHooks = ' + JSON.stringify(hooks) + ';\n';
        html += 'var _bmKbWipLimits = ' + JSON.stringify(wipLimits) + ';\n';
        html += 'function bmKbInit() {\n';
        html += '  var cards = document.querySelectorAll(".bm-kb-card");\n';
        html += '  var zones = document.querySelectorAll(".bm-kb-dropzone");\n';
        html += '  var dragSrc = null;\n';
        html += '  cards.forEach(function(card) {\n';
        html += '    card.addEventListener("dragstart", function(e) {\n';
        html += '      dragSrc = card;\n';
        html += '      card.style.opacity = "0.4";\n';
        html += '      e.dataTransfer.effectAllowed = "move";\n';
        html += '      e.dataTransfer.setData("text/plain", card.dataset.id);\n';
        html += '    });\n';
        html += '    card.addEventListener("dragend", function() {\n';
        html += '      card.style.opacity = "1";\n';
        html += '      document.querySelectorAll(".bm-kb-dropzone").forEach(function(z) { z.classList.remove("bm-kb-drag-over"); });\n';
        html += '    });\n';
        html += '  });\n';
        html += '  zones.forEach(function(zone) {\n';
        html += '    zone.addEventListener("dragover", function(e) {\n';
        html += '      e.preventDefault();\n';
        html += '      e.dataTransfer.dropEffect = "move";\n';
        html += '      zone.classList.add("bm-kb-drag-over");\n';
        html += '    });\n';
        html += '    zone.addEventListener("dragleave", function() { zone.classList.remove("bm-kb-drag-over"); });\n';
        html += '    zone.addEventListener("drop", function(e) {\n';
        html += '      e.preventDefault();\n';
        html += '      zone.classList.remove("bm-kb-drag-over");\n';
        html += '      if (!dragSrc) return;\n';
        html += '      var itemId = dragSrc.dataset.id;\n';
        html += '      var fromStage = dragSrc.dataset.stage;\n';
        html += '      var toStage = zone.dataset.stage;\n';
        html += '      if (fromStage === toStage) return;\n';
        html += '      var col = zone.closest(".bm-kb-col");\n';
        html += '      var slug2 = col ? col.dataset.slug : "";\n';
        html += '      var field = col ? col.dataset.field : "";\n';
        html += '      if (!slug2 || !field) return;\n';
        html += '      // WIP limit check\n';
        html += '      var wipLimit = _bmKbWipLimits[toStage] || 0;\n';
        html += '      var currentCount = zone.querySelectorAll(".bm-kb-card").length;\n';
        html += '      if (wipLimit > 0 && currentCount >= wipLimit) {\n';
        html += '        if (!confirm("WIP limit of " + wipLimit + " reached for column \\"" + toStage + "\\". Move anyway?")) return;\n';
        html += '      }\n';
        html += '      // Move card in DOM immediately for responsiveness\n';
        html += '      var empty = zone.querySelector(".bm-kb-empty");\n';
        html += '      if (empty) empty.remove();\n';
        html += '      dragSrc.dataset.stage = toStage;\n';
        html += '      zone.appendChild(dragSrc);\n';
        html += '      // Remove empty placeholder from source if no cards remain\n';
        html += '      var srcZone = document.querySelector(".bm-kb-dropzone[data-stage=\\"" + CSS.escape(fromStage) + "\\"]");\n';
        html += '      if (srcZone && srcZone.querySelectorAll(".bm-kb-card").length === 0) {\n';
        html += '        srcZone.innerHTML = \'<div class="text-center text-muted small py-3 bm-kb-empty"><i class="bi bi-inbox"></i><br>Drop cards here</div>\';\n';
        html += '      }\n';
        html += '      // PATCH the field value via API\n';
        html += '      var patch = {};\n';
        html += '      patch[field] = toStage;\n';
        html += '      var csrfToken = document.querySelector(\'meta[name="csrf-token"]\');\n';
        html += '      var headers = { "Content-Type": "application/json" };\n';
        html += '      if (csrfToken) headers["X-CSRF-Token"] = csrfToken.content;\n';
        html += '      fetch("/api/" + encodeURIComponent(slug2) + "/" + encodeURIComponent(itemId), {\n';
        html += '        method: "PATCH",\n';
        html += '        headers: headers,\n';
        html += '        body: JSON.stringify(patch),\n';
        html += '        credentials: "same-origin"\n';
        html += '      }).then(function(r) {\n';
        html += '        if (!r.ok) {\n';
        html += '          r.text().then(function(t) { alert("Move failed: " + t); });\n';
        html += '          return null;\n';
        html += '        }\n';
        html += '        return r.json();\n';
        html += '      }).then(function(updated) {\n';
        html += '        if (!updated) return;\n';
        html += '        // Automation hook: run command if configured for target stage\n';
        html += '        var hookCmd = _bmKbHooks[toStage];\n';
        html += '        if (hookCmd) {\n';
        html += '          var hookHeaders = { "Content-Type": "application/json" };\n';
        html += '          if (csrfToken) hookHeaders["X-CSRF-Token"] = csrfToken.content;\n';
        html += '          fetch("/api/" + encodeURIComponent(slug2) + "/" + encodeURIComponent(itemId) + "/_command/" + encodeURIComponent(hookCmd), {\n';
        html += '            method: "POST",\n';
        html += '            headers: hookHeaders,\n';
        html += '            body: JSON.stringify(updated),\n';
        html += '            credentials: "same-origin"\n';
        html += '          }).then(function(hr) {\n';
        html += '            if (!hr.ok) hr.text().then(function(t) { console.warn("Hook command failed:", t); });\n';
        html += '            else console.log("Hook \\\"" + hookCmd + "\\\" executed for item " + itemId);\n';
        html += '          }).catch(function(err) { console.warn("Hook error:", err); });\n';
        html += '        }\n';
        html += '      }).catch(function(err) { alert("Network error: " + err.message); });\n';
        html += '    });\n';
        html += '  });\n';
        html += '}\n';
        // bmKanbanApplySettings — reads WIP inputs + hook selects, rebuilds URL params, navigates
        html += 'window.bmKanbanApplySettings = function(slug3) {\n';
        html += '  var url = new URL(location.href);\n';
        html += '  // Clear old wip/hook params\n';
        html += '  var toDelete = [];\n';
        html += '  url.searchParams.forEach(function(v, k) { if (k.indexOf("wipLimit_") === 0 || k.indexOf("hook_") === 0) toDelete.push(k); });\n';
        html += '  toDelete.forEach(function(k) { url.searchParams.delete(k); });\n';
        html += '  document.querySelectorAll(".bm-kb-wip").forEach(function(inp) {\n';
        html += '    var v = parseInt(inp.value, 10);\n';
        html += '    if (v > 0) url.searchParams.set("wipLimit_" + inp.dataset.stage, v);\n';
        html += '  });\n';
        html += '  document.querySelectorAll(".bm-kb-hook").forEach(function(sel) {\n';
        html += '    if (sel.value) url.searchParams.set("hook_" + sel.dataset.stage, sel.value);\n';
        html += '  });\n';
        html += '  location.href = url.toString();\n';
        html += '};\n';
        html += 'if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", bmKbInit); } else { bmKbInit(); }\n';
        html += '}());<\/script>';

        // Drag-over highlight style (injected once)
        html += '<style>.bm-kb-dropzone.bm-kb-drag-over{background:rgba(13,110,253,.08);border:2px dashed #0d6efd;border-radius:.375rem}.bm-kb-card{cursor:grab}.bm-kb-card:active{cursor:grabbing}<\/style>';

        return html;
    }

    // ── Aggregation Browser View ────────────────────────────────────────────
    function renderAggregationView(meta, items, slug, baseUrl, query) {
        var html = '<div class="card mb-3"><div class="card-header"><i class="bi bi-bar-chart-line me-2"></i>Aggregations</div><div class="card-body">';
        html += '<div id="bm-agg-container"><div class="text-center py-3"><div class="spinner-border spinner-border-sm" role="status"></div> Loading aggregation definitions\u2026</div></div>';
        html += '</div></div>';

        // Load aggregation definitions and render drill-through
        setTimeout(function () {
            apiFetch('/api/_binary/' + encodeURIComponent(slug) + '/_aggregations')
                .then(function (defs) {
                    var container = document.getElementById('bm-agg-container');
                    if (!container) return;
                    if (!defs || defs.length === 0) {
                        container.innerHTML = '<div class="bm-empty-state"><i class="bi bi-bar-chart-line"></i><p>No aggregation definitions</p><small>Add AggregationDefinition records for this entity</small></div>';
                        return;
                    }
                    var aggHtml = '';
                    defs.forEach(function (def, idx) {
                        var levels = (def.groupByFields || '').split('|').filter(Boolean);
                        var measures = (def.measures || '').split('|').filter(Boolean);
                        aggHtml += '<div class="card mb-3"><div class="card-header fw-semibold">' + escHtml(def.name) + '</div>';
                        aggHtml += '<div class="card-body">';
                        aggHtml += '<div class="mb-2"><small class="text-muted">Levels: ' + levels.map(escHtml).join(' → ') + '</small></div>';
                        aggHtml += '<div id="bm-agg-tree-' + idx + '" class="bm-agg-tree"></div>';
                        aggHtml += '</div></div>';
                    });
                    container.innerHTML = aggHtml;

                    // Build each aggregation tree from data
                    defs.forEach(function (def, idx) {
                        var levels = (def.groupByFields || '').split('|').filter(Boolean);
                        var measures = (def.measures || '').split('|').filter(Boolean);
                        var tree = buildAggTree(items, levels, measures, meta);
                        var treeEl = document.getElementById('bm-agg-tree-' + idx);
                        if (treeEl) treeEl.innerHTML = renderAggTreeNode(tree, levels, 0, measures, slug, baseUrl);
                    });
                })
                .catch(function (err) {
                    var container = document.getElementById('bm-agg-container');
                    if (container) container.innerHTML = '<div class="text-danger">Error loading aggregations: ' + escHtml(err.message) + '</div>';
                });
        }, 50);

        return html;
    }

    function buildAggTree(items, levels, measures, meta) {
        var root = { _children: {}, _count: 0, _items: items };
        items.forEach(function (item) {
            var node = root;
            node._count++;
            levels.forEach(function (lvl) {
                var val = (nestedGet(item, lvl) || '(empty)').toString();
                if (!node._children[val]) node._children[val] = { _children: {}, _count: 0, _items: [] };
                node._children[val]._count++;
                node._children[val]._items.push(item);
                node = node._children[val];
            });
        });
        return root;
    }

    function renderAggTreeNode(node, levels, depth, measures, slug, baseUrl) {
        var html = '';
        var keys = Object.keys(node._children).sort();
        if (keys.length === 0) return html;
        html += '<table class="table table-sm table-hover mb-0">';
        html += '<thead><tr><th>' + escHtml(levels[depth] || 'Value') + '</th>';
        measures.forEach(function (m) { html += '<th class="text-end">' + escHtml(m) + '</th>'; });
        html += '<th class="text-end">Count</th></tr></thead><tbody>';
        keys.forEach(function (k) {
            var child = node._children[k];
            var hasChildren = Object.keys(child._children).length > 0;
            html += '<tr class="' + (hasChildren ? 'bm-cursor-pointer' : '') + '" data-bm-agg-expand>';
            html += '<td>';
            if (hasChildren) html += '<i class="bi bi-chevron-right me-1 bm-agg-chevron"></i>';
            html += escHtml(k) + '</td>';
            measures.forEach(function (m) {
                var parts = m.split(':');
                var fn = parts[0] || 'count';
                var field = parts[1] || '';
                var val = computeMeasure(child._items, fn, field);
                html += '<td class="text-end">' + val + '</td>';
            });
            html += '<td class="text-end"><span class="badge bg-secondary">' + child._count + '</span></td>';
            html += '</tr>';
            if (hasChildren) {
                html += '<tr class="bm-agg-detail" style="display:none"><td colspan="' + (measures.length + 2) + '" class="ps-4">';
                html += renderAggTreeNode(child, levels, depth + 1, measures, slug, baseUrl);
                html += '</td></tr>';
            }
        });
        html += '</tbody></table>';

        setTimeout(function () {
            document.querySelectorAll('[data-bm-agg-expand]').forEach(function (tr) {
                if (tr.dataset.bmAggBound) return;
                tr.dataset.bmAggBound = '1';
                tr.addEventListener('click', function () {
                    var detail = tr.nextElementSibling;
                    if (detail && detail.classList.contains('bm-agg-detail')) {
                        var visible = detail.style.display !== 'none';
                        detail.style.display = visible ? 'none' : '';
                        var chev = tr.querySelector('.bm-agg-chevron');
                        if (chev) chev.className = visible ? 'bi bi-chevron-right me-1 bm-agg-chevron' : 'bi bi-chevron-down me-1 bm-agg-chevron';
                    }
                });
            });
        }, 100);

        return html;
    }

    function computeMeasure(items, fn, field) {
        if (fn === 'count') return items.length;
        var vals = items.map(function (it) { return parseFloat(nestedGet(it, field)) || 0; });
        if (fn === 'sum') return vals.reduce(function (a, b) { return a + b; }, 0).toFixed(2);
        if (fn === 'avg') return vals.length ? (vals.reduce(function (a, b) { return a + b; }, 0) / vals.length).toFixed(2) : '0';
        if (fn === 'min') return vals.length ? Math.min.apply(null, vals).toFixed(2) : '0';
        if (fn === 'max') return vals.length ? Math.max.apply(null, vals).toFixed(2) : '0';
        return items.length;
    }

    /**
     * Render a simple horizontal-flow graph in the given container element.
     * Nodes are grouped into columns by their position in the chain.
     * Arrows between columns represent flows (record counts).
     */
    function renderSankeyGraph(graph, containerId) {
        var el = document.getElementById(containerId);
        if (!el) return;

        var nodes = graph.nodes || [];
        var links = graph.links || [];

        if (nodes.length === 0) {
            el.innerHTML = '<span class="text-muted small">No document-chain relationships detected.</span>';
            return;
        }

        // Topological ordering: build a DAG and assign column depths
        var depth = {};
        nodes.forEach(function (n) { depth[n.slug] = 0; });

        // links go from → to, so "to" is always one level deeper
        var changed = true;
        for (var iter = 0; iter < 20 && changed; iter++) {
            changed = false;
            links.forEach(function (l) {
                var d = (depth[l.from] || 0) + 1;
                if (d > (depth[l.to] || 0)) { depth[l.to] = d; changed = true; }
            });
        }

        // Group nodes by depth column
        var cols = {};
        nodes.forEach(function (n) {
            var d = depth[n.slug] || 0;
            if (!cols[d]) cols[d] = [];
            cols[d].push(n);
        });
        var colKeys = Object.keys(cols).map(Number).sort(function (a, b) { return a - b; });

        var html = '<div class="bm-sankey-flow">';
        colKeys.forEach(function (col, ci) {
            if (ci > 0) {
                // Render arrows between columns
                html += '<div class="bm-sankey-connector">';
                var colLinks = links.filter(function (l) {
                    return (depth[l.from] || 0) === col - 1 && (depth[l.to] || 0) === col;
                });
                if (colLinks.length > 0) {
                    colLinks.forEach(function (l) {
                        html += '<div class="bm-sankey-arrow" title="' + escHtml(String(l.count) + ' linked') + '">' +
                            '<span class="bm-sankey-arrow-label">' + escHtml(String(l.count)) + '</span>' +
                            '<i class="bi bi-arrow-right"></i></div>';
                    });
                } else {
                    html += '<div class="bm-sankey-arrow"><i class="bi bi-arrow-right"></i></div>';
                }
                html += '</div>';
            }

            html += '<div class="bm-sankey-col">';
            cols[col].forEach(function (n) {
                html += '<div class="bm-sankey-node">' +
                    '<div class="bm-sankey-node-name">' + escHtml(n.name) + '</div>' +
                    '<div class="bm-sankey-node-count badge bg-secondary">' + escHtml(String(n.count)) + ' records</div>' +
                    '</div>';
            });
            html += '</div>';
        });
        html += '</div>';

        el.innerHTML = html;
    }

    // ── Zero-dependency SVG Chart Renderer ──────────────────────────────────
    var CHART_COLORS = ['#4e79a7','#f28e2b','#e15759','#76b7b2','#59a14f','#edc948','#b07aa1','#ff9da7','#9c755f','#bab0ac'];

    function renderChartView(meta, items, slug, baseUrl, query) {
        var numericFields = meta.fields.filter(function (f) { return f.type === 'Integer' || f.type === 'Decimal' || f.type === 'Currency'; });
        var groupFields = meta.fields.filter(function (f) { return f.type === 'Enum' || f.type === 'Lookup' || f.type === 'String'; });
        var dateFields = meta.fields.filter(function (f) { return f.type === 'DateOnly' || f.type === 'DateTime'; });
        var labelField = meta.fields[0]; // first field as default label

        var html = '<div class="card mb-3"><div class="card-header"><i class="bi bi-graph-up me-2"></i>Charts</div><div class="card-body">';
        html += '<div class="row mb-3" id="bm-chart-controls">';
        html += '<div class="col-auto"><label class="form-label form-label-sm">Type</label><select class="form-select form-select-sm" id="bm-chart-type">';
        html += '<option value="column">Column</option><option value="stacked">Stacked Column</option><option value="line">Line</option><option value="pie">Pie</option>';
        html += '</select></div>';
        html += '<div class="col-auto"><label class="form-label form-label-sm">Group By</label><select class="form-select form-select-sm" id="bm-chart-group">';
        groupFields.concat(dateFields).forEach(function (f) { html += '<option value="' + escHtml(f.name) + '">' + escHtml(f.label || f.name) + '</option>'; });
        html += '</select></div>';
        html += '<div class="col-auto"><label class="form-label form-label-sm">Measure</label><select class="form-select form-select-sm" id="bm-chart-measure">';
        html += '<option value="count">Count</option>';
        numericFields.forEach(function (f) { html += '<option value="sum:' + escHtml(f.name) + '">Sum ' + escHtml(f.label || f.name) + '</option>'; });
        numericFields.forEach(function (f) { html += '<option value="avg:' + escHtml(f.name) + '">Avg ' + escHtml(f.label || f.name) + '</option>'; });
        html += '</select></div>';
        html += '<div class="col-auto d-flex align-items-end"><button class="btn btn-sm btn-primary" id="bm-chart-render">Render</button></div>';
        html += '</div>';
        html += '<div id="bm-chart-canvas" style="min-height:320px"></div>';
        html += '</div></div>';

        setTimeout(function () {
            var btn = document.getElementById('bm-chart-render');
            if (!btn) return;
            btn.addEventListener('click', function () {
                var chartType = document.getElementById('bm-chart-type').value;
                var groupBy = document.getElementById('bm-chart-group').value;
                var measure = document.getElementById('bm-chart-measure').value;
                var canvas = document.getElementById('bm-chart-canvas');
                if (!canvas) return;
                var groups = {};
                items.forEach(function (it) {
                    var key = (nestedGet(it, groupBy) || '(empty)').toString();
                    if (!groups[key]) groups[key] = [];
                    groups[key].push(it);
                });
                var labels = Object.keys(groups).sort();
                var values = labels.map(function (k) {
                    var parts = measure.split(':');
                    return parseFloat(computeMeasure(groups[k], parts[0], parts[1] || '')) || 0;
                });
                if (chartType === 'column') canvas.innerHTML = svgColumnChart(labels, values);
                else if (chartType === 'stacked') canvas.innerHTML = svgStackedColumnChart(labels, groups, meta, numericFields);
                else if (chartType === 'line') canvas.innerHTML = svgLineChart(labels, values);
                else if (chartType === 'pie') canvas.innerHTML = svgPieChart(labels, values);
            });
            // auto-render on load
            document.getElementById('bm-chart-render').click();
        }, 50);
        return html;
    }

    function svgColumnChart(labels, values) {
        var W = 700, H = 320, pad = 50, barGap = 4;
        var maxV = Math.max.apply(null, values) || 1;
        var barW = Math.max(8, (W - pad * 2) / labels.length - barGap);
        var svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" style="width:100%;max-width:' + W + 'px;font-family:sans-serif;font-size:11px">';
        // Y axis gridlines
        for (var g = 0; g <= 4; g++) {
            var yy = pad + (H - pad * 2) * (1 - g / 4);
            svg += '<line x1="' + pad + '" y1="' + yy + '" x2="' + (W - 10) + '" y2="' + yy + '" stroke="#e0e0e0"/>';
            svg += '<text x="' + (pad - 5) + '" y="' + (yy + 4) + '" text-anchor="end" fill="#666">' + (maxV * g / 4).toFixed(0) + '</text>';
        }
        labels.forEach(function (lbl, i) {
            var barH = (values[i] / maxV) * (H - pad * 2);
            var x = pad + i * (barW + barGap);
            var y = H - pad - barH;
            svg += '<rect x="' + x + '" y="' + y + '" width="' + barW + '" height="' + barH + '" fill="' + CHART_COLORS[i % CHART_COLORS.length] + '" rx="2">';
            svg += '<title>' + escHtml(lbl) + ': ' + values[i] + '</title></rect>';
            svg += '<text x="' + (x + barW / 2) + '" y="' + (H - pad + 14) + '" text-anchor="middle" fill="#333" style="font-size:10px">' + escHtml(lbl.length > 10 ? lbl.substring(0, 9) + '\u2026' : lbl) + '</text>';
        });
        svg += '</svg>';
        return svg;
    }

    function svgStackedColumnChart(labels, groups, meta, numericFields) {
        var W = 700, H = 320, pad = 50, barGap = 4;
        var series = numericFields.slice(0, 5);
        if (series.length === 0) return '<div class="text-muted">No numeric fields for stacked chart</div>';
        var stacks = labels.map(function (k) {
            var sums = series.map(function (f) {
                return groups[k].reduce(function (s, it) { return s + (parseFloat(nestedGet(it, f.name)) || 0); }, 0);
            });
            return { label: k, values: sums, total: sums.reduce(function (a, b) { return a + b; }, 0) };
        });
        var maxV = Math.max.apply(null, stacks.map(function (s) { return s.total; })) || 1;
        var barW = Math.max(8, (W - pad * 2) / labels.length - barGap);
        var svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" style="width:100%;max-width:' + W + 'px;font-family:sans-serif;font-size:11px">';
        for (var g = 0; g <= 4; g++) {
            var yy = pad + (H - pad * 2) * (1 - g / 4);
            svg += '<line x1="' + pad + '" y1="' + yy + '" x2="' + (W - 10) + '" y2="' + yy + '" stroke="#e0e0e0"/>';
            svg += '<text x="' + (pad - 5) + '" y="' + (yy + 4) + '" text-anchor="end" fill="#666">' + (maxV * g / 4).toFixed(0) + '</text>';
        }
        stacks.forEach(function (s, i) {
            var x = pad + i * (barW + barGap);
            var cumY = H - pad;
            s.values.forEach(function (v, si) {
                var segH = (v / maxV) * (H - pad * 2);
                cumY -= segH;
                svg += '<rect x="' + x + '" y="' + cumY + '" width="' + barW + '" height="' + segH + '" fill="' + CHART_COLORS[si % CHART_COLORS.length] + '" rx="1">';
                svg += '<title>' + escHtml(series[si].label || series[si].name) + ': ' + v.toFixed(2) + '</title></rect>';
            });
            svg += '<text x="' + (x + barW / 2) + '" y="' + (H - pad + 14) + '" text-anchor="middle" fill="#333" style="font-size:10px">' + escHtml(s.label.length > 10 ? s.label.substring(0, 9) + '\u2026' : s.label) + '</text>';
        });
        // Legend
        series.forEach(function (f, si) {
            svg += '<rect x="' + (pad + si * 100) + '" y="5" width="12" height="12" fill="' + CHART_COLORS[si % CHART_COLORS.length] + '" rx="2"/>';
            svg += '<text x="' + (pad + si * 100 + 16) + '" y="15" fill="#333" style="font-size:10px">' + escHtml(f.label || f.name) + '</text>';
        });
        svg += '</svg>';
        return svg;
    }

    function svgLineChart(labels, values) {
        var W = 700, H = 320, pad = 50;
        var maxV = Math.max.apply(null, values) || 1;
        var svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" style="width:100%;max-width:' + W + 'px;font-family:sans-serif;font-size:11px">';
        for (var g = 0; g <= 4; g++) {
            var yy = pad + (H - pad * 2) * (1 - g / 4);
            svg += '<line x1="' + pad + '" y1="' + yy + '" x2="' + (W - 10) + '" y2="' + yy + '" stroke="#e0e0e0"/>';
            svg += '<text x="' + (pad - 5) + '" y="' + (yy + 4) + '" text-anchor="end" fill="#666">' + (maxV * g / 4).toFixed(0) + '</text>';
        }
        var points = labels.map(function (lbl, i) {
            var x = pad + (i / (labels.length - 1 || 1)) * (W - pad * 2);
            var y = H - pad - (values[i] / maxV) * (H - pad * 2);
            return { x: x, y: y, label: lbl, value: values[i] };
        });
        if (points.length > 1) {
            var pathD = 'M' + points.map(function (p) { return p.x + ',' + p.y; }).join(' L');
            svg += '<path d="' + pathD + '" fill="none" stroke="' + CHART_COLORS[0] + '" stroke-width="2.5"/>';
        }
        points.forEach(function (p, i) {
            svg += '<circle cx="' + p.x + '" cy="' + p.y + '" r="4" fill="' + CHART_COLORS[0] + '"><title>' + escHtml(p.label) + ': ' + p.value + '</title></circle>';
            if (labels.length <= 20) svg += '<text x="' + p.x + '" y="' + (H - pad + 14) + '" text-anchor="middle" fill="#333" style="font-size:10px">' + escHtml(p.label.length > 8 ? p.label.substring(0, 7) + '\u2026' : p.label) + '</text>';
        });
        svg += '</svg>';
        return svg;
    }

    function svgPieChart(labels, values) {
        var W = 400, H = 320, cx = W / 2, cy = H / 2 - 10, R = 120;
        var total = values.reduce(function (a, b) { return a + b; }, 0) || 1;
        var svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" style="width:100%;max-width:' + W + 'px;font-family:sans-serif;font-size:11px">';
        var angle = -Math.PI / 2;
        labels.forEach(function (lbl, i) {
            var slice = (values[i] / total) * Math.PI * 2;
            var x1 = cx + R * Math.cos(angle);
            var y1 = cy + R * Math.sin(angle);
            var x2 = cx + R * Math.cos(angle + slice);
            var y2 = cy + R * Math.sin(angle + slice);
            var large = slice > Math.PI ? 1 : 0;
            svg += '<path d="M' + cx + ',' + cy + ' L' + x1 + ',' + y1 + ' A' + R + ',' + R + ' 0 ' + large + ',1 ' + x2 + ',' + y2 + ' Z" fill="' + CHART_COLORS[i % CHART_COLORS.length] + '" stroke="#fff" stroke-width="1.5">';
            svg += '<title>' + escHtml(lbl) + ': ' + values[i] + ' (' + (values[i] / total * 100).toFixed(1) + '%)</title></path>';
            angle += slice;
        });
        // Legend
        var ly = 10;
        labels.forEach(function (lbl, i) {
            if (i < 12) {
                svg += '<rect x="5" y="' + ly + '" width="10" height="10" fill="' + CHART_COLORS[i % CHART_COLORS.length] + '" rx="2"/>';
                svg += '<text x="20" y="' + (ly + 9) + '" fill="#333" style="font-size:10px">' + escHtml(lbl.length > 20 ? lbl.substring(0, 19) + '\u2026' : lbl) + ' (' + values[i] + ')</text>';
                ly += 16;
            }
        });
        svg += '</svg>';
        return svg;
    }

    function openImportModal(slug, baseUrl, query) {
        var id = 'import-modal-' + Date.now();
        var container = document.getElementById('vnext-modal-container');
        container.insertAdjacentHTML('beforeend',
            '<div class="modal fade" id="' + id + '" tabindex="-1" aria-modal="true" role="dialog">' +
            '<div class="modal-dialog"><div class="modal-content">' +
            '<div class="modal-header"><h5 class="modal-title"><i class="bi bi-upload me-2"></i>Import CSV</h5>' +
            '<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>' +
            '<div class="modal-body">' +
            '<p class="text-muted small">Upload a CSV file to import records. The first row must contain field names as headers.</p>' +
            '<form id="' + id + '-form" enctype="multipart/form-data">' +
            '<div class="mb-3"><label class="form-label fw-semibold">CSV File <span class="text-danger">*</span></label>' +
            '<input type="file" class="form-control" id="' + id + '-file" name="csv_file" accept=".csv,text/csv" required></div>' +
            '<div class="form-check mb-2">' +
            '<input class="form-check-input" type="checkbox" id="' + id + '-upsert" name="upsert" value="true">' +
            '<label class="form-check-label" for="' + id + '-upsert">Upsert (update existing records matched by ID)</label>' +
            '</div></form>' +
            '<div id="' + id + '-result" class="mt-2"></div>' +
            '</div>' +
            '<div class="modal-footer">' +
            '<button class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>' +
            '<button class="btn btn-primary" id="' + id + '-save"><i class="bi bi-upload"></i> Import</button>' +
            '</div></div></div></div>');

        var el = document.getElementById(id);
        var modal = new bootstrap.Modal(el);
        modal.show();

        document.getElementById(id + '-save').addEventListener('click', function () {
            var form = document.getElementById(id + '-form');
            var fileInput = document.getElementById(id + '-file');
            if (!fileInput.files.length) { showToast('Please select a CSV file.', 'error'); return; }

            var saveBtn = document.getElementById(id + '-save');
            saveBtn.disabled = true;
            saveBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Importing\u2026';

            var fd = new FormData(form);
            var resultEl = document.getElementById(id + '-result');

            fetch(API + '/' + encodeURIComponent(slug) + '/import', {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'X-CSRF-Token': getCsrfToken() },
                body: fd
            }).then(function (r) {
                return r.json().then(function (data) {
                    if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
                    return data;
                });
            }).then(function (data) {
                var cls = (data.errors && data.errors.length) ? 'alert-warning' : 'alert-success';
                var msg = '<strong>Import complete:</strong> ' + data.created + ' created, ' + data.updated + ' updated, ' + data.skipped + ' skipped.';
                if (data.errors && data.errors.length) {
                    msg += '<ul class="mt-2 mb-0 small">' + data.errors.slice(0, 10).map(function (e) { return '<li>' + escHtml(e) + '</li>'; }).join('') + '</ul>';
                }
                resultEl.innerHTML = '<div class="alert ' + cls + ' py-2">' + msg + '</div>';
                saveBtn.innerHTML = '<i class="bi bi-upload"></i> Import';
                saveBtn.disabled = false;
                clearLookupCache(slug);
                showToast('Import complete: ' + data.created + ' created, ' + data.updated + ' updated.', data.skipped ? 'warning' : 'success');
            }).catch(function (err) {
                resultEl.innerHTML = '<div class="alert alert-danger py-2">' + escHtml(err.message) + '</div>';
                saveBtn.innerHTML = '<i class="bi bi-upload"></i> Import';
                saveBtn.disabled = false;
                showToast('Import failed: ' + err.message, 'error');
            });
        });

        el.addEventListener('hidden.bs.modal', function () {
            // Reload list after modal closes if any imports happened
            el.remove();
            BMRouter.navigate(buildUrl(baseUrl, query));
        });
    }

    function wireListEvents(slug, baseUrl, query, top, sort, dir) {
        var selectAll = document.getElementById('vnext-select-all');
        if (selectAll) {
            selectAll.addEventListener('change', function () {
                document.querySelectorAll('.vnext-row-select').forEach(function (cb) { cb.checked = selectAll.checked; });
                updateBulkBar();
            });
        }
        document.querySelectorAll('.vnext-row-select').forEach(function (cb) {
            cb.addEventListener('change', updateBulkBar);
        });

        document.querySelectorAll('.vnext-row-delete').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var id = btn.dataset.id;
                showConfirm('Delete this record?', 'This action cannot be undone.', function () {
                    apiDelete(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id))
                        .then(function () { showToast('Record deleted.', 'success'); clearLookupCache(slug); BMRouter.navigate(buildUrl(baseUrl, query)); })
                        .catch(function (err) { showToast('Delete failed: ' + err.message, 'error'); });
                });
            });
        });

        // Clone button handler — loads item, strips ID/audit fields, POSTs as new
        document.querySelectorAll('.vnext-row-clone').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var id = btn.dataset.id;
                btn.disabled = true;
                apiFetch(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id))
                    .then(function (item) {
                        var clone = JSON.parse(JSON.stringify(item));
                        delete clone.id; delete clone.Id;
                        delete clone.createdOnUtc; delete clone.CreatedOnUtc;
                        delete clone.updatedOnUtc; delete clone.UpdatedOnUtc;
                        delete clone.createdBy; delete clone.CreatedBy;
                        delete clone.updatedBy; delete clone.UpdatedBy;
                        delete clone.eTag; delete clone.ETag;
                        return apiPost(API + '/' + encodeURIComponent(slug), clone);
                    })
                    .then(function (result) {
                        showToast('Record cloned.', 'success');
                        clearLookupCache(slug);
                        BMRouter.navigate(buildUrl(baseUrl, query));
                    })
                    .catch(function (err) { showToast('Clone failed: ' + err.message, 'error'); })
                    .finally(function () { btn.disabled = false; });
            });
        });

        var bulkDeleteBtn = document.getElementById('vnext-bulk-delete');
        if (bulkDeleteBtn) {
            bulkDeleteBtn.addEventListener('click', function () {
                var ids = getSelectedIds();
                if (!ids.length) return;
                showConfirm('Delete ' + ids.length + ' records?', 'This cannot be undone.', function () {
                    Promise.all(ids.map(function (id) {
                        return apiDelete(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id));
                    })).then(function () {
                        showToast('Deleted ' + ids.length + ' records.', 'success');
                        clearLookupCache(slug);
                        BMRouter.navigate(buildUrl(baseUrl, query));
                    }).catch(function (err) { showToast('Bulk delete failed: ' + err.message, 'error'); });
                });
            });
        }

        var bulkExport = document.getElementById('vnext-bulk-export-csv');
        if (bulkExport) {
            bulkExport.addEventListener('click', function () {
                var ids = getSelectedIds();
                if (!ids.length) return;
                var rows = [['id']];
                ids.forEach(function (id) { rows.push([id]); });
                downloadCsv(slug + '-export.csv', rows);
            });
        }
    }

    function getSelectedIds() {
        var result = [];
        document.querySelectorAll('.vnext-row-select:checked').forEach(function (cb) { result.push(cb.value); });
        return result;
    }

    function updateBulkBar() {
        var ids = getSelectedIds();
        var bar = document.getElementById('vnext-bulk-bar');
        if (bar) bar.classList.toggle('d-none', ids.length === 0);
    }

    function renderPagination(total, skip, top, baseUrl, query) {
        var startRecord = total === 0 ? 0 : skip + 1;
        var endRecord = Math.min(skip + top, total);
        var sizes = [10, 25, 50, 100, 1000, 10000];
        var sizeOptions = '';
        for (var si = 0; si < sizes.length; si++) {
            sizeOptions += '<option value="' + sizes[si] + '"' + (sizes[si] === top ? ' selected' : '') + '>' + sizes[si] + '</option>';
        }
        var summary = '<div class="d-flex align-items-center gap-2 small text-muted mt-2">' +
            '<span>Records ' + startRecord + ' \u2013 ' + endRecord + ' of ' + total + '</span>' +
            '<select class="form-select form-select-sm d-inline-block bm-w-auto" id="vnext-page-size">' + sizeOptions + '</select>' +
            '<span>per page</span></div>';
        if (total <= top) {
            // Still show size selector even when everything fits on one page
            return summary;
        }
        var pages = Math.ceil(total / top);
        var current = Math.floor(skip / top);
        var html = summary + '<nav class="mt-3"><ul class="pagination pagination-sm">';

        function pageLink(p, label) {
            var disabled = p < 0 || p >= pages;
            var active   = p === current;
            var href = disabled ? '#' : buildUrl(baseUrl, Object.assign({}, query, { skip: p * top, top: top }));
            return '<li class="page-item' + (disabled ? ' disabled' : '') + (active ? ' active' : '') + '">' +
                '<a class="page-link" href="' + escHtml(href) + '">' + label + '</a></li>';
        }

        html += pageLink(current - 1, '&laquo;');
        var start = Math.max(0, current - 2);
        var end   = Math.min(pages - 1, current + 2);
        if (start > 0)  html += pageLink(0, '1') + '<li class="page-item disabled"><a class="page-link">\u2026</a></li>';
        for (var p = start; p <= end; p++) html += pageLink(p, p + 1);
        if (end < pages - 1) html += '<li class="page-item disabled"><a class="page-link">\u2026</a></li>' + pageLink(pages - 1, pages);
        html += pageLink(current + 1, '&raquo;');
        html += '</ul></nav>';
        return html;
    }

    // ── Detail / View record ──────────────────────────────────────────────────
    function renderView(slug, id) {
        showLoading();
        Promise.all([fetchMeta(slug), apiFetch(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id))])
            .then(function (r) { renderViewResult(r[0], r[1], slug, id); })
            .catch(function (err) { showError(err.message); });
    }

    function renderViewResult(meta, item, slug, id) {
        var baseUrl  = BASE + '/' + encodeURIComponent(slug);
        var viewFields = meta.fields.filter(function (f) { return f.view; }).sort(function (a, b) { return a.order - b.order; });
        var commands   = meta.commands || [];

        var html = '<div class="p-3">';
        // Breadcrumb
        html += '<nav aria-label="breadcrumb"><ol class="breadcrumb">' +
            '<li class="breadcrumb-item"><a href="' + BASE + '">Home</a></li>' +
            '<li class="breadcrumb-item"><a href="' + baseUrl + '">' + escHtml(meta.name) + '</a></li>' +
            '<li class="breadcrumb-item active">' + escHtml(id) + '</li></ol></nav>';

        // Title + action bar
        html += '<div class="d-flex align-items-center mb-3 flex-wrap gap-2">';
        html += '<h2 class="mb-0 me-3">' + escHtml(meta.name) + ' — View</h2>';
        html += '<a class="btn btn-warning btn-sm" href="' + baseUrl + '/' + encodeURIComponent(id) + '/edit"><i class="bi bi-pencil"></i> Edit</a>';

        // Export buttons
        html += '<a class="btn btn-outline-secondary btn-sm" href="' + API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id) + '" target="_blank"><i class="bi bi-filetype-json"></i> JSON</a>';

        // Command buttons
        commands.forEach(function (cmd) {
            var cls = cmd.destructive ? 'btn-outline-danger' : 'btn-outline-secondary';
            html += '<button class="btn btn-sm ' + cls + ' vnext-cmd-btn" data-cmd="' + escHtml(cmd.name) + '" data-confirm="' + escHtml(cmd.confirmMessage || '') + '">' +
                (cmd.icon ? '<i class="bi ' + escHtml(cmd.icon) + ' me-1"></i>' : '') +
                escHtml(cmd.label) + '</button>';
        });
        html += '</div>';

        // Fields — grouped into cards when fieldGroup is set
        var viewGroups = [];
        var viewGroupMap = {};
        viewFields.forEach(function (f) {
            var g = f.fieldGroup || '';
            if (!viewGroupMap[g]) { viewGroupMap[g] = []; viewGroups.push(g); }
            viewGroupMap[g].push(f);
        });
        viewGroups.forEach(function (g) {
            var groupFields = viewGroupMap[g];
            html += '<div class="card bm-page-card mb-3"><div class="card-body">';
            if (g) html += '<h6 class="card-title mb-3">' + escHtml(g) + '</h6>';
            html += '<dl class="row mb-0">';
            groupFields.forEach(function (f) {
                var val = nestedGet(item, f.name);

                if (f.type === 'CustomHtml') {
                    var subItems = Array.isArray(val) ? val : [];
                    html += '<dt class="col-sm-3">' + escHtml(f.label) + '</dt>';
                    html += '<dd class="col-sm-9">' + renderSubListReadonly(subItems, f) + '</dd>';
                } else if (f.lookup && f.lookup.targetSlug && val) {
                    html += '<dt class="col-sm-3">' + escHtml(f.label) + '</dt>';
                    html += '<dd class="col-sm-9" data-lookup-field="' + escHtml(f.name) + '" data-target-slug="' + escHtml(f.lookup.targetSlug) + '" data-display-field="' + escHtml(f.lookup.displayField) + '" data-value="' + escHtml(String(val)) + '">' +
                        '<a href="' + BASE + '/' + escHtml(f.lookup.targetSlug) + '/' + encodeURIComponent(val) + '">' + escHtml(String(val)) + '</a></dd>';
                } else {
                    html += '<dt class="col-sm-3">' + escHtml(f.label) + '</dt>';
                    html += '<dd class="col-sm-9">' + fmtValue(val, f.type) + '</dd>';
                }
            });
            html += '</dl></div></div>';
        });

        // Document chain panel — shown when the entity has [RelatedDocument] fields
        var relFields = meta.documentRelationFields || [];
        if (relFields.length > 0) {
            html += '<div class="card bm-page-card mt-3" id="bm-doc-chain-card">';
            html += '<div class="card-header"><h6 class="mb-0"><i class="bi bi-diagram-3 me-2"></i>Document Chain</h6></div>';
            html += '<div class="card-body" id="bm-doc-chain-body">';
            html += '<div class="text-muted small"><i class="bi bi-hourglass-split me-1"></i>Loading related documents\u2026</div>';
            html += '</div></div>';
        }

        // Attachments panel — always shown on every record view
        html += '<div class="card bm-page-card mt-3" id="bm-attachments-card">';
        html += '<div class="card-header d-flex align-items-center justify-content-between">';
        html += '<h6 class="mb-0"><i class="bi bi-paperclip me-2"></i>Attachments</h6>';
        html += '<button class="btn btn-sm btn-outline-primary" id="bm-attach-toggle-upload"><i class="bi bi-upload me-1"></i>Upload</button>';
        html += '</div>';
        html += '<div class="card-body">';
        html += '<div id="bm-attach-upload-form" style="display:none" class="mb-3 border rounded p-3 bg-light">';
        html += '<form id="bm-attach-form" enctype="multipart/form-data">';
        html += '<div class="mb-2"><label class="form-label small fw-semibold">File</label>';
        html += '<input type="file" name="file" class="form-control form-control-sm" required id="bm-attach-file-input"></div>';
        html += '<div class="mb-2"><label class="form-label small fw-semibold">Description (optional)</label>';
        html += '<input type="text" name="description" class="form-control form-control-sm" placeholder="Description\u2026" id="bm-attach-desc-input"></div>';
        html += '<input type="hidden" name="replacesId" id="bm-attach-replaces-id" value="">';
        html += '<div class="d-flex gap-2">';
        html += '<button type="submit" class="btn btn-sm btn-primary"><i class="bi bi-upload me-1"></i>Upload</button>';
        html += '<button type="button" class="btn btn-sm btn-secondary" id="bm-attach-cancel">Cancel</button>';
        html += '</div></form></div>';
        html += '<div id="bm-attachments-body"><div class="text-muted small"><i class="bi bi-hourglass-split me-1"></i>Loading attachments\u2026</div></div>';
        html += '</div></div>';

        // Comments panel — Slack-style chat thread on every record
        html += '<div class="card bm-page-card mt-3" id="bm-comments-card">';
        html += '<div class="card-header d-flex align-items-center justify-content-between">';
        html += '<h6 class="mb-0"><i class="bi bi-chat-dots me-2"></i>Comments</h6>';
        html += '<span class="badge bg-secondary" id="bm-comments-count">0</span>';
        html += '</div>';
        html += '<div class="card-body">';
        html += '<div id="bm-comments-body"><div class="text-muted small"><i class="bi bi-hourglass-split me-1"></i>Loading comments\u2026</div></div>';
        html += '<div class="mt-3 border-top pt-3">';
        html += '<div class="d-flex gap-2">';
        html += '<input type="text" class="form-control form-control-sm" id="bm-comment-input" placeholder="Write a comment\u2026" maxlength="4000">';
        html += '<button class="btn btn-sm btn-primary" id="bm-comment-send" disabled><i class="bi bi-send"></i></button>';
        html += '</div></div>';
        html += '</div></div>';

        html += '</div>';
        setContent(html);

        // Resolve lookup display values in background
        resolveViewLookups(slug);

        // Load document chain async
        if (relFields.length > 0) {
            apiFetch(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id) + '/_related-chain')
                .then(function (chain) { renderDocumentChainPanel(chain, 'bm-doc-chain-body'); })
                .catch(function (err) {
                    var panel = document.getElementById('bm-doc-chain-body');
                    if (panel) panel.innerHTML = '<span class="text-warning small">Could not load chain: ' + escHtml(err.message) + '</span>';
                });
        }

        // Load and wire attachments panel
        loadAttachmentsPanel(slug, id);

        // Load and wire comments panel
        loadCommentsPanel(slug, id);

        // Wire command buttons
        document.querySelectorAll('.vnext-cmd-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var cmdName = btn.dataset.cmd;
                var confirm = btn.dataset.confirm;
                var doRun = function () {
                    apiPost(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id) + '/_command/' + encodeURIComponent(cmdName), item)
                        .then(function (resp) {
                            showToast((resp && resp.message) || 'Command executed.', 'success');
                            if (resp && resp.data) renderViewResult(meta, resp.data, slug, id);
                        })
                        .catch(function (err) { showToast('Command failed: ' + err.message, 'error'); });
                };
                if (confirm) showConfirm('Run command?', confirm, doRun);
                else doRun();
            });
        });
    }

    /**
     * Render the document chain panel inside the given container element.
     * Shows upstream (parent documents this record was created from) and
     * downstream (child documents that reference this record) in a visual chain.
     */
    function renderDocumentChainPanel(chain, containerId) {
        var el = document.getElementById(containerId);
        if (!el) return;

        var upstream   = chain.upstream   || [];
        var downstream = chain.downstream || [];

        if (upstream.length === 0 && downstream.length === 0) {
            el.innerHTML = '<span class="text-muted small">No related documents found.</span>';
            return;
        }

        var html = '<div class="bm-doc-chain">';

        // Upstream (parent documents)
        if (upstream.length > 0) {
            html += '<div class="bm-doc-chain-section">';
            html += '<div class="bm-doc-chain-label text-muted small fw-semibold mb-1"><i class="bi bi-arrow-up-circle me-1"></i>Source Documents</div>';
            upstream.forEach(function (doc) {
                var href = BASE + '/' + encodeURIComponent(doc.targetSlug) + '/' + encodeURIComponent(doc.id);
                html += '<div class="bm-doc-chain-node bm-doc-chain-upstream">' +
                    '<span class="badge bg-secondary me-2">' + escHtml(doc.targetName || doc.targetSlug) + '</span>' +
                    '<a href="' + href + '">' + escHtml(doc.label || doc.id) + '</a>' +
                    '</div>';
            });
            html += '</div>';
        }

        // Current node marker
        html += '<div class="bm-doc-chain-current"><i class="bi bi-circle-fill me-1"></i>' +
            '<span class="fw-semibold">' + escHtml(chain.sourceSlug) + ' #' + escHtml(chain.sourceId) + '</span></div>';

        // Downstream (child documents)
        if (downstream.length > 0) {
            html += '<div class="bm-doc-chain-section">';
            html += '<div class="bm-doc-chain-label text-muted small fw-semibold mt-2 mb-1"><i class="bi bi-arrow-down-circle me-1"></i>Derived Documents</div>';
            downstream.forEach(function (doc) {
                var href = BASE + '/' + encodeURIComponent(doc.targetSlug) + '/' + encodeURIComponent(doc.id);
                html += '<div class="bm-doc-chain-node bm-doc-chain-downstream">' +
                    '<span class="badge bg-primary me-2">' + escHtml(doc.targetName || doc.targetSlug) + '</span>' +
                    '<a href="' + href + '">' + escHtml(doc.label || doc.id) + '</a>' +
                    '</div>';
            });
            html += '</div>';
        }

        html += '</div>';
        el.innerHTML = html;
    }

    function resolveViewLookups(slug) {
        // Group elements by targetSlug so we can batch all IDs for the same entity in one request
        var groups = {};
        document.querySelectorAll('[data-lookup-field]').forEach(function (el) {
            var targetSlug  = el.dataset.targetSlug;
            var value       = el.dataset.value;
            if (!targetSlug || !value) return;
            if (!groups[targetSlug]) groups[targetSlug] = [];
            groups[targetSlug].push(el);
        });

        // Consume server-inlined lookup prefetch (one-shot: cleared after first use)
        var prefetch = window.__BMW_LOOKUP_PREFETCH__;
        if (prefetch) window.__BMW_LOOKUP_PREFETCH__ = null;

        function applyLookupResults(els, results) {
            els.forEach(function (el) {
                var value        = el.dataset.value;
                var displayField = el.dataset.displayField;
                var obj = results[value];
                if (obj) {
                    var display = nestedGet(obj, displayField) || value;
                    var href = BASE + '/' + encodeURIComponent(el.dataset.targetSlug) + '/' + encodeURIComponent(value);
                    el.innerHTML = '<a href="' + escHtml(href) + '">' + escHtml(String(display)) + '</a>';
                }
            });
        }

        Object.keys(groups).forEach(function (targetSlug) {
            var els = groups[targetSlug];
            var uniqueIds = els.map(function (el) { return el.dataset.value; })
                              .filter(function (v, i, a) { return a.indexOf(v) === i; });

            // Apply server-inlined prefetch data immediately for available IDs
            var prefetchData = prefetch && prefetch[targetSlug];
            if (prefetchData) {
                applyLookupResults(els, prefetchData);
                // Only fetch IDs that were not covered by the prefetch
                uniqueIds = uniqueIds.filter(function (id) { return !prefetchData[id]; });
                if (uniqueIds.length === 0) return; // all resolved from prefetch
            }

            apiPost(API + '/_lookup/' + encodeURIComponent(targetSlug) + '/_batch', { ids: uniqueIds })
                .then(function (resp) {
                    var results = resp && resp.results ? resp.results : {};
                    applyLookupResults(els, results);
                })
                .catch(function (err) {
                    console.warn('Batch lookup failed for ' + targetSlug + ':', err);
                    els.forEach(function (el) {
                        el.classList.add('text-warning');
                        el.title = 'Lookup resolution failed';
                    });
                });
        });
    }

    function isSubListField(val) {
        return Array.isArray(val) && val.length > 0 && typeof val[0] === 'object';
    }

    /**
     * Load the attachments panel for a record and wire up upload/delete/version-history actions.
     */
    function loadAttachmentsPanel(slug, id) {
        var attachmentsBody  = document.getElementById('bm-attachments-body');
        var toggleBtn        = document.getElementById('bm-attach-toggle-upload');
        var uploadFormWrap   = document.getElementById('bm-attach-upload-form');
        var attachForm       = document.getElementById('bm-attach-form');
        var cancelBtn        = document.getElementById('bm-attach-cancel');
        var replacesIdInput  = document.getElementById('bm-attach-replaces-id');

        function refreshList() {
            if (!attachmentsBody) return;
            attachmentsBody.innerHTML = '<div class="text-muted small"><i class="bi bi-hourglass-split me-1"></i>Loading\u2026</div>';
            apiFetch(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id) + '/_attachments')
                .then(function (items) { renderAttachmentsList(items, attachmentsBody, slug, id, replacesIdInput, uploadFormWrap); })
                .catch(function (err) {
                    if (attachmentsBody) attachmentsBody.innerHTML = '<span class="text-warning small">Could not load attachments: ' + escHtml(err.message) + '</span>';
                });
        }

        if (toggleBtn) {
            toggleBtn.addEventListener('click', function () {
                if (!uploadFormWrap) return;
                var hidden = uploadFormWrap.style.display === 'none';
                uploadFormWrap.style.display = hidden ? '' : 'none';
                if (hidden && replacesIdInput) replacesIdInput.value = '';
            });
        }
        if (cancelBtn) {
            cancelBtn.addEventListener('click', function () {
                if (uploadFormWrap) uploadFormWrap.style.display = 'none';
                if (replacesIdInput) replacesIdInput.value = '';
            });
        }

        if (attachForm) {
            attachForm.addEventListener('submit', function (e) {
                e.preventDefault();
                var fileInput = document.getElementById('bm-attach-file-input');
                var descInput = document.getElementById('bm-attach-desc-input');
                if (!fileInput || fileInput.files.length === 0) {
                    showToast('Please select a file to upload.', 'error');
                    return;
                }
                var fd = new FormData();
                fd.append('file', fileInput.files[0]);
                if (descInput && descInput.value) fd.append('description', descInput.value);
                if (replacesIdInput && replacesIdInput.value) fd.append('replacesId', replacesIdInput.value);

                var submitBtn = attachForm.querySelector('[type=submit]');
                if (submitBtn) submitBtn.disabled = true;

                fetch(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id) + '/_attachments', {
                    method: 'POST',
                    body: fd,
                    credentials: 'same-origin',
                    headers: { 'X-CSRF-Token': getCsrfToken(), 'X-Requested-With': 'BareMetalWeb' }
                })
                .then(function (resp) {
                    if (!resp.ok) return resp.text().then(function (t) { throw new Error(t || resp.statusText); });
                    return resp.json();
                })
                .then(function () {
                    showToast('File uploaded successfully.', 'success');
                    attachForm.reset();
                    if (replacesIdInput) replacesIdInput.value = '';
                    if (uploadFormWrap) uploadFormWrap.style.display = 'none';
                    refreshList();
                })
                .catch(function (err) { showToast('Upload failed: ' + err.message, 'error'); })
                .finally(function () { if (submitBtn) submitBtn.disabled = false; });
            });
        }

        refreshList();
    }

    function renderAttachmentsList(items, container, slug, id, replacesIdInput, uploadFormWrap) {
        if (!container) return;
        if (!items || items.length === 0) {
            container.innerHTML = '<span class="text-muted small">No attachments yet.</span>';
            return;
        }

        function fmtSize(bytes) {
            if (!bytes) return '0 B';
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1048576) return Math.round(bytes / 1024) + ' KB';
            return (bytes / 1048576).toFixed(1) + ' MB';
        }

        function iconForMime(ct) {
            ct = (ct || '').toLowerCase();
            if (ct.startsWith('image/')) return 'bi-file-image';
            if (ct === 'application/pdf') return 'bi-file-earmark-pdf';
            if (ct.includes('word') || ct.includes('document')) return 'bi-file-earmark-word';
            if (ct.includes('excel') || ct.includes('spreadsheet')) return 'bi-file-earmark-excel';
            if (ct.startsWith('text/')) return 'bi-file-earmark-text';
            if (ct.includes('zip') || ct.includes('archive')) return 'bi-file-earmark-zip';
            return 'bi-file-earmark';
        }

        var html = '<div class="table-responsive"><table class="table table-sm table-hover mb-0">';
        html += '<thead><tr><th>File</th><th>Size</th><th>Uploaded by</th><th>Uploaded at</th><th>Ver</th><th></th></tr></thead><tbody>';

        items.forEach(function (a) {
            var icon = iconForMime(a.contentType);
            var downloadUrl = a.downloadUrl || (API + '/_attachments/' + a.id + '/download');
            html += '<tr>';
            html += '<td><i class="bi ' + escHtml(icon) + ' me-1 text-muted"></i><a href="' + escHtml(downloadUrl) + '" target="_blank">' + escHtml(a.fileName) + '</a>';
            if (a.description) html += '<br><small class="text-muted">' + escHtml(a.description) + '</small>';
            html += '</td>';
            html += '<td class="text-nowrap text-muted small">' + fmtSize(a.sizeBytes) + '</td>';
            html += '<td class="text-muted small">' + escHtml(a.uploadedBy || '') + '</td>';
            html += '<td class="text-muted small text-nowrap">' + (a.uploadedAt ? new Date(a.uploadedAt).toLocaleString() : '') + '</td>';
            html += '<td class="text-center"><span class="badge bg-secondary">v' + (a.versionNumber || 1) + '</span></td>';
            html += '<td class="text-nowrap">';
            html += '<button class="btn btn-xs btn-outline-secondary bm-attach-versions-btn me-1" data-id="' + a.id + '" data-group="' + a.attachmentGroupId + '" title="Version history"><i class="bi bi-clock-history"></i></button>';
            html += '<button class="btn btn-xs btn-outline-primary bm-attach-newver-btn me-1" data-id="' + a.id + '" data-filename="' + escHtml(a.fileName) + '" title="Upload new version"><i class="bi bi-arrow-up-circle"></i></button>';
            html += '<button class="btn btn-xs btn-outline-danger bm-attach-del-btn" data-id="' + a.id + '" title="Delete"><i class="bi bi-trash"></i></button>';
            html += '</td></tr>';
        });

        html += '</tbody></table></div>';
        container.innerHTML = html;

        // Wire action buttons
        container.querySelectorAll('.bm-attach-del-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                showConfirm('Delete attachment?', 'Are you sure you want to delete this attachment? This cannot be undone.', function () {
                    apiFetch(API + '/_attachments/' + encodeURIComponent(btn.dataset.id), { method: 'DELETE' })
                        .then(function () {
                            showToast('Attachment deleted.', 'success');
                            apiFetch(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id) + '/_attachments')
                                .then(function (newItems) { renderAttachmentsList(newItems, container, slug, id, replacesIdInput, uploadFormWrap); })
                                .catch(function () {});
                        })
                        .catch(function (err) { showToast('Delete failed: ' + err.message, 'error'); });
                });
            });
        });

        container.querySelectorAll('.bm-attach-newver-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                if (replacesIdInput) replacesIdInput.value = btn.dataset.id;
                var descInput = document.getElementById('bm-attach-desc-input');
                if (descInput) descInput.placeholder = 'Description for new version of ' + btn.dataset.filename + '\u2026';
                if (uploadFormWrap) uploadFormWrap.style.display = '';
            });
        });

        container.querySelectorAll('.bm-attach-versions-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var versionsRow = document.getElementById('bm-attach-versions-' + btn.dataset.id);
                if (versionsRow) { versionsRow.remove(); return; }
                apiFetch(API + '/_attachments/' + encodeURIComponent(btn.dataset.id) + '/versions')
                    .then(function (versions) {
                        var tr = document.createElement('tr');
                        tr.id = 'bm-attach-versions-' + btn.dataset.id;
                        tr.className = 'bm-attach-versions-row';
                        var td = document.createElement('td');
                        td.colSpan = 6;
                        td.className = 'p-0';
                        if (!versions || versions.length === 0) {
                            td.innerHTML = '<div class="px-3 py-2 text-muted small">No version history.</div>';
                        } else {
                            var vh = '<div class="px-3 py-2"><strong class="small">Version history</strong><ul class="list-unstyled mb-0 mt-1">';
                            versions.forEach(function (v) {
                                var badge = v.isCurrentVersion ? ' <span class="badge bg-success ms-1">current</span>' : '';
                                vh += '<li class="small d-flex align-items-center gap-2 py-1 border-bottom">';
                                vh += '<span class="badge bg-secondary">v' + (v.versionNumber || 1) + '</span>';
                                vh += '<a href="' + escHtml(v.downloadUrl) + '" target="_blank">' + escHtml(v.fileName) + '</a>' + badge;
                                vh += '<span class="text-muted">' + (v.uploadedAt ? new Date(v.uploadedAt).toLocaleString() : '') + '</span>';
                                vh += '<span class="text-muted">by ' + escHtml(v.uploadedBy || '') + '</span>';
                                vh += '</li>';
                            });
                            vh += '</ul></div>';
                            td.innerHTML = vh;
                        }
                        tr.appendChild(td);
                        btn.closest('tr').insertAdjacentElement('afterend', tr);
                    })
                    .catch(function (err) { showToast('Could not load version history: ' + err.message, 'error'); });
            });
        });
    }

    /**
     * Load comments panel for a record and wire up post/edit/delete.
     */
    function loadCommentsPanel(slug, id) {
        var commentsBody = document.getElementById('bm-comments-body');
        var commentInput = document.getElementById('bm-comment-input');
        var sendBtn = document.getElementById('bm-comment-send');
        var countBadge = document.getElementById('bm-comments-count');
        if (!commentsBody || !commentInput || !sendBtn) return;

        commentInput.addEventListener('input', function () {
            sendBtn.disabled = !commentInput.value.trim();
        });
        commentInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' && !sendBtn.disabled) postComment();
        });
        sendBtn.addEventListener('click', postComment);

        function postComment() {
            var text = commentInput.value.trim();
            if (!text) return;
            sendBtn.disabled = true;
            commentInput.disabled = true;
            apiFetch(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id) + '/_comments', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text: text })
            }).then(function () {
                commentInput.value = '';
                commentInput.disabled = false;
                loadComments();
            }).catch(function (err) {
                showToast('Could not post comment: ' + err.message, 'error');
                commentInput.disabled = false;
                sendBtn.disabled = false;
            });
        }

        function loadComments() {
            apiFetch(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id) + '/_comments')
                .then(function (comments) {
                    if (countBadge) countBadge.textContent = comments.length;
                    if (!comments || comments.length === 0) {
                        commentsBody.innerHTML = '<div class="text-muted small">No comments yet. Be the first to comment!</div>';
                        return;
                    }
                    var h = '';
                    comments.forEach(function (c) {
                        var date = new Date(c.createdAt);
                        var edited = c.updatedAt && c.updatedAt !== c.createdAt;
                        var timeStr = date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
                        h += '<div class="d-flex mb-2 bm-comment" data-id="' + c.id + '">';
                        h += '<div class="flex-shrink-0 me-2">';
                        h += '<div class="rounded-circle bg-primary text-white d-flex align-items-center justify-content-center" style="width:32px;height:32px;font-size:14px">';
                        h += escHtml((c.author || '?').charAt(0).toUpperCase());
                        h += '</div></div>';
                        h += '<div class="flex-grow-1">';
                        h += '<div class="d-flex align-items-baseline gap-2">';
                        h += '<strong class="small">' + escHtml(c.author || 'Unknown') + '</strong>';
                        h += '<span class="text-muted" style="font-size:0.75rem">' + timeStr + '</span>';
                        if (edited) h += '<span class="text-muted" style="font-size:0.7rem">(edited)</span>';
                        h += '</div>';
                        h += '<div class="small bm-comment-text">' + escHtml(c.text) + '</div>';
                        h += '<div class="bm-comment-actions mt-1" style="display:none">';
                        h += '<button class="btn btn-xs btn-link text-muted p-0 me-2 bm-comment-edit-btn" data-id="' + c.id + '" data-text="' + escHtml(c.text).replace(/"/g, '&quot;') + '"><i class="bi bi-pencil"></i> Edit</button>';
                        h += '<button class="btn btn-xs btn-link text-danger p-0 bm-comment-delete-btn" data-id="' + c.id + '"><i class="bi bi-trash"></i> Delete</button>';
                        h += '</div>';
                        h += '</div></div>';
                    });
                    commentsBody.innerHTML = h;

                    // Show actions on hover
                    commentsBody.querySelectorAll('.bm-comment').forEach(function (el) {
                        var actions = el.querySelector('.bm-comment-actions');
                        el.addEventListener('mouseenter', function () { if (actions) actions.style.display = ''; });
                        el.addEventListener('mouseleave', function () { if (actions) actions.style.display = 'none'; });
                    });

                    // Wire edit buttons
                    commentsBody.querySelectorAll('.bm-comment-edit-btn').forEach(function (btn) {
                        btn.addEventListener('click', function () {
                            var newText = prompt('Edit comment:', btn.dataset.text);
                            if (newText !== null && newText.trim()) {
                                apiFetch(API + '/_comments/' + btn.dataset.id, {
                                    method: 'PATCH',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ text: newText.trim() })
                                }).then(loadComments)
                                  .catch(function (err) { showToast(err.message, 'error'); });
                            }
                        });
                    });

                    // Wire delete buttons
                    commentsBody.querySelectorAll('.bm-comment-delete-btn').forEach(function (btn) {
                        btn.addEventListener('click', function () {
                            if (confirm('Delete this comment?')) {
                                apiFetch(API + '/_comments/' + btn.dataset.id, { method: 'DELETE' })
                                    .then(loadComments)
                                    .catch(function (err) { showToast(err.message, 'error'); });
                            }
                        });
                    });
                })
                .catch(function (err) {
                    commentsBody.innerHTML = '<span class="text-warning small">Could not load comments: ' + escHtml(err.message) + '</span>';
                });
        }

        loadComments();
    }

    function renderSubListReadonly(items, field) {
        var sf = (field && Array.isArray(field.subFields) && field.subFields.length > 0) ? field.subFields : null;
        if (!items || items.length === 0) {
            if (sf) {
                var colHeaders = sf.map(function (s) { return '<th>' + escHtml(s.label) + '</th>'; }).join('');
                return '<div class="table-responsive"><table class="table table-sm table-bordered">' +
                    '<thead><tr>' + colHeaders + '</tr></thead>' +
                    '<tbody><tr><td colspan="' + sf.length + '" class="text-muted text-center">None</td></tr></tbody></table></div>';
            }
            return '<span class="text-muted">None</span>';
        }
        if (sf) {
            var html = '<div class="table-responsive"><table class="table table-sm table-bordered vnext-sublist-readonly">';
            html += '<thead><tr>' + sf.map(function (s) { return '<th>' + escHtml(s.label) + '</th>'; }).join('') + '</tr></thead>';
            html += '<tbody>';
            items.forEach(function (row) {
                html += '<tr>' + sf.map(function (s) {
                    var v = row[s.name] != null ? String(row[s.name]) : '';
                    if (s.type === 'LookupList' && s.lookup && s.lookup.targetSlug && v) {
                        return '<td data-lookup-field="' + escHtml(s.name) + '"' +
                            ' data-target-slug="' + escHtml(s.lookup.targetSlug) + '"' +
                            ' data-display-field="' + escHtml(s.lookup.displayField) + '"' +
                            ' data-value="' + escHtml(v) + '">' + escHtml(v) + '</td>';
                    }
                    if (s.type === 'YesNo') {
                        return '<td>' + (v === 'true' ? '<i class="bi bi-check-circle-fill text-success"></i>' : '<i class="bi bi-circle text-muted"></i>') + '</td>';
                    }
                    return '<td>' + escHtml(v) + '</td>';
                }).join('') + '</tr>';
            });
            html += '</tbody></table></div>';
            return html;
        }
        var keys = Object.keys(items[0]).filter(function (k) { return k !== '__type'; });
        var html = '<div class="table-responsive"><table class="table table-sm table-bordered">';
        html += '<thead><tr>' + keys.map(function (k) { return '<th>' + escHtml(k) + '</th>'; }).join('') + '</tr></thead>';
        html += '<tbody>';
        items.forEach(function (row) {
            html += '<tr>' + keys.map(function (k) { return '<td>' + escHtml(String(row[k] != null ? row[k] : '')) + '</td>'; }).join('') + '</tr>';
        });
        html += '</tbody></table></div>';
        return html;
    }

    // ── Edit / Create form ────────────────────────────────────────────────────
    function renderCreate(slug, prefill) {
        showLoading();
        fetchMeta(slug)
            .then(function (meta) { renderFormView(meta, null, slug, null, prefill || {}); })
            .catch(function (err) { showError(err.message); });
    }

    function renderEdit(slug, id) {
        showLoading();
        Promise.all([fetchMeta(slug), apiFetch(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id))])
            .then(function (r) { renderFormView(r[0], r[1], slug, id); })
            .catch(function (err) { showError(err.message); });
    }

    function renderFormView(meta, item, slug, id, prefill) {
        var isCreate = id == null;
        var prefillData = (isCreate && prefill) ? prefill : {};
        var baseUrl  = BASE + '/' + encodeURIComponent(slug);
        var formFields = meta.fields.filter(function (f) { return isCreate ? f.create : f.edit; })
                                    .sort(function (a, b) { return a.order - b.order; });
        var commands   = (!isCreate && meta.commands) ? meta.commands : [];

        var html = '<div class="p-3">';
        // Breadcrumb
        html += '<nav aria-label="breadcrumb"><ol class="breadcrumb">' +
            '<li class="breadcrumb-item"><a href="' + BASE + '">Home</a></li>' +
            '<li class="breadcrumb-item"><a href="' + baseUrl + '">' + escHtml(meta.name) + '</a></li>' +
            '<li class="breadcrumb-item active">' + (isCreate ? 'New' : 'Edit') + '</li></ol></nav>';
        html += '<h2 class="mb-3">' + escHtml(meta.name) + ' — ' + (isCreate ? 'New Record' : 'Edit') + '</h2>';

        html += '<form id="vnext-editor-form" novalidate>';
        html += '<input type="hidden" name="__csrf" value="' + escHtml(getCsrfToken()) + '">';

        var isWizard = (meta.formLayout || '').toLowerCase() === 'wizard';
        if (isWizard) {
            html += renderWizardFormFields(formFields, function (f) { return item ? nestedGet(item, f.name) : (prefillData[f.name] != null ? prefillData[f.name] : null); }, meta, item, commands, baseUrl, id, isCreate);
        } else {
            html += renderGroupedFormFields(formFields, function (f) { return item ? nestedGet(item, f.name) : (prefillData[f.name] != null ? prefillData[f.name] : null); }, meta, item);

            html += '<div class="mt-4 d-flex gap-2 flex-wrap">';
            html += '<button type="submit" class="btn btn-primary" id="vnext-save-btn"><i class="bi bi-check-lg"></i> Save</button>';
            html += '<a class="btn btn-secondary" href="' + (id ? baseUrl + '/' + encodeURIComponent(id) : baseUrl) + '"><i class="bi bi-x-lg"></i> Cancel</a>';
            // Command buttons (edit mode only)
            commands.forEach(function (cmd) {
                var cls = cmd.destructive ? 'btn-outline-danger' : 'btn-outline-secondary';
                html += '<button type="button" class="btn btn-sm ' + cls + ' vnext-cmd-btn" data-cmd="' + escHtml(cmd.name) + '" data-confirm="' + escHtml(cmd.confirmMessage || '') + '">' +
                    (cmd.icon ? '<i class="bi ' + escHtml(cmd.icon) + ' me-1"></i>' : '') +
                    escHtml(cmd.label) + '</button>';
            });
            html += '</div>';
        }
        html += '</form></div>';

        setContent(html);
        initFormBehaviours(meta, item, slug, id, isCreate, formFields);
        if (isWizard) initWizardBehaviour();

        // Wire command buttons
        document.querySelectorAll('.vnext-cmd-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var cmdName = btn.dataset.cmd;
                var confirm = btn.dataset.confirm;
                var doRun = function () {
                    apiPost(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id) + '/_command/' + encodeURIComponent(cmdName), {})
                        .then(function () {
                            showToast('Command executed.', 'success');
                            return apiFetch(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id));
                        })
                        .then(function (updated) {
                            if (updated) renderFormView(meta, updated, slug, id);
                        })
                        .catch(function (err) { showToast('Command failed: ' + err.message, 'error'); });
                };
                if (confirm) showConfirm('Run command?', confirm, doRun);
                else doRun();
            });
        });
    }

    // ── Wizard form rendering ──────────────────────────────────────────────
    // Groups fields by fieldGroup into sequential steps with step indicator
    // and prev/next/finish navigation. Falls back to single step if no groups.
    function renderWizardFormFields(fields, valueFn, meta, item, commands, baseUrl, id, isCreate) {
        var steps = [];
        var stepMap = {};
        fields.forEach(function (f) {
            var g = f.fieldGroup || 'Details';
            if (!stepMap[g]) { stepMap[g] = []; steps.push(g); }
            stepMap[g].push(f);
        });
        if (steps.length < 2) steps = ['Details'];

        var html = '';
        // Step indicator
        html += '<div class="d-flex justify-content-center mb-4">';
        steps.forEach(function (s, i) {
            html += '<div class="text-center mx-3 bm-wizard-step-indicator" data-step="' + i + '">';
            html += '<div class="rounded-circle d-inline-flex align-items-center justify-content-center border border-2 ' +
                (i === 0 ? 'border-primary text-primary' : 'border-secondary text-muted') +
                '" style="width:36px;height:36px;font-weight:600;">' + (i + 1) + '</div>';
            html += '<div class="small mt-1 ' + (i === 0 ? 'text-primary fw-semibold' : 'text-muted') + '">' + escHtml(s) + '</div>';
            html += '</div>';
        });
        html += '</div>';

        // Step panels
        steps.forEach(function (s, i) {
            var stepFields = stepMap[s] || fields;
            html += '<div class="bm-wizard-panel" data-step="' + i + '" style="' + (i > 0 ? 'display:none' : '') + '">';
            html += '<div class="card mb-3"><div class="card-header fw-semibold"><i class="bi bi-' + (i + 1) + '-circle me-2"></i>' + escHtml(s) + '</div><div class="card-body">';
            html += '<div class="row g-3">';
            stepFields.forEach(function (f) {
                var span = f.columnSpan || 12;
                html += '<div class="col-md-' + span + '">';
                html += renderFormField(f, valueFn(f), meta, item);
                html += '</div>';
            });
            html += '</div></div></div></div>';
        });

        // Navigation buttons
        html += '<div class="mt-4 d-flex gap-2 flex-wrap">';
        html += '<a class="btn btn-secondary" href="' + (id ? baseUrl + '/' + encodeURIComponent(id) : baseUrl) + '"><i class="bi bi-x-lg"></i> Cancel</a>';
        html += '<button type="button" class="btn btn-outline-primary bm-wizard-prev" style="display:none"><i class="bi bi-chevron-left"></i> Previous</button>';
        html += '<button type="button" class="btn btn-primary bm-wizard-next"><i class="bi bi-chevron-right"></i> Next</button>';
        html += '<button type="submit" class="btn btn-success bm-wizard-finish" style="display:none" id="vnext-save-btn"><i class="bi bi-check-lg"></i> Finish</button>';
        commands.forEach(function (cmd) {
            var cls = cmd.destructive ? 'btn-outline-danger' : 'btn-outline-secondary';
            html += '<button type="button" class="btn btn-sm ' + cls + ' vnext-cmd-btn" data-cmd="' + escHtml(cmd.name) + '" data-confirm="' + escHtml(cmd.confirmMessage || '') + '">' +
                (cmd.icon ? '<i class="bi ' + escHtml(cmd.icon) + ' me-1"></i>' : '') +
                escHtml(cmd.label) + '</button>';
        });
        html += '</div>';
        return html;
    }

    function initWizardBehaviour() {
        var panels = document.querySelectorAll('.bm-wizard-panel');
        var indicators = document.querySelectorAll('.bm-wizard-step-indicator');
        var prevBtn = document.querySelector('.bm-wizard-prev');
        var nextBtn = document.querySelector('.bm-wizard-next');
        var finishBtn = document.querySelector('.bm-wizard-finish');
        if (!panels.length || !nextBtn) return;
        var current = 0;
        var total = panels.length;

        function showStep(idx) {
            panels.forEach(function (p, i) { p.style.display = i === idx ? '' : 'none'; });
            indicators.forEach(function (ind, i) {
                var circle = ind.querySelector('.rounded-circle');
                var label = ind.querySelector('.small');
                if (i < idx) {
                    circle.className = 'rounded-circle d-inline-flex align-items-center justify-content-center border border-2 border-success text-success';
                    label.className = 'small mt-1 text-success';
                } else if (i === idx) {
                    circle.className = 'rounded-circle d-inline-flex align-items-center justify-content-center border border-2 border-primary text-primary';
                    label.className = 'small mt-1 text-primary fw-semibold';
                } else {
                    circle.className = 'rounded-circle d-inline-flex align-items-center justify-content-center border border-2 border-secondary text-muted';
                    label.className = 'small mt-1 text-muted';
                }
            });
            prevBtn.style.display = idx > 0 ? '' : 'none';
            nextBtn.style.display = idx < total - 1 ? '' : 'none';
            finishBtn.style.display = idx === total - 1 ? '' : 'none';
            current = idx;
        }

        prevBtn.addEventListener('click', function () { if (current > 0) showStep(current - 1); });
        nextBtn.addEventListener('click', function () {
            // Validate current step fields before advancing
            var panel = panels[current];
            var inputs = panel.querySelectorAll('input,select,textarea');
            var valid = true;
            inputs.forEach(function (inp) { if (!inp.checkValidity()) { inp.reportValidity(); valid = false; } });
            if (valid && current < total - 1) showStep(current + 1);
        });
    }

    // ── Multi-column grouped form rendering ─────────────────────────────────
    // Groups fields by fieldGroup, renders each group in a card with a row grid.
    // Fields use col-md-{columnSpan} (default 12 = full width).
    function renderGroupedFormFields(fields, valueFn, meta, item) {
        var groups = [];
        var groupMap = {};
        fields.forEach(function (f) {
            var g = f.fieldGroup || '';
            if (!groupMap[g]) { groupMap[g] = []; groups.push(g); }
            groupMap[g].push(f);
        });
        var html = '';
        groups.forEach(function (g) {
            var items = groupMap[g];
            if (g) {
                html += '<div class="card mb-3"><div class="card-header fw-semibold">' + escHtml(g) + '</div><div class="card-body"><div class="row g-3">';
            } else {
                html += '<div class="row g-3">';
            }
            items.forEach(function (f) {
                var span = f.columnSpan || 12;
                html += '<div class="col-md-' + span + '">';
                html += renderFormField(f, valueFn(f), meta, item);
                html += '</div>';
            });
            html += g ? '</div></div></div>' : '</div>';
        });
        return html;
    }

    function renderFormField(f, val, meta, item) {
        var id_ = 'f_' + escHtml(f.name);
        var req  = f.required ? ' required' : '';
        var rdonly = (f.readOnly || f.isIdField || f.computed || f.calculated) ? ' readonly' : '';
        var placeholder = f.placeholder ? ' placeholder="' + escHtml(f.placeholder) + '"' : '';

        var label = '<label for="' + id_ + '" class="form-label">' + escHtml(f.label) +
            (f.required ? ' <span class="text-danger">*</span>' : '') + '</label>';
        var feedback = '<div class="invalid-feedback"></div>';

        // Computed / calculated fields
        if (f.computed || f.calculated) {
            return '<div class="mb-3">' + label +
                '<input type="text" class="form-control form-control-sm bg-light" id="' + id_ + '" name="' + escHtml(f.name) + '" value="' + escHtml(String(val != null ? val : '')) + '" readonly' +
                ' data-calculated="' + (f.calculated ? escHtml(f.calculated.expression) : '') + '">' +
                '<div class="form-text text-muted"><i class="bi bi-calculator"></i> ' + (f.computed ? 'Computed (' + escHtml(f.computed.strategy) + ')' : 'Calculated') + '</div>' +
                '</div>';
        }

        // ID field (readonly in edit, hidden in create)
        if (f.isIdField) {
            return '<div class="mb-3">' + label +
                '<input type="text" class="form-control form-control-sm bg-light" id="' + id_ + '" name="' + escHtml(f.name) + '" value="' + escHtml(String(val != null ? val : '(auto)')) + '" readonly>' +
                '</div>';
        }

        if (f.type === 'Hidden') {
            return '<input type="hidden" name="' + escHtml(f.name) + '" value="' + escHtml(String(val != null ? val : '')) + '">';
        }

        var validation = '';
        if (f.validation) {
            if (f.validation.minLength != null) validation += ' minlength="' + f.validation.minLength + '"';
            if (f.validation.maxLength != null) validation += ' maxlength="' + f.validation.maxLength + '"';
            if (f.validation.rangeMin  != null) validation += ' min="' + f.validation.rangeMin + '"';
            if (f.validation.rangeMax  != null) validation += ' max="' + f.validation.rangeMax + '"';
            if (f.validation.pattern)           validation += ' pattern="' + escHtml(f.validation.pattern) + '"';
        }

        // Lookup list field
        if (f.type === 'LookupList' && f.lookup && f.lookup.targetSlug) {
            return '<div class="mb-3" data-lookup-container="' + escHtml(f.name) + '">' + label +
                '<div class="input-group input-group-sm">' +
                '<select class="form-select" id="' + id_ + '" name="' + escHtml(f.name) + '"' + req + '>' +
                '<option value="">Loading\u2026</option></select>' +
                '<button type="button" class="btn btn-outline-secondary vnext-lookup-add" data-target-slug="' + escHtml(f.lookup.targetSlug) + '" title="Add new"><i class="bi bi-plus"></i></button>' +
                '<button type="button" class="btn btn-outline-secondary vnext-lookup-refresh" data-field="' + escHtml(f.name) + '" data-target-slug="' + escHtml(f.lookup.targetSlug) + '" title="Refresh"><i class="bi bi-arrow-clockwise"></i></button>' +
                '</div>' + feedback + '</div>';
        }

        // Enum field
        if (f.type === 'Enum') {
            return '<div class="mb-3">' + label +
                '<select class="form-select form-select-sm" id="' + id_ + '" name="' + escHtml(f.name) + '"' + req + '>' +
                '<option value="">— Select —</option>' +
                '</select>' + feedback + '</div>';
        }

        // YesNo / Boolean
        if (f.type === 'YesNo') {
            var checked = (val === true || val === 'true' || val === 1) ? ' checked' : '';
            return '<div class="mb-3 form-check">' +
                '<input type="checkbox" class="form-check-input" id="' + id_ + '" name="' + escHtml(f.name) + '" value="true"' + checked + '>' +
                '<label class="form-check-label" for="' + id_ + '">' + escHtml(f.label) + '</label></div>';
        }

        // TextArea
        if (f.type === 'TextArea') {
            var taVal = Array.isArray(val) ? val.join('\n') : (val != null ? String(val) : '');
            return '<div class="mb-3">' + label +
                '<textarea class="form-control form-control-sm" id="' + id_ + '" name="' + escHtml(f.name) + '" rows="4"' + req + rdonly + placeholder + validation + '>' +
                escHtml(taVal) + '</textarea>' + feedback + '</div>';
        }

        // Markdown editor with live preview
        if (f.type === 'Markdown') {
            var mdVal = val != null ? String(val) : '';
            return '<div class="mb-3">' + label +
                '<textarea class="form-control form-control-sm bm-md-editor" id="' + id_ + '" name="' + escHtml(f.name) + '" rows="8"' + req + rdonly + placeholder + validation + '>' +
                escHtml(mdVal) + '</textarea>' +
                '<div class="card mt-2"><div class="card-header py-1 small text-muted">Preview</div>' +
                '<div class="card-body bm-md-preview" id="' + id_ + '_preview">' + renderMarkdownToHtml(mdVal) + '</div></div>' +
                feedback + '</div>';
        }

        // Tags (pill-based input)
        if (f.type === 'Tags') {
            var tags = Array.isArray(val) ? val : (val ? String(val).split(',').map(function(s){return s.trim();}).filter(Boolean) : []);
            var pills = tags.map(function (t) {
                return '<span class="badge bg-info text-dark me-1 vnext-tag-pill">' + escHtml(t) +
                    ' <button type="button" class="btn-close btn-close-sm ms-1 bm-tag-close" aria-label="Remove"></button></span>';
            }).join('');
            return '<div class="mb-3">' + label +
                '<div class="vnext-tag-container form-control form-control-sm d-flex flex-wrap align-items-center gap-1" data-field="' + escHtml(f.name) + '">' +
                pills +
                '<input type="text" class="vnext-tag-input border-0 flex-grow-1" placeholder="Type and press Enter">' +
                '</div>' +
                '<input type="hidden" name="' + escHtml(f.name) + '" id="' + id_ + '" value="' + escHtml(JSON.stringify(tags)) + '">' +
                feedback + '</div>';
        }

        // Password
        if (f.type === 'Password') {
            return '<div class="mb-3">' + label +
                '<input type="password" class="form-control form-control-sm" id="' + id_ + '" name="' + escHtml(f.name) + '" autocomplete="new-password"' + req + placeholder + validation + '>' +
                feedback + '</div>';
        }

        // DateTime / DateOnly / TimeOnly
        var inputType = 'text';
        var inputVal  = val != null ? String(val) : '';
        if (f.type === 'DateTime')  { inputType = 'datetime-local'; inputVal = toDateTimeLocalStr(val); }
        if (f.type === 'DateOnly')  { inputType = 'date'; inputVal = toDateStr(val); }
        if (f.type === 'TimeOnly')  { inputType = 'time'; inputVal = toTimeStr(val); }
        if (f.type === 'Email')     { inputType = 'email'; }
        if (f.type === 'Integer')   { inputType = 'number'; if (!validation) validation += ' step="1"'; }
        if (f.type === 'Decimal' || f.type === 'Money') { inputType = 'number'; validation += ' step="0.01"'; }
        if (f.type === 'ReadOnly')  { rdonly = ' readonly'; }

        // Image / File
        if (f.type === 'Image' || f.type === 'File') {
            var accept = f.upload ? f.upload.allowedMimeTypes.join(',') : (f.type === 'Image' ? 'image/*' : '');
            return '<div class="mb-3">' + label +
                '<input type="file" class="form-control form-control-sm" id="' + id_ + '" name="' + escHtml(f.name) + '"' + (accept ? ' accept="' + escHtml(accept) + '"' : '') + req + '>' +
                (val ? '<div class="form-text">Current: ' + escHtml(typeof val === 'object' ? val.fileName || '' : String(val)) + '</div>' : '') +
                feedback + '</div>';
        }

        // Country dropdown
        if (f.type === 'Country') {
            return '<div class="mb-3">' + label +
                '<select class="form-select form-select-sm" id="' + id_ + '" name="' + escHtml(f.name) + '"' + req + '>' +
                renderCountryOptions(val) +
                '</select>' + feedback + '</div>';
        }

        // Money (value + currency side by side)
        if (f.type === 'Money') {
            var moneyObj = val && typeof val === 'object' ? val : { amount: val, currency: 'USD' };
            return '<div class="mb-3">' + label +
                '<div class="input-group input-group-sm">' +
                '<input type="number" class="form-control" id="' + id_ + '" name="' + escHtml(f.name) + '_amount" step="0.01" value="' + escHtml(String(moneyObj.amount || '')) + '"' + req + validation + '>' +
                '<input type="text" class="form-control bm-currency-input" name="' + escHtml(f.name) + '_currency" placeholder="USD" value="' + escHtml(String(moneyObj.currency || 'USD')) + '" maxlength="3">' +
                '</div>' + feedback + '</div>';
        }

        // Sub-list (List<T> child collection)
        if (f.type === 'CustomHtml') {
            var subItems = Array.isArray(val) ? val : [];
            if (f.subFields && Array.isArray(f.subFields) && f.subFields.length > 0) {
                return renderSubListEditor(f, subItems);
            }
            return '';
        }

        // Default: text input
        return '<div class="mb-3">' + label +
            '<input type="' + inputType + '" class="form-control form-control-sm" id="' + id_ + '" name="' + escHtml(f.name) + '"' +
            ' value="' + escHtml(inputVal) + '"' + req + rdonly + placeholder + validation + '>' +
            feedback + '</div>';
    }

    // ── Sub-list (child List<T>) editor ───────────────────────────────────────
    function renderSubListEditor(field, items) {
        var sf   = field.subFields || [];
        var tblId  = 'sub_tbl_' + field.name;
        var jsonId = 'sub_json_' + field.name;

        var colHeaders = sf.map(function (s) { return '<th>' + escHtml(s.label) + '</th>'; }).join('');
        var rowsHtml   = items.map(function (row, idx) { return buildSubListTableRow(idx, row, field, sf); }).join('');

        var html = '<div class="mb-3 vnext-sublist-container" data-field="' + escHtml(field.name) + '">';
        html += '<input type="hidden" id="' + escHtml(jsonId) + '" name="' + escHtml(field.name) + '" value="' + escHtml(JSON.stringify(items)) + '">';
        html += '<div class="d-flex align-items-center justify-content-between mb-2">';
        html += '<label class="form-label mb-0">' + escHtml(field.label) + '</label>';
        html += '<button type="button" class="btn btn-sm btn-outline-success vnext-sublist-add" data-field="' + escHtml(field.name) + '">';
        html += '<i class="bi bi-plus-lg"></i> Add</button>';
        html += '</div>';
        html += '<div class="table-responsive"><table class="table table-sm table-striped align-middle mb-0" id="' + escHtml(tblId) + '">';
        html += '<thead><tr><th>Actions</th>' + colHeaders + '</tr></thead>';
        html += '<tbody>' + rowsHtml + '</tbody></table></div>';
        html += '</div>';
        return html;
    }

    function buildSubListTableRow(idx, row, field, subFields) {
        var html = '<tr data-sub-idx="' + idx + '">';
        html += '<td class="text-nowrap">';
        html += '<button type="button" class="btn btn-sm btn-outline-info me-1 vnext-sublist-edit"' +
            ' data-field="' + escHtml(field.name) + '" data-idx="' + idx + '" title="Edit"><i class="bi bi-pencil"></i></button>';
        html += '<button type="button" class="btn btn-sm btn-outline-danger vnext-sublist-del"' +
            ' data-field="' + escHtml(field.name) + '" data-idx="' + idx + '" title="Delete"><i class="bi bi-x-lg"></i></button>';
        html += '</td>';
        subFields.forEach(function (sf) {
            var val = row[sf.name] != null ? String(row[sf.name]) : '';
            if (sf.type === 'LookupList' && sf.lookup && sf.lookup.targetSlug && val) {
                html += '<td data-lookup-field="' + escHtml(sf.name) + '"' +
                    ' data-target-slug="' + escHtml(sf.lookup.targetSlug) + '"' +
                    ' data-display-field="' + escHtml(sf.lookup.displayField) + '"' +
                    ' data-value="' + escHtml(val) + '">' + escHtml(val) + '</td>';
            } else if (sf.type === 'YesNo') {
                html += '<td>' + (val === 'true' ? '<i class="bi bi-check-circle-fill text-success"></i>' : '<i class="bi bi-circle text-muted"></i>') + '</td>';
            } else {
                html += '<td>' + escHtml(val) + '</td>';
            }
        });
        html += '</tr>';
        return html;
    }

    function refreshSubListTable(field, rows) {
        var tbody = document.querySelector('#sub_tbl_' + field.name + ' tbody');
        if (!tbody) return;
        var sf = field.subFields || [];
        tbody.innerHTML = rows.map(function (row, idx) { return buildSubListTableRow(idx, row, field, sf); }).join('');
        resolveSubListLookups(field.name);
    }

    function resolveSubListLookups(fieldName) {
        // Group elements by targetSlug for batched lookup requests
        var groups = {};
        document.querySelectorAll('#sub_tbl_' + fieldName + ' [data-lookup-field]').forEach(function (el) {
            var targetSlug  = el.dataset.targetSlug;
            var value       = el.dataset.value;
            if (!targetSlug || !value) return;
            if (!groups[targetSlug]) groups[targetSlug] = [];
            groups[targetSlug].push(el);
        });

        Object.keys(groups).forEach(function (targetSlug) {
            var els = groups[targetSlug];
            var uniqueIds = els.map(function (el) { return el.dataset.value; })
                              .filter(function (v, i, a) { return a.indexOf(v) === i; });
            apiPost(API + '/_lookup/' + encodeURIComponent(targetSlug) + '/_batch', { ids: uniqueIds })
                .then(function (resp) {
                    var results = resp && resp.results ? resp.results : {};
                    els.forEach(function (el) {
                        var value       = el.dataset.value;
                        var displayField = el.dataset.displayField;
                        var obj = results[value];
                        if (obj) {
                            var display = nestedGet(obj, displayField) || value;
                            el.textContent = String(display);
                        }
                    });
                }).catch(function (err) { console.warn('Sub-list lookup failed for ' + targetSlug + ':', err); });
        });
    }

    function renderSubListFormField(sf, val) {
        var id_  = 'sf_' + escHtml(sf.name);
        var req  = sf.required ? ' required' : '';
        var label = '<label for="' + id_ + '" class="form-label">' + escHtml(sf.label) +
            (sf.required ? ' <span class="text-danger">*</span>' : '') + '</label>';

        if (sf.calculated) {
            return '<div class="mb-3">' + label +
                '<div class="input-group input-group-sm">' +
                '<input class="form-control" type="text" id="' + id_ + '" data-field="' + escHtml(sf.name) + '" readonly data-calculated="true"' +
                ' data-expression="' + escHtml(sf.calculated.expression) + '" value="' + escHtml(String(val != null ? val : '')) + '">' +
                '<span class="input-group-text" title="Calculated"><i class="bi bi-calculator-fill"></i></span></div></div>';
        }

        if (sf.type === 'LookupList' && sf.lookup && sf.lookup.targetSlug) {
            var copyAttrs = (sf.lookupCopyFields && sf.lookupTargetSlug) ?
                (' data-copy-entity="' + escHtml(sf.lookupTargetSlug) + '" data-copy-fields="' + escHtml(sf.lookupCopyFields) + '"') : '';
            return '<div class="mb-3" data-sublookup-container="' + escHtml(sf.name) + '">' + label +
                '<div class="input-group input-group-sm">' +
                '<select class="form-select" id="' + id_ + '" data-field="' + escHtml(sf.name) + '"' + req + copyAttrs + '>' +
                '<option value="">Loading\u2026</option></select>' +
                '<button type="button" class="btn btn-outline-secondary vnext-sublookup-refresh"' +
                ' data-field="' + escHtml(sf.name) + '" data-target-slug="' + escHtml(sf.lookup.targetSlug) + '" title="Refresh"><i class="bi bi-arrow-clockwise"></i></button>' +
                '</div></div>';
        }

        if (sf.type === 'Enum') {
            return '<div class="mb-3">' + label +
                '<select class="form-select form-select-sm" id="' + id_ + '" data-field="' + escHtml(sf.name) + '"' + req + '>' +
                '<option value="">— Select —</option></select></div>';
        }

        if (sf.type === 'YesNo') {
            var checked = (val === true || val === 'true' || val === 1) ? ' checked' : '';
            return '<div class="mb-3 form-check">' +
                '<input type="checkbox" class="form-check-input" id="' + id_ + '" data-field="' + escHtml(sf.name) + '" value="true"' + checked + '>' +
                '<label class="form-check-label" for="' + id_ + '">' + escHtml(sf.label) + '</label></div>';
        }

        if (sf.type === 'TextArea') {
            return '<div class="mb-3">' + label +
                '<textarea class="form-control form-control-sm" id="' + id_ + '" data-field="' + escHtml(sf.name) + '" rows="3"' + req + '>' +
                escHtml(String(val != null ? val : '')) + '</textarea></div>';
        }

        var inputType = 'text';
        var inputVal  = val != null ? String(val) : '';
        if (sf.type === 'DateTime')     { inputType = 'datetime-local'; inputVal = toDateTimeLocalStr(val); }
        if (sf.type === 'DateOnly')     { inputType = 'date'; inputVal = toDateStr(val); }
        if (sf.type === 'TimeOnly')     { inputType = 'time'; inputVal = toTimeStr(val); }
        if (sf.type === 'Email')        inputType = 'email';
        if (sf.type === 'Integer')      inputType = 'number';
        if (sf.type === 'Decimal' || sf.type === 'Money') inputType = 'number';

        return '<div class="mb-3">' + label +
            '<input type="' + inputType + '" class="form-control form-control-sm" id="' + id_ + '"' +
            ' data-field="' + escHtml(sf.name) + '" value="' + escHtml(inputVal) + '"' + req + '></div>';
    }

    function recalcSubListModal(form, subFields) {
        subFields.forEach(function (sf) {
            if (!sf.calculated) return;
            var el = form.querySelector('[data-field="' + sf.name + '"]');
            if (!el) return;
            try {
                var vals = {};
                form.querySelectorAll('[data-field]').forEach(function (f) {
                    var n = f.getAttribute('data-field');
                    if (f.type === 'checkbox') vals[n] = f.checked ? 1 : 0;
                    else vals[n] = parseFloat(f.value) || 0;
                });
                var result = bmwEvalAst(sf.calculated.expression, function (n) { return parseFloat(vals[n]) || 0; });
                el.value = (typeof result === 'number' && !isNaN(result)) ? parseFloat(result).toFixed(2) : '';
            } catch (ex) {}
        });
    }

    function loadSubListLookupSelect(sf, currentValue, form) {
        if (!form) return;
        var sel = form.querySelector('select[data-field="' + sf.name + '"]');
        if (!sel) return;
        var lk = sf.lookup;
        fetchLookupOptions(lk.targetSlug, lk.queryField, lk.queryValue, lk.sortField, lk.sortDirection, lk.queryOperator)
            .then(function (items) {
                sel.innerHTML = '<option value="">— Select —</option>';
                items.forEach(function (opt) {
                    var optVal = nestedGet(opt, lk.valueField) || '';
                    var optLbl = nestedGet(opt, lk.displayField) || optVal;
                    var selected = String(optVal) === String(currentValue) ? ' selected' : '';
                    sel.insertAdjacentHTML('beforeend', '<option value="' + escHtml(String(optVal)) + '"' + selected + '>' + escHtml(String(optLbl)) + '</option>');
                });
                if (currentValue && !Array.from(sel.options).find(function (o) { return o.value === String(currentValue); })) {
                    sel.insertAdjacentHTML('afterbegin', '<option value="' + escHtml(String(currentValue)) + '" selected>' + escHtml(String(currentValue)) + '</option>');
                }
            }).catch(function () { sel.innerHTML = '<option value="">— ' + escHtml(sf.label) + ' load failed —</option>'; });
    }

    function loadSubListEnumOptions(sf, currentValue, form) {
        if (!form) return;
        var sel = form.querySelector('select[data-field="' + sf.name + '"]');
        if (!sel) return;
        var options = Array.isArray(sf.enumValues) ? sf.enumValues : [];
        var html = '<option value="">— Select —</option>';
        options.forEach(function (o) {
            var val = o.value != null ? o.value : o;
            var lbl = o.label != null ? o.label : String(val);
            var selected = currentValue != null && String(currentValue) === String(val) ? ' selected' : '';
            html += '<option value="' + escHtml(String(val)) + '"' + selected + '>' + escHtml(String(lbl)) + '</option>';
        });
        sel.innerHTML = html;
    }

    function openSubListRowModal(field, editEntry, parentItem) {
        var isNew   = editEntry == null;
        var rowIdx  = isNew ? -1 : editEntry.idx;
        var rowData = isNew ? {} : (editEntry.row || {});
        var sf      = field.subFields || [];
        var modalId = 'vnext-slmodal-' + field.name + '-' + Date.now();
        var formId  = 'vnext-slform-' + field.name;

        var formHtml = '<form id="' + escHtml(formId) + '" novalidate>';
        sf.forEach(function (subField) {
            var val = rowData[subField.name] != null ? rowData[subField.name] : null;
            formHtml += renderSubListFormField(subField, val);
        });
        formHtml += '</form>';

        var container = document.getElementById('vnext-modal-container');
        container.insertAdjacentHTML('beforeend',
            '<div class="modal fade" id="' + modalId + '" tabindex="-1" aria-modal="true" role="dialog">' +
            '<div class="modal-dialog modal-lg modal-dialog-scrollable"><div class="modal-content">' +
            '<div class="modal-header"><h5 class="modal-title">' + (isNew ? 'Add' : 'Edit') + ' Row</h5>' +
            '<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>' +
            '<div class="modal-body">' + formHtml + '</div>' +
            '<div class="modal-footer">' +
            '<button class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>' +
            '<button class="btn btn-primary" id="' + modalId + '-save">Save</button>' +
            '</div></div></div></div>');

        var el    = document.getElementById(modalId);
        var modal = new bootstrap.Modal(el);
        var form  = document.getElementById(formId);

        // Load lookups and enum options for modal fields
        sf.forEach(function (subField) {
            var curVal = rowData[subField.name] != null ? String(rowData[subField.name]) : null;
            if (subField.type === 'LookupList' && subField.lookup && subField.lookup.targetSlug) {
                loadSubListLookupSelect(subField, curVal, form);
            }
            if (subField.type === 'Enum') {
                loadSubListEnumOptions(subField, curVal, form);
            }
        });

        if (form) {
            recalcSubListModal(form, sf);

            form.addEventListener('input', function (ev) {
                if (ev.target.getAttribute('data-calculated') === 'true') return;
                recalcSubListModal(form, sf);
            });
            form.addEventListener('change', function (ev) {
                var t = ev.target;
                if (t.getAttribute('data-calculated') === 'true') return;
                var copyEntity = t.getAttribute('data-copy-entity');
                var copyFields = t.getAttribute('data-copy-fields');
                if (copyEntity && copyFields && t.value) {
                    apiFetch(API + '/_lookup/' + encodeURIComponent(copyEntity) + '/' + encodeURIComponent(t.value))
                        .then(function (ent) {
                            copyFields.split(',').forEach(function (pair) {
                                var parts = pair.split('->');
                                if (parts.length !== 2) return;
                                var src = parts[0].trim(), dst = parts[1].trim();
                                var df = form.querySelector('[data-field="' + dst + '"]');
                                if (df && df.getAttribute('data-calculated') !== 'true') {
                                    df.value = ent[src] !== undefined ? String(ent[src]) : '';
                                    df.dispatchEvent(new Event('input', {bubbles: true}));
                                }
                            });
                            recalcSubListModal(form, sf);
                        }).catch(function () {});
                }
                recalcSubListModal(form, sf);
            });

            // Lookup refresh buttons inside the sub-list modal
            form.addEventListener('click', function (ev) {
                var refBtn = ev.target.closest('.vnext-sublookup-refresh');
                if (refBtn) {
                    ev.preventDefault();
                    var subField = sf.find(function (s) { return s.name === refBtn.dataset.field; });
                    if (subField) {
                        var sel = form.querySelector('select[data-field="' + subField.name + '"]');
                        var curVal = sel ? sel.value : null;
                        clearLookupCache(refBtn.dataset.targetSlug);
                        loadSubListLookupSelect(subField, curVal, form);
                    }
                }
            });
        }

        // CopyFromParent for new rows
        if (isNew && form) {
            sf.filter(function (s) { return s.copyFromParent; }).forEach(function (subField) {
                var cpf = subField.copyFromParent;
                var pe  = document.querySelector('[name="' + cpf.parentField + '"]');
                if (pe && pe.value && window.bmw && bmw.lookup) {
                    bmw.lookup(cpf.entitySlug, pe.value).then(function (ent) {
                        var df = form.querySelector('[data-field="' + subField.name + '"]');
                        if (df && df.getAttribute('data-calculated') !== 'true' && !df.value) {
                            df.value = ent[cpf.sourceField] !== undefined ? String(ent[cpf.sourceField]) : '';
                            df.dispatchEvent(new Event('input', {bubbles: true}));
                        }
                        recalcSubListModal(form, sf);
                    }).catch(function () {});
                }
            });
        }

        document.getElementById(modalId + '-save').addEventListener('click', function () {
            if (!form) return;
            var row = {};
            form.querySelectorAll('input[data-field], select[data-field], textarea[data-field]').forEach(function (el) {
                var name = el.getAttribute('data-field');
                if (el.type === 'checkbox') row[name] = el.checked ? 'true' : 'false';
                else row[name] = el.value || '';
            });
            var jsonInput = document.getElementById('sub_json_' + field.name);
            if (jsonInput) {
                var rows = [];
                try { rows = JSON.parse(jsonInput.value || '[]'); } catch (e) {}
                if (isNew) rows.push(row);
                else rows[rowIdx] = row;
                jsonInput.value = JSON.stringify(rows);
                refreshSubListTable(field, rows);
            }
            modal.hide();
        });

        el.addEventListener('hidden.bs.modal', function () { el.remove(); });
        modal.show();
    }

    function initFormBehaviours(meta, item, slug, id, isCreate, formFields) {
        var form = document.getElementById('vnext-editor-form');
        if (!form) return;

        // Wire markdown live preview
        form.querySelectorAll('.bm-md-editor').forEach(function (ta) {
            var preview = document.getElementById(ta.id + '_preview');
            if (preview) {
                ta.addEventListener('input', function () { preview.innerHTML = renderMarkdownToHtml(ta.value); });
            }
        });

        // Load lookup options async
        formFields.forEach(function (f) {
            if (f.type === 'LookupList' && f.lookup && f.lookup.targetSlug) {
                // Self-referencing lookup: inject current entity ID as queryValue to exclude self
                if (f.lookup.queryField && !f.lookup.queryValue && f.lookup.targetSlug === slug && id) {
                    f = Object.assign({}, f, { lookup: Object.assign({}, f.lookup, { queryValue: id }) });
                }
                var curVal = item ? (nestedGet(item, f.name)) : null;
                loadLookupSelect(f, curVal);
            }
            // Load enum options
            if (f.type === 'Enum') {
                loadEnumOptions(f, item ? (nestedGet(item, f.name)) : null);
            }
            // Resolve lookup display values in sub-list table cells
            if (f.type === 'CustomHtml') {
                resolveSubListLookups(f.name);
            }
        });

        // ── Cascading dropdown support ─────────────────────────────────────────
        // When a source field changes, re-load any lookup fields that cascade from it
        formFields.forEach(function (f) {
            if (f.type !== 'LookupList' || !f.lookup || !f.lookup.cascadeFromField || !f.lookup.cascadeFilterField) return;
            var sourceFieldName = f.lookup.cascadeFromField;
            var filterField = f.lookup.cascadeFilterField;
            var sourceEl = document.querySelector('[name="' + sourceFieldName + '"]');
            if (!sourceEl) return;
            sourceEl.addEventListener('change', function () {
                var sourceVal = sourceEl.value || '';
                // Clear the lookup cache for the target slug so we get fresh results
                clearLookupCache(f.lookup.targetSlug);
                // Re-load with filter: set queryField and queryValue to filter by the source value
                var cascadeField = Object.assign({}, f, {
                    lookup: Object.assign({}, f.lookup, {
                        queryField: filterField,
                        queryValue: sourceVal,
                        queryOperator: 'Equals'
                    })
                });
                loadLookupSelect(cascadeField, null);
            });
        });

        // Lookup add/refresh buttons
        form.addEventListener('click', function (e) {
            // Tag pill remove button
            var closeBtn = e.target.closest('.vnext-tag-pill .btn-close');
            if (closeBtn) {
                e.preventDefault();
                var pill = closeBtn.closest('.vnext-tag-pill');
                var container = pill.closest('.vnext-tag-container');
                pill.remove();
                syncTagHidden(container);
                return;
            }
            // Focus tag input when clicking container
            var tagContainer = e.target.closest('.vnext-tag-container');
            if (tagContainer && e.target === tagContainer) {
                tagContainer.querySelector('.vnext-tag-input').focus();
            }

            var addBtn = e.target.closest('.vnext-lookup-add');
            if (addBtn) {
                e.preventDefault();
                openNewRecordModal(addBtn.dataset.targetSlug, function () {
                    // Refresh all lookups for this target
                    clearLookupCache(addBtn.dataset.targetSlug);
                    delete _metaCache[addBtn.dataset.targetSlug];
                    formFields.forEach(function (f) {
                        if (f.lookup && f.lookup.targetSlug === addBtn.dataset.targetSlug) {
                            var sel = form.querySelector('select#f_' + f.name);
                            if (sel) {
                                // Standard dropdown: reload options
                                loadLookupSelect(f, sel.value);
                            }
                            // High-cardinality fields use a hidden input + search modal;
                            // cache was already cleared above, no reload needed.
                        }
                    });
                });
            }
            var refBtn = e.target.closest('.vnext-lookup-refresh');
            if (refBtn) {
                e.preventDefault();
                clearLookupCache(refBtn.dataset.targetSlug);
                var f = formFields.find(function (x) { return x.name === refBtn.dataset.field; });
                if (f) {
                    var sel = form.querySelector('select#f_' + f.name);
                    loadLookupSelect(f, sel ? sel.value : null);
                }
            }

            // Sub-list add row (new modal UI)
            var subListAdd = e.target.closest('.vnext-sublist-add');
            if (subListAdd) {
                e.preventDefault();
                var fieldName = subListAdd.dataset.field;
                var subField  = formFields.find(function (f) { return f.name === fieldName; });
                if (subField) openSubListRowModal(subField, null, item);
            }

            // Sub-list edit row (new modal UI)
            var subListEdit = e.target.closest('.vnext-sublist-edit');
            if (subListEdit) {
                e.preventDefault();
                var fieldName = subListEdit.dataset.field;
                var idx       = parseInt(subListEdit.dataset.idx, 10);
                var subField  = formFields.find(function (f) { return f.name === fieldName; });
                if (subField) {
                    var jsonInput = document.getElementById('sub_json_' + fieldName);
                    var rows = [];
                    try { rows = JSON.parse(jsonInput ? jsonInput.value : '[]'); } catch (e) {}
                    openSubListRowModal(subField, {idx: idx, row: rows[idx]}, item);
                }
            }

            // Sub-list delete row (new modal UI)
            var subListDel = e.target.closest('.vnext-sublist-del');
            if (subListDel) {
                e.preventDefault();
                var fieldName = subListDel.dataset.field;
                var idx       = parseInt(subListDel.dataset.idx, 10);
                var subField  = formFields.find(function (f) { return f.name === fieldName; });
                var jsonInput = document.getElementById('sub_json_' + fieldName);
                if (jsonInput && subField) {
                    var rows = [];
                    try { rows = JSON.parse(jsonInput.value || '[]'); } catch (e) {}
                    rows.splice(idx, 1);
                    jsonInput.value = JSON.stringify(rows);
                    refreshSubListTable(subField, rows);
                }
            }
        });

        // Tag input: add tag on Enter or comma, remove on Backspace
        form.addEventListener('keydown', function (e) {
            var inp = e.target;
            if (!inp.classList.contains('vnext-tag-input')) return;
            var container = inp.closest('.vnext-tag-container');
            if (e.key === 'Enter' || e.key === ',') {
                e.preventDefault();
                var text = inp.value.replace(/,/g, '').trim();
                if (!text) return;
                var pill = document.createElement('span');
                pill.className = 'badge bg-info text-dark me-1 vnext-tag-pill';
                pill.innerHTML = escHtml(text) + ' <button type="button" class="btn-close btn-close-sm ms-1 bm-tag-close" aria-label="Remove"></button>';
                container.insertBefore(pill, inp);
                inp.value = '';
                syncTagHidden(container);
            }
            if (e.key === 'Backspace' && !inp.value) {
                var pills = container.querySelectorAll('.vnext-tag-pill');
                if (pills.length) { pills[pills.length - 1].remove(); syncTagHidden(container); }
            }
        });

        // Calculated field live update
        formFields.forEach(function (f) {
            if (f.calculated && f.calculated.expression) {
                var fieldEl = form.querySelector('#f_' + f.name);
                if (!fieldEl) return;
                var isAsync = bmwAstHasAsync(f.calculated.expression);
                form.addEventListener('input', function () {
                    try {
                        var vals = collectFormValues(form, formFields);
                        if (isAsync) {
                            evalExpressionAsync(f.calculated.expression, vals, slug)
                                .then(function (result) { fieldEl.value = result != null ? String(result) : ''; })
                                .catch(function () {});
                        } else {
                            var result = evalExpression(f.calculated.expression, vals);
                            fieldEl.value = result != null ? String(result) : '';
                        }
                    } catch (ex) {}
                });
            }
        });

        // Clear validation errors as user corrects fields
        form.addEventListener('input', function (ev) {
            var el = ev.target;
            if (el && el.classList.contains('is-invalid') && el.checkValidity()) {
                el.classList.remove('is-invalid');
            }
        });

        // Form submit
        form.addEventListener('submit', function (e) {
            e.preventDefault();
            if (!validateForm(form)) return;

            var payload = buildPayload(form, formFields, item);
            var url  = isCreate ? API + '/' + encodeURIComponent(slug) : API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id);
            var call = isCreate ? apiPost(url, payload) : apiPut(url, payload);

            var saveBtn = document.getElementById('vnext-save-btn');
            if (saveBtn) { saveBtn.disabled = true; saveBtn.textContent = 'Saving\u2026'; }

            call.then(function (result) {
                showToast('Saved successfully.', 'success');
                clearLookupCache(slug);
                var savedId = (result && (result.id || result.Id)) || id || '';
                var dest = savedId ? BASE + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(savedId) : BASE + '/' + encodeURIComponent(slug);
                BMRouter.navigate(dest);
            }).catch(function (err) {
                showToast('Save failed: ' + err.message, 'error');
                if (saveBtn) { saveBtn.disabled = false; saveBtn.innerHTML = '<i class="bi bi-check-lg"></i> Save'; }
            });
        });
    }

    function loadLookupSelect(field, currentValue) {
        var sel = document.querySelector('select#f_' + field.name);
        if (!sel) return;
        var lk = field.lookup;
        fetchLookupOptions(lk.targetSlug, lk.queryField, lk.queryValue, lk.sortField, lk.sortDirection, lk.queryOperator)
            .then(function (items) {
                if (items.length > LOOKUP_CARDINALITY_THRESHOLD) {
                    // Replace select with search-based input
                    renderLookupSearchInput(sel, field, items, currentValue);
                    return;
                }
                sel.innerHTML = '<option value="">— Select —</option>';
                items.forEach(function (opt) {
                    var optVal = nestedGet(opt, lk.valueField) || '';
                    var optLbl = nestedGet(opt, lk.displayField) || optVal;
                    var selected = String(optVal) === String(currentValue) ? ' selected' : '';
                    sel.insertAdjacentHTML('beforeend', '<option value="' + escHtml(String(optVal)) + '"' + selected + '>' + escHtml(String(optLbl)) + '</option>');
                });
                // Ensure current value is represented even if not in list
                if (currentValue && !Array.from(sel.options).find(function (o) { return o.value === String(currentValue); })) {
                    sel.insertAdjacentHTML('afterbegin', '<option value="' + escHtml(String(currentValue)) + '" selected>' + escHtml(String(currentValue)) + '</option>');
                }
            }).catch(function () {
                sel.innerHTML = '<option value="">— Load failed —</option>';
            });
    }

    function renderLookupSearchInput(selectEl, field, allItems, currentValue) {
        var lk = field.lookup;
        var container = selectEl.closest('[data-lookup-container]');
        if (!container) return;

        // Resolve display value from pre-loaded items
        var currentDisplay = '';
        if (currentValue) {
            var curItem = allItems.find(function (o) {
                var v = nestedGet(o, lk.valueField);
                return String(v) === String(currentValue);
            });
            if (curItem) currentDisplay = nestedGet(curItem, lk.displayField) || currentValue;
        }

        var n = escHtml(field.name);
        var tName = escHtml(lk.targetName || lk.targetSlug || '');
        container.querySelector('.input-group').innerHTML =
            '<input type="text" class="form-control form-control-sm" id="f_' + n + '_display"' +
                ' placeholder="Click \uD83D\uDD0D to search\u2026"' +
                ' value="' + escHtml(String(currentDisplay)) + '" readonly>' +
            '<input type="hidden" name="' + n + '" id="f_' + n + '" value="' + escHtml(String(currentValue || '')) + '">' +
            '<button type="button" class="btn btn-outline-info btn-sm"' +
                ' data-vnext-lookup-search="' + escHtml(lk.targetSlug) + '"' +
                ' data-lookup-field="f_' + n + '"' +
                ' data-lookup-display="f_' + n + '_display"' +
                ' data-lookup-display-field="' + escHtml(lk.displayField) + '"' +
                ' data-lookup-value-field="' + escHtml(lk.valueField || 'id') + '"' +
                ' data-lookup-target-name="' + tName + '"' +
                ' data-lookup-from="' + escHtml(lk.sourceSlug || '') + '"' +
                ' data-lookup-via="' + escHtml(lk.sourceFieldName || '') + '"' +
                ' title="Search ' + tName + '">' +
                '<i class="bi bi-search" aria-hidden="true"></i></button>' +
            '<button type="button" class="btn btn-outline-secondary vnext-lookup-add"' +
                ' data-target-slug="' + escHtml(lk.targetSlug) + '"' +
                ' title="Add new"><i class="bi bi-plus"></i></button>';
    }

    // --- VNext high-cardinality lookup search modal ---

    var _vnextSearchModal = null;
    var _vnextSearchDebounce = null;

    function getOrCreateVNextSearchModal() {
        if (_vnextSearchModal) return _vnextSearchModal;
        var el = document.createElement('div');
        el.className = 'modal fade';
        el.id = 'vnext-lookup-search-modal';
        el.setAttribute('tabindex', '-1');
        el.setAttribute('aria-hidden', 'true');
        el.innerHTML =
            '<div class="modal-dialog modal-lg modal-dialog-scrollable">' +
              '<div class="modal-content">' +
                '<div class="modal-header">' +
                  '<h5 class="modal-title" id="vnext-lookup-search-title">Search</h5>' +
                  '<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>' +
                '</div>' +
                '<div class="modal-body">' +
                  '<div class="mb-3">' +
                    '<input type="text" class="form-control" id="vnext-lookup-search-input" placeholder="Type to search..." autocomplete="off" />' +
                  '</div>' +
                  '<div id="vnext-lookup-search-results"><p class="text-muted small">Enter search terms above to find matching records.</p></div>' +
                '</div>' +
                '<div class="modal-footer">' +
                  '<button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>' +
                '</div>' +
              '</div>' +
            '</div>';
        document.body.appendChild(el);
        _vnextSearchModal = el;
        document.getElementById('vnext-lookup-search-input').addEventListener('input', function () {
            clearTimeout(_vnextSearchDebounce);
            _vnextSearchDebounce = setTimeout(doVNextLookupSearch, 300);
        });
        return _vnextSearchModal;
    }

    function openVNextLookupSearch(targetSlug, fieldId, displayFieldId, displayField, valueField, targetTypeName, sourceSlug, sourceFieldName) {
        var modal = getOrCreateVNextSearchModal();
        modal.dataset.targetSlug = targetSlug;
        modal.dataset.fieldId = fieldId;
        modal.dataset.displayFieldId = displayFieldId;
        modal.dataset.displayField = displayField;
        modal.dataset.valueField = valueField || 'id';
        modal.dataset.lookupFrom = sourceSlug || '';
        modal.dataset.lookupVia = sourceFieldName || '';
        var title = document.getElementById('vnext-lookup-search-title');
        if (title) title.textContent = 'Search ' + (targetTypeName || '');
        var input = document.getElementById('vnext-lookup-search-input');
        if (input) input.value = '';
        var results = document.getElementById('vnext-lookup-search-results');
        if (results) results.innerHTML = '<p class="text-muted small">Enter search terms above to find matching records.</p>';
        var bsModal = new bootstrap.Modal(modal);
        bsModal.show();
        if (input) setTimeout(function () { input.focus(); }, 300); // wait for Bootstrap modal animation
    }

    function doVNextLookupSearch() {
        var modal = document.getElementById('vnext-lookup-search-modal');
        if (!modal) return;
        var targetSlug = modal.dataset.targetSlug;
        var displayField = modal.dataset.displayField;
        var searchInput = document.getElementById('vnext-lookup-search-input');
        var resultsEl = document.getElementById('vnext-lookup-search-results');
        if (!targetSlug || !resultsEl) return;
        var term = searchInput ? searchInput.value.trim() : '';
        if (term.length === 0) {
            resultsEl.innerHTML = '<p class="text-muted small">Enter search terms above to find matching records.</p>';
            return;
        }
        resultsEl.innerHTML = '<p class="text-muted small">Searching...</p>';
        var url = '/api/_lookup/' + encodeURIComponent(targetSlug) +
            '?search=' + encodeURIComponent(term) +
            '&searchField=' + encodeURIComponent(displayField) +
            '&top=30';
        var fromSlug = modal.dataset.lookupFrom;
        var viaField = modal.dataset.lookupVia;
        if (fromSlug && viaField) {
            url += '&from=' + encodeURIComponent(fromSlug) + '&via=' + encodeURIComponent(viaField);
        }
        fetch(url, { credentials: 'same-origin' })
            .then(function (r) {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            })
            .then(function (data) {
                var rows = (data && Array.isArray(data.data)) ? data.data : [];
                if (rows.length === 0) {
                    resultsEl.innerHTML = '<p class="text-muted small">No results found.</p>';
                    return;
                }
                var keys = Object.keys(rows[0] || {});
                var html = '<table class="table table-sm table-hover table-striped"><thead><tr><th></th>';
                keys.forEach(function (k) { html += '<th>' + escHtml(k) + '</th>'; });
                html += '</tr></thead><tbody>';
                rows.forEach(function (row) {
                    html += '<tr class="bm-cursor-pointer" data-vnext-select-row>';
                    html += '<td><button type="button" class="btn btn-sm btn-primary">Select</button></td>';
                    keys.forEach(function (k) {
                        html += '<td data-field="' + escHtml(k) + '">' + escHtml(row[k] != null ? String(row[k]) : '') + '</td>';
                    });
                    html += '</tr>';
                });
                html += '</tbody></table>';
                resultsEl.innerHTML = html;
            })
            .catch(function (err) {
                console.error('Lookup search failed:', err);
                resultsEl.innerHTML = '<p class="text-danger small">Error fetching results.</p>';
            });
    }

    function loadEnumOptions(field, currentValue) {
        var sel = document.querySelector('select#f_' + field.name);
        if (!sel) return;
        var options = Array.isArray(field.enumValues) ? field.enumValues : [];
        var html = '<option value="">— Select —</option>';
        options.forEach(function (o) {
            var val = o.value != null ? o.value : o;
            var lbl = o.label != null ? o.label : String(val);
            var selected = currentValue != null && String(currentValue) === String(val) ? ' selected' : '';
            html += '<option value="' + escHtml(String(val)) + '"' + selected + '>' + escHtml(String(lbl)) + '</option>';
        });
        sel.innerHTML = html;
    }

    function collectFormValues(form, fields) {
        var vals = {};
        var formData = new FormData(form);
        formData.forEach(function (v, k) { vals[k] = v; });
        return vals;
    }

    /**
     * CSP-safe JSON AST evaluator (synchronous).
     * Walks the expression tree from ExpressionNode.ToJsonAst() without eval/new Function.
     */
    function bmwEvalAst(ast, getField) {
        if (!ast) return 0;
        switch (ast.t) {
            case 'lit': return ast.v != null ? ast.v : 0;
            case 'field': return getField(ast.n);
            case 'bin': {
                var l = bmwEvalAst(ast.l, getField), r = bmwEvalAst(ast.r, getField);
                var ln = parseFloat(l) || 0, rn = parseFloat(r) || 0;
                switch (ast.op) {
                    case '+': return (typeof l === 'string' || typeof r === 'string') ? '' + l + r : ln + rn;
                    case '-': return ln - rn;
                    case '*': return ln * rn;
                    case '/': return rn !== 0 ? ln / rn : 0;
                    case '%': return rn !== 0 ? ln % rn : 0;
                    case '>': return ln > rn;
                    case '<': return ln < rn;
                    case '>=': return ln >= rn;
                    case '<=': return ln <= rn;
                    case '==': return ln === rn;
                    case '!=': return ln !== rn;
                }
                return 0;
            }
            case 'unary': {
                var x = parseFloat(bmwEvalAst(ast.x, getField)) || 0;
                return ast.op === '-' ? -x : x;
            }
            case 'fn': {
                var args = ast.args.map(function (a) { return bmwEvalAst(a, getField); });
                switch (ast.fn) {
                    case 'round': return args.length >= 2
                        ? Math.round(args[0] * Math.pow(10, args[1])) / Math.pow(10, args[1])
                        : Math.round(args[0]);
                    case 'min': return Math.min.apply(null, args);
                    case 'max': return Math.max.apply(null, args);
                    case 'abs': return Math.abs(args[0]);
                    case 'if': return args[0] ? args[1] : args[2];
                }
                return 0;
            }
            default: return 0;
        }
    }

    /**
     * CSP-safe JSON AST evaluator (async — supports RelatedLookup, QueryLookup, dot-access).
     */
    function bmwEvalAstAsync(ast, getField, relLookup, qryLookup) {
        if (!ast) return Promise.resolve(0);
        switch (ast.t) {
            case 'lit': return Promise.resolve(ast.v != null ? ast.v : 0);
            case 'field': return Promise.resolve(getField(ast.n));
            case 'bin':
                return Promise.all([
                    bmwEvalAstAsync(ast.l, getField, relLookup, qryLookup),
                    bmwEvalAstAsync(ast.r, getField, relLookup, qryLookup)
                ]).then(function (parts) {
                    var l = parts[0], r = parts[1];
                    var ln = parseFloat(l) || 0, rn = parseFloat(r) || 0;
                    switch (ast.op) {
                        case '+': return (typeof l === 'string' || typeof r === 'string') ? '' + l + r : ln + rn;
                        case '-': return ln - rn;
                        case '*': return ln * rn;
                        case '/': return rn !== 0 ? ln / rn : 0;
                        case '%': return rn !== 0 ? ln % rn : 0;
                        case '>': return ln > rn;
                        case '<': return ln < rn;
                        case '>=': return ln >= rn;
                        case '<=': return ln <= rn;
                        case '==': return ln === rn;
                        case '!=': return ln !== rn;
                    }
                    return 0;
                });
            case 'unary':
                return bmwEvalAstAsync(ast.x, getField, relLookup, qryLookup)
                    .then(function (val) { var x = parseFloat(val) || 0; return ast.op === '-' ? -x : x; });
            case 'fn':
                return Promise.all(ast.args.map(function (a) { return bmwEvalAstAsync(a, getField, relLookup, qryLookup); }))
                    .then(function (args) {
                        switch (ast.fn) {
                            case 'round': return args.length >= 2
                                ? Math.round(args[0] * Math.pow(10, args[1])) / Math.pow(10, args[1])
                                : Math.round(args[0]);
                            case 'min': return Math.min.apply(null, args);
                            case 'max': return Math.max.apply(null, args);
                            case 'abs': return Math.abs(args[0]);
                            case 'if': return args[0] ? args[1] : args[2];
                            case 'relatedlookup': return relLookup ? relLookup(args[0], args[1]) : Promise.resolve(null);
                            case 'querylookup':
                            case 'lookupmultilevel': return qryLookup ? qryLookup.apply(null, args) : Promise.resolve(null);
                        }
                        return 0;
                    });
            case 'dot':
                if (!relLookup) return Promise.resolve(null);
                // ast.fk is the FK field; ast.path is the chain of subsequent fields.
                // For single-hop (path.length === 1), delegate to relLookup(fk, targetField).
                // Multi-hop is not yet supported client-side; falls back to null.
                if (ast.path.length === 1) return relLookup(ast.fk, ast.path[0]);
                return Promise.resolve(null);
            default: return Promise.resolve(0);
        }
    }

    /** Returns true if the AST contains any async nodes (dot-access, relatedlookup, querylookup). */
    function bmwAstHasAsync(ast) {
        if (!ast) return false;
        switch (ast.t) {
            case 'dot': return true;
            case 'fn':
                if (ast.fn === 'relatedlookup' || ast.fn === 'querylookup' || ast.fn === 'lookupmultilevel') return true;
                return ast.args.some(bmwAstHasAsync);
            case 'bin': return bmwAstHasAsync(ast.l) || bmwAstHasAsync(ast.r);
            case 'unary': return bmwAstHasAsync(ast.x);
            default: return false;
        }
    }

    function evalExpression(ast, vals) {
        if (!ast) return null;
        try {
            return bmwEvalAst(ast, function (n) { var v = parseFloat(vals[n]); return isNaN(v) ? 0 : v; });
        } catch (e) { return null; }
    }

    // Async expression evaluation for lookup-based calculated fields
    function evalExpressionAsync(ast, vals, entitySlug) {
        try {
            function getField(n) { var v = parseFloat(vals[n]); return isNaN(v) ? 0 : v; }
            var relLookup = function (fkField, targetField) { return bmwRelatedLookup(entitySlug, fkField, targetField, vals); };
            var qryLookup = function () { return bmwQueryLookup.apply(null, arguments); };
            return bmwEvalAstAsync(ast, getField, relLookup, qryLookup);
        } catch (e) { return Promise.resolve(null); }
    }

    // Resolve a field value from a related entity via a lookup FK field
    function bmwRelatedLookup(entitySlug, fkField, targetField, vals) {
        var fkValue = vals && vals[fkField];
        if (!fkValue) return Promise.resolve(null);
        // Use the lookup API to load the related entity
        return apiGet(API + '/_lookup/' + encodeURIComponent(entitySlug) + '/' + encodeURIComponent(fkField) + '/' + encodeURIComponent(fkValue))
            .then(function (entity) {
                if (!entity) return null;
                return entity[targetField] || entity[targetField.charAt(0).toLowerCase() + targetField.slice(1)] || null;
            })
            .catch(function () { return null; });
    }

    // Query an entity with filter conditions and return a field value
    function bmwQueryLookup(targetEntitySlug /*, filterField1, filterVal1, ..., returnField */) {
        var args = Array.prototype.slice.call(arguments);
        if (args.length < 4 || args.length % 2 !== 0) return Promise.resolve(null);
        var slug = args[0];
        var returnField = args[args.length - 1];
        var filterPairs = [];
        for (var i = 1; i < args.length - 1; i += 2) {
            filterPairs.push(encodeURIComponent(args[i]) + '=' + encodeURIComponent(args[i + 1] || ''));
        }
        return apiGet(API + '/_lookup/' + encodeURIComponent(slug) + '?filter=' + filterPairs.join('&'))
            .then(function (items) {
                if (!items || !items.length) return null;
                var first = items[0];
                return first[returnField] || first[returnField.charAt(0).toLowerCase() + returnField.slice(1)] || null;
            })
            .catch(function () { return null; });
    }

    function validateForm(form) {
        var valid = true;
        form.querySelectorAll('input, select, textarea').forEach(function (el) {
            if (el.type === 'hidden' || el.readOnly || el.disabled) return;
            if (!el.checkValidity()) {
                el.classList.add('is-invalid');
                var fb = el.nextElementSibling;
                if (fb && fb.classList.contains('invalid-feedback')) {
                    fb.textContent = el.validationMessage || 'Invalid value.';
                }
                valid = false;
            } else {
                el.classList.remove('is-invalid');
            }
        });
        return valid;
    }

    function buildPayload(form, fields, existingItem) {
        var fd = new FormData(form);
        var obj = existingItem ? JSON.parse(JSON.stringify(existingItem)) : {};

        fields.forEach(function (f) {
            if (f.type === 'Hidden' && f.name === '__csrf') return;
            if (f.readOnly || f.isIdField || f.computed || f.calculated) return;

            if (f.type === 'Tags') {
                var hiddenInput = form.querySelector('input[name="' + f.name + '"]');
                try { obj[f.name] = JSON.parse(hiddenInput ? hiddenInput.value : '[]'); } catch(e) { obj[f.name] = []; }
                return;
            }

            if (f.type === 'YesNo') {
                obj[f.name] = fd.has(f.name) && fd.get(f.name) === 'true';
                return;
            }
            if (f.type === 'Money') {
                var amt = fd.get(f.name + '_amount');
                var cur = fd.get(f.name + '_currency');
                if (amt != null) obj[f.name] = { amount: parseFloat(amt) || 0, currency: cur || 'USD' };
                return;
            }
            // Sub-list reconstruction from hidden JSON input
            if (f.type === 'CustomHtml') {
                var jsonInput = document.getElementById('sub_json_' + f.name);
                if (jsonInput) {
                    try {
                        var rows = JSON.parse(jsonInput.value || '[]');
                        // Coerce string values to proper types based on subField metadata
                        if (f.subFields && Array.isArray(f.subFields)) {
                            rows = rows.map(function (row) {
                                var out = {};
                                f.subFields.forEach(function (sf) {
                                    var v = row[sf.name];
                                    if (sf.type === 'Integer') out[sf.name] = (v === '' || v == null) ? null : parseInt(v, 10);
                                    else if (sf.type === 'Decimal' || sf.type === 'Money') out[sf.name] = (v === '' || v == null) ? null : parseFloat(v);
                                    else if (sf.type === 'YesNo') out[sf.name] = (v === 'true' || v === true);
                                    else out[sf.name] = v != null ? v : '';
                                });
                                return out;
                            });
                        }
                        obj[f.name] = rows;
                    } catch (e) { obj[f.name] = []; }
                } else {
                    obj[f.name] = [];
                }
                return;
            }

            var v = fd.get(f.name);
            if (v == null) return;
            if (f.type === 'Integer') { obj[f.name] = v === '' ? null : parseInt(v, 10); return; }
            if (f.type === 'Decimal' || f.type === 'Money') { obj[f.name] = v === '' ? null : parseFloat(v); return; }
            if (v === '' && !f.required) { obj[f.name] = null; return; }
            obj[f.name] = v;
        });

        return obj;
    }

    // ── Delete confirmation ────────────────────────────────────────────────────
    function renderDelete(slug, id) {
        showLoading();
        Promise.all([fetchMeta(slug), apiFetch(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id))])
            .then(function (r) {
                var meta = r[0]; var item = r[1];
                var baseUrl = BASE + '/' + encodeURIComponent(slug);
                var html = '<div class="p-3">' +
                    '<div class="alert alert-danger">' +
                    '<h4 class="alert-heading"><i class="bi bi-exclamation-triangle-fill"></i> Confirm Delete</h4>' +
                    '<p>Are you sure you want to delete this ' + escHtml(meta.name) + ' record?</p>' +
                    '<hr><p class="mb-0 small text-muted">ID: ' + escHtml(id) + '</p>' +
                    '</div>' +
                    '<div class="d-flex gap-2">' +
                    '<button class="btn btn-danger" id="vnext-confirm-delete"><i class="bi bi-trash"></i> Delete</button>' +
                    '<a class="btn btn-secondary" href="' + baseUrl + '/' + encodeURIComponent(id) + '">Cancel</a>' +
                    '</div></div>';
                setContent(html);
                document.getElementById('vnext-confirm-delete').addEventListener('click', function () {
                    apiDelete(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id))
                        .then(function () { showToast('Deleted.', 'success'); clearLookupCache(slug); BMRouter.navigate(baseUrl); })
                        .catch(function (err) { showToast('Delete failed: ' + err.message, 'error'); });
                });
            }).catch(function (err) { showError(err.message); });
    }

    // ── Confirm modal ──────────────────────────────────────────────────────────
    function showConfirm(title, message, onConfirm) {
        var id = 'confirm-modal-' + Date.now();
        var container = document.getElementById('vnext-modal-container');
        container.insertAdjacentHTML('beforeend',
            '<div class="modal fade" id="' + id + '" tabindex="-1" aria-modal="true" role="dialog">' +
            '<div class="modal-dialog"><div class="modal-content">' +
            '<div class="modal-header"><h5 class="modal-title">' + escHtml(title) + '</h5>' +
            '<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>' +
            '<div class="modal-body">' + escHtml(message) + '</div>' +
            '<div class="modal-footer">' +
            '<button class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>' +
            '<button class="btn btn-danger" id="' + id + '-confirm">Confirm</button>' +
            '</div></div></div></div>');
        var el = document.getElementById(id);
        var modal = new bootstrap.Modal(el);
        modal.show();
        document.getElementById(id + '-confirm').addEventListener('click', function () {
            modal.hide();
            onConfirm();
        });
        el.addEventListener('hidden.bs.modal', function () { el.remove(); });
    }

    // ── New record modal (for lookup + button) ─────────────────────────────────
    function openNewRecordModal(targetSlug, onSaved) {
        showLoading();
        fetchMeta(targetSlug).then(function (meta) {
            var formFields = meta.fields.filter(function (f) { return f.create; }).sort(function (a, b) { return a.order - b.order; });
            var formHtml = '<form id="vnext-modal-form" novalidate>';
            formHtml += '<input type="hidden" name="__csrf" value="' + escHtml(getCsrfToken()) + '">';
            formFields.forEach(function (f) { formHtml += renderFormField(f, null, meta, null); });
            formHtml += '</form>';

            var id = 'new-record-modal-' + Date.now();
            var container = document.getElementById('vnext-modal-container');
            container.insertAdjacentHTML('beforeend',
                '<div class="modal fade" id="' + id + '" tabindex="-1" aria-modal="true" role="dialog">' +
                '<div class="modal-dialog modal-lg"><div class="modal-content">' +
                '<div class="modal-header"><h5 class="modal-title">New ' + escHtml(meta.name) + '</h5>' +
                '<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>' +
                '<div class="modal-body">' + formHtml + '</div>' +
                '<div class="modal-footer">' +
                '<button class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>' +
                '<button class="btn btn-primary" id="' + id + '-save">Save</button>' +
                '</div></div></div></div>');

            var el = document.getElementById(id);
            var modal = new bootstrap.Modal(el);
            modal.show();

            // Load lookups inside modal
            formFields.forEach(function (f) {
                if (f.type === 'LookupList' && f.lookup && f.lookup.targetSlug) loadLookupSelect(f, null);
            });

            document.getElementById(id + '-save').addEventListener('click', function () {
                var form = document.getElementById('vnext-modal-form');
                if (!validateForm(form)) return;
                var payload = buildPayload(form, formFields, null);
                apiPost(API + '/' + encodeURIComponent(targetSlug), payload)
                    .then(function () {
                        modal.hide();
                        showToast('Record saved.', 'success');
                        if (onSaved) onSaved();
                    })
                    .catch(function (err) { showToast('Save failed: ' + err.message, 'error'); });
            });

            el.addEventListener('hidden.bs.modal', function () { el.remove(); });
        }).catch(function (err) { showError(err.message); });
    }

    // ── Utility helpers ───────────────────────────────────────────────────────
    function buildUrl(base, params) {
        var parts = [];
        Object.keys(params).forEach(function (k) {
            var v = params[k];
            if (v == null || v === '') return;
            parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(v));
        });
        return parts.length ? base + '?' + parts.join('&') : base;
    }

    function toDateTimeLocalStr(val) {
        if (!val) return '';
        try {
            var d = new Date(val);
            if (isNaN(d.getTime())) return String(val);
            return d.getFullYear() + '-' +
                pad(d.getMonth() + 1) + '-' +
                pad(d.getDate()) + 'T' +
                pad(d.getHours()) + ':' +
                pad(d.getMinutes());
        } catch (e) { return String(val); }
    }

    function toDateStr(val) {
        if (!val) return '';
        // Already in yyyy-MM-dd format
        if (/^\d{4}-\d{2}-\d{2}$/.test(String(val))) return String(val);
        try {
            var d = new Date(val);
            if (isNaN(d.getTime())) return '';
            return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
        } catch (e) { return ''; }
    }

    function toTimeStr(val) {
        if (!val) return '';
        // Already in HH:mm or HH:mm:ss format
        if (/^\d{2}:\d{2}(:\d{2})?$/.test(String(val))) return String(val).substring(0, 5);
        try {
            var d = new Date(val);
            if (isNaN(d.getTime())) return String(val);
            return pad(d.getHours()) + ':' + pad(d.getMinutes());
        } catch (e) { return ''; }
    }

    function pad(n) { return n < 10 ? '0' + n : '' + n; }

    function downloadCsv(filename, rows) {
        var csv = rows.map(function (r) { return r.map(function (c) { return '"' + String(c).replace(/"/g, '""') + '"'; }).join(','); }).join('\r\n');
        var blob = new Blob([csv], { type: 'text/csv' });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(a.href);
    }

    function renderCountryOptions(selected) {
        // ISO 3166-1 alpha-2 country codes (abbreviated list; extend as needed)
        var countries = [
            ['AF','Afghanistan'],['AL','Albania'],['DZ','Algeria'],['AR','Argentina'],['AU','Australia'],
            ['AT','Austria'],['BE','Belgium'],['BR','Brazil'],['CA','Canada'],['CN','China'],
            ['CO','Colombia'],['HR','Croatia'],['CZ','Czech Republic'],['DK','Denmark'],['EG','Egypt'],
            ['FI','Finland'],['FR','France'],['DE','Germany'],['GR','Greece'],['HK','Hong Kong'],
            ['HU','Hungary'],['IN','India'],['ID','Indonesia'],['IE','Ireland'],['IL','Israel'],
            ['IT','Italy'],['JP','Japan'],['MX','Mexico'],['NL','Netherlands'],['NZ','New Zealand'],
            ['NG','Nigeria'],['NO','Norway'],['PK','Pakistan'],['PH','Philippines'],['PL','Poland'],
            ['PT','Portugal'],['RO','Romania'],['RU','Russia'],['SA','Saudi Arabia'],['SG','Singapore'],
            ['ZA','South Africa'],['KR','South Korea'],['ES','Spain'],['SE','Sweden'],['CH','Switzerland'],
            ['TW','Taiwan'],['TH','Thailand'],['TR','Turkey'],['UA','Ukraine'],['AE','United Arab Emirates'],
            ['GB','United Kingdom'],['US','United States'],['VN','Vietnam']
        ];
        var html = '<option value="">— Select —</option>';
        countries.forEach(function (c) {
            html += '<option value="' + escHtml(c[0]) + '"' + (c[0] === selected ? ' selected' : '') + '>' + escHtml(c[1]) + '</option>';
        });
        return html;
    }

    // ── Cascaded lookup support ────────────────────────────────────────────────
    // When a field is decorated with a cascade target, re-load the dependent dropdown.
    function initCascadeLookup(form, sourceFieldName, targetFieldName, targetMeta) {
        var source = form.querySelector('[name="' + sourceFieldName + '"]');
        if (!source) return;
        source.addEventListener('change', function () {
            var val = source.value;
            if (!val) return;
            clearLookupCache(targetMeta.lookup.targetSlug);
            // Override queryValue dynamically
            var cascadedField = Object.assign({}, targetMeta, { lookup: Object.assign({}, targetMeta.lookup, { queryValue: val }) });
            loadLookupSelect(cascadedField, null);
        });
    }

    // ── App init / routing ────────────────────────────────────────────────────
    function init() {
        // Build nav from metadata (async, non-blocking)
        fetchMetaObjects().then(buildNav).catch(function () {});

        // Theme restore (matches main app behaviour)
        try {
            var m = document.cookie.match(/(?:^|;\s*)bm-selected-theme=([^;]+)/);
            if (m) {
                var t = decodeURIComponent(m[1]);
                var allowed = ['cerulean','cosmo','cyborg','darkly','flatly','journal','litera','lumen','lux',
                    'materia','minty','morph','pulse','quartz','sandstone','simplex','sketchy','slate',
                    'solar','spacelab','superhero','united','vapor','yeti','zephyr'];
                if (allowed.indexOf(t) >= 0) {
                    var el = document.getElementById('bootswatch-theme');
                    if (el) el.href = '/static/css/themes/' + encodeURIComponent(t) + '.min.css';
                }
            }
        } catch (e) {}

        // Skin restore
        try {
            var sm = document.cookie.match(/(?:^|;\s*)bm-selected-skin=([^;]+)/);
            if (sm) {
                var sk = decodeURIComponent(sm[1]);
                var allowedSkins = ['default','sidebar','compact','focus','bmw'];
                if (allowedSkins.indexOf(sk) >= 0 && sk !== 'default') {
                    document.body.setAttribute('data-bm-skin', sk);
                }
            }
        } catch (e) {}

        // Register routes
        BMRouter
            // /d is the data-browser home entry point from the admin nav; must be registered
            // before /:entity so the router does not treat 'd' as an entity slug.
            .on('/d',                         function () { renderHome(); })
            .on(BASE + '/:entity/create', function (p, q) { renderCreate(p.entity, q); })
            .on(BASE + '/:entity/:id/edit',   function (p) { renderEdit(p.entity, p.id); })
            .on(BASE + '/:entity/:id/delete', function (p) { renderDelete(p.entity, p.id); })
            .on(BASE + '/:entity/:id',        function (p, q) { renderView(p.entity, p.id); })
            .on(BASE + '/:entity',            function (p, q) { renderList(p.entity, q); })
            .on(BASE + '/',                           function () { renderHome(); })
            .on(BASE,                                    function () { renderHome(); })
            .notFound(function (path) {
                showError('Page not found: ' + path);
            })
            .start();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Event delegation for high-cardinality lookup search button and row selection
    document.addEventListener('click', function (e) {
        var searchBtn = e.target.closest('[data-vnext-lookup-search]');
        if (searchBtn) {
            e.preventDefault();
            openVNextLookupSearch(
                searchBtn.dataset.vnextLookupSearch,
                searchBtn.dataset.lookupField,
                searchBtn.dataset.lookupDisplay,
                searchBtn.dataset.lookupDisplayField,
                searchBtn.dataset.lookupValueField || 'id',
                searchBtn.dataset.lookupTargetName,
                searchBtn.dataset.lookupFrom || '',
                searchBtn.dataset.lookupVia || ''
            );
            return;
        }
        var row = e.target.closest('[data-vnext-select-row]');
        if (row) {
            var modal = document.getElementById('vnext-lookup-search-modal');
            if (!modal) return;
            var fieldId = modal.dataset.fieldId;
            var displayFieldId = modal.dataset.displayFieldId;
            var displayField = modal.dataset.displayField || '';
            var valueField = modal.dataset.valueField || 'id';
            var valueFieldLower = valueField.toLowerCase();
            var displayFieldLower = displayField.toLowerCase();
            var valueCell = null, displayCell = null;
            row.querySelectorAll('td[data-field]').forEach(function (td) {
                var f = (td.getAttribute('data-field') || '').toLowerCase();
                if (f === valueFieldLower) valueCell = td;
                if (displayFieldLower && f === displayFieldLower) displayCell = td;
            });
            var idValue = valueCell ? valueCell.textContent.trim() : '';
            var displayValue = displayCell ? displayCell.textContent.trim() : idValue;
            var hiddenInput = document.getElementById(fieldId);
            if (hiddenInput) hiddenInput.value = idValue;
            var displayInput = document.getElementById(displayFieldId);
            if (displayInput) displayInput.value = displayValue;
            var bsModal = bootstrap.Modal.getInstance(modal);
            if (bsModal) bsModal.hide();
        }
    });

})(window);
// VNext Router — thin SPA router powered by BareMetalRendering
// Parses /{slug}[/{id}[/edit|/delete]|/create]
// Depends on: BareMetalRest, BareMetalBind, BareMetalTemplate, BareMetalRendering
(async function () {
  'use strict';
  BareMetalRest.setRoot('/api/');

  const R   = document.getElementById('vnext-root') || document.getElementById('vnext-content');
  if (!R) return;

  // ── SPA Activation: hide server-rendered content, take over navigation ──
  // Use class-based hiding (not display:none) to avoid CLS — the .bm-ssr-hidden
  // class uses visibility:hidden + position:absolute so the element is removed
  // from visual flow without triggering a layout shift.
  const ssrContent = document.querySelector('.bm-ssr-content');
  if (ssrContent) ssrContent.classList.add('bm-ssr-hidden');
  R.style.display = '';

  // Intercept ALL internal link clicks for SPA navigation (not just [data-go])
  document.addEventListener('click', function (e) {
    const anchor = e.target.closest('a[href]');
    if (!anchor) return;
    var href = anchor.getAttribute('href');
    if (!href || href.startsWith('#') || anchor.target === '_blank') return;
    if (href.startsWith('http://') || href.startsWith('https://')) {
      try { var u = new URL(href); if (u.host !== location.host) return; href = u.pathname + u.search; }
      catch (_) { return; }
    }
    // Skip non-SPA paths
    if (href.startsWith('/api/') || href.startsWith('/auth/') || href.startsWith('/admin/') ||
        href.startsWith('/login') || href.startsWith('/logout') || href.startsWith('/meta/') ||
        href.startsWith('/static/') || href.startsWith('/bmw/') ||
        href === '/status' || href === '/metrics') return;
    e.preventDefault();
    go(href);
  }, true);

  const esc = s => String(s ?? '').replace(/[&<>"]/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
  const el  = (tag, props, children) => {
    const e = Object.assign(document.createElement(tag), props);
    (children || []).forEach(c => typeof c === 'string' ? e.append(c) : e.appendChild(c));
    return e;
  };
  const go  = url => { history.pushState({}, '', url); route(); };
  const isBoolTrue = v => v === true || v === 'true' || v === 1;
  const lookupSlug = url => url.replace(/[?#].*$/, '').replace(/\/$/, '').split('/').pop();
  window.addEventListener('popstate', route);

  // Module-local entity list cache (separate from BareMetalRendering's internal cache)
  let _entityList = null;

  // Auto-refresh handle for the dashboard view — cleared on every navigation.
  let _dashboardRefreshHandle = null;

  function wire() {
    R.querySelectorAll('[data-go]').forEach(a =>
      a.addEventListener('click', e => { e.preventDefault(); go(a.getAttribute('href')); })
    );
  }

  function navbar(activeSlug) {
    const all = _entityList || [];
    const nav = el('nav', { className: 'navbar navbar-expand navbar-dark bg-dark mb-3 px-3' });
    const brand = el('a', { className: 'navbar-brand', href: BASE, textContent: '\u26A1 VNext' });
    brand.setAttribute('data-go', '');
    nav.appendChild(brand);
    const ul = el('ul', { className: 'navbar-nav me-auto' });

    // Group entities by navGroup for dropdown menus
    const groups = new Map();
    all.filter(e => e.showOnNav).forEach(e => {
      const g = e.navGroup || '';
      if (!groups.has(g)) groups.set(g, []);
      groups.get(g).push(e);
    });

    groups.forEach((entities, groupName) => {
      if (!groupName || entities.length === 1) {
        // No group or single item — render as flat nav links
        entities.forEach(e => {
          const li = el('li', { className: 'nav-item' });
          const a  = el('a', { className: 'nav-link' + (e.slug === activeSlug ? ' active' : ''), href: BASE + '/' + e.slug, textContent: e.name });
          a.setAttribute('data-go', '');
          li.appendChild(a);
          ul.appendChild(li);
        });
      } else {
        // Multiple items in a group — Bootstrap dropdown
        const li = el('li', { className: 'nav-item dropdown' });
        const toggle = el('a', {
          className: 'nav-link dropdown-toggle' + (entities.some(e => e.slug === activeSlug) ? ' active' : ''),
          href: '#', textContent: groupName, role: 'button'
        });
        toggle.setAttribute('data-bs-toggle', 'dropdown');
        toggle.setAttribute('aria-expanded', 'false');
        li.appendChild(toggle);
        const menu = el('ul', { className: 'dropdown-menu' });
        entities.forEach(e => {
          const mli = el('li');
          const a = el('a', { className: 'dropdown-item' + (e.slug === activeSlug ? ' active' : ''), href: BASE + '/' + e.slug, textContent: e.name });
          a.setAttribute('data-go', '');
          mli.appendChild(a);
          menu.appendChild(mli);
        });
        li.appendChild(menu);
        ul.appendChild(li);
      }
    });

    nav.appendChild(ul);

    // Right-side: Tools dropdown + bell icon
    const rightUl = el('ul', { className: 'navbar-nav ms-auto d-flex align-items-center' });

    // Tools dropdown (sample data, wipe data)
    const toolsLi = el('li', { className: 'nav-item dropdown' });
    const toolsToggle = el('a', {
      className: 'nav-link dropdown-toggle' + (['_sample-data', '_wipe-data', '_query-plans', '_dashboards'].includes(activeSlug) ? ' active' : ''),
      href: '#', role: 'button', title: 'Admin Tools'
    });
    toolsToggle.setAttribute('data-bs-toggle', 'dropdown');
    toolsToggle.setAttribute('aria-expanded', 'false');
    toolsToggle.innerHTML = '<i class="bi bi-tools"></i>';
    toolsLi.appendChild(toolsToggle);
    const toolsMenu = el('ul', { className: 'dropdown-menu dropdown-menu-end' });
    [
      { slug: '_sample-data', label: '\uD83E\uDDEA Generate Sample Data' },
      { slug: '_wipe-data',   label: '\uD83D\uDDD1\uFE0F Wipe All Data' },
      { slug: '_query-plans', label: '\uD83D\uDCCA Query Plan History' },
      { slug: '_dashboards',  label: '\uD83D\uDCCA Dashboards' }
    ].forEach(function (t) {
      const mli = el('li');
      const ma  = el('a', { className: 'dropdown-item' + (activeSlug === t.slug ? ' active' : ''), href: BASE + '/' + t.slug, textContent: t.label });
      ma.setAttribute('data-go', '');
      mli.appendChild(ma);
      toolsMenu.appendChild(mli);
    });
    toolsLi.appendChild(toolsMenu);
    rightUl.appendChild(toolsLi);

    // Bell icon linking to inbox page
    const jobsLi  = el('li', { className: 'nav-item' });
    const jobsA   = el('a', {
      className: 'nav-link position-relative' + (activeSlug === '_inbox' ? ' active' : ''),
      href: BASE + '/_inbox',
      title: 'Inbox'
    });
    jobsA.setAttribute('data-go', '');
    jobsA.innerHTML = '<i class="bi bi-bell"></i>' +
      '<span id="vnext-inbox-badge" class="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger d-none">0</span>';
    jobsLi.appendChild(jobsA);
    rightUl.appendChild(jobsLi);

    // Search icon button (opens global search modal, Ctrl+K)
    const searchLi = el('li', { className: 'nav-item' });
    const searchBtn = el('button', {
      className: 'btn btn-link nav-link',
      title: 'Global Search (Ctrl+K)'
    });
    searchBtn.setAttribute('type', 'button');
    searchBtn.innerHTML = '<i class="bi bi-search"></i>';
    searchBtn.addEventListener('click', openGlobalSearchModal);
    searchLi.appendChild(searchBtn);
    rightUl.appendChild(searchLi);

    nav.appendChild(rightUl);

    // Sync inbox badge after DOM insertion
    setTimeout(_updateInboxBadge, 0);

    return nav;
  }


  // ── Global Search Modal ──────────────────────────────────────────────────────
  function openGlobalSearchModal() {
    const modalId = 'vnext-global-search-modal';
    const existing = document.getElementById(modalId);
    if (existing) {
      const bsEx = bootstrap.Modal.getInstance(existing) || new bootstrap.Modal(existing);
      bsEx.show();
      setTimeout(function () {
        const inp = document.getElementById(modalId + '-input');
        if (inp) inp.focus();
      }, 300);
      return;
    }

    let container = document.getElementById('vnext-modal-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'vnext-modal-container';
      document.body.appendChild(container);
    }

    const html =
      '<div class="modal fade" id="' + modalId + '" tabindex="-1" aria-modal="true" role="dialog">' +
        '<div class="modal-dialog modal-lg modal-dialog-scrollable">' +
          '<div class="modal-content">' +
            '<div class="modal-header py-2">' +
              '<div class="input-group">' +
                '<span class="input-group-text bg-transparent border-0"><i class="bi bi-search"></i></span>' +
                '<input type="text" class="form-control border-0 shadow-none fs-5" id="' + modalId + '-input"' +
                  ' placeholder="Search across all modules\u2026" autocomplete="off" />' +
                '<span class="input-group-text bg-transparent border-0 text-muted small">Ctrl+K</span>' +
              '</div>' +
              '<button type="button" class="btn-close ms-2" data-bs-dismiss="modal" aria-label="Close"></button>' +
            '</div>' +
            '<div class="modal-body" id="' + modalId + '-results">' +
              '<p class="text-muted text-center py-4">Type to search across all modules you have access to.</p>' +
            '</div>' +
          '</div>' +
        '</div>' +
      '</div>';

    container.insertAdjacentHTML('beforeend', html);
    const modalEl  = document.getElementById(modalId);
    const bsModal  = new bootstrap.Modal(modalEl);
    const input    = document.getElementById(modalId + '-input');
    const resultsDiv = document.getElementById(modalId + '-results');
    let debounceTimer = null;

    input.addEventListener('input', function () {
      clearTimeout(debounceTimer);
      const searchTerm = input.value.trim();
      if (searchTerm.length < 2) {
        resultsDiv.innerHTML = '<p class="text-muted text-center py-4">Type at least 2 characters to search.</p>';
        return;
      }
      resultsDiv.innerHTML = '<p class="text-muted text-center py-3"><span class="spinner-border spinner-border-sm me-2"></span>Searching\u2026</p>';
      debounceTimer = setTimeout(function () {
        apiGet('/api/_global-search?q=' + encodeURIComponent(searchTerm))
          .then(function (data) {
            renderGlobalSearchResults(resultsDiv, data, searchTerm, bsModal);
          })
          .catch(function (err) {
            resultsDiv.innerHTML = '<div class="alert alert-danger m-3">' + esc(err.message) + '</div>';
          });
      }, 300);
    });

    input.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { bsModal.hide(); }
    });

    modalEl.addEventListener('hidden.bs.modal', function () {
      modalEl.remove();
    });

    bsModal.show();
    setTimeout(function () { input.focus(); }, 300);
  }

  function renderGlobalSearchResults(container, data, searchTerm, modal) {
    container.innerHTML = '';
    const groups = (data && data.groups) ? data.groups : [];
    if (groups.length === 0) {
      container.innerHTML = '<p class="text-muted text-center py-4">No results found for <strong>' + esc(searchTerm) + '</strong>.</p>';
      return;
    }
    groups.forEach(function (group) {
      const section = document.createElement('div');
      section.className = 'mb-3';

      const heading = document.createElement('div');
      heading.className = 'fw-semibold text-muted small text-uppercase px-3 pb-1 pt-2 border-bottom';
      heading.textContent = group.name;
      section.appendChild(heading);

      const list = document.createElement('div');
      list.className = 'list-group list-group-flush';
      (group.items || []).forEach(function (item) {
        const a = document.createElement('a');
        a.className = 'list-group-item list-group-item-action px-3 py-2';
        a.href = BASE + '/' + encodeURIComponent(group.slug) + '/' + encodeURIComponent(item.id);
        a.setAttribute('data-go', '');
        a.innerHTML = highlightMatch(esc(item.label), esc(searchTerm));
        a.addEventListener('click', function (e) {
          e.preventDefault();
          if (modal) modal.hide();
          go(a.getAttribute('href'));
        });
        list.appendChild(a);
      });
      section.appendChild(list);
      container.appendChild(section);
    });
  }

  function highlightMatch(escapedText, escapedQuery) {
    if (!escapedQuery) return escapedText;
    const idx = escapedText.toLowerCase().indexOf(escapedQuery.toLowerCase());
    if (idx < 0) return escapedText;
    return escapedText.substring(0, idx) +
      '<mark class="p-0">' + escapedText.substring(idx, idx + escapedQuery.length) + '</mark>' +
      escapedText.substring(idx + escapedQuery.length);
  }

  // Ctrl+K shortcut to open global search
  document.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      openGlobalSearchModal();
    }
  });
  function renderInboxPage(container) {
    var hdr = el('div', { className: 'd-flex align-items-center justify-content-between gap-3 mb-3 flex-wrap' });
    hdr.appendChild(el('h2', { className: 'mb-0', textContent: '\uD83D\uDCEC Inbox' }));
    var readAllBtn = el('button', { className: 'btn btn-outline-secondary btn-sm', textContent: '\u2713 Mark All Read' });
    hdr.appendChild(readAllBtn);
    container.appendChild(hdr);

    var listDiv = el('div');
    container.appendChild(listDiv);

    function categoryBadge(cat) {
      if (!cat) return '';
      var cls = 'secondary';
      if (cat === 'Lead') cls = 'success';
      else if (cat === 'Payment') cls = 'danger';
      else if (cat === 'Ticket') cls = 'primary';
      return '<span class="badge bg-' + cls + ' me-2">' + escHtml(cat) + '</span>';
    }

    function loadMessages() {
      listDiv.innerHTML = '<div class="text-muted text-center py-4">Loading\u2026</div>';
      fetch(BASE + '/api/inbox', { credentials: 'same-origin' })
        .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
        .then(function (messages) {
          if (!messages || messages.length === 0) {
            listDiv.innerHTML = '<div class="text-center py-5 text-muted"><i class="bi bi-inbox display-4 d-block mb-2"></i>No messages</div>';
            return;
          }
          var html = '<div class="list-group">';
          messages.forEach(function (msg) {
            var ts = msg.createdAtUtc ? new Date(msg.createdAtUtc).toLocaleString() : '';
            var unreadCls = msg.isRead ? '' : ' list-group-item-light fw-semibold';
            var link = (msg.entitySlug && msg.entityId) ? BASE + '/' + encodeURIComponent(msg.entitySlug) + '/' + encodeURIComponent(msg.entityId) : null;
            html += '<div class="list-group-item' + unreadCls + ' d-flex gap-3 align-items-start" data-inbox-id="' + escHtml(String(msg.id)) + '">';
            if (!msg.isRead) {
              html += '<span class="mt-1 text-primary flex-shrink-0" title="Unread"><i class="bi bi-circle-fill" style="font-size:.5rem"></i></span>';
            } else {
              html += '<span class="mt-1 text-muted flex-shrink-0"><i class="bi bi-circle" style="font-size:.5rem"></i></span>';
            }
            html += '<div class="flex-grow-1">';
            html += '<div class="d-flex justify-content-between flex-wrap gap-1">';
            html += '<span>' + categoryBadge(msg.category) + '<strong>' + escHtml(msg.subject) + '</strong></span>';
            html += '<small class="text-muted">' + escHtml(ts) + '</small>';
            html += '</div>';
            if (msg.body) {
              html += '<div class="mt-1 text-muted small">' + escHtml(msg.body) + '</div>';
            }
            if (link) {
              html += '<div class="mt-1"><a href="' + escHtml(link) + '" class="btn btn-sm btn-link p-0" data-go="">View record \u2192</a></div>';
            }
            html += '</div>';
            html += '</div>';
          });
          html += '</div>';
          listDiv.innerHTML = html;

          // Mark as read on click
          listDiv.querySelectorAll('[data-inbox-id]').forEach(function (item) {
            item.addEventListener('click', function () {
              var id = item.getAttribute('data-inbox-id');
              if (item.classList.contains('fw-semibold')) {
                fetch(BASE + '/api/inbox/' + id + '/read', { method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': getCsrfToken(), 'X-Requested-With': 'BareMetalWeb' } })
                  .then(function () {
                    item.classList.remove('list-group-item-light', 'fw-semibold');
                    var dot = item.querySelector('.bi-circle-fill');
                    if (dot) dot.className = 'bi bi-circle';
                    _updateInboxBadge();
                  })
                  .catch(function () {});
              }
            });
          });
          _updateInboxBadge();
        })
        .catch(function () {
          listDiv.innerHTML = '<div class="alert alert-danger">Failed to load inbox.</div>';
        });
    }

    readAllBtn.addEventListener('click', function () {
      readAllBtn.disabled = true;
      fetch(BASE + '/api/inbox/read-all', { method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': getCsrfToken(), 'X-Requested-With': 'BareMetalWeb' } })
        .then(function () { loadMessages(); })
        .catch(function () { readAllBtn.disabled = false; });
    });

    loadMessages();
  }

  function renderSampleDataPage(container) {
    container.appendChild(el('h2', { className: 'mb-3', textContent: '\u{1F9EA} Generate Sample Data' }));
    container.appendChild(el('p', { className: 'text-muted', textContent: 'Generate sample data for load and indexing tests. The job runs in the background; a toast notification will appear on completion.' }));

    var msgDiv = el('div');
    container.appendChild(msgDiv);

    var form = el('form');
    container.appendChild(form);

    function addIntField(labelText, name, defaultVal) {
      var grp = el('div', { className: 'mb-3' });
      grp.appendChild(el('label', { className: 'form-label', textContent: labelText, htmlFor: 'sd_' + name }));
      var inp = el('input', { type: 'number', className: 'form-control', id: 'sd_' + name, name: name, min: '0', max: '100000', value: String(defaultVal), required: true });
      grp.appendChild(inp);
      form.appendChild(grp);
    }

    addIntField('Addresses',        'addresses',      100);
    addIntField('Customers',        'customers',       50);
    addIntField('Units of Measure', 'units',           25);
    addIntField('Products',         'products',        25);
    addIntField('Employees',        'employees',       10);
    addIntField('Orders',           'orders',          25);
    addIntField('To-Do Items',      'todos',           20);
    addIntField('Time Table Plans', 'timeTablePlans',  10);
    addIntField('Lesson Logs',      'lessonLogs',      10);

    var clearGrp = el('div', { className: 'mb-3 form-check' });
    var clearChk = el('input', { type: 'checkbox', className: 'form-check-input', id: 'sd_clearExisting' });
    clearGrp.appendChild(clearChk);
    clearGrp.appendChild(el('label', { className: 'form-check-label text-danger', htmlFor: 'sd_clearExisting', textContent: 'Clear existing data first' }));
    form.appendChild(clearGrp);

    var submitBtn = el('button', { type: 'submit', className: 'btn btn-primary', textContent: 'Generate' });
    form.appendChild(submitBtn);

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      msgDiv.innerHTML = '';
      submitBtn.disabled = true;
      submitBtn.textContent = 'Submitting\u2026';

      var body = {
        addresses:      parseInt(form.querySelector('[name="addresses"]').value, 10) || 0,
        customers:      parseInt(form.querySelector('[name="customers"]').value, 10) || 0,
        units:          parseInt(form.querySelector('[name="units"]').value, 10) || 0,
        products:       parseInt(form.querySelector('[name="products"]').value, 10) || 0,
        employees:      parseInt(form.querySelector('[name="employees"]').value, 10) || 0,
        orders:         parseInt(form.querySelector('[name="orders"]').value, 10) || 0,
        todos:          parseInt(form.querySelector('[name="todos"]').value, 10) || 0,
        timeTablePlans: parseInt(form.querySelector('[name="timeTablePlans"]').value, 10) || 0,
        lessonLogs:     parseInt(form.querySelector('[name="lessonLogs"]').value, 10) || 0,
        clearExisting:  clearChk.checked
      };

      apiPost('/api/admin/sample-data', body)
        .then(function () {
          // 202 is handled by apiFetch → trackJob(); navigate to jobs page
          go(BASE + '/_jobs');
        })
        .catch(function (err) {
          msgDiv.innerHTML = '<div class="alert alert-danger">' + escHtml(err.message) + '</div>';
          submitBtn.disabled = false;
          submitBtn.textContent = 'Generate';
        });
    });
  }

  function renderWipeDataPage(container) {
    container.appendChild(el('div', { className: 'alert alert-danger',
      innerHTML: '<h4 class="alert-heading">&#9888; DANGER ZONE &#9888;</h4>' +
        '<p><strong>This action will permanently delete ALL data in every entity store.</strong></p>' +
        '<p>This operation is <strong>irreversible</strong>.</p>' +
        '<p>Enter the configured wipe token (the <code>admin.allowWipeData</code> setting) to confirm.</p>' }));

    var msgDiv = el('div');
    container.appendChild(msgDiv);

    var form = el('form');
    container.appendChild(form);

    var grp = el('div', { className: 'mb-3' });
    grp.appendChild(el('label', { className: 'form-label', htmlFor: 'wd_token', textContent: 'Enter wipe token to confirm' }));
    var tokenInp = el('input', { type: 'password', className: 'form-control', id: 'wd_token', required: true, autocomplete: 'off' });
    grp.appendChild(tokenInp);
    form.appendChild(grp);

    var submitBtn = el('button', { type: 'submit', className: 'btn btn-danger', textContent: 'WIPE ALL DATA' });
    form.appendChild(submitBtn);

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      msgDiv.innerHTML = '';
      submitBtn.disabled = true;
      submitBtn.textContent = 'Submitting\u2026';

      apiPost('/api/admin/wipe-data', { confirmToken: tokenInp.value })
        .then(function () {
          // 202 is handled by apiFetch → trackJob(); navigate to jobs page
          go(BASE + '/_jobs');
        })
        .catch(function (err) {
          msgDiv.innerHTML = '<div class="alert alert-danger">' + escHtml(err.message) + '</div>';
          submitBtn.disabled = false;
          submitBtn.textContent = 'WIPE ALL DATA';
        });
    });
  }

  function renderJobsPage(container) {
    var hdr = el('div', { className: 'd-flex align-items-center gap-3 mb-3 flex-wrap' });
    hdr.appendChild(el('h2', { className: 'mb-0', textContent: '\uD83D\uDD14 Background Jobs' }));
    var refreshBtn = el('button', { className: 'btn btn-outline-secondary btn-sm', textContent: '\u21BB Refresh' });
    hdr.appendChild(refreshBtn);
    container.appendChild(hdr);

    var tableWrap = el('div');
    container.appendChild(tableWrap);

    function statusBadge(status) {
      if (status === 'succeeded') return '<span class="badge bg-success">Succeeded</span>';
      if (status === 'failed')    return '<span class="badge bg-danger">Failed</span>';
      if (status === 'running')   return '<span class="badge bg-primary">Running</span>';
      return '<span class="badge bg-secondary">Queued</span>';
    }

    function progressBar(j) {
      if (j.status !== 'running' && j.status !== 'succeeded') return '';
      var pct = j.percentComplete || 0;
      return '<div class="progress bm-job-progress"><div class="progress-bar" role="progressbar" data-progress-pct="' + pct + '" aria-valuenow="' + pct + '" aria-valuemin="0" aria-valuemax="100">' + pct + '%</div></div>';
    }

    function loadJobs() {
      apiFetch(API + '/jobs').then(function (jobs) {
        if (!Array.isArray(jobs) || jobs.length === 0) {
          tableWrap.innerHTML = '<p class="text-muted">No background jobs in the last hour.</p>';
          return;
        }
        var html = '<div class="table-responsive"><table class="table table-sm table-hover align-middle">';
        html += '<thead class="table-dark"><tr>' +
          '<th>Operation</th><th>Status</th><th>Progress</th>' +
          '<th>Started</th><th>Completed</th><th>Details</th><th></th></tr></thead><tbody>';
        jobs.forEach(function (j) {
          var started   = j.startedAt   ? new Date(j.startedAt).toLocaleTimeString()   : '';
          var completed = j.completedAt ? new Date(j.completedAt).toLocaleTimeString() : '';
          var details   = j.error
            ? '<span class="text-danger">' + escHtml(j.error) + '</span>'
            : escHtml(j.description || '');
          var canCancel = j.status === 'running' || j.status === 'queued';
          var cancelBtn = canCancel
            ? '<button class="btn btn-danger btn-sm" data-cancel-job="' + escHtml(j.jobId) + '" title="Cancel job">\u26D4 Cancel</button>'
            : '';
          html += '<tr>' +
            '<td>' + escHtml(j.operationName) + '</td>' +
            '<td>' + statusBadge(j.status) + '</td>' +
            '<td>' + progressBar(j) + '</td>' +
            '<td class="text-nowrap">' + escHtml(started) + '</td>' +
            '<td class="text-nowrap">' + escHtml(completed) + '</td>' +
            '<td>' + details + '</td>' +
            '<td>' + cancelBtn + '</td>' +
            '</tr>';
        });
        html += '</tbody></table></div>';
        tableWrap.innerHTML = html;
        tableWrap.querySelectorAll('[data-progress-pct]').forEach(function (el) {
          el.style.width = el.dataset.progressPct + '%';
        });
        tableWrap.querySelectorAll('[data-cancel-job]').forEach(function (btn) {
          btn.addEventListener('click', function () {
            var jobId = btn.dataset.cancelJob;
            if (!confirm('Cancel this job?')) return;
            btn.disabled = true;
            var origText = btn.textContent;
            btn.textContent = 'Cancelling\u2026';
            apiDelete(API + '/jobs/' + encodeURIComponent(jobId))
              .then(function () { loadJobs(); })
              .catch(function (err) { alert('Failed to cancel job: ' + err.message); })
              .finally(function () { btn.disabled = false; btn.textContent = origText; });
          });
        });
      }).catch(function (err) {
        tableWrap.innerHTML = '<div class="alert alert-danger">' + escHtml(err.message) + '</div>';
      });
    }

    refreshBtn.addEventListener('click', loadJobs);
    loadJobs();

    // Register with the global poller so auto-refresh works whenever polling runs
    _jobsPageRefreshCallback = loadJobs;
    // Clear callback when navigating away
    var cleanupTimer = setInterval(function () {
      if (!document.contains(container)) {
        _jobsPageRefreshCallback = null;
        clearInterval(cleanupTimer);
      }
    }, 1000);
  }

  function renderQueryPlansPage(container) {
    var LATENCY_THRESHOLD_GREEN_MS = 10;
    var LATENCY_THRESHOLD_AMBER_MS = 100;

    var hdr = el('div', { className: 'd-flex align-items-center gap-3 mb-3 flex-wrap' });
    hdr.appendChild(el('h2', { className: 'mb-0', textContent: '\uD83D\uDCCA Query Plan History' }));
    var refreshBtn = el('button', { className: 'btn btn-outline-secondary btn-sm', textContent: '\u21BB Refresh' });
    hdr.appendChild(refreshBtn);
    container.appendChild(hdr);
    container.appendChild(el('p', { className: 'text-muted', textContent: 'Shows the last 100 query plan executions. Each entry includes the optimised execution steps, cardinality estimates, index usage, and missing-index recommendations.' }));

    var listWrap = el('div');
    container.appendChild(listWrap);

    function stepBadge(stepType) {
      var colours = { LoadEntity: 'primary', HashJoin: 'info', PostJoinFilter: 'warning', ProjectAndSort: 'secondary' };
      var colour = colours[stepType] || 'dark';
      return '<span class="badge bg-' + colour + '">' + escHtml(stepType) + '</span>';
    }

    function renderPlan(entry) {
      var wrap = el('div', { className: 'card mb-3' });
      var body = el('div', { className: 'card-body' });

      // Header row
      var hdrRow = el('div', { className: 'd-flex flex-wrap gap-3 align-items-baseline mb-2' });
      hdrRow.appendChild(el('strong', { textContent: entry.rootEntity || '—' }));
      var badges = el('span');
      badges.innerHTML =
        '<span class="badge bg-secondary">' + (entry.joinCount || 0) + ' join(s)</span> ' +
        '<span class="badge bg-secondary">' + (entry.resultRowCount || 0) + ' rows</span> ' +
        '<span class="badge bg-' + (entry.elapsedMs < LATENCY_THRESHOLD_GREEN_MS ? 'success' : entry.elapsedMs < LATENCY_THRESHOLD_AMBER_MS ? 'warning' : 'danger') + '">' +
        escHtml(String(entry.elapsedMs)) + ' ms</span>' +
        (entry.joinOrderOptimised ? ' <span class="badge bg-info text-dark">join-order optimised</span>' : '') +
        (entry.canStreamAggregate ? ' <span class="badge bg-info text-dark">stream aggregate</span>' : '');
      hdrRow.appendChild(badges);
      var ts = el('small', { className: 'text-muted ms-auto', textContent: new Date(entry.executedAt).toLocaleString() });
      hdrRow.appendChild(ts);
      body.appendChild(hdrRow);

      // Steps graph
      var stepsWrap = el('div', { className: 'mb-2' });
      (entry.steps || []).forEach(function (s, i) {
        var stepEl = el('div', { className: 'border rounded p-2 mb-1 bg-light' });
        var stepHdr = el('div', { className: 'd-flex flex-wrap gap-2 align-items-center' });
        stepHdr.innerHTML =
          '<span class="fw-semibold">' + (i + 1) + '.</span> ' + stepBadge(s.stepType) +
          ' <span class="text-muted small">' + escHtml(s.entitySlug) + '</span>' +
          (s.estimatedRows > 0 ? ' <span class="text-muted small">~' + escHtml(String(s.estimatedRows)) + ' rows</span>' : '');
        if (s.indexedFields && s.indexedFields.length > 0) {
          var idxSpan = el('span', { className: 'text-muted small' });
          idxSpan.innerHTML = '\uD83D\uDD0D indexed: ' + s.indexedFields.map(function (f) { return '<code>' + escHtml(f) + '</code>'; }).join(', ');
          stepHdr.appendChild(idxSpan);
        }
        stepEl.appendChild(stepHdr);
        if (s.join) {
          var joinEl = el('div', { className: 'text-muted small mt-1' });
          joinEl.innerHTML =
            escHtml(s.join.joinType) + ' JOIN ' +
            '<code>' + escHtml(s.join.fromEntity) + '.' + escHtml(s.join.fromField) + '</code> → ' +
            '<code>' + escHtml(s.join.toField) + '</code>' +
            (s.join.buildSideIndexed ? ' <span class="badge bg-success text-white">indexed build side</span>' : ' <span class="badge bg-warning text-dark">unindexed build</span>');
          stepEl.appendChild(joinEl);
        }
        stepsWrap.appendChild(stepEl);
      });
      body.appendChild(stepsWrap);

      // Missing index recommendations
      var recs = entry.missingIndexRecommendations || [];
      if (recs.length > 0) {
        var recHdr = el('div', { className: 'd-flex align-items-center gap-2 mb-1' });
        recHdr.innerHTML = '<span class="fw-semibold text-warning">\u26A0\uFE0F Missing Index Recommendations</span>';
        body.appendChild(recHdr);
        var recUl = el('ul', { className: 'list-group list-group-flush mb-1' });
        recs.forEach(function (r) {
          var li = el('li', { className: 'list-group-item list-group-item-warning py-1' });
          li.innerHTML =
            '<code>' + escHtml(r.entitySlug) + '.' + escHtml(r.fieldName) + '</code> — ' +
            escHtml(r.reason);
          recUl.appendChild(li);
        });
        body.appendChild(recUl);
      }

      wrap.appendChild(body);
      return wrap;
    }

    function loadPlans() {
      apiFetch(API + '/admin/query-plans').then(function (plans) {
        listWrap.innerHTML = '';
        if (!Array.isArray(plans) || plans.length === 0) {
          listWrap.innerHTML = '<p class="text-muted">No query plans recorded yet. Run a report query to see plan history here.</p>';
          return;
        }
        plans.forEach(function (entry) {
          listWrap.appendChild(renderPlan(entry));
        });
      }).catch(function (err) {
        listWrap.innerHTML = '<div class="alert alert-danger">' + escHtml(err.message) + '</div>';
      });
    }

    refreshBtn.addEventListener('click', loadPlans);
    loadPlans();
  }

  // ── Dashboard / KPI view ──────────────────────────────────────────────────

  function renderDashboardsListPage(container) {
    container.appendChild(el('h2', { className: 'mb-3', textContent: '\uD83D\uDCCA Dashboards' }));
    container.appendChild(el('p', { className: 'text-muted', textContent: 'Executive KPI dashboards with live aggregate tiles. Create and manage dashboards via Dashboard Definitions.' }));

    var addLink = el('a', { href: BASE + '/dashboard-definitions/create', className: 'btn btn-sm btn-primary mb-3', textContent: '+ New Dashboard' });
    addLink.setAttribute('data-go', '');
    container.appendChild(addLink);

    var listWrap = el('div');
    container.appendChild(listWrap);

    apiFetch('/api/dashboards')
      .then(function (dashboards) {
        listWrap.innerHTML = '';
        if (!Array.isArray(dashboards) || dashboards.length === 0) {
          listWrap.innerHTML = '<div class="bm-empty-state"><i class="bi bi-speedometer2"></i><p>No dashboards defined yet</p><small>Create one via <a href="' + BASE + '/dashboard-definitions/create" data-go>Dashboard Definitions</a></small></div>';
          wire();
          return;
        }
        var row = el('div', { className: 'row g-3' });
        dashboards.forEach(function (d) {
          var card = el('div', { className: 'col-sm-6 col-md-4 col-lg-3' });
          var inner = el('div', { className: 'card h-100' });
          var body = el('div', { className: 'card-body' });
          body.appendChild(el('h5', { className: 'card-title', innerHTML: '<i class="bi bi-speedometer2 me-2"></i>' + escHtml(d.name) }));
          if (d.description) body.appendChild(el('p', { className: 'card-text text-muted small', textContent: d.description }));
          body.appendChild(el('p', { className: 'card-text', innerHTML: '<small class="text-muted">' + escHtml(String(d.tileCount)) + ' KPI tile' + (d.tileCount !== 1 ? 's' : '') + '</small>' }));
          var footer = el('div', { className: 'card-footer d-flex gap-2' });
          var viewBtn = el('a', { href: BASE + '/_dashboards/' + encodeURIComponent(String(d.id)), className: 'btn btn-sm btn-primary', innerHTML: '<i class="bi bi-eye"></i> View' });
          viewBtn.setAttribute('data-go', '');
          footer.appendChild(viewBtn);
          var editBtn = el('a', { href: BASE + '/dashboard-definitions/' + encodeURIComponent(String(d.id)) + '/edit', className: 'btn btn-sm btn-outline-secondary', innerHTML: '<i class="bi bi-pencil"></i> Edit' });
          editBtn.setAttribute('data-go', '');
          footer.appendChild(editBtn);
          inner.appendChild(body);
          inner.appendChild(footer);
          card.appendChild(inner);
          row.appendChild(card);
        });
        listWrap.appendChild(row);
        wire();
      })
      .catch(function (err) {
        listWrap.innerHTML = '<div class="alert alert-danger">' + escHtml(err.message) + '</div>';
      });
  }

  function renderDashboardViewPage(container, dashId) {
    var hdr = el('div', { className: 'd-flex align-items-center gap-3 mb-3 flex-wrap' });
    hdr.appendChild(el('h2', { className: 'mb-0', textContent: '\uD83D\uDCCA Dashboard' }));
    var backLink = el('a', { href: BASE + '/_dashboards', className: 'btn btn-outline-secondary btn-sm', innerHTML: '<i class="bi bi-arrow-left"></i> All Dashboards' });
    backLink.setAttribute('data-go', '');
    hdr.appendChild(backLink);
    var refreshBtn = el('button', { className: 'btn btn-outline-secondary btn-sm', innerHTML: '<i class="bi bi-arrow-clockwise"></i> Refresh' });
    hdr.appendChild(refreshBtn);
    container.appendChild(hdr);

    var descEl = el('p', { className: 'text-muted' });
    container.appendChild(descEl);

    var tilesWrap = el('div', { className: 'row g-3', id: 'bm-dashboard-tiles' });
    container.appendChild(tilesWrap);

    function colorToBs(color) {
      var allowed = ['primary','success','danger','warning','info','secondary','dark','light'];
      return allowed.includes(color) ? color : 'primary';
    }

    function buildSparklineSvg(bars, color) {
      if (!bars || bars.length === 0) return '';
      var max = Math.max.apply(null, bars.map(function(b){return b.value;}));
      if (max <= 0) max = 1;
      var w = 160, h = 40, pad = 2;
      var barW = Math.max(1, Math.floor((w - pad * (bars.length + 1)) / bars.length));
      var cssColors = { success: '#198754', danger: '#dc3545', warning: '#ffc107', info: '#0dcaf0', secondary: '#6c757d' };
      var fill = cssColors[color] || '#0d6efd';
      var svg = '<svg viewBox="0 0 ' + w + ' ' + h + '" width="' + w + '" height="' + h + '" aria-hidden="true">';
      bars.forEach(function (b, i) {
        var barH = Math.max(1, Math.round((b.value / max) * (h - 2)));
        var x = pad + i * (barW + pad);
        var y = h - barH;
        svg += '<rect x="' + x + '" y="' + y + '" width="' + barW + '" height="' + barH + '" fill="' + fill + '" opacity="0.7" rx="1"><title>' + escHtml(b.label) + ': ' + b.value + '</title></rect>';
      });
      svg += '</svg>';
      return svg;
    }

    function renderTiles(data) {
      tilesWrap.innerHTML = '';
      if (data.name) hdr.querySelector('h2').textContent = '\uD83D\uDCCA ' + data.name;
      if (data.description) descEl.textContent = data.description;
      if (!data.tiles || data.tiles.length === 0) {
        tilesWrap.innerHTML = '<div class="col-12"><div class="bm-empty-state"><i class="bi bi-speedometer2"></i><p>No KPI tiles configured</p></div></div>';
        return;
      }
      data.tiles.forEach(function (t, idx) {
        var color = colorToBs(t.color);
        var col = el('div', { className: 'col-6 col-md-4 col-lg-3' });
        col.innerHTML =
          '<div class="card border-' + color + ' h-100">' +
          '<div class="card-header bg-' + color + ' text-white d-flex align-items-center gap-2">' +
          '<i class="bi ' + escHtml(t.icon || 'bi-bar-chart-fill') + '"></i> ' + escHtml(t.title || '') +
          '</div>' +
          '<div class="card-body text-center py-4">' +
          '<div class="display-5 fw-bold" id="bm-kpi-value-' + idx + '">' + escHtml(t.displayValue || '—') + '</div>' +
          (t.sparkline && t.sparkline.length > 0 ? '<div class="mt-2">' + buildSparklineSvg(t.sparkline, color) + '</div>' : '') +
          '</div></div>';
        tilesWrap.appendChild(col);
      });
    }

    function loadDashboard() {
      apiFetch('/api/dashboards/' + encodeURIComponent(dashId))
        .then(function (data) { renderTiles(data); wire(); })
        .catch(function (err) {
          tilesWrap.innerHTML = '<div class="col-12"><div class="alert alert-danger">' + escHtml(err.message) + '</div></div>';
        });
    }

    refreshBtn.addEventListener('click', loadDashboard);
    loadDashboard();

    // Auto-refresh every 60 seconds; use module-level variable so route() can clear it on navigation.
    _dashboardRefreshHandle = setInterval(loadDashboard, 60000);
  }

  async function route() {
    // Cancel any in-flight navigation fetches from the previous route
    cancelNavigation();

    const p      = location.pathname.replace(/^\//, '').split('/').filter(Boolean);
    const slug   = p[0], rawId = p[1], action = p[2];
    const id     = (rawId && rawId !== 'create') ? rawId : null;

    // Clear any running dashboard auto-refresh on every navigation.
    if (_dashboardRefreshHandle !== null) {
      clearInterval(_dashboardRefreshHandle);
      _dashboardRefreshHandle = null;
    }

    R.replaceChildren(
      el('div', { className: 'd-flex justify-content-center mt-5' }, [
        el('div', { className: 'spinner-border', role: 'status' }, [
          el('span', { className: 'visually-hidden', textContent: 'Loading\u2026' })
        ])
      ])
    );

    try {
      if (!_entityList) _entityList = await BareMetalRendering.listEntities();

      // ── Home: entity cards ───────────────────────────────────────────────
      if (!slug) {
        R.replaceChildren(navbar());
        const container = el('div', { className: 'container' });
        const row = el('div', { className: 'row g-3 mt-1' });
        (_entityList || []).filter(e => e.showOnNav).forEach(e => {
          const card = el('a', { className: 'card card-body text-decoration-none', href: BASE + '/' + e.slug });
          card.setAttribute('data-go', '');
          card.appendChild(el('strong', { textContent: e.name }));
          card.appendChild(el('p', { className: 'text-muted small mb-0', textContent: e.navGroup || '' }));
          row.appendChild(el('div', { className: 'col-sm-6 col-md-3' }, [card]));
        });
        container.appendChild(row);
        R.appendChild(container);
        wire(); return;
      }

      // ── Inbox page ─────────────────────────────────────────────────────────
      if (slug === '_inbox') {
        R.replaceChildren(navbar('_inbox'));
        const main = el('div', { className: 'container mt-3' });
        R.appendChild(main);
        renderInboxPage(main);
        wire(); return;
      }

      // ── Background Jobs page ──────────────────────────────────────────────
      if (slug === '_jobs') {
        R.replaceChildren(navbar('_jobs'));
        const main = el('div', { className: 'container mt-3' });
        R.appendChild(main);
        renderJobsPage(main);
        wire(); return;
      }

      // ── Generate Sample Data page ─────────────────────────────────────────
      if (slug === '_sample-data') {
        R.replaceChildren(navbar('_sample-data'));
        const main = el('div', { className: 'container mt-3' });
        R.appendChild(main);
        renderSampleDataPage(main);
        wire(); return;
      }

      // ── Wipe All Data page ────────────────────────────────────────────────
      if (slug === '_wipe-data') {
        R.replaceChildren(navbar('_wipe-data'));
        const main = el('div', { className: 'container mt-3' });
        R.appendChild(main);
        renderWipeDataPage(main);
        wire(); return;
      }

      // ── Query Plan History page ───────────────────────────────────────────
      if (slug === '_query-plans') {
        R.replaceChildren(navbar('_query-plans'));
        const main = el('div', { className: 'container mt-3' });
        R.appendChild(main);
        renderQueryPlansPage(main);
        wire(); return;
      }

      // ── Dashboards list page ──────────────────────────────────────────────
      if (slug === '_dashboards' && !rawId) {
        R.replaceChildren(navbar('_dashboards'));
        const main = el('div', { className: 'container mt-3' });
        R.appendChild(main);
        renderDashboardsListPage(main);
        wire(); return;
      }

      // ── Individual dashboard view ─────────────────────────────────────────
      if (slug === '_dashboards' && rawId) {
        R.replaceChildren(navbar('_dashboards'));
        const main = el('div', { className: 'container mt-3' });
        R.appendChild(main);
        renderDashboardViewPage(main, rawId);
        wire(); return;
      }

      const entity = await BareMetalRendering.createEntity(slug);
      R.replaceChildren(navbar(slug));
      const main = el('div', { className: 'container' });
      R.appendChild(main);

      if (!rawId) {
        // ── List view ───────────────────────────────────────────────────────
        const items  = await BareMetalRest.entity(slug).list();
        const allItems = Array.isArray(items) ? items : [];
        const schemaFields = entity.meta.schema?.fields || {};

        const hdr = el('div', { className: 'd-flex gap-2 align-items-center mb-3 flex-wrap' });
        hdr.appendChild(el('h2', { className: 'mb-0 me-2', textContent: entity.meta.name || slug }));
        const addBtn = el('a', { href: BASE + '/' + slug + '/create', className: 'btn btn-success btn-sm', textContent: '+ Add' });
        addBtn.setAttribute('data-go', '');
        hdr.appendChild(addBtn);

        // Edit mode toggle
        let editModeActive = false;
        const editModeBtn = el('button', { className: 'btn btn-outline-secondary btn-sm', textContent: '\u270F Edit Mode' });

        const buildReadTable = () => BareMetalTemplate.buildTable(schemaFields, allItems, {
          resolve:  (name, v) => entity.resolve(name, v),
          onView:   i => go(`${BASE}/${slug}/${i}`),
          onEdit:   i => go(`${BASE}/${slug}/${i}/edit`),
          onDelete: async i => {
            if (!confirm('Delete this record? This cannot be undone.')) return;
            try { await BareMetalRest.entity(slug).remove(i); go(`${BASE}/${slug}`); }
            catch (err) { alert('Delete failed: ' + err.message); }
          }
        });

        const buildEditTable = () => {
          const mkEl = (tag, props) => Object.assign(document.createElement(tag), props);
          const names = Object.keys(schemaFields).filter(n => {
            const f = schemaFields[n]; return f && !f.readonly && f.type !== 'hidden';
          }).slice(0, 6);
          const wrap = mkEl('div', { className: 'table-responsive' });
          const tbl  = mkEl('table', { className: 'table table-hover table-sm align-middle' });
          const hrow = tbl.createTHead().insertRow();
          names.forEach(n => hrow.appendChild(mkEl('th', { textContent: schemaFields[n]?.label || n })));
          hrow.appendChild(mkEl('th', { className: 'text-end' }));
          const tbody = tbl.createTBody();
          allItems.forEach(item => {
            const tr = tbody.insertRow();
            const rowData = Object.assign({}, item);
            names.forEach(n => {
              const td = tr.insertCell();
              const f = schemaFields[n];
              let inp;
              if (f?.type === 'boolean') {
                inp = mkEl('input', { type: 'checkbox', className: 'form-check-input' });
                inp.checked = !!rowData[n];
                inp.addEventListener('change', () => { rowData[n] = inp.checked; });
              } else {
                inp = mkEl('input', { type: 'text', className: 'form-control form-control-sm', value: String(rowData[n] ?? '') });
                inp.addEventListener('input', () => { rowData[n] = inp.value; });
              }
              td.appendChild(inp);
            });
            const td = tr.insertCell(); td.className = 'text-end text-nowrap';
            const rowId = item.id || item.Id || '';
            const saveBtn = mkEl('button', { className: 'btn btn-sm btn-success', title: 'Save row' });
            saveBtn.innerHTML = '<i class="bi bi-check-lg"></i>';
            saveBtn.onclick = async () => {
              try {
                saveBtn.disabled = true;
                await BareMetalRest.entity(slug).update(rowId, rowData);
                saveBtn.className = 'btn btn-sm btn-success';
              } catch (err) { alert('Save failed: ' + err.message); }
              finally { saveBtn.disabled = false; }
            };
            td.appendChild(saveBtn);
          });
          wrap.appendChild(tbl);
          return wrap;
        };

        let tableWrap = buildReadTable();
        editModeBtn.addEventListener('click', () => {
          editModeActive = !editModeActive;
          editModeBtn.textContent = editModeActive ? '\u2715 View Mode' : '\u270F Edit Mode';
          editModeBtn.className = 'btn btn-sm ' + (editModeActive ? 'btn-secondary' : 'btn-outline-secondary');
          const newTable = editModeActive ? buildEditTable() : buildReadTable();
          tableWrap.replaceWith(newTable);
          tableWrap = newTable;
        });
        hdr.appendChild(editModeBtn);

        main.appendChild(hdr);
        main.appendChild(tableWrap);

      } else {
        // ── Create / Edit / View ─────────────────────────────────────────────
        const isCreate = rawId === 'create';
        const isEdit   = !isCreate && action === 'edit';
        const isView   = !isCreate && !isEdit;

        if (id) await entity.load(id);

        const hdr = el('div', { className: 'd-flex justify-content-between align-items-center mb-3 gap-2 flex-wrap' });
        const title = isCreate ? 'New' : isEdit ? 'Edit' : '';
        hdr.appendChild(el('h2', { textContent: (title ? title + ' ' : '') + (entity.meta.name || slug) }));

        const back = el('a', {
          href: isView ? `${BASE}/${slug}` : id ? `${BASE}/${slug}/${id}` : `${BASE}/${slug}`,
          className: 'btn btn-secondary btn-sm',
          textContent: '\u2190 Back'
        });
        back.setAttribute('data-go', '');
        hdr.appendChild(back);

        if (isView && id) {
          const editBtn = el('a', { href: `${BASE}/${slug}/${id}/edit`, className: 'btn btn-primary btn-sm', textContent: '\u270F Edit' });
          editBtn.setAttribute('data-go', '');
          hdr.appendChild(editBtn);

          // Clone and Clone & Edit buttons
          const cloneRecord = async (andEdit) => {
            try {
              const rec = await BareMetalRest.entity(slug).get(id);
              if (!rec) return;
              delete rec.id; delete rec.Id;
              const created = await BareMetalRest.entity(slug).create(rec);
              const newId = created?.id || created?.Id;
              go(newId ? `${BASE}/${slug}/${newId}${andEdit ? '/edit' : ''}` : `${BASE}/${slug}`);
            } catch (err) { alert('Clone failed: ' + err.message); }
          };
          const cloneBtn = el('button', { className: 'btn btn-outline-secondary btn-sm', textContent: '\u29C9 Clone' });
          cloneBtn.addEventListener('click', () => cloneRecord(false));
          hdr.appendChild(cloneBtn);
          const cloneEditBtn = el('button', { className: 'btn btn-outline-secondary btn-sm', textContent: '\u29C9 Clone & Edit' });
          cloneEditBtn.addEventListener('click', () => cloneRecord(true));
          hdr.appendChild(cloneEditBtn);
        }

        main.appendChild(hdr);

        if (isView) {
          const dl = el('dl', { className: 'row' });
          Object.entries(entity.meta.schema?.fields || {}).forEach(([name, f]) => {
            if (!f || f.type === 'hidden') return;
            const dt = el('dt', { className: 'col-sm-3 fw-semibold', textContent: f.label || name });
            const v  = entity.state[name];
            const display = entity.resolve(name, v);
            const dd = el('dd', { className: 'col-sm-9' });
            if (v == null || v === '') {
              dd.textContent = '\u2014';
            } else if (f.lookupUrl) {
              const targetSlug = lookupSlug(f.lookupUrl);
              const a = el('a', { href: `${BASE}/${targetSlug}/${encodeURIComponent(String(v))}`, textContent: display });
              a.setAttribute('data-go', '');
              dd.appendChild(a);
            } else if (f.type === 'boolean') {
              dd.innerHTML = isBoolTrue(v)
                ? '<span class="badge bg-success">Yes</span>'
                : '<span class="badge bg-secondary">No</span>';
            } else {
              dd.textContent = display;
            }
            dl.append(dt, dd);
          });
          main.appendChild(dl);

        } else {
          entity.renderUI(main);
          // Wire lookup Refresh buttons added by BareMetalTemplate for select fields
          main.addEventListener('click', async e => {
            const refBtn = e.target.closest('[data-lookup-refresh]');
            if (!refBtn) return;
            e.preventDefault();
            const fieldName = refBtn.dataset.lookupRefresh;
            const lookupUrl = refBtn.dataset.lookupUrl;
            const valueField = refBtn.dataset.lookupValueField;
            const displayField = refBtn.dataset.lookupDisplayField;
            const sel = main.querySelector(`select[rv-value="${fieldName}"]`);
            if (!sel) return;
            refBtn.disabled = true;
            try {
              const raw = await BareMetalRest.call('GET', lookupUrl);
              const list = Array.isArray(raw) ? raw : (raw?.data || []);
              const cur = sel.value;
              sel.innerHTML = '<option value="">— Select —</option>';
              list.forEach(i => {
                const o = document.createElement('option');
                o.value = String(i[valueField] ?? i.id ?? i.Id ?? '');
                o.textContent = String(i[displayField] ?? i.Name ?? i.name ?? '');
                if (o.value === cur) o.selected = true;
                sel.appendChild(o);
              });
            } catch (err) { alert('Refresh failed: ' + err.message); }
            finally { refBtn.disabled = false; }
          });
          entity.state.save = async () => {
            try {
              await entity.save();
              const savedId = entity.state.id || entity.state.Id;
              go(savedId ? `${BASE}/${slug}/${savedId}` : `${BASE}/${slug}`);
            } catch (err) {
              main.prepend(el('div', { className: 'alert alert-danger mt-2', textContent: err.message }));
            }
          };
        }
      }

      wire();
    } catch (e) {
      R.replaceChildren(
        el('div', { className: 'container mt-3' }, [
          el('div', { className: 'alert alert-danger', textContent: e.message })
        ])
      );
    }
  }

  route();
})();
