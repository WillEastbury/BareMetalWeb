// vnext-app.js — BareMetalWeb VNext client-side rendering engine
// Consumes /meta/* and /api/* to render full CRUD UI without any server-side HTML templating.
// Requires BareMetalRouting.js and Bootstrap 5 to be loaded first.
(function (global) {
    'use strict';

    // ── Configuration ─────────────────────────────────────────────────────────
    var BASE = '/vnext';
    var API  = '/api';
    var META = '/meta';
    var LOOKUP_CARDINALITY_THRESHOLD = 20; // above this count, show a search dialog

    // ── CSRF support ──────────────────────────────────────────────────────────
    function getCsrfToken() {
        var el = document.querySelector('meta[name="csrf-token"]');
        return el ? el.getAttribute('content') : '';
    }

    // ── Metadata cache ────────────────────────────────────────────────────────
    var _metaObjects = null;
    var _metaCache   = {};

    function fetchMetaObjects() {
        if (_metaObjects) return Promise.resolve(_metaObjects);
        return apiFetch(META + '/objects').then(function (data) {
            _metaObjects = data;
            return data;
        });
    }

    function fetchMeta(slug) {
        if (_metaCache[slug]) return Promise.resolve(_metaCache[slug]);
        return apiFetch(META + '/' + encodeURIComponent(slug)).then(function (data) {
            _metaCache[slug] = data;
            return data;
        });
    }

    // ── Lookup cache ──────────────────────────────────────────────────────────
    var _lookupCache = {};

    function fetchLookupOptions(targetSlug, queryField, queryValue, sortField, sortDir) {
        var key = targetSlug + '|' + (queryField || '') + '|' + (queryValue || '') + '|' + (sortField || '') + '|' + (sortDir || '');
        if (_lookupCache[key]) return Promise.resolve(_lookupCache[key]);

        var params = [];
        if (queryField && queryValue) params.push('f_' + encodeURIComponent(queryField) + '=' + encodeURIComponent(queryValue));
        if (sortField) { params.push('sort=' + encodeURIComponent(sortField)); }
        if (sortDir)   { params.push('dir='  + encodeURIComponent(sortDir)); }
        params.push('top=500');

        var url = API + '/' + encodeURIComponent(targetSlug) + (params.length ? '?' + params.join('&') : '');
        return apiFetch(url).then(function (items) {
            _lookupCache[key] = Array.isArray(items) ? items : (items.items || []);
            return _lookupCache[key];
        });
    }

    function clearLookupCache(slug) {
        Object.keys(_lookupCache).forEach(function (k) {
            if (k.indexOf(slug + '|') === 0) delete _lookupCache[k];
        });
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────
    function apiFetch(url, options) {
        var opts = Object.assign({ credentials: 'same-origin', headers: {} }, options || {});
        opts.headers['Accept'] = 'application/json';
        if (opts.method && opts.method !== 'GET') {
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
            return r.json();
        });
    }

    function apiPost(url, body)   { return apiFetch(url, { method: 'POST',   headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); }
    function apiPut(url, body)    { return apiFetch(url, { method: 'PUT',    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); }
    function apiDelete(url)       { return apiFetch(url, { method: 'DELETE' }); }

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
        var cls = type === 'error' ? 'bg-danger text-white' : type === 'warning' ? 'bg-warning' : 'bg-success text-white';
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

    function escHtml(str) {
        if (str == null) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function fmtValue(val, fieldType) {
        if (val == null || val === '') return '<span class="text-muted">—</span>';
        if (fieldType === 'YesNo' || fieldType === 'Boolean') {
            return val === true || val === 'true' || val === 1
                ? '<span class="badge bg-success">Yes</span>'
                : '<span class="badge bg-secondary">No</span>';
        }
        if (fieldType === 'Password') return '<span class="text-muted">••••••••</span>';
        if (fieldType === 'Image') {
            if (typeof val === 'object' && val.url) return '<img src="' + escHtml(val.url) + '" class="img-thumbnail" style="max-height:48px" alt="">';
            return escHtml(String(val));
        }
        if (typeof val === 'object') return '<code>' + escHtml(JSON.stringify(val)) + '</code>';
        return escHtml(String(val));
    }

    function nestedGet(obj, path) {
        if (!obj || !path) return undefined;
        var parts = path.split('.');
        var cur = obj;
        for (var i = 0; i < parts.length; i++) {
            if (cur == null) return undefined;
            cur = cur[parts[i]];
        }
        return cur;
    }

    // ── Navigation builder ────────────────────────────────────────────────────
    function buildNav(entities) {
        var navEl = document.getElementById('vnext-nav-items');
        if (!navEl) return;

        var groups = {};
        entities.forEach(function (e) {
            if (!e.showOnNav) return;
            var g = e.navGroup || 'Other';
            if (!groups[g]) groups[g] = [];
            groups[g].push(e);
        });

        var html = '';
        Object.keys(groups).sort().forEach(function (groupName) {
            var items = groups[groupName];
            if (items.length === 1) {
                html += '<li class="nav-item"><a class="nav-link" href="' + BASE + '/admin/data/' + escHtml(items[0].slug) + '">' + escHtml(items[0].name) + '</a></li>';
            } else {
                html += '<li class="nav-item dropdown">';
                html += '<a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">' + escHtml(groupName) + '</a>';
                html += '<ul class="dropdown-menu dropdown-menu-dark">';
                items.sort(function (a, b) { return (a.navOrder || 0) - (b.navOrder || 0) || a.name.localeCompare(b.name); })
                     .forEach(function (e) {
                        html += '<li><a class="dropdown-item" href="' + BASE + '/admin/data/' + escHtml(e.slug) + '">' + escHtml(e.name) + '</a></li>';
                     });
                html += '</ul></li>';
            }
        });
        navEl.innerHTML = html;
    }

    // ── Home view ─────────────────────────────────────────────────────────────
    function renderHome() {
        fetchMetaObjects().then(function (entities) {
            var html = '<div class="p-4"><h2>Data Objects</h2><div class="row row-cols-1 row-cols-md-3 g-3 mt-2">';
            entities.filter(function (e) { return e.showOnNav; })
                    .sort(function (a, b) { return (a.navOrder || 0) - (b.navOrder || 0) || a.name.localeCompare(b.name); })
                    .forEach(function (e) {
                        html += '<div class="col"><div class="card h-100">' +
                            '<div class="card-body">' +
                            '<h5 class="card-title">' + escHtml(e.name) + '</h5>' +
                            '<p class="card-text text-muted small">' + escHtml(e.navGroup || '') + '</p>' +
                            '</div>' +
                            '<div class="card-footer">' +
                            '<a class="btn btn-primary btn-sm" href="' + BASE + '/admin/data/' + escHtml(e.slug) + '">Open</a>' +
                            '</div></div></div>';
                    });
            html += '</div></div>';
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

        fetchMeta(slug).then(function (meta) {
            // Build API query
            var params = ['skip=' + skip, 'top=' + top];
            if (search)  params.push('q=' + encodeURIComponent(search));
            if (sort)    params.push('sort=' + encodeURIComponent(sort), 'dir=' + encodeURIComponent(dir));
            // Per-field filters from query string
            meta.fields.filter(function (f) { return f.list; }).forEach(function (f) {
                var v = query['f_' + f.name];
                if (v) params.push('f_' + encodeURIComponent(f.name) + '=' + encodeURIComponent(v));
            });

            return apiFetch(API + '/' + encodeURIComponent(slug) + '?' + params.join('&'))
                .then(function (result) { renderListResult(meta, result, slug, query, skip, top, search, sort, dir); });
        }).catch(function (err) { showError(err.message); });
    }

    function renderListResult(meta, result, slug, query, skip, top, search, sort, dir) {
        var items = Array.isArray(result) ? result : (result.items || []);
        var total = (result && result.total != null) ? result.total : items.length;
        var listFields = meta.fields.filter(function (f) { return f.list; }).sort(function (a, b) { return a.order - b.order; });

        var baseUrl = BASE + '/admin/data/' + encodeURIComponent(slug);

        function buildSortUrl(fieldName) {
            var newDir = (sort === fieldName && dir === 'asc') ? 'desc' : 'asc';
            return buildUrl(baseUrl, Object.assign({}, query, { sort: fieldName, dir: newDir, skip: 0 }));
        }

        var html = '<div class="p-3">';
        // Breadcrumb
        html += '<nav aria-label="breadcrumb"><ol class="breadcrumb"><li class="breadcrumb-item"><a href="' + BASE + '">Home</a></li>';
        html += '<li class="breadcrumb-item active">' + escHtml(meta.name) + '</li></ol></nav>';

        // Title + action bar
        html += '<div class="d-flex align-items-center mb-3 flex-wrap gap-2">';
        html += '<h2 class="mb-0 me-3">' + escHtml(meta.name) + '</h2>';
        html += '<a class="btn btn-primary btn-sm" href="' + baseUrl + '/create"><i class="bi bi-plus-lg"></i> New</a>';
        html += '<a class="btn btn-outline-secondary btn-sm" href="' + API + '/' + encodeURIComponent(slug) + '?format=csv" download><i class="bi bi-filetype-csv"></i> CSV</a>';
        html += '<a class="btn btn-outline-secondary btn-sm" href="' + API + '/' + encodeURIComponent(slug) + '?format=json" download><i class="bi bi-filetype-json"></i> JSON</a>';
        html += '</div>';

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
        html += '<div class="table-responsive"><table class="table table-hover table-striped table-sm align-middle">';
        html += '<thead><tr>';
        html += '<th scope="col"><input type="checkbox" class="form-check-input" id="vnext-select-all" title="Select all"></th>';
        listFields.forEach(function (f) {
            var sortIcon = '';
            if (sort === f.name) sortIcon = dir === 'asc' ? ' <i class="bi bi-sort-up"></i>' : ' <i class="bi bi-sort-down"></i>';
            html += '<th scope="col"><a class="text-decoration-none text-reset" href="' + escHtml(buildSortUrl(f.name)) + '">' + escHtml(f.label) + sortIcon + '</a></th>';
        });
        html += '<th scope="col">Actions</th></tr></thead>';
        html += '<tbody>';

        if (items.length === 0) {
            html += '<tr><td colspan="' + (listFields.length + 2) + '" class="text-center text-muted py-4">No records found.</td></tr>';
        } else {
            items.forEach(function (item) {
                var id = item.id || item.Id || '';
                var encId = encodeURIComponent(id);
                html += '<tr data-id="' + escHtml(id) + '">';
                html += '<td><input type="checkbox" class="form-check-input vnext-row-select" value="' + escHtml(id) + '"></td>';
                listFields.forEach(function (f) {
                    var val = nestedGet(item, f.name) || nestedGet(item, f.name.charAt(0).toLowerCase() + f.name.slice(1));
                    html += '<td>' + fmtValue(val, f.type) + '</td>';
                });
                html += '<td class="text-nowrap">';
                html += '<a class="btn btn-xs btn-outline-info btn-sm me-1" href="' + baseUrl + '/' + encId + '" title="View"><i class="bi bi-eye"></i></a>';
                html += '<a class="btn btn-xs btn-outline-warning btn-sm me-1" href="' + baseUrl + '/' + encId + '/edit" title="Edit"><i class="bi bi-pencil"></i></a>';
                html += '<button class="btn btn-xs btn-outline-danger btn-sm vnext-row-delete" data-id="' + escHtml(id) + '" data-slug="' + escHtml(slug) + '" title="Delete"><i class="bi bi-trash"></i></button>';
                html += '</td></tr>';
            });
        }

        html += '</tbody></table></div>';

        // Pagination
        html += renderPagination(total, skip, top, baseUrl, query);

        html += '</div>';
        setContent(html);

        // Wire up events
        var form = document.getElementById('vnext-search-form');
        if (form) form.addEventListener('submit', function (e) {
            e.preventDefault();
            var q = form.querySelector('input[name=q]').value;
            BMRouter.navigate(buildUrl(baseUrl, { q: q, skip: 0, top: top, sort: sort, dir: dir }));
        });

        wireListEvents(slug, baseUrl, query, top, sort, dir);
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
        if (total <= top) return '';
        var pages = Math.ceil(total / top);
        var current = Math.floor(skip / top);
        var html = '<nav class="mt-3"><ul class="pagination pagination-sm">';

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
        var baseUrl  = BASE + '/admin/data/' + encodeURIComponent(slug);
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

        // Fields table
        html += '<div class="card"><div class="card-body"><dl class="row mb-0">';
        viewFields.forEach(function (f) {
            var val = nestedGet(item, f.name) || nestedGet(item, f.name.charAt(0).toLowerCase() + f.name.slice(1));

            if (isSubListField(val)) {
                html += '<dt class="col-sm-3">' + escHtml(f.label) + '</dt>';
                html += '<dd class="col-sm-9">' + renderSubListReadonly(val, f) + '</dd>';
            } else if (f.lookup && f.lookup.targetSlug) {
                html += '<dt class="col-sm-3">' + escHtml(f.label) + '</dt>';
                html += '<dd class="col-sm-9" data-lookup-field="' + escHtml(f.name) + '" data-target-slug="' + escHtml(f.lookup.targetSlug) + '" data-display-field="' + escHtml(f.lookup.displayField) + '" data-value="' + escHtml(String(val || '')) + '">' +
                    '<a href="' + BASE + '/admin/data/' + escHtml(f.lookup.targetSlug) + '/' + encodeURIComponent(val || '') + '">' + escHtml(String(val || '')) + '</a></dd>';
            } else {
                html += '<dt class="col-sm-3">' + escHtml(f.label) + '</dt>';
                html += '<dd class="col-sm-9">' + fmtValue(val, f.type) + '</dd>';
            }
        });
        html += '</dl></div></div>';
        html += '</div>';
        setContent(html);

        // Resolve lookup display values in background
        resolveViewLookups(slug);

        // Wire command buttons
        document.querySelectorAll('.vnext-cmd-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var cmdName = btn.dataset.cmd;
                var confirm = btn.dataset.confirm;
                var doRun = function () {
                    apiPost(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id) + '/_command/' + encodeURIComponent(cmdName), item)
                        .then(function (updated) {
                            showToast('Command executed.', 'success');
                            if (updated) renderViewResult(meta, updated, slug, id);
                        })
                        .catch(function (err) { showToast('Command failed: ' + err.message, 'error'); });
                };
                if (confirm) showConfirm('Run command?', confirm, doRun);
                else doRun();
            });
        });
    }

    function resolveViewLookups(slug) {
        document.querySelectorAll('[data-lookup-field]').forEach(function (el) {
            var targetSlug  = el.dataset.targetSlug;
            var displayField = el.dataset.displayField;
            var value       = el.dataset.value;
            if (!targetSlug || !value) return;
            apiFetch(API + '/_lookup/' + encodeURIComponent(targetSlug) + '/' + encodeURIComponent(value))
                .then(function (obj) {
                    if (obj) {
                        var display = nestedGet(obj, displayField) || nestedGet(obj, displayField.charAt(0).toLowerCase() + displayField.slice(1)) || value;
                        var href = BASE + '/admin/data/' + encodeURIComponent(targetSlug) + '/' + encodeURIComponent(value);
                        el.innerHTML = '<a href="' + escHtml(href) + '">' + escHtml(String(display)) + '</a>';
                    }
                })
                .catch(function () {});
        });
    }

    function isSubListField(val) {
        return Array.isArray(val) && val.length > 0 && typeof val[0] === 'object';
    }

    function renderSubListReadonly(items, field) {
        if (!items || items.length === 0) return '<span class="text-muted">None</span>';
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
    function renderCreate(slug) {
        showLoading();
        fetchMeta(slug)
            .then(function (meta) { renderFormView(meta, null, slug, null); })
            .catch(function (err) { showError(err.message); });
    }

    function renderEdit(slug, id) {
        showLoading();
        Promise.all([fetchMeta(slug), apiFetch(API + '/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id))])
            .then(function (r) { renderFormView(r[0], r[1], slug, id); })
            .catch(function (err) { showError(err.message); });
    }

    function renderFormView(meta, item, slug, id) {
        var isCreate = id == null;
        var baseUrl  = BASE + '/admin/data/' + encodeURIComponent(slug);
        var formFields = meta.fields.filter(function (f) { return isCreate ? f.create : f.edit; })
                                    .sort(function (a, b) { return a.order - b.order; });

        var html = '<div class="p-3">';
        // Breadcrumb
        html += '<nav aria-label="breadcrumb"><ol class="breadcrumb">' +
            '<li class="breadcrumb-item"><a href="' + BASE + '">Home</a></li>' +
            '<li class="breadcrumb-item"><a href="' + baseUrl + '">' + escHtml(meta.name) + '</a></li>' +
            '<li class="breadcrumb-item active">' + (isCreate ? 'New' : 'Edit') + '</li></ol></nav>';
        html += '<h2 class="mb-3">' + escHtml(meta.name) + ' — ' + (isCreate ? 'New Record' : 'Edit') + '</h2>';

        html += '<form id="vnext-editor-form" novalidate>';
        html += '<input type="hidden" name="__csrf" value="' + escHtml(getCsrfToken()) + '">';

        formFields.forEach(function (f) {
            var curVal = item ? (nestedGet(item, f.name) || nestedGet(item, f.name.charAt(0).toLowerCase() + f.name.slice(1))) : null;
            html += renderFormField(f, curVal, meta, item);
        });

        html += '<div class="mt-4 d-flex gap-2">';
        html += '<button type="submit" class="btn btn-primary" id="vnext-save-btn"><i class="bi bi-check-lg"></i> Save</button>';
        html += '<a class="btn btn-secondary" href="' + (id ? baseUrl + '/' + encodeURIComponent(id) : baseUrl) + '"><i class="bi bi-x-lg"></i> Cancel</a>';
        html += '</div></form></div>';

        setContent(html);
        initFormBehaviours(meta, item, slug, id, isCreate, formFields);
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
            return '<div class="mb-3">' + label +
                '<textarea class="form-control form-control-sm" id="' + id_ + '" name="' + escHtml(f.name) + '" rows="4"' + req + rdonly + placeholder + validation + '>' +
                escHtml(String(val != null ? val : '')) + '</textarea>' + feedback + '</div>';
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
        if (f.type === 'DateOnly')  { inputType = 'date'; }
        if (f.type === 'TimeOnly')  { inputType = 'time'; }
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
                '<input type="text" class="form-control" style="max-width:80px" name="' + escHtml(f.name) + '_currency" placeholder="USD" value="' + escHtml(String(moneyObj.currency || 'USD')) + '" maxlength="3">' +
                '</div>' + feedback + '</div>';
        }

        // Sub-list (List<T> child collection)
        if (f.type === 'CustomHtml') {
            var subItems = val;
            if (Array.isArray(subItems) && subItems.length > 0 && typeof subItems[0] === 'object') {
                return '<div class="mb-3">' + label + renderSubListEditor(f, subItems) + '</div>';
            }
            return '';
        }

        // Default: text input
        return '<div class="mb-3">' + label +
            '<input type="' + inputType + '" class="form-control form-control-sm" id="' + id_ + '" name="' + escHtml(f.name) + '"' +
            ' value="' + escHtml(inputVal) + '"' + req + rdonly + placeholder + validation + '>' +
            feedback + '</div>';
    }

    function renderSubListEditor(field, items) {
        if (!items || items.length === 0) return '<p class="text-muted">No items.</p>';
        var keys = Object.keys(items[0]).filter(function (k) { return k !== '__type'; });
        var html = '<div class="table-responsive"><table class="table table-sm table-bordered" id="sub_' + escHtml(field.name) + '">';
        html += '<thead><tr>' + keys.map(function (k) { return '<th>' + escHtml(k) + '</th>'; }).join('') + '<th></th></tr></thead>';
        html += '<tbody>';
        items.forEach(function (row, idx) {
            html += '<tr data-sub-idx="' + idx + '">' + keys.map(function (k) {
                return '<td><input type="text" class="form-control form-control-sm" name="' + escHtml(field.name) + '[' + idx + '].' + escHtml(k) + '" value="' + escHtml(String(row[k] != null ? row[k] : '')) + '"></td>';
            }).join('') + '<td><button type="button" class="btn btn-xs btn-outline-danger btn-sm vnext-sub-del" data-idx="' + idx + '"><i class="bi bi-trash"></i></button></td></tr>';
        });
        html += '</tbody></table>';
        html += '<button type="button" class="btn btn-sm btn-outline-primary mt-2 vnext-sub-add" data-field="' + escHtml(field.name) + '" data-keys="' + escHtml(keys.join(',')) + '"><i class="bi bi-plus"></i> Add Row</button>';
        html += '</div>';
        return html;
    }

    function initFormBehaviours(meta, item, slug, id, isCreate, formFields) {
        var form = document.getElementById('vnext-editor-form');
        if (!form) return;

        // Load lookup options async
        formFields.forEach(function (f) {
            if (f.type === 'LookupList' && f.lookup && f.lookup.targetSlug) {
                var curVal = item ? (nestedGet(item, f.name) || nestedGet(item, f.name.charAt(0).toLowerCase() + f.name.slice(1))) : null;
                loadLookupSelect(f, curVal);
            }
            // Load enum options
            if (f.type === 'Enum') {
                loadEnumOptions(f, item ? (nestedGet(item, f.name) || nestedGet(item, f.name.charAt(0).toLowerCase() + f.name.slice(1))) : null);
            }
        });

        // Lookup add/refresh buttons
        form.addEventListener('click', function (e) {
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
                            var curVal = sel ? sel.value : null;
                            loadLookupSelect(f, curVal);
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

            // Sub-list row delete
            var subDel = e.target.closest('.vnext-sub-del');
            if (subDel) {
                e.preventDefault();
                var row = subDel.closest('tr');
                if (row) row.remove();
            }

            // Sub-list add row
            var subAdd = e.target.closest('.vnext-sub-add');
            if (subAdd) {
                e.preventDefault();
                var fieldName = subAdd.dataset.field;
                var keys = subAdd.dataset.keys.split(',');
                var tbody = document.querySelector('#sub_' + fieldName + ' tbody');
                if (tbody) {
                    var idx = tbody.querySelectorAll('tr').length;
                    var newRow = '<tr data-sub-idx="' + idx + '">' + keys.map(function (k) {
                        return '<td><input type="text" class="form-control form-control-sm" name="' + escHtml(fieldName) + '[' + idx + '].' + escHtml(k) + '" value=""></td>';
                    }).join('') + '<td><button type="button" class="btn btn-xs btn-outline-danger btn-sm vnext-sub-del" data-idx="' + idx + '"><i class="bi bi-trash"></i></button></td></tr>';
                    tbody.insertAdjacentHTML('beforeend', newRow);
                }
            }
        });

        // Calculated field live update
        formFields.forEach(function (f) {
            if (f.calculated && f.calculated.expression) {
                var fieldEl = form.querySelector('#f_' + f.name);
                if (!fieldEl) return;
                form.addEventListener('input', function () {
                    try {
                        var vals = collectFormValues(form, formFields);
                        var result = evalExpression(f.calculated.expression, vals);
                        fieldEl.value = result != null ? String(result) : '';
                    } catch (ex) {}
                });
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
                var dest = savedId ? BASE + '/admin/data/' + encodeURIComponent(slug) + '/' + encodeURIComponent(savedId) : BASE + '/admin/data/' + encodeURIComponent(slug);
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
        fetchLookupOptions(lk.targetSlug, lk.queryField, lk.queryValue, lk.sortField, lk.sortDirection)
            .then(function (items) {
                if (items.length > LOOKUP_CARDINALITY_THRESHOLD) {
                    // Replace select with search-based input
                    renderLookupSearchInput(sel, field, items, currentValue);
                    return;
                }
                sel.innerHTML = '<option value="">— Select —</option>';
                items.forEach(function (opt) {
                    var optVal = nestedGet(opt, lk.valueField) || nestedGet(opt, lk.valueField.charAt(0).toLowerCase() + lk.valueField.slice(1)) || '';
                    var optLbl = nestedGet(opt, lk.displayField) || nestedGet(opt, lk.displayField.charAt(0).toLowerCase() + lk.displayField.slice(1)) || optVal;
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

        // Build initial display value
        var currentDisplay = '';
        if (currentValue) {
            var curItem = allItems.find(function (o) {
                var v = nestedGet(o, lk.valueField) || nestedGet(o, lk.valueField.charAt(0).toLowerCase() + lk.valueField.slice(1));
                return String(v) === String(currentValue);
            });
            if (curItem) currentDisplay = nestedGet(curItem, lk.displayField) || nestedGet(curItem, lk.displayField.charAt(0).toLowerCase() + lk.displayField.slice(1)) || currentValue;
        }

        container.querySelector('.input-group').innerHTML =
            '<input type="text" class="form-control form-control-sm" id="f_' + escHtml(field.name) + '_search" placeholder="Search\u2026" value="' + escHtml(String(currentDisplay)) + '" autocomplete="off">' +
            '<input type="hidden" name="' + escHtml(field.name) + '" id="f_' + escHtml(field.name) + '" value="' + escHtml(String(currentValue || '')) + '">' +
            '<div class="dropdown-menu" id="lu_' + escHtml(field.name) + '" style="position:absolute;z-index:1055;max-height:200px;overflow-y:auto"></div>' +
            '<button type="button" class="btn btn-outline-secondary vnext-lookup-add" data-target-slug="' + escHtml(lk.targetSlug) + '" title="Add new"><i class="bi bi-plus"></i></button>';

        var searchInput = container.querySelector('input[type=text]');
        var hiddenInput = container.querySelector('input[type=hidden]');
        var dropdown    = container.querySelector('[id^="lu_"]');

        function filterItems(q) {
            var lower = q.toLowerCase();
            return allItems.filter(function (o) {
                var d = nestedGet(o, lk.displayField) || nestedGet(o, lk.displayField.charAt(0).toLowerCase() + lk.displayField.slice(1)) || '';
                return String(d).toLowerCase().indexOf(lower) >= 0;
            }).slice(0, 30);
        }

        searchInput.addEventListener('input', function () {
            var q = searchInput.value;
            var matches = filterItems(q);
            dropdown.innerHTML = '';
            if (matches.length === 0) { dropdown.classList.remove('show'); return; }
            matches.forEach(function (o) {
                var v = nestedGet(o, lk.valueField) || nestedGet(o, lk.valueField.charAt(0).toLowerCase() + lk.valueField.slice(1)) || '';
                var d = nestedGet(o, lk.displayField) || nestedGet(o, lk.displayField.charAt(0).toLowerCase() + lk.displayField.slice(1)) || v;
                dropdown.insertAdjacentHTML('beforeend', '<a class="dropdown-item" href="#" data-val="' + escHtml(String(v)) + '" data-display="' + escHtml(String(d)) + '">' + escHtml(String(d)) + '</a>');
            });
            dropdown.classList.add('show');
        });

        dropdown.addEventListener('click', function (e) {
            var a = e.target.closest('a[data-val]');
            if (!a) return;
            e.preventDefault();
            hiddenInput.value = a.dataset.val;
            searchInput.value = a.dataset.display;
            dropdown.classList.remove('show');
        });

        document.addEventListener('click', function (e) {
            if (!container.contains(e.target)) dropdown.classList.remove('show');
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

    function evalExpression(jsExpr, vals) {
        // jsExpr originates from server-generated metadata (CalculatedFieldAttribute.Expression
        // compiled to JavaScript by ExpressionParser.ToJavaScript). It is not user-supplied
        // input, so using Function constructor here is acceptable.
        try {
            var keys   = Object.keys(vals);
            var values = keys.map(function (k) { return parseFloat(vals[k]) || 0; });
            // eslint-disable-next-line no-new-func
            return new Function(keys, 'return ' + jsExpr).apply(null, values);
        } catch (e) { return null; }
    }

    function validateForm(form) {
        var valid = true;
        form.querySelectorAll('input[required], select[required], textarea[required]').forEach(function (el) {
            if (!el.value.trim()) {
                el.classList.add('is-invalid');
                var fb = el.nextElementSibling;
                if (fb && fb.classList.contains('invalid-feedback')) fb.textContent = el.labels && el.labels[0] ? el.labels[0].textContent.trim() + ' is required.' : 'Required.';
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
            // Sub-list reconstruction
            if (f.type === 'CustomHtml') {
                var subKeys = {};
                for (var pair of fd.entries()) {
                    var m = pair[0].match(new RegExp('^' + f.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\[(\\d+)\\]\\.(.+)$'));
                    if (!m) continue;
                    var idx = parseInt(m[1], 10);
                    var key = m[2];
                    if (!subKeys[idx]) subKeys[idx] = {};
                    subKeys[idx][key] = pair[1];
                }
                var subArr = Object.keys(subKeys).sort(function (a, b) { return parseInt(a) - parseInt(b); }).map(function (i) { return subKeys[i]; });
                if (subArr.length) obj[f.name] = subArr;
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
                var baseUrl = BASE + '/admin/data/' + encodeURIComponent(slug);
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
                    if (el) el.href = 'https://cdn.jsdelivr.net/npm/bootswatch@5.3.3/dist/' + encodeURIComponent(t) + '/bootstrap.min.css';
                }
            }
        } catch (e) {}

        // Register routes
        BMRouter
            .on(BASE + '/admin/data/:entity/create', function (p) { renderCreate(p.entity); })
            .on(BASE + '/admin/data/:entity/:id/edit',   function (p) { renderEdit(p.entity, p.id); })
            .on(BASE + '/admin/data/:entity/:id/delete', function (p) { renderDelete(p.entity, p.id); })
            .on(BASE + '/admin/data/:entity/:id',        function (p, q) { renderView(p.entity, p.id); })
            .on(BASE + '/admin/data/:entity',            function (p, q) { renderList(p.entity, q); })
            .on(BASE + '/admin/data',                    function () { renderHome(); })
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

})(window);
// VNext Router — thin SPA router powered by BareMetalRendering
// Parses /vnext[/admin/data]/[{slug}[/{id}[/edit]|/create]]
// Depends on: BareMetalRest, BareMetalBind, BareMetalTemplate, BareMetalRendering
(async function () {
  'use strict';
  BareMetalRest.setRoot('/api/');

  const R   = document.getElementById('vnext-root');
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

  function wire() {
    R.querySelectorAll('[data-go]').forEach(a =>
      a.addEventListener('click', e => { e.preventDefault(); go(a.getAttribute('href')); })
    );
  }

  function navbar(activeSlug) {
    const all = _entityList || [];
    const nav = el('nav', { className: 'navbar navbar-expand navbar-dark bg-dark mb-3 px-3' });
    const brand = el('a', { className: 'navbar-brand', href: '/vnext', textContent: '\u26A1 VNext' });
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
          const a  = el('a', { className: 'nav-link' + (e.slug === activeSlug ? ' active' : ''), href: '/vnext/' + e.slug, textContent: e.name });
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
          const a = el('a', { className: 'dropdown-item' + (e.slug === activeSlug ? ' active' : ''), href: '/vnext/' + e.slug, textContent: e.name });
          a.setAttribute('data-go', '');
          mli.appendChild(a);
          menu.appendChild(mli);
        });
        li.appendChild(menu);
        ul.appendChild(li);
      }
    });

    nav.appendChild(ul);
    nav.appendChild(el('a', { className: 'btn btn-sm btn-outline-light', href: '/admin/data', textContent: 'Classic UI' }));
    return nav;
  }

  async function route() {
    const p      = location.pathname.replace(/^\/vnext\/?/, '').replace(/^admin\/data\/?/, '').split('/').filter(Boolean);
    const slug   = p[0], rawId = p[1], action = p[2];
    const id     = (rawId && rawId !== 'create') ? rawId : null;

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
          const card = el('a', { className: 'card card-body text-decoration-none', href: '/vnext/' + e.slug });
          card.setAttribute('data-go', '');
          card.appendChild(el('strong', { textContent: e.name }));
          card.appendChild(el('p', { className: 'text-muted small mb-0', textContent: e.navGroup || '' }));
          row.appendChild(el('div', { className: 'col-sm-6 col-md-3' }, [card]));
        });
        container.appendChild(row);
        R.appendChild(container);
        wire(); return;
      }

      const entity = await BareMetalRendering.createEntity(slug);
      R.replaceChildren(navbar(slug));
      const main = el('div', { className: 'container' });
      R.appendChild(main);

      if (!rawId) {
        // ── List view ───────────────────────────────────────────────────────
        const items  = await BareMetalRest.entity(slug).list();
        const allItems = Array.isArray(items) ? items : (items?.items || []);
        const schemaFields = entity.meta.schema?.fields || {};

        const hdr = el('div', { className: 'd-flex gap-2 align-items-center mb-3 flex-wrap' });
        hdr.appendChild(el('h2', { className: 'mb-0 me-2', textContent: entity.meta.name || slug }));
        const addBtn = el('a', { href: '/vnext/' + slug + '/create', className: 'btn btn-success btn-sm', textContent: '+ Add' });
        addBtn.setAttribute('data-go', '');
        hdr.appendChild(addBtn);

        // Edit mode toggle
        let editModeActive = false;
        const editModeBtn = el('button', { className: 'btn btn-outline-secondary btn-sm', textContent: '\u270F Edit Mode' });

        const buildReadTable = () => BareMetalTemplate.buildTable(schemaFields, allItems, {
          resolve:  (name, v) => entity.resolve(name, v),
          onView:   i => go(`/vnext/${slug}/${i}`),
          onEdit:   i => go(`/vnext/${slug}/${i}/edit`),
          onDelete: async i => {
            if (!confirm('Delete this record? This cannot be undone.')) return;
            try { await BareMetalRest.entity(slug).remove(i); go(`/vnext/${slug}`); }
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
          href: isView ? `/vnext/${slug}` : id ? `/vnext/${slug}/${id}` : `/vnext/${slug}`,
          className: 'btn btn-secondary btn-sm',
          textContent: '\u2190 Back'
        });
        back.setAttribute('data-go', '');
        hdr.appendChild(back);

        if (isView && id) {
          const editBtn = el('a', { href: `/vnext/${slug}/${id}/edit`, className: 'btn btn-primary btn-sm', textContent: '\u270F Edit' });
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
              go(newId ? `/vnext/${slug}/${newId}${andEdit ? '/edit' : ''}` : `/vnext/${slug}`);
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
              const a = el('a', { href: `/vnext/${targetSlug}/${encodeURIComponent(String(v))}`, textContent: display });
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
              go(savedId ? `/vnext/${slug}/${savedId}` : `/vnext/${slug}`);
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
