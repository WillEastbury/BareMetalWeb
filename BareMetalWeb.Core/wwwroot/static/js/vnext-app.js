// vnext-app.js — BareMetalWeb VNext client-side rendering engine
// Consumes /meta/* and /api/* to render full CRUD UI without any server-side HTML templating.
// Requires BareMetalRouting.js and Bootstrap 5 to be loaded first.
(function (global) {
    'use strict';

    // ── Configuration ─────────────────────────────────────────────────────────
    var BASE = '/UI';
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
                html += '<li class="nav-item"><a class="nav-link" href="' + BASE + '/data/' + escHtml(items[0].slug) + '">' + escHtml(items[0].name) + '</a></li>';
            } else {
                html += '<li class="nav-item dropdown">';
                html += '<a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">' + escHtml(groupName) + '</a>';
                html += '<ul class="dropdown-menu dropdown-menu-dark">';
                items.sort(function (a, b) { return (a.navOrder || 0) - (b.navOrder || 0) || a.name.localeCompare(b.name); })
                     .forEach(function (e) {
                        html += '<li><a class="dropdown-item" href="' + BASE + '/data/' + escHtml(e.slug) + '">' + escHtml(e.name) + '</a></li>';
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
                            '<a class="btn btn-primary btn-sm" href="' + BASE + '/data/' + escHtml(e.slug) + '">Open</a>' +
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
            // Hierarchy/calendar views need all items (no pagination)
            var vt = meta.viewType || '';
            var activeView = query.view || '';
            var isHierarchyView = (vt === 'TreeView' || vt === 'OrgChart' || vt === 'Timeline' || meta.canShowTimetable ||
                activeView === 'TreeView' || activeView === 'OrgChart' || activeView === 'Timeline' || activeView === 'Timetable');

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

            return apiFetch(API + '/' + encodeURIComponent(slug) + '?' + params.join('&'))
                .then(function (result) { renderListResult(meta, result, slug, query, skip, top, search, sort, dir); });
        }).catch(function (err) { showError(err.message); });
    }

    function renderListResult(meta, result, slug, query, skip, top, search, sort, dir) {
        var items = Array.isArray(result) ? result : (result.items || []);
        var total = (result && result.total != null) ? result.total : items.length;
        var listFields = meta.fields.filter(function (f) { return f.list; }).sort(function (a, b) { return a.order - b.order; });

        var baseUrl = BASE + '/data/' + encodeURIComponent(slug);

        function buildSortUrl(fieldName) {
            var newDir = (sort === fieldName && dir === 'asc') ? 'desc' : 'asc';
            return buildUrl(baseUrl, Object.assign({}, query, { sort: fieldName, dir: newDir, skip: 0 }));
        }

        var viewType = meta.viewType || 'Table';
        var activeView = query.view || viewType;

        var html = '<div class="p-3">';
        // Breadcrumb
        html += '<nav aria-label="breadcrumb"><ol class="breadcrumb"><li class="breadcrumb-item"><a href="' + BASE + '">Home</a></li>';
        html += '<li class="breadcrumb-item active">' + escHtml(meta.name) + '</li></ol></nav>';

        // Title + action bar
        html += '<div class="d-flex align-items-center mb-3 flex-wrap gap-2">';
        html += '<h2 class="mb-0 me-3">' + escHtml(meta.name) + '</h2>';
        html += '<span class="badge bg-secondary" title="Total records" aria-label="' + total + ' total records">' + total + ' records</span>';
        html += '<a class="btn btn-primary btn-sm" href="' + baseUrl + '/create"><i class="bi bi-plus-lg"></i> New</a>';
        html += '<a class="btn btn-outline-secondary btn-sm" href="' + API + '/' + encodeURIComponent(slug) + '?format=csv" download><i class="bi bi-filetype-csv"></i> Export CSV</a>';
        html += '<a class="btn btn-outline-secondary btn-sm" href="' + API + '/' + encodeURIComponent(slug) + '?format=json" download><i class="bi bi-filetype-json"></i> Export JSON</a>';
        html += '<button class="btn btn-outline-secondary btn-sm" id="vnext-import-btn" data-slug="' + escHtml(slug) + '"><i class="bi bi-upload"></i> Import CSV</button>';
        // View type switcher (when entity supports alternate views or has a parent field for hierarchy)
        var hasParentField = meta.parentField != null;
        if (viewType !== 'Table' || hasParentField) {
            html += '<div class="btn-group btn-group-sm ms-2">';
            html += '<a class="btn btn-outline-secondary' + (activeView === 'Table' ? ' active' : '') + '" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'Table' })) + '" title="Table View"><i class="bi bi-table"></i></a>';
            if (viewType === 'TreeView' || hasParentField)  html += '<a class="btn btn-outline-secondary' + (activeView === 'TreeView' ? ' active' : '') + '" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'TreeView' })) + '" title="Tree View"><i class="bi bi-diagram-3"></i></a>';
            if (viewType === 'OrgChart' || hasParentField) html += '<a class="btn btn-outline-secondary' + (activeView === 'OrgChart' ? ' active' : '') + '" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'OrgChart' })) + '" title="Org Chart"><i class="bi bi-diagram-2"></i></a>';
            if (viewType === 'Timeline') html += '<a class="btn btn-outline-secondary' + (activeView === 'Timeline' ? ' active' : '') + '" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'Timeline' })) + '" title="Timeline"><i class="bi bi-calendar-range"></i></a>';
            if (viewType === 'Timetable') html += '<a class="btn btn-outline-secondary' + (activeView === 'Timetable' ? ' active' : '') + '" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'Timetable' })) + '" title="Timetable"><i class="bi bi-calendar3"></i></a>';
        // View type switcher (when entity supports alternate views)
        if (viewType !== 'Table' || meta.canShowTimetable || meta.canShowTimeline) {
            html += '<div class="btn-group btn-group-sm ms-2">';
            html += '<a class="btn btn-outline-secondary' + (activeView === 'Table' ? ' active' : '') + '" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'Table' })) + '" title="Table View"><i class="bi bi-table"></i></a>';
            if (viewType === 'TreeView' || (viewType === 'OrgChart' && meta.parentField)) html += '<a class="btn btn-outline-secondary' + (activeView === 'TreeView' ? ' active' : '') + '" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'TreeView' })) + '" title="Tree View"><i class="bi bi-diagram-3"></i></a>';
            if (viewType === 'OrgChart' || (viewType === 'TreeView' && meta.parentField)) html += '<a class="btn btn-outline-secondary' + (activeView === 'OrgChart' ? ' active' : '') + '" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'OrgChart' })) + '" title="Org Chart"><i class="bi bi-people"></i></a>';
            if (viewType === 'Timeline' || meta.canShowTimeline) html += '<a class="btn btn-outline-secondary' + (activeView === 'Timeline' ? ' active' : '') + '" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'Timeline' })) + '" title="Timeline"><i class="bi bi-calendar-range"></i></a>';
            if (meta.canShowTimetable) html += '<a class="btn btn-outline-secondary' + (activeView === 'Timetable' ? ' active' : '') + '" href="' + buildUrl(baseUrl, Object.assign({}, query, { view: 'Timetable' })) + '" title="Timetable"><i class="bi bi-calendar3"></i></a>';
            html += '</div>';
        }
        html += '</div>';

        if (activeView === 'TreeView' || (activeView === '' && viewType === 'TreeView')) {
            html += renderTreeView(meta, items, slug, baseUrl);
        } else if (activeView === 'OrgChart' || (activeView === '' && viewType === 'OrgChart')) {
            html += renderOrgChart(meta, items, slug, baseUrl);
        } else if ((activeView === 'Timeline' || (activeView === '' && viewType === 'Timeline')) && items.length > 0) {
            html += renderTimeline(meta, items, slug, baseUrl);
        } else if ((activeView === 'Timetable' || (activeView === '' && viewType === 'Timetable')) && items.length > 0) {
            html += renderTimetable(meta, items, slug, baseUrl);
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
            // Card layout for narrow viewports
            html += '<div class="d-md-none vnext-card-list">';
            if (items.length === 0) {
                html += '<p class="text-center text-muted py-4">No records found.</p>';
            } else {
                items.forEach(function (item) {
                    var id = item.id || item.Id || '';
                    var encId = encodeURIComponent(id);
                    html += '<div class="card mb-2"><div class="card-body p-2">';
                    listFields.forEach(function (f) {
                        var val = nestedGet(item, f.name) || nestedGet(item, f.name.charAt(0).toLowerCase() + f.name.slice(1));
                        html += '<div class="d-flex justify-content-between"><small class="text-muted">' + escHtml(f.label) + '</small><span>' + fmtValue(val, f.type) + '</span></div>';
                    });
                    html += '<div class="mt-2 d-flex gap-1">';
                    html += '<a class="btn btn-xs btn-outline-info btn-sm" href="' + baseUrl + '/' + encId + '"><i class="bi bi-eye"></i></a>';
                    html += '<a class="btn btn-xs btn-outline-warning btn-sm" href="' + baseUrl + '/' + encId + '/edit"><i class="bi bi-pencil"></i></a>';
                    html += '<button class="btn btn-xs btn-outline-primary btn-sm vnext-row-clone" data-id="' + escHtml(id) + '" data-slug="' + escHtml(slug) + '"><i class="bi bi-files"></i></button>';
                    html += '<button class="btn btn-xs btn-outline-danger btn-sm vnext-row-delete" data-id="' + escHtml(id) + '" data-slug="' + escHtml(slug) + '"><i class="bi bi-trash"></i></button>';
                    html += '</div></div></div>';
                });
            }
            html += '</div>';

            // Table layout for wider viewports
            html += '<div class="d-none d-md-block table-responsive"><table class="table table-hover table-striped table-sm align-middle">';
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
                        if (f.lookup && f.lookup.targetSlug && val) {
                            html += '<td data-lookup-field="' + escHtml(f.name) + '" data-target-slug="' + escHtml(f.lookup.targetSlug) + '" data-display-field="' + escHtml(f.lookup.displayField) + '" data-value="' + escHtml(String(val)) + '">' +
                                '<a href="' + BASE + '/data/' + escHtml(f.lookup.targetSlug) + '/' + encodeURIComponent(val) + '">' + escHtml(String(val)) + '</a></td>';
                        } else {
                            html += '<td>' + fmtValue(val, f.type) + '</td>';
                        }
                    });
                    html += '<td class="text-nowrap">';
                    html += '<a class="btn btn-xs btn-outline-info btn-sm me-1" href="' + baseUrl + '/' + encId + '" title="View"><i class="bi bi-eye"></i></a>';
                    html += '<a class="btn btn-xs btn-outline-warning btn-sm me-1" href="' + baseUrl + '/' + encId + '/edit" title="Edit"><i class="bi bi-pencil"></i></a>';
                    html += '<button class="btn btn-xs btn-outline-primary btn-sm me-1 vnext-row-clone" data-id="' + escHtml(id) + '" data-slug="' + escHtml(slug) + '" title="Clone"><i class="bi bi-files"></i></button>';
                    html += '<button class="btn btn-xs btn-outline-danger btn-sm vnext-row-delete" data-id="' + escHtml(id) + '" data-slug="' + escHtml(slug) + '" title="Delete"><i class="bi bi-trash"></i></button>';
                    html += '</td></tr>';
                });
            }

            html += '</tbody></table></div>';

            // Pagination
            html += renderPagination(total, skip, top, baseUrl, query);
        }

        html += '</div>';
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

        wireListEvents(slug, baseUrl, query, top, sort, dir);
    }

    // ── Alternate view renderers ──────────────────────────────────────────────

    function renderTreeView(meta, items, slug, baseUrl) {
        // Find the parent field for hierarchical grouping
        var parentField = meta.parentField ? meta.parentField.name : null;
        var labelField = meta.fields.filter(function (f) { return f.list; }).sort(function (a, b) { return a.order - b.order; })[0];
        var html = '<div class="vnext-tree-view">';

        if (items.length === 0) {
            html += '<p class="text-center text-muted py-4"><i class="bi bi-diagram-3 me-2"></i>No records found.</p>';
            html += '</div>';
            return html;
        }

        function getLabel(item) {
            var id = item.id || item.Id || '';
            return labelField ? (nestedGet(item, labelField.name) || nestedGet(item, labelField.name.charAt(0).toLowerCase() + labelField.name.slice(1)) || id) : id;
        }

        function buildNodeHtml(node, depth) {
            var id = node.item.id || node.item.Id || '';
            var label = getLabel(node.item);
            var indent = depth * 20;
            var row = '<div class="vnext-tree-node d-flex align-items-center py-1 border-bottom" style="padding-left:' + indent + 'px" data-id="' + escHtml(id) + '">';
            if (node.children.length > 0) row += '<i class="bi bi-chevron-down text-muted me-1" style="cursor:pointer" onclick="this.closest(\'.vnext-tree-node\').nextElementSibling.classList.toggle(\'d-none\');this.classList.toggle(\'bi-chevron-right\');this.classList.toggle(\'bi-chevron-down\')"></i>';
            else row += '<i class="bi bi-dot text-muted me-1"></i>';
            row += '<a class="link-body-emphasis text-decoration-none me-2" href="' + baseUrl + '/' + encodeURIComponent(id) + '">' + escHtml(String(label)) + '</a>';
            row += '<a class="btn btn-xs btn-outline-warning btn-sm me-1" href="' + baseUrl + '/' + encodeURIComponent(id) + '/edit" title="Edit"><i class="bi bi-pencil"></i></a>';
            row += '</div>';
            if (node.children.length > 0) {
                row += '<div class="vnext-tree-children">';
                node.children.forEach(function (child) { row += buildNodeHtml(child, depth + 1); });
                row += '</div>';
            }
            return row;
        }

        function renderFlatList() {
            items.forEach(function (item) {
                var id = item.id || item.Id || '';
                var label = getLabel(item);
                html += '<div class="vnext-tree-node d-flex align-items-center py-1 border-bottom">' +
                    '<i class="bi bi-dot text-muted me-1"></i>' +
                    '<a class="link-body-emphasis text-decoration-none me-2" href="' + baseUrl + '/' + encodeURIComponent(id) + '">' + escHtml(String(label)) + '</a>' +
                    '<a class="btn btn-xs btn-outline-warning btn-sm me-1" href="' + baseUrl + '/' + encodeURIComponent(id) + '/edit" title="Edit"><i class="bi bi-pencil"></i></a>' +
                    '</div>';
            });
        }

        if (parentField) {
            var roots = [], nodeMap = {};
            items.forEach(function (item) {
                var id = item.id || item.Id || '';
                nodeMap[id] = { item: item, children: [] };
            });
            items.forEach(function (item) {
                var id = item.id || item.Id || '';
                var parentId = nestedGet(item, parentField) || nestedGet(item, parentField.charAt(0).toLowerCase() + parentField.slice(1)) || '';
                if (parentId && nodeMap[parentId] && parentId !== id) nodeMap[parentId].children.push(nodeMap[id]);
                else roots.push(nodeMap[id]);
            });
            if (roots.length > 0) {
                roots.forEach(function (root) { html += buildNodeHtml(root, 0); });
            } else {
                // All items reference parents not in the set — fall back to flat list
                renderFlatList();
            }
        } else {
            renderFlatList();
        }
        html += '</div>';
        return html;
    }

    function renderOrgChart(meta, items, slug, baseUrl) {
        var parentField = meta.parentField ? meta.parentField.name : null;
        var labelField = meta.fields.filter(function (f) { return f.list; }).sort(function (a, b) { return a.order - b.order; })[0];
        var subtitleField = meta.fields.filter(function (f) { return f.list && f !== labelField; }).sort(function (a, b) { return a.order - b.order; })[0];

        function buildCardHtml(item) {
            var id = item.id || item.Id || '';
            var label = labelField ? (nestedGet(item, labelField.name) || nestedGet(item, labelField.name.charAt(0).toLowerCase() + labelField.name.slice(1)) || id) : id;
            var subtitle = subtitleField ? (nestedGet(item, subtitleField.name) || nestedGet(item, subtitleField.name.charAt(0).toLowerCase() + subtitleField.name.slice(1)) || '') : '';
            return '<div class="card text-center" style="min-width:140px;display:inline-block;margin:4px;vertical-align:top">' +
                '<div class="card-body p-2">' +
                '<p class="card-text small mb-0"><strong>' + escHtml(String(label)) + '</strong></p>' +
                (subtitle ? '<p class="card-text small text-muted mb-1">' + escHtml(String(subtitle)) + '</p>' : '<p class="mb-1"></p>') +
                '<a class="btn btn-xs btn-outline-primary btn-sm" href="' + baseUrl + '/' + encodeURIComponent(id) + '" style="font-size:0.7rem">View</a>' +
                '</div></div>';
        }

        var html = '<div class="vnext-orgchart overflow-auto py-3">';

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
                var parentId = nestedGet(item, parentField) || nestedGet(item, parentField.charAt(0).toLowerCase() + parentField.slice(1)) || '';
                if (parentId && nodeMap[parentId] && parentId !== id) nodeMap[parentId].children.push(nodeMap[id]);
                else roots.push(nodeMap[id]);
            });
            if (roots.length === 0) {
                // Circular reference or all items are children — break cycle, show all as top-level
                items.forEach(function (item) { var k = item.id || item.Id || ''; if (k && nodeMap[k]) roots.push(nodeMap[k]); });
            }

            function buildLevel(nodes) {
                var out = '<div class="d-flex flex-wrap gap-3 mb-3 justify-content-center">';
                var nextLevel = [];
                nodes.forEach(function (n) {
                    out += buildCardHtml(n.item);
                    n.children.forEach(function (c) { nextLevel.push(c); });
                });
                out += '</div>';
                if (nextLevel.length) out += buildLevel(nextLevel);
                return out;
            }
            if (roots.length > 0) {
                html += buildLevel(roots);
            } else {
                // All items form cycles — fall back to flat card grid
                html += '<div class="d-flex flex-wrap gap-3">';
                items.forEach(function (item) { html += buildCardHtml(item); });
                html += '</div>';
            }
        } else {
            html += '<div class="d-flex flex-wrap gap-3">';
            items.forEach(function (item) { html += buildCardHtml(item); });
            html += '</div>';
        }
        html += '</div>';
        return html;
    }

    function renderTimeline(meta, items, slug, baseUrl) {
        // Find first two DateOnly/DateTime fields: start date, optional end date
        var dateFields = meta.fields.filter(function (f) { return f.type === 'DateTime' || f.type === 'DateOnly'; });
        if (!dateFields.length) return '<p class="text-warning">Timeline view requires a DateOnly or DateTime field.</p>';

        var startField = dateFields[0];
        var endField = dateFields.length > 1 ? dateFields[1] : null;
        var labelField = meta.fields.filter(function (f) { return f.list; }).sort(function (a, b) { return a.order - b.order; })[0];

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

        // Render Gantt chart HTML (matches SSR bm-gantt-* classes)
        var html = '<div class="bm-gantt-container"><div class="bm-gantt-inner">';

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
        ganttItems.forEach(function (g, i) {
            var sd = new Date(g.start.y, g.start.m, g.start.d);
            var ed = new Date(g.end.y, g.end.m, g.end.d);
            var startDays = (sd - chartStart) / 86400000;
            var endDays = (ed - chartStart) / 86400000 + 1;
            var barLeft = startDays / totalDays * 100;
            var barWidth = Math.max((endDays - startDays) / totalDays * 100, 0.5);
            var color = barColors[i % barColors.length];

            var tooltip = endField
                ? escHtml(g.label) + ': ' + sd.toISOString().slice(0,10) + ' \u2013 ' + ed.toISOString().slice(0,10)
                : escHtml(g.label) + ': ' + sd.toISOString().slice(0,10);

            html += '<div class="bm-gantt-row">';
            html += '<div class="bm-gantt-lbl" title="' + escHtml(g.label) + '"><a href="' + baseUrl + '/' + encodeURIComponent(g.id) + '">' + escHtml(g.label) + '</a></div>';
            html += '<div class="bm-gantt-bar-area">';
            months.forEach(function (mo) {
                html += '<div class="bm-gantt-sep" data-gantt-left="' + mo.left.toFixed(2) + '%"></div>';
            });
            html += '<a href="' + baseUrl + '/' + encodeURIComponent(g.id) + '/edit" class="bm-gantt-bar" data-gantt-left="' + barLeft.toFixed(2) + '%" data-gantt-width="' + barWidth.toFixed(2) + '%" data-gantt-bg="' + escHtml(color) + '" title="' + tooltip + '">';
            html += '<span class="bm-gantt-bar-text">' + escHtml(g.label) + '</span>';
            html += '</a></div></div>';
        });

        html += '</div></div>';

        // Apply dynamic styles (same as gantt-view.js does for SSR)
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
                html += '<tr><td style="white-space:nowrap">' +
                    '<a class="btn btn-outline-info btn-sm me-1" href="' + baseUrl + '/' + encodeURIComponent(id) + '" title="View"><i class="bi bi-eye"></i></a>' +
                    '<a class="btn btn-outline-warning btn-sm me-1" href="' + baseUrl + '/' + encodeURIComponent(id) + '/edit" title="Edit"><i class="bi bi-pencil"></i></a>' +
                    '<a class="btn btn-outline-secondary btn-sm me-1" href="' + baseUrl + '/create?cloneFrom=' + encodeURIComponent(id) + '" title="Clone"><i class="bi bi-copy"></i></a>' +
                    '<button class="btn btn-outline-danger btn-sm" data-delete-id="' + escHtml(id) + '" title="Delete"><i class="bi bi-trash"></i></button>' +
                    '</td>';
                listFields.forEach(function (f) {
                    html += '<td>' + fmtValue(nestedGet(item, f.name), f.type) + '</td>';
                });
                html += '</tr>';
            });
            html += '</tbody></table></div></div>';
        });

        if (!html) return '<p class="text-muted">No timetable items found.</p>';
        return html;
    }

    // ── CSV Import modal ──────────────────────────────────────────────────────

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
        var summary = '<div class="small text-muted mt-2">Records ' + startRecord + ' to ' + endRecord + ' of ' + total + ' total</div>';
        if (total <= top) return summary;
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
        var baseUrl  = BASE + '/data/' + encodeURIComponent(slug);
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
                    '<a href="' + BASE + '/data/' + escHtml(f.lookup.targetSlug) + '/' + encodeURIComponent(val || '') + '">' + escHtml(String(val || '')) + '</a></dd>';
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
        // Group elements by targetSlug so we can batch all IDs for the same entity in one request
        var groups = {};
        document.querySelectorAll('[data-lookup-field]').forEach(function (el) {
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
                            var display = nestedGet(obj, displayField) || nestedGet(obj, displayField.charAt(0).toLowerCase() + displayField.slice(1)) || value;
                            var href = BASE + '/data/' + encodeURIComponent(targetSlug) + '/' + encodeURIComponent(value);
                            el.innerHTML = '<a href="' + escHtml(href) + '">' + escHtml(String(display)) + '</a>';
                        }
                    });
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
        var baseUrl  = BASE + '/data/' + encodeURIComponent(slug);
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
            var taVal = Array.isArray(val) ? val.join('\n') : (val != null ? String(val) : '');
            return '<div class="mb-3">' + label +
                '<textarea class="form-control form-control-sm" id="' + id_ + '" name="' + escHtml(f.name) + '" rows="4"' + req + rdonly + placeholder + validation + '>' +
                escHtml(taVal) + '</textarea>' + feedback + '</div>';
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
                '<input type="text" class="form-control" style="max-width:80px" name="' + escHtml(f.name) + '_currency" placeholder="USD" value="' + escHtml(String(moneyObj.currency || 'USD')) + '" maxlength="3">' +
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
                            var display = nestedGet(obj, displayField) || nestedGet(obj, displayField.charAt(0).toLowerCase() + displayField.slice(1)) || value;
                            el.textContent = String(display);
                        }
                    });
                }).catch(function () {});
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
        fetchLookupOptions(lk.targetSlug, lk.queryField, lk.queryValue, lk.sortField, lk.sortDirection)
            .then(function (items) {
                sel.innerHTML = '<option value="">— Select —</option>';
                items.forEach(function (opt) {
                    var optVal = nestedGet(opt, lk.valueField) || nestedGet(opt, lk.valueField.charAt(0).toLowerCase() + lk.valueField.slice(1)) || '';
                    var optLbl = nestedGet(opt, lk.displayField) || nestedGet(opt, lk.displayField.charAt(0).toLowerCase() + lk.displayField.slice(1)) || optVal;
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
            form.querySelectorAll('[data-field]').forEach(function (el) {
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
            // Resolve lookup display values in sub-list table cells
            if (f.type === 'CustomHtml') {
                resolveSubListLookups(f.name);
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
                var dest = savedId ? BASE + '/data/' + encodeURIComponent(slug) + '/' + encodeURIComponent(savedId) : BASE + '/data/' + encodeURIComponent(slug);
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

        // Resolve display value from pre-loaded items
        var currentDisplay = '';
        if (currentValue) {
            var curItem = allItems.find(function (o) {
                var v = nestedGet(o, lk.valueField) || nestedGet(o, lk.valueField.charAt(0).toLowerCase() + lk.valueField.slice(1));
                return String(v) === String(currentValue);
            });
            if (curItem) currentDisplay = nestedGet(curItem, lk.displayField) || nestedGet(curItem, lk.displayField.charAt(0).toLowerCase() + lk.displayField.slice(1)) || currentValue;
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

    function openVNextLookupSearch(targetSlug, fieldId, displayFieldId, displayField, valueField, targetTypeName) {
        var modal = getOrCreateVNextSearchModal();
        modal.dataset.targetSlug = targetSlug;
        modal.dataset.fieldId = fieldId;
        modal.dataset.displayFieldId = displayFieldId;
        modal.dataset.displayField = displayField;
        modal.dataset.valueField = valueField || 'id';
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
        fetch(url, { credentials: 'same-origin' })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var rows = (data && data.data) ? data.data : [];
                if (rows.length === 0) {
                    resultsEl.innerHTML = '<p class="text-muted small">No results found.</p>';
                    return;
                }
                var keys = Object.keys(rows[0]);
                var html = '<table class="table table-sm table-hover table-striped"><thead><tr><th></th>';
                keys.forEach(function (k) { html += '<th>' + escHtml(k) + '</th>'; });
                html += '</tr></thead><tbody>';
                rows.forEach(function (row) {
                    html += '<tr style="cursor:pointer" data-vnext-select-row>';
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
                var baseUrl = BASE + '/data/' + encodeURIComponent(slug);
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
                    if (el) el.href = 'https://cdn.jsdelivr.net/npm/bootswatch@5.3.3/dist/' + encodeURIComponent(t) + '/bootstrap.min.css';
                }
            }
        } catch (e) {}

        // Register routes
        BMRouter
            .on(BASE + '/data/:entity/create', function (p) { renderCreate(p.entity); })
            .on(BASE + '/data/:entity/:id/edit',   function (p) { renderEdit(p.entity, p.id); })
            .on(BASE + '/data/:entity/:id/delete', function (p) { renderDelete(p.entity, p.id); })
            .on(BASE + '/data/:entity/:id',        function (p, q) { renderView(p.entity, p.id); })
            .on(BASE + '/data/:entity',            function (p, q) { renderList(p.entity, q); })
            .on(BASE + '/data',                    function () { renderHome(); })
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
                searchBtn.dataset.lookupTargetName
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
            var displayFieldKey = displayField.length > 0
                ? displayField.charAt(0).toLowerCase() + displayField.slice(1)
                : displayField;
            var valueField = modal.dataset.valueField || 'id';
            var valueCell = row.querySelector('td[data-field="' + valueField + '"]');
            var displayCell = row.querySelector('td[data-field="' + displayFieldKey + '"]');
            var idValue = valueCell ? valueCell.textContent : '';
            var displayValue = displayCell ? displayCell.textContent : idValue;
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
// Parses /UI/[{slug}[/{id}[/edit|/delete]|/create]]
// Depends on: BareMetalRest, BareMetalBind, BareMetalTemplate, BareMetalRendering
(async function () {
  'use strict';
  BareMetalRest.setRoot('/api/');

  const R   = document.getElementById('vnext-root');
  if (!R) return;
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
    nav.appendChild(el('a', { className: 'btn btn-sm btn-outline-light', href: '/ssr/admin/data', textContent: 'Classic UI' }));
    return nav;
  }

  async function route() {
    const p      = location.pathname.replace(/^\/UI\/?/, '').replace(/^data\/?/, '').split('/').filter(Boolean);
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
