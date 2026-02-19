// BareMetalWeb VNext - Client-side UI renderer
// Renders entity views entirely in the browser using /api/_meta and /api/* endpoints.
// Supports Bootstrap theming, all view types (table, tree, orgchart, timeline, timetable),
// CRUD operations, lookups, and export.
(function () {
    'use strict';

    // ── Metadata cache ───────────────────────────────────────────────────────
    var _meta = null;           // array of entity metadata objects
    var _metaBySlug = {};       // keyed by slug
    var _lookupCache = {};      // key: slug → { data, expires }
    var LOOKUP_TTL = 30000;     // 30 s

    // ── Router ───────────────────────────────────────────────────────────────
    // URL scheme: /vnext[/admin/data[/{type}[/{id}[/edit|/delete]]|/create]]
    function parsePath() {
        var path = window.location.pathname;
        // strip /vnext prefix
        var base = path.replace(/^\/vnext\/?/, '');
        // strip /admin/data prefix
        base = base.replace(/^admin\/data\/?/, '');
        var parts = base.split('/').filter(function (p) { return p.length > 0; });
        if (parts.length === 0) return { view: 'home' };
        var slug = parts[0];
        if (parts.length === 1) return { view: 'list', slug: slug };
        if (parts[1] === 'create') return { view: 'create', slug: slug };
        var id = parts[1];
        if (parts.length === 2) return { view: 'detail', slug: slug, id: id };
        if (parts[2] === 'edit') return { view: 'edit', slug: slug, id: id };
        if (parts[2] === 'delete') return { view: 'delete', slug: slug, id: id };
        return { view: 'detail', slug: slug, id: id };
    }

    function navigate(url) {
        window.history.pushState({}, '', url);
        render();
    }

    window.addEventListener('popstate', function () { render(); });

    // ── API helpers ──────────────────────────────────────────────────────────
    function apiFetch(url, options) {
        return fetch(url, options).then(function (res) {
            if (res.status === 401) {
                window.location.href = '/login?returnUrl=' + encodeURIComponent(window.location.href);
                return Promise.reject(new Error('Unauthorized'));
            }
            return res;
        });
    }

    function apiJson(url, options) {
        return apiFetch(url, options).then(function (res) {
            if (!res.ok) return res.text().then(function (t) { throw new Error(t || res.statusText); });
            return res.json();
        });
    }

    function loadMeta() {
        if (_meta) return Promise.resolve(_meta);
        return apiJson('/api/_meta').then(function (data) {
            _meta = data;
            _metaBySlug = {};
            (data || []).forEach(function (e) { _metaBySlug[e.slug] = e; });
            return _meta;
        });
    }

    function loadLookup(slug, filterField, filterValue) {
        var key = slug + (filterField ? ':' + filterField + ':' + filterValue : '');
        var cached = _lookupCache[key];
        if (cached && cached.expires > Date.now()) return Promise.resolve(cached.data);
        var url = '/api/_lookup/' + encodeURIComponent(slug);
        if (filterField && filterValue) {
            url += '?filter=' + encodeURIComponent(filterField + ':' + filterValue);
        }
        return apiJson(url).then(function (data) {
            _lookupCache[key] = { data: data, expires: Date.now() + LOOKUP_TTL };
            return data;
        });
    }

    // ── CSRF helper ──────────────────────────────────────────────────────────
    function getCsrfMeta() {
        // VNext uses token from a hidden meta or fetches from the server
        var m = document.querySelector('meta[name="csrf-token"]');
        return m ? m.content : '';
    }

    // ── Theme helper ─────────────────────────────────────────────────────────
    function getThemeName() {
        var m = document.cookie.match(/(?:^|;\s*)bm-selected-theme=([^;]+)/);
        return m ? decodeURIComponent(m[1]) : '';
    }

    // ── Escape ───────────────────────────────────────────────────────────────
    function esc(v) {
        if (v == null) return '';
        return String(v)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    // ── Toast ────────────────────────────────────────────────────────────────
    function showToast(msg, type) {
        type = type || 'success';
        var container = document.getElementById('vnext-toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'vnext-toast-container';
            container.style.cssText = 'position:fixed;bottom:1rem;z-index:9999;display:flex;flex-direction:column;gap:.5rem;right:1rem';
            document.body.appendChild(container);
        }
        var el = document.createElement('div');
        el.className = 'toast align-items-center text-bg-' + type + ' border-0 show';
        el.innerHTML = '<div class="d-flex"><div class="toast-body">' + esc(msg) + '</div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div>';
        container.appendChild(el);
        el.querySelector('button').onclick = function () { el.remove(); };
        setTimeout(function () { el.remove(); }, 4000);
    }

    // ── Root element ─────────────────────────────────────────────────────────
    function getRoot() { return document.getElementById('vnext-root'); }

    // ── Render dispatcher ─────────────────────────────────────────────────────
    function render() {
        var route = parsePath();
        getRoot().innerHTML = '<div class="d-flex justify-content-center mt-5"><div class="spinner-border" role="status"><span class="visually-hidden">Loading…</span></div></div>';
        loadMeta().then(function () {
            switch (route.view) {
                case 'home': return renderHome();
                case 'list': return renderList(route.slug);
                case 'create': return renderCreate(route.slug);
                case 'detail': return renderDetail(route.slug, route.id);
                case 'edit': return renderEdit(route.slug, route.id);
                case 'delete': return renderDeleteConfirm(route.slug, route.id);
                default: return renderHome();
            }
        }).catch(function (e) {
            getRoot().innerHTML = '<div class="container mt-4"><div class="alert alert-danger">' + esc(e.message) + '</div></div>';
        });
    }

    // ── Navigation bar ────────────────────────────────────────────────────────
    function buildNavbar(activeSlug) {
        var theme = getThemeName();
        var navGroups = {};
        (_meta || []).forEach(function (e) {
            if (!e.showOnNav) return;
            var g = e.navGroup || 'Other';
            if (!navGroups[g]) navGroups[g] = [];
            navGroups[g].push(e);
        });
        var groups = Object.keys(navGroups).sort();
        var dropdowns = groups.map(function (g) {
            var items = navGroups[g].map(function (e) {
                var active = e.slug === activeSlug ? ' active' : '';
                return '<li><a class="dropdown-item' + active + '" href="/vnext/admin/data/' + esc(e.slug) + '" data-vnav>' + esc(e.name) + '</a></li>';
            }).join('');
            return '<li class="nav-item dropdown">' +
                '<a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">' + esc(g) + '</a>' +
                '<ul class="dropdown-menu">' + items + '</ul></li>';
        }).join('');
        var themeOptions = ['vapor','darkly','cyborg','slate','superhero','flatly','lux']
            .map(function (t) {
                var sel = t === theme ? ' selected' : '';
                return '<option value="' + t + '"' + sel + '>' + t.charAt(0).toUpperCase() + t.slice(1) + '</option>';
            }).join('');
        return '<nav class="navbar navbar-expand-lg bg-dark navbar-dark mb-3">' +
            '<div class="container-fluid">' +
            '<a class="navbar-brand" href="/vnext" data-vnav><i class="bi bi-lightning-charge-fill"></i> VNext</a>' +
            '<button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#vnext-nav"><span class="navbar-toggler-icon"></span></button>' +
            '<div class="collapse navbar-collapse" id="vnext-nav">' +
            '<ul class="navbar-nav me-auto">' + dropdowns + '</ul>' +
            '<span class="navbar-text me-2 small">Theme:</span>' +
            '<select id="vnext-theme-select" class="form-select form-select-sm" style="width:auto">' + themeOptions + '</select>' +
            '<a class="btn btn-sm btn-outline-light ms-2" href="/admin/data">Classic UI</a>' +
            '<a class="btn btn-sm btn-outline-secondary ms-2" href="/logout">Logout</a>' +
            '</div></div></nav>';
    }

    function wireNavEvents(container) {
        // SPA navigation
        container.querySelectorAll('[data-vnav]').forEach(function (a) {
            a.addEventListener('click', function (e) {
                e.preventDefault();
                navigate(a.getAttribute('href'));
            });
        });
        // Theme switcher
        var ts = container.querySelector('#vnext-theme-select');
        if (ts) {
            ts.addEventListener('change', function () {
                var t = ts.value;
                document.cookie = 'bm-selected-theme=' + encodeURIComponent(t) + ';path=/;max-age=31536000';
                var link = document.getElementById('bootswatch-theme');
                if (link) {
                    link.href = 'https://cdn.jsdelivr.net/npm/bootswatch@5.3.3/dist/' + encodeURIComponent(t) + '/bootstrap.min.css';
                }
            });
        }
    }

    // ── Home / entity list ────────────────────────────────────────────────────
    function renderHome() {
        var html = buildNavbar(null);
        html += '<div class="container-fluid"><h2>Entities</h2><div class="row g-3 mt-1">';
        (_meta || []).filter(function (e) { return e.showOnNav; }).forEach(function (e) {
            html += '<div class="col-sm-6 col-md-4 col-lg-3">' +
                '<a class="card text-decoration-none h-100" href="/vnext/admin/data/' + esc(e.slug) + '" data-vnav>' +
                '<div class="card-body"><h5 class="card-title">' + esc(e.name) + '</h5>' +
                '<p class="card-text text-muted small">' + esc(e.navGroup || '') + '</p></div></a></div>';
        });
        html += '</div></div>';
        var root = getRoot();
        root.innerHTML = html;
        wireNavEvents(root);
    }

    // ── List view ─────────────────────────────────────────────────────────────
    function renderList(slug) {
        var meta = _metaBySlug[slug];
        if (!meta) { getRoot().innerHTML = '<div class="container mt-4"><div class="alert alert-warning">Entity not found: ' + esc(slug) + '</div></div>'; return; }
        var params = new URLSearchParams(window.location.search);
        var view = params.get('view') || meta.viewType || 'Table';
        var page = parseInt(params.get('page') || '1', 10) || 1;
        var q = params.get('q') || '';
        var size = parseInt(params.get('size') || '25', 10) || 25;

        var apiUrl = '/api/' + encodeURIComponent(slug) + '?_skip=' + ((page - 1) * size) + '&_top=' + size;
        if (q) apiUrl += '&q=' + encodeURIComponent(q);

        apiJson(apiUrl).then(function (data) {
            var items = Array.isArray(data) ? data : (data.items || []);
            var total = data.total != null ? data.total : items.length;

            var html = buildNavbar(slug);
            html += '<div class="container-fluid">';
            html += '<div class="d-flex align-items-center justify-content-between mb-2 flex-wrap gap-2">';
            html += '<h2>' + esc(meta.name) + '</h2>';
            html += '<div class="d-flex gap-2 flex-wrap align-items-center">';
            // View switcher
            html += buildViewSwitcher(slug, view);
            // Search
            html += '<form class="d-flex" id="vnext-search-form"><input class="form-control form-control-sm me-1" type="search" placeholder="Search…" id="vnext-q" value="' + esc(q) + '"><button class="btn btn-sm btn-outline-secondary" type="submit"><i class="bi bi-search"></i></button></form>';
            // Add button
            html += '<a class="btn btn-sm btn-success" href="/vnext/admin/data/' + esc(slug) + '/create" data-vnav><i class="bi bi-plus-lg"></i> Add</a>';
            // Export
            html += '<div class="dropdown"><button class="btn btn-sm btn-outline-secondary dropdown-toggle" data-bs-toggle="dropdown">Export</button>' +
                '<ul class="dropdown-menu">' +
                '<li><a class="dropdown-item" href="/admin/data/' + esc(slug) + '/csv" target="_blank">CSV</a></li>' +
                '<li><a class="dropdown-item" href="/admin/data/' + esc(slug) + '/html" target="_blank">HTML</a></li>' +
                '<li><a class="dropdown-item" href="/admin/data/' + esc(slug) + '/export" target="_blank">JSON</a></li>' +
                '</ul></div>';
            html += '</div></div>';

            // Render based on view type
            var normalizedView = view.toLowerCase();
            if (normalizedView === 'treeview' || normalizedView === 'tree') {
                html += buildTreeView(meta, items, slug);
            } else if (normalizedView === 'orgchart') {
                html += buildOrgChart(meta, items, slug);
            } else if (normalizedView === 'timeline') {
                html += buildTimeline(meta, items, slug);
            } else {
                html += buildTableView(meta, items, slug, page, size, total, q);
            }
            html += '</div>';

            var root = getRoot();
            root.innerHTML = html;
            wireNavEvents(root);

            // Search form
            var sf = root.querySelector('#vnext-search-form');
            if (sf) sf.addEventListener('submit', function (e) {
                e.preventDefault();
                var qv = root.querySelector('#vnext-q').value;
                navigate('/vnext/admin/data/' + slug + '?q=' + encodeURIComponent(qv) + (view !== 'Table' ? '&view=' + view : ''));
            });
        }).catch(function (e) {
            getRoot().innerHTML = buildNavbar(slug) + '<div class="container mt-4"><div class="alert alert-danger">' + esc(e.message) + '</div></div>';
        });
    }

    function buildViewSwitcher(slug, current) {
        var views = [
            { id: 'Table', icon: 'bi-table', label: 'Table' },
            { id: 'TreeView', icon: 'bi-diagram-3', label: 'Tree' },
            { id: 'OrgChart', icon: 'bi-people', label: 'Org Chart' },
            { id: 'Timeline', icon: 'bi-calendar3', label: 'Timeline' }
        ];
        var btns = views.map(function (v) {
            var active = v.id.toLowerCase() === (current || '').toLowerCase() ? ' active' : '';
            return '<a class="btn btn-sm btn-outline-secondary' + active + '" href="/vnext/admin/data/' + esc(slug) + '?view=' + v.id + '" data-vnav title="' + v.label + '"><i class="bi ' + v.icon + '"></i></a>';
        }).join('');
        return '<div class="btn-group" role="group">' + btns + '</div>';
    }

    // ── Table view ───────────────────────────────────────────────────────────
    function buildTableView(meta, items, slug, page, size, total, q) {
        var listFields = meta.fields.filter(function (f) { return f.list; });
        if (listFields.length === 0) listFields = meta.fields.slice(0, 4);

        var html = '<div class="table-responsive"><table class="table table-hover table-sm align-middle">';
        html += '<thead><tr>';
        listFields.forEach(function (f) { html += '<th>' + esc(f.label) + '</th>'; });
        html += '<th class="text-end">Actions</th></tr></thead><tbody>';

        if (items.length === 0) {
            html += '<tr><td colspan="' + (listFields.length + 1) + '" class="text-center text-muted">No records found.</td></tr>';
        }
        items.forEach(function (item) {
            html += '<tr>';
            listFields.forEach(function (f) {
                var v = item[f.name] != null ? item[f.name] : '';
                html += '<td>' + esc(formatFieldValue(f, v)) + '</td>';
            });
            var id = item.id || item.Id || '';
            html += '<td class="text-end"><a class="btn btn-sm btn-outline-primary me-1" href="/vnext/admin/data/' + esc(slug) + '/' + esc(id) + '" data-vnav title="View"><i class="bi bi-eye"></i></a>' +
                '<a class="btn btn-sm btn-outline-secondary me-1" href="/vnext/admin/data/' + esc(slug) + '/' + esc(id) + '/edit" data-vnav title="Edit"><i class="bi bi-pencil"></i></a>' +
                '<a class="btn btn-sm btn-outline-danger" href="/vnext/admin/data/' + esc(slug) + '/' + esc(id) + '/delete" data-vnav title="Delete"><i class="bi bi-trash"></i></a></td>';
            html += '</tr>';
        });
        html += '</tbody></table></div>';

        // Pagination
        var totalPages = Math.max(1, Math.ceil(total / size));
        if (totalPages > 1) {
            html += '<nav><ul class="pagination pagination-sm justify-content-center">';
            for (var p = 1; p <= totalPages; p++) {
                var active = p === page ? ' active' : '';
                var href = '/vnext/admin/data/' + slug + '?page=' + p + '&size=' + size + (q ? '&q=' + encodeURIComponent(q) : '');
                html += '<li class="page-item' + active + '"><a class="page-link" href="' + esc(href) + '" data-vnav>' + p + '</a></li>';
            }
            html += '</ul></nav>';
        }
        html += '<p class="text-muted small text-center">' + esc(String(items.length)) + ' of ' + esc(String(total)) + ' records</p>';
        return html;
    }

    // ── Tree view ────────────────────────────────────────────────────────────
    function buildTreeView(meta, items, slug) {
        var parentFieldName = meta.parentField;
        if (!parentFieldName) return buildTableView(meta, items, slug, 1, items.length, items.length, '');

        var byId = {};
        items.forEach(function (item) { byId[item.id || item.Id] = item; });

        var roots = items.filter(function (item) {
            var pid = item[parentFieldName];
            return !pid || !byId[pid];
        });

        function renderNode(item, depth) {
            var id = item.id || item.Id;
            var label = getDisplayValue(meta, item);
            var children = items.filter(function (c) {
                return (c[parentFieldName]) === id;
            });
            var indent = '<span style="padding-left:' + (depth * 20) + 'px"></span>';
            var toggle = children.length > 0 ? '<i class="bi bi-chevron-right me-1 vnext-tree-toggle" style="cursor:pointer"></i>' : '<i class="bi bi-dot me-1"></i>';
            var html = '<tr class="vnext-tree-node" data-parent-id="' + esc(id) + '">' +
                '<td>' + indent + toggle + esc(label) + '</td>' +
                '<td class="text-end"><a class="btn btn-xs btn-outline-primary me-1" href="/vnext/admin/data/' + esc(slug) + '/' + esc(id) + '" data-vnav><i class="bi bi-eye"></i></a>' +
                '<a class="btn btn-xs btn-outline-secondary me-1" href="/vnext/admin/data/' + esc(slug) + '/' + esc(id) + '/edit" data-vnav><i class="bi bi-pencil"></i></a></td></tr>';
            children.forEach(function (child) { html += renderNode(child, depth + 1); });
            return html;
        }

        var html = '<div class="table-responsive"><table class="table table-sm"><thead><tr><th>Name</th><th class="text-end">Actions</th></tr></thead><tbody>';
        roots.forEach(function (r) { html += renderNode(r, 0); });
        html += '</tbody></table></div>';
        return html;
    }

    // ── Org chart ────────────────────────────────────────────────────────────
    function buildOrgChart(meta, items, slug) {
        var parentFieldName = meta.parentField;
        if (!parentFieldName) return buildTableView(meta, items, slug, 1, items.length, items.length, '');

        var byId = {};
        items.forEach(function (item) { byId[item.id || item.Id] = item; });
        var roots = items.filter(function (item) {
            var pid = item[parentFieldName];
            return !pid || !byId[pid];
        });

        function renderCard(item, depth) {
            var id = item.id || item.Id;
            var label = getDisplayValue(meta, item);
            var subtitle = '';
            meta.fields.filter(function (f) { return f.list && f.name !== 'Id' && f.name !== 'id'; }).slice(0, 2).forEach(function (f) {
                if (item[f.name]) subtitle += '<br><small class="text-muted">' + esc(f.label) + ': ' + esc(formatFieldValue(f, item[f.name])) + '</small>';
            });
            var children = items.filter(function (c) { return (c[parentFieldName]) === id; });
            var childHtml = children.length > 0
                ? '<div class="d-flex gap-2 justify-content-center flex-wrap mt-2">' + children.map(function (c) { return renderCard(c, depth + 1); }).join('') + '</div>'
                : '';
            return '<div class="text-center" style="min-width:120px">' +
                '<a class="card card-body p-2 text-decoration-none d-inline-block" href="/vnext/admin/data/' + esc(slug) + '/' + esc(id) + '" data-vnav style="min-width:100px">' +
                '<strong>' + esc(label) + '</strong>' + subtitle + '</a>' +
                (children.length > 0 ? '<div style="width:2px;height:16px;background:#aaa;margin:0 auto"></div>' : '') +
                childHtml + '</div>';
        }

        var html = '<div class="overflow-auto pb-3"><div class="d-flex gap-4 justify-content-center flex-wrap">';
        roots.forEach(function (r) { html += renderCard(r, 0); });
        html += '</div></div>';
        return html;
    }

    // ── Timeline view ────────────────────────────────────────────────────────
    function buildTimeline(meta, items, slug) {
        // Find a date field
        var dateField = meta.fields.find(function (f) { return f.type === 'DateOnly' || f.type === 'DateTime'; });
        if (!dateField) return buildTableView(meta, items, slug, 1, items.length, items.length, '');

        var sorted = items.slice().sort(function (a, b) {
            var da = new Date(a[dateField.name] || 0);
            var db = new Date(b[dateField.name] || 0);
            return da - db;
        });

        var html = '<ul class="list-group">';
        sorted.forEach(function (item) {
            var id = item.id || item.Id;
            var label = getDisplayValue(meta, item);
            var date = item[dateField.name] ? new Date(item[dateField.name]).toLocaleDateString() : '';
            html += '<li class="list-group-item d-flex justify-content-between align-items-center">' +
                '<div><span class="badge bg-secondary me-2">' + esc(date) + '</span>' + esc(label) + '</div>' +
                '<div><a class="btn btn-sm btn-outline-primary me-1" href="/vnext/admin/data/' + esc(slug) + '/' + esc(id) + '" data-vnav><i class="bi bi-eye"></i></a>' +
                '<a class="btn btn-sm btn-outline-secondary" href="/vnext/admin/data/' + esc(slug) + '/' + esc(id) + '/edit" data-vnav><i class="bi bi-pencil"></i></a></div>' +
                '</li>';
        });
        html += '</ul>';
        return html;
    }

    // ── Detail view ──────────────────────────────────────────────────────────
    function renderDetail(slug, id) {
        var meta = _metaBySlug[slug];
        if (!meta) { getRoot().innerHTML = '<div class="container mt-4"><div class="alert alert-warning">Entity not found: ' + esc(slug) + '</div></div>'; return; }
        apiJson('/api/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id)).then(function (item) {
            var html = buildNavbar(slug);
            html += '<div class="container-fluid">';
            html += '<div class="d-flex align-items-center justify-content-between mb-3 flex-wrap gap-2">';
            html += '<h2>' + esc(meta.name) + ' <small class="text-muted fs-6">' + esc(id) + '</small></h2>';
            html += '<div class="d-flex gap-2">';
            html += '<a class="btn btn-sm btn-secondary" href="/vnext/admin/data/' + esc(slug) + '" data-vnav><i class="bi bi-arrow-left"></i> Back</a>';
            html += '<a class="btn btn-sm btn-primary" href="/vnext/admin/data/' + esc(slug) + '/' + esc(id) + '/edit" data-vnav><i class="bi bi-pencil"></i> Edit</a>';
            html += '<a class="btn btn-sm btn-danger" href="/vnext/admin/data/' + esc(slug) + '/' + esc(id) + '/delete" data-vnav><i class="bi bi-trash"></i> Delete</a>';
            // Export links
            html += '<div class="dropdown"><button class="btn btn-sm btn-outline-secondary dropdown-toggle" data-bs-toggle="dropdown">Export</button>' +
                '<ul class="dropdown-menu">' +
                '<li><a class="dropdown-item" href="/admin/data/' + esc(slug) + '/' + esc(id) + '/html" target="_blank">HTML</a></li>' +
                '<li><a class="dropdown-item" href="/admin/data/' + esc(slug) + '/' + esc(id) + '/rtf" target="_blank">RTF</a></li>' +
                '<li><a class="dropdown-item" href="/admin/data/' + esc(slug) + '/' + esc(id) + '/export" target="_blank">JSON</a></li>' +
                '</ul></div>';
            // Remote commands
            if (meta.commands && meta.commands.length > 0) {
                meta.commands.forEach(function (cmd) {
                    var btnClass = cmd.destructive ? 'btn-outline-danger' : 'btn-outline-secondary';
                    var icon = cmd.icon ? '<i class="bi ' + esc(cmd.icon) + ' me-1"></i>' : '';
                    html += '<button class="btn btn-sm ' + btnClass + ' vnext-cmd-btn" data-cmd="' + esc(cmd.name) + '" data-confirm="' + esc(cmd.confirmMessage || '') + '" data-slug="' + esc(slug) + '" data-id="' + esc(id) + '">' + icon + esc(cmd.label) + '</button>';
                });
            }
            html += '</div></div>';

            // Fields table
            var viewFields = meta.fields.filter(function (f) { return f.view; });
            html += '<div class="card"><div class="card-body"><dl class="row mb-0">';
            viewFields.forEach(function (f) {
                var v = item[f.name];
                var displayVal = formatFieldValueForDetail(f, v);
                html += '<dt class="col-sm-3">' + esc(f.label) + '</dt><dd class="col-sm-9">' + displayVal + '</dd>';
            });
            html += '</dl></div></div>';
            html += '</div>';

            var root = getRoot();
            root.innerHTML = html;
            wireNavEvents(root);

            // Wire command buttons
            root.querySelectorAll('.vnext-cmd-btn').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    var confirmMsg = btn.getAttribute('data-confirm');
                    if (confirmMsg && !window.confirm(confirmMsg)) return;
                    var cmdSlug = btn.getAttribute('data-slug');
                    var cmdId = btn.getAttribute('data-id');
                    var cmdName = btn.getAttribute('data-cmd');
                    apiFetch('/api/' + encodeURIComponent(cmdSlug) + '/' + encodeURIComponent(cmdId) + '/_command/' + encodeURIComponent(cmdName), { method: 'POST' })
                        .then(function (res) { return res.json(); })
                        .then(function (result) {
                            showToast(result.message || 'Command executed.', result.success ? 'success' : 'warning');
                            if (result.success) renderDetail(cmdSlug, cmdId);
                        }).catch(function (e) { showToast(e.message, 'danger'); });
                });
            });
        }).catch(function (e) {
            getRoot().innerHTML = buildNavbar(slug) + '<div class="container mt-4"><div class="alert alert-danger">' + esc(e.message) + '</div></div>';
        });
    }

    // ── Create view ──────────────────────────────────────────────────────────
    function renderCreate(slug) {
        var meta = _metaBySlug[slug];
        if (!meta) { getRoot().innerHTML = '<div class="alert alert-warning">Entity not found: ' + esc(slug) + '</div>'; return; }
        renderForm(meta, slug, null, {});
    }

    // ── Edit view ────────────────────────────────────────────────────────────
    function renderEdit(slug, id) {
        var meta = _metaBySlug[slug];
        if (!meta) { getRoot().innerHTML = '<div class="alert alert-warning">Entity not found: ' + esc(slug) + '</div>'; return; }
        apiJson('/api/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id)).then(function (item) {
            renderForm(meta, slug, id, item);
        }).catch(function (e) {
            getRoot().innerHTML = buildNavbar(slug) + '<div class="container mt-4"><div class="alert alert-danger">' + esc(e.message) + '</div></div>';
        });
    }

    // ── Form renderer ─────────────────────────────────────────────────────────
    function renderForm(meta, slug, id, item) {
        var isCreate = id == null;
        var formFields = meta.fields.filter(function (f) { return isCreate ? f.create : f.edit; });

        // Collect all lookups needed
        var lookupPromises = {};
        formFields.forEach(function (f) {
            if (f.lookupTargetSlug && !lookupPromises[f.name]) {
                lookupPromises[f.name] = loadLookup(f.lookupTargetSlug, f.lookupFilterField, f.lookupFilterValue);
            }
        });

        var lookupData = {};
        var keys = Object.keys(lookupPromises);
        Promise.all(keys.map(function (k) {
            return lookupPromises[k].then(function (data) { lookupData[k] = data; });
        })).then(function () {
            var html = buildNavbar(slug);
            html += '<div class="container-fluid">';
            html += '<div class="d-flex align-items-center justify-content-between mb-3">';
            html += '<h2>' + (isCreate ? 'Create ' : 'Edit ') + esc(meta.name) + '</h2>';
            html += '<a class="btn btn-sm btn-secondary" href="/vnext/admin/data/' + esc(slug) + (id ? '/' + esc(id) : '') + '" data-vnav><i class="bi bi-arrow-left"></i> Back</a>';
            html += '</div>';
            html += '<div class="card"><div class="card-body">';
            html += '<form id="vnext-form">';
            html += '<input type="hidden" name="_method" value="' + (isCreate ? 'POST' : 'PUT') + '">';

            formFields.forEach(function (f) {
                var val = item[f.name] != null ? item[f.name] : '';
                html += renderFormField(f, val, lookupData[f.name]);
            });

            html += '<div class="mt-3 d-flex gap-2">';
            html += '<button type="submit" class="btn btn-primary"><i class="bi bi-save me-1"></i>' + (isCreate ? 'Create' : 'Save') + '</button>';
            html += '<a class="btn btn-secondary" href="/vnext/admin/data/' + esc(slug) + (id ? '/' + esc(id) : '') + '" data-vnav>Cancel</a>';
            html += '</div></form></div></div></div>';

            var root = getRoot();
            root.innerHTML = html;
            wireNavEvents(root);

            // Wire form submit
            var form = root.querySelector('#vnext-form');
            if (form) {
                form.addEventListener('submit', function (e) {
                    e.preventDefault();
                    var formData = new FormData(form);
                    var body = {};
                    formData.forEach(function (v, k) {
                        if (k === '_method') return;
                        if (body[k] !== undefined) {
                            if (!Array.isArray(body[k])) body[k] = [body[k]];
                            body[k].push(v);
                        } else {
                            body[k] = v;
                        }
                    });

                    // Convert types
                    formFields.forEach(function (f) {
                        if (body[f.name] === undefined) {
                            if (f.type === 'YesNo') body[f.name] = false;
                            return;
                        }
                        if (f.type === 'Integer') body[f.name] = parseInt(body[f.name], 10) || 0;
                        else if (f.type === 'Decimal' || f.type === 'Money') body[f.name] = parseFloat(body[f.name]) || 0;
                        else if (f.type === 'YesNo') body[f.name] = body[f.name] === 'true' || body[f.name] === 'on' || body[f.name] === true;
                    });

                    var url = '/api/' + encodeURIComponent(slug);
                    var method = isCreate ? 'POST' : 'PUT';
                    if (!isCreate) url += '/' + encodeURIComponent(id);

                    apiFetch(url, {
                        method: method,
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(body)
                    }).then(function (res) {
                        if (!res.ok) return res.text().then(function (t) { throw new Error(t || res.statusText); });
                        return res.json();
                    }).then(function (saved) {
                        var savedId = saved.id || saved.Id || id;
                        showToast(isCreate ? 'Created successfully.' : 'Saved successfully.', 'success');
                        navigate('/vnext/admin/data/' + slug + '/' + savedId);
                    }).catch(function (err) {
                        showToast('Error: ' + err.message, 'danger');
                    });
                });
            }
        });
    }

    function renderFormField(f, val, lookupItems) {
        var id = 'vnext_' + f.name;
        var required = f.required ? ' required' : '';
        var readOnly = f.readOnly ? ' readonly disabled' : '';
        var placeholder = f.placeholder ? ' placeholder="' + esc(f.placeholder) + '"' : '';
        var html = '<div class="mb-3"><label class="form-label" for="' + id + '">' + esc(f.label) + (f.required ? ' <span class="text-danger">*</span>' : '') + '</label>';

        switch (f.type) {
            case 'TextArea':
                html += '<textarea class="form-control" id="' + id + '" name="' + esc(f.name) + '" rows="4"' + required + readOnly + placeholder + '>' + esc(String(val)) + '</textarea>';
                break;
            case 'YesNo':
                html += '<div class="form-check"><input class="form-check-input" type="checkbox" id="' + id + '" name="' + esc(f.name) + '" value="true"' + (val ? ' checked' : '') + readOnly + '><label class="form-check-label" for="' + id + '">' + esc(f.label) + '</label></div>';
                break;
            case 'Enum':
            case 'LookupList':
                if (lookupItems && lookupItems.length > 0) {
                    html += '<select class="form-select" id="' + id + '" name="' + esc(f.name) + '"' + required + readOnly + '>';
                    html += '<option value="">-- Select --</option>';
                    lookupItems.forEach(function (opt) {
                        var optVal = opt[f.lookupValueField || 'id'] || opt.id || opt.Id || '';
                        var optLabel = opt[f.lookupDisplayField || 'name'] || opt.name || opt.Name || optVal;
                        var sel = String(val) === String(optVal) ? ' selected' : '';
                        html += '<option value="' + esc(optVal) + '"' + sel + '>' + esc(optLabel) + '</option>';
                    });
                    html += '</select>';
                } else {
                    html += '<input class="form-control" type="text" id="' + id + '" name="' + esc(f.name) + '" value="' + esc(String(val)) + '"' + required + readOnly + placeholder + '>';
                }
                break;
            case 'Country':
                html += buildCountrySelect(id, f.name, String(val), required, readOnly);
                break;
            case 'DateOnly':
                html += '<input class="form-control" type="date" id="' + id + '" name="' + esc(f.name) + '" value="' + esc(val ? String(val).substring(0, 10) : '') + '"' + required + readOnly + '>';
                break;
            case 'TimeOnly':
                html += '<input class="form-control" type="time" id="' + id + '" name="' + esc(f.name) + '" value="' + esc(String(val)) + '"' + required + readOnly + '>';
                break;
            case 'DateTime':
                var dtVal = val ? String(val).replace(' ', 'T').substring(0, 16) : '';
                html += '<input class="form-control" type="datetime-local" id="' + id + '" name="' + esc(f.name) + '" value="' + esc(dtVal) + '"' + required + readOnly + '>';
                break;
            case 'Integer':
                html += '<input class="form-control" type="number" step="1" id="' + id + '" name="' + esc(f.name) + '" value="' + esc(String(val)) + '"' + required + readOnly + placeholder + '>';
                break;
            case 'Decimal':
            case 'Money':
                html += '<input class="form-control" type="number" step="0.01" id="' + id + '" name="' + esc(f.name) + '" value="' + esc(String(val)) + '"' + required + readOnly + placeholder + '>';
                break;
            case 'Email':
                html += '<input class="form-control" type="email" id="' + id + '" name="' + esc(f.name) + '" value="' + esc(String(val)) + '"' + required + readOnly + placeholder + '>';
                break;
            case 'Password':
                html += '<input class="form-control" type="password" id="' + id + '" name="' + esc(f.name) + '" value=""' + required + readOnly + placeholder + '>';
                break;
            case 'Hidden':
                html += '<input type="hidden" id="' + id + '" name="' + esc(f.name) + '" value="' + esc(String(val)) + '">';
                break;
            case 'ReadOnly':
            case 'Button':
            case 'Link':
            case 'CustomHtml':
                html += '<input class="form-control" type="text" id="' + id + '" name="' + esc(f.name) + '" value="' + esc(String(val)) + '" readonly>';
                break;
            default:
                html += '<input class="form-control" type="text" id="' + id + '" name="' + esc(f.name) + '" value="' + esc(String(val)) + '"' + required + readOnly + placeholder + '>';
        }

        if (f.isComputed || f.isCalculated || f.readOnly) {
            html += '<div class="form-text text-muted">' + (f.isComputed ? 'Computed automatically.' : f.isCalculated ? 'Calculated field.' : 'Read-only.') + '</div>';
        }
        html += '</div>';
        return html;
    }

    // ── Delete confirmation ───────────────────────────────────────────────────
    function renderDeleteConfirm(slug, id) {
        var meta = _metaBySlug[slug];
        if (!meta) { getRoot().innerHTML = '<div class="alert alert-warning">Entity not found</div>'; return; }
        apiJson('/api/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id)).then(function (item) {
            var label = getDisplayValue(meta, item);
            var html = buildNavbar(slug);
            html += '<div class="container" style="max-width:600px">';
            html += '<div class="card border-danger mt-4"><div class="card-header bg-danger text-white"><i class="bi bi-exclamation-triangle me-2"></i>Confirm Delete</div>';
            html += '<div class="card-body"><p>Are you sure you want to delete <strong>' + esc(label) + '</strong>? This cannot be undone.</p>';
            html += '<div class="d-flex gap-2">';
            html += '<button class="btn btn-danger" id="vnext-confirm-delete"><i class="bi bi-trash me-1"></i>Delete</button>';
            html += '<a class="btn btn-secondary" href="/vnext/admin/data/' + esc(slug) + '/' + esc(id) + '" data-vnav>Cancel</a>';
            html += '</div></div></div></div>';
            var root = getRoot();
            root.innerHTML = html;
            wireNavEvents(root);
            var btn = root.querySelector('#vnext-confirm-delete');
            if (btn) {
                btn.addEventListener('click', function () {
                    btn.disabled = true;
                    apiFetch('/api/' + encodeURIComponent(slug) + '/' + encodeURIComponent(id), { method: 'DELETE' })
                        .then(function (res) {
                            if (!res.ok) return res.text().then(function (t) { throw new Error(t); });
                            showToast('Deleted successfully.', 'success');
                            navigate('/vnext/admin/data/' + slug);
                        }).catch(function (e) {
                            showToast('Error: ' + e.message, 'danger');
                            btn.disabled = false;
                        });
                });
            }
        }).catch(function (e) {
            getRoot().innerHTML = buildNavbar(slug) + '<div class="container mt-4"><div class="alert alert-danger">' + esc(e.message) + '</div></div>';
        });
    }

    // ── Format helpers ────────────────────────────────────────────────────────
    function getDisplayValue(meta, item) {
        var nameField = meta.fields.find(function (f) { return f.name.toLowerCase() === 'name' || f.name.toLowerCase() === 'title'; });
        if (nameField && item[nameField.name]) return String(item[nameField.name]);
        var firstListField = meta.fields.find(function (f) { return f.list; });
        if (firstListField && item[firstListField.name]) return String(item[firstListField.name]);
        return item.id || item.Id || '';
    }

    function formatFieldValue(field, v) {
        if (v == null || v === '') return '';
        switch (field.type) {
            case 'YesNo': return v ? '✓ Yes' : '✗ No';
            case 'DateOnly': return v ? new Date(v).toLocaleDateString() : '';
            case 'DateTime': return v ? new Date(v).toLocaleString() : '';
            case 'Money': return v != null ? '$' + parseFloat(v).toFixed(2) : '';
            case 'Image': return v ? '(image)' : '';
            case 'File': return v ? '(file)' : '';
            case 'Password': return '••••••••';
            default: return String(v);
        }
    }

    function formatFieldValueForDetail(field, v) {
        if (v == null || v === '') return '<span class="text-muted">—</span>';
        switch (field.type) {
            case 'YesNo': return v ? '<span class="badge bg-success">Yes</span>' : '<span class="badge bg-secondary">No</span>';
            case 'DateOnly': return esc(new Date(v).toLocaleDateString());
            case 'DateTime': return esc(new Date(v).toLocaleString());
            case 'Money': return esc('$' + parseFloat(v).toFixed(2));
            case 'Image': return v ? '<img src="' + esc(v) + '" class="img-thumbnail" style="max-width:200px">' : '<span class="text-muted">—</span>';
            case 'File': return v ? '<a href="' + esc(v) + '" target="_blank"><i class="bi bi-file-earmark me-1"></i>' + esc(v) + '</a>' : '<span class="text-muted">—</span>';
            case 'Password': return '<span class="text-muted">••••••••</span>';
            case 'Email': return v ? '<a href="mailto:' + esc(v) + '">' + esc(v) + '</a>' : '<span class="text-muted">—</span>';
            case 'Link': return v ? '<a href="' + esc(v) + '" target="_blank">' + esc(v) + '</a>' : '<span class="text-muted">—</span>';
            case 'TextArea': return '<pre class="mb-0" style="white-space:pre-wrap">' + esc(String(v)) + '</pre>';
            default:
                if (typeof v === 'object') return '<pre class="mb-0" style="white-space:pre-wrap">' + esc(JSON.stringify(v, null, 2)) + '</pre>';
                return esc(String(v));
        }
    }

    // ── Country select ────────────────────────────────────────────────────────
    var _countries = [
        ['AF','Afghanistan'],['AL','Albania'],['DZ','Algeria'],['AD','Andorra'],['AO','Angola'],
        ['AG','Antigua and Barbuda'],['AR','Argentina'],['AM','Armenia'],['AU','Australia'],['AT','Austria'],
        ['AZ','Azerbaijan'],['BS','Bahamas'],['BH','Bahrain'],['BD','Bangladesh'],['BB','Barbados'],
        ['BY','Belarus'],['BE','Belgium'],['BZ','Belize'],['BJ','Benin'],['BT','Bhutan'],
        ['BO','Bolivia'],['BA','Bosnia and Herzegovina'],['BW','Botswana'],['BR','Brazil'],['BN','Brunei'],
        ['BG','Bulgaria'],['BF','Burkina Faso'],['BI','Burundi'],['CV','Cabo Verde'],['KH','Cambodia'],
        ['CM','Cameroon'],['CA','Canada'],['CF','Central African Republic'],['TD','Chad'],['CL','Chile'],
        ['CN','China'],['CO','Colombia'],['KM','Comoros'],['CD','Congo, DR'],['CG','Congo, Republic'],
        ['CR','Costa Rica'],['HR','Croatia'],['CU','Cuba'],['CY','Cyprus'],['CZ','Czech Republic'],
        ['DK','Denmark'],['DJ','Djibouti'],['DM','Dominica'],['DO','Dominican Republic'],['EC','Ecuador'],
        ['EG','Egypt'],['SV','El Salvador'],['GQ','Equatorial Guinea'],['ER','Eritrea'],['EE','Estonia'],
        ['SZ','Eswatini'],['ET','Ethiopia'],['FJ','Fiji'],['FI','Finland'],['FR','France'],
        ['GA','Gabon'],['GM','Gambia'],['GE','Georgia'],['DE','Germany'],['GH','Ghana'],
        ['GR','Greece'],['GD','Grenada'],['GT','Guatemala'],['GN','Guinea'],['GW','Guinea-Bissau'],
        ['GY','Guyana'],['HT','Haiti'],['HN','Honduras'],['HU','Hungary'],['IS','Iceland'],
        ['IN','India'],['ID','Indonesia'],['IR','Iran'],['IQ','Iraq'],['IE','Ireland'],
        ['IL','Israel'],['IT','Italy'],['JM','Jamaica'],['JP','Japan'],['JO','Jordan'],
        ['KZ','Kazakhstan'],['KE','Kenya'],['KI','Kiribati'],['KP','Korea, North'],['KR','Korea, South'],
        ['KW','Kuwait'],['KG','Kyrgyzstan'],['LA','Laos'],['LV','Latvia'],['LB','Lebanon'],
        ['LS','Lesotho'],['LR','Liberia'],['LY','Libya'],['LI','Liechtenstein'],['LT','Lithuania'],
        ['LU','Luxembourg'],['MG','Madagascar'],['MW','Malawi'],['MY','Malaysia'],['MV','Maldives'],
        ['ML','Mali'],['MT','Malta'],['MH','Marshall Islands'],['MR','Mauritania'],['MU','Mauritius'],
        ['MX','Mexico'],['FM','Micronesia'],['MD','Moldova'],['MC','Monaco'],['MN','Mongolia'],
        ['ME','Montenegro'],['MA','Morocco'],['MZ','Mozambique'],['MM','Myanmar'],['NA','Namibia'],
        ['NR','Nauru'],['NP','Nepal'],['NL','Netherlands'],['NZ','New Zealand'],['NI','Nicaragua'],
        ['NE','Niger'],['NG','Nigeria'],['MK','North Macedonia'],['NO','Norway'],['OM','Oman'],
        ['PK','Pakistan'],['PW','Palau'],['PA','Panama'],['PG','Papua New Guinea'],['PY','Paraguay'],
        ['PE','Peru'],['PH','Philippines'],['PL','Poland'],['PT','Portugal'],['QA','Qatar'],
        ['RO','Romania'],['RU','Russia'],['RW','Rwanda'],['KN','Saint Kitts and Nevis'],['LC','Saint Lucia'],
        ['VC','Saint Vincent and the Grenadines'],['WS','Samoa'],['SM','San Marino'],['ST','Sao Tome and Principe'],
        ['SA','Saudi Arabia'],['SN','Senegal'],['RS','Serbia'],['SC','Seychelles'],['SL','Sierra Leone'],
        ['SG','Singapore'],['SK','Slovakia'],['SI','Slovenia'],['SB','Solomon Islands'],['SO','Somalia'],
        ['ZA','South Africa'],['SS','South Sudan'],['ES','Spain'],['LK','Sri Lanka'],['SD','Sudan'],
        ['SR','Suriname'],['SE','Sweden'],['CH','Switzerland'],['SY','Syria'],['TW','Taiwan'],
        ['TJ','Tajikistan'],['TZ','Tanzania'],['TH','Thailand'],['TL','Timor-Leste'],['TG','Togo'],
        ['TO','Tonga'],['TT','Trinidad and Tobago'],['TN','Tunisia'],['TR','Turkey'],['TM','Turkmenistan'],
        ['TV','Tuvalu'],['UG','Uganda'],['UA','Ukraine'],['AE','United Arab Emirates'],['GB','United Kingdom'],
        ['US','United States'],['UY','Uruguay'],['UZ','Uzbekistan'],['VU','Vanuatu'],['VE','Venezuela'],
        ['VN','Vietnam'],['YE','Yemen'],['ZM','Zambia'],['ZW','Zimbabwe']
    ];

    function buildCountrySelect(id, name, currentVal, required, readOnly) {
        var opts = '<option value="">-- Select Country --</option>';
        _countries.forEach(function (c) {
            var sel = c[0] === currentVal ? ' selected' : '';
            opts += '<option value="' + esc(c[0]) + '"' + sel + '>' + esc(c[1]) + '</option>';
        });
        return '<select class="form-select" id="' + id + '" name="' + esc(name) + '"' + required + readOnly + '>' + opts + '</select>';
    }

    // ── Bootstrap init ────────────────────────────────────────────────────────
    function waitForBootstrap(cb) {
        if (typeof bootstrap !== 'undefined') { cb(); return; }
        var attempts = 0;
        var t = setInterval(function () {
            attempts++;
            if (typeof bootstrap !== 'undefined') { clearInterval(t); cb(); }
            else if (attempts > 50) { clearInterval(t); cb(); } // give up after 5s
        }, 100);
    }

    // ── Boot ──────────────────────────────────────────────────────────────────
    waitForBootstrap(function () {
        render();
    });
})();
