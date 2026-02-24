(function () {
    'use strict';

    var FIELD_TYPES = [
        { value: 'string', label: 'String' },
        { value: 'multiline', label: 'Text Area' },
        { value: 'email', label: 'Email' },
        { value: 'int', label: 'Integer' },
        { value: 'decimal', label: 'Decimal' },
        { value: 'bool', label: 'Yes/No' },
        { value: 'date', label: 'Date' },
        { value: 'time', label: 'Time' },
        { value: 'datetime', label: 'DateTime' },
        { value: 'enum', label: 'Enum (dropdown)' },
        { value: 'lookup', label: 'Lookup (FK)' }
    ];

    var VIEW_TYPES = ['Table', 'TreeView', 'OrgChart', 'Timeline', 'Timetable'];
    var ID_STRATEGIES = ['guid', 'sequential', 'none'];

    var entity = {
        entityId: crypto.randomUUID(),
        name: '', slug: '', showOnNav: true, permissions: '',
        idStrategy: 'guid', navGroup: 'Admin', navOrder: 0,
        viewType: null, parentField: null, fields: []
    };

    function escHtml(s) {
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    function render() {
        var container = document.getElementById('designer-root');
        if (!container) return;

        var html = '<div class="row g-3">';

        // Left panel: visual editor
        html += '<div class="col-lg-7">';
        html += '<div class="card bm-page-card mb-3"><div class="card-header"><h5 class="mb-0"><i class="bi bi-diagram-3 me-2"></i>Entity Designer</h5></div><div class="card-body">';

        // Entity properties
        html += '<h6 class="fw-bold mb-2">Entity Properties</h6>';
        html += '<div class="row g-2 mb-3">';
        html += '<div class="col-md-4"><label class="form-label">Name <span class="text-danger">*</span></label><input type="text" class="form-control form-control-sm" id="ed-name" value="' + escHtml(entity.name) + '" placeholder="e.g. Ticket"></div>';
        html += '<div class="col-md-4"><label class="form-label">Slug</label><input type="text" class="form-control form-control-sm" id="ed-slug" value="' + escHtml(entity.slug || '') + '" placeholder="auto from name"></div>';
        html += '<div class="col-md-4"><label class="form-label">Nav Group</label><input type="text" class="form-control form-control-sm" id="ed-navGroup" value="' + escHtml(entity.navGroup) + '"></div>';
        html += '</div>';
        html += '<div class="row g-2 mb-3">';
        html += '<div class="col-md-3"><label class="form-label">Nav Order</label><input type="number" class="form-control form-control-sm" id="ed-navOrder" value="' + entity.navOrder + '"></div>';
        html += '<div class="col-md-3"><label class="form-label">ID Strategy</label><select class="form-select form-select-sm" id="ed-idStrategy">';
        ID_STRATEGIES.forEach(function (s) { html += '<option' + (entity.idStrategy === s ? ' selected' : '') + '>' + s + '</option>'; });
        html += '</select></div>';
        html += '<div class="col-md-3"><label class="form-label">View Type</label><select class="form-select form-select-sm" id="ed-viewType"><option value="">Table (default)</option>';
        VIEW_TYPES.forEach(function (v) { html += '<option value="' + v + '"' + (entity.viewType === v ? ' selected' : '') + '>' + v + '</option>'; });
        html += '</select></div>';
        html += '<div class="col-md-3"><label class="form-label">Permissions</label><input type="text" class="form-control form-control-sm" id="ed-permissions" value="' + escHtml(entity.permissions || '') + '" placeholder="e.g. admin"></div>';
        html += '</div>';
        html += '<div class="row g-2 mb-3">';
        html += '<div class="col-md-3"><div class="form-check mt-4"><input class="form-check-input" type="checkbox" id="ed-showOnNav"' + (entity.showOnNav ? ' checked' : '') + '><label class="form-check-label" for="ed-showOnNav">Show in Nav</label></div></div>';
        html += '<div class="col-md-4"><label class="form-label">Parent Field</label><input type="text" class="form-control form-control-sm" id="ed-parentField" value="' + escHtml(entity.parentField || '') + '" placeholder="for tree/orgchart"></div>';
        html += '</div>';

        // Fields
        html += '<hr><h6 class="fw-bold mb-2">Fields <button class="btn btn-sm btn-outline-primary ms-2" id="ed-add-field"><i class="bi bi-plus"></i> Add Field</button></h6>';
        html += '<div id="ed-fields-list">';

        entity.fields.forEach(function (f, idx) {
            html += '<div class="card mb-2 ed-field-card" data-idx="' + idx + '">';
            html += '<div class="card-body p-2">';
            html += '<div class="row g-2 align-items-center">';
            html += '<div class="col-auto"><i class="bi bi-grip-vertical text-muted" style="cursor:grab"></i></div>';
            html += '<div class="col"><input type="text" class="form-control form-control-sm ed-field-name" placeholder="fieldName" value="' + escHtml(f.name) + '"></div>';
            html += '<div class="col"><input type="text" class="form-control form-control-sm ed-field-label" placeholder="Label" value="' + escHtml(f.label || '') + '"></div>';
            html += '<div class="col"><select class="form-select form-select-sm ed-field-type">';
            FIELD_TYPES.forEach(function (t) { html += '<option value="' + t.value + '"' + (f.type === t.value ? ' selected' : '') + '>' + t.label + '</option>'; });
            html += '</select></div>';
            html += '<div class="col-auto"><div class="form-check"><input class="form-check-input ed-field-required" type="checkbox"' + (f.required ? ' checked' : '') + '><label class="form-check-label small">Req</label></div></div>';
            html += '<div class="col-auto"><div class="form-check"><input class="form-check-input ed-field-list" type="checkbox"' + (f.list !== false ? ' checked' : '') + '><label class="form-check-label small">List</label></div></div>';
            html += '<div class="col-auto"><button class="btn btn-sm btn-outline-danger ed-field-remove" title="Remove"><i class="bi bi-trash"></i></button></div>';
            html += '</div>';

            // Extra config for enum/lookup
            if (f.type === 'enum') {
                html += '<div class="mt-2"><label class="form-label small">Enum Values (comma-separated)</label><input type="text" class="form-control form-control-sm ed-field-values" value="' + escHtml((f.values || []).join(', ')) + '"></div>';
            }
            if (f.type === 'lookup') {
                html += '<div class="row g-2 mt-1">';
                html += '<div class="col"><input type="text" class="form-control form-control-sm ed-field-lookupEntity" placeholder="Target entity slug" value="' + escHtml(f.lookupEntity || '') + '"></div>';
                html += '<div class="col"><input type="text" class="form-control form-control-sm ed-field-lookupDisplayField" placeholder="Display field" value="' + escHtml(f.lookupDisplayField || '') + '"></div>';
                html += '</div>';
            }

            html += '</div></div>';
        });

        html += '</div>';
        html += '</div></div>';

        // Action buttons
        html += '<div class="d-flex gap-2 mb-3">';
        html += '<button class="btn btn-primary" id="ed-download"><i class="bi bi-download me-1"></i>Download JSON</button>';
        html += '<button class="btn btn-outline-secondary" id="ed-copy"><i class="bi bi-clipboard me-1"></i>Copy JSON</button>';
        html += '<label class="btn btn-outline-secondary mb-0"><i class="bi bi-upload me-1"></i>Import JSON<input type="file" id="ed-import" accept=".json" class="d-none"></label>';
        html += '<button class="btn btn-outline-danger ms-auto" id="ed-reset"><i class="bi bi-arrow-counterclockwise me-1"></i>Reset</button>';
        html += '</div>';
        html += '</div>';

        // Right panel: JSON preview
        html += '<div class="col-lg-5">';
        html += '<div class="card bm-page-card" style="position:sticky;top:70px"><div class="card-header d-flex justify-content-between align-items-center"><h5 class="mb-0"><i class="bi bi-code-square me-2"></i>JSON Preview</h5></div>';
        html += '<div class="card-body p-0"><pre id="ed-json-preview" class="p-3 mb-0" style="max-height:75vh;overflow:auto;font-size:0.8rem;background:var(--bs-tertiary-bg,#f8f9fa);border-radius:0 0 1rem 1rem"></pre></div>';
        html += '</div></div>';

        html += '</div>';

        container.innerHTML = html;
        updateJsonPreview();
        wireEvents();
    }

    function buildJson() {
        var out = {
            entityId: entity.entityId,
            name: entity.name,
            showOnNav: entity.showOnNav,
            idStrategy: entity.idStrategy,
            navGroup: entity.navGroup,
            navOrder: entity.navOrder,
            fields: entity.fields.map(function (f, i) {
                var field = { fieldId: f.fieldId, name: f.name, type: f.type, order: i + 1, required: f.required, list: f.list };
                if (f.label) field.label = f.label;
                if (f.placeholder) field.placeholder = f.placeholder;
                if (f.type === 'enum' && f.values) field.values = f.values;
                if (f.type === 'lookup') {
                    if (f.lookupEntity) field.lookupEntity = f.lookupEntity;
                    if (f.lookupDisplayField) field.lookupDisplayField = f.lookupDisplayField;
                }
                if (f.minLength != null) field.minLength = f.minLength;
                if (f.maxLength != null) field.maxLength = f.maxLength;
                return field;
            })
        };
        if (entity.slug) out.slug = entity.slug;
        if (entity.permissions) out.permissions = entity.permissions;
        if (entity.viewType) out.viewType = entity.viewType;
        if (entity.parentField) out.parentField = entity.parentField;
        return out;
    }

    function updateJsonPreview() {
        var el = document.getElementById('ed-json-preview');
        if (el) el.textContent = JSON.stringify({ virtualEntities: [buildJson()] }, null, 2);
    }

    function syncEntityFromInputs() {
        entity.name = (document.getElementById('ed-name') || {}).value || '';
        entity.slug = (document.getElementById('ed-slug') || {}).value || '';
        entity.navGroup = (document.getElementById('ed-navGroup') || {}).value || 'Admin';
        entity.navOrder = parseInt((document.getElementById('ed-navOrder') || {}).value, 10) || 0;
        entity.idStrategy = (document.getElementById('ed-idStrategy') || {}).value || 'guid';
        entity.viewType = (document.getElementById('ed-viewType') || {}).value || null;
        entity.permissions = (document.getElementById('ed-permissions') || {}).value || '';
        entity.showOnNav = !!(document.getElementById('ed-showOnNav') || {}).checked;
        entity.parentField = (document.getElementById('ed-parentField') || {}).value || null;
    }

    function syncFieldsFromInputs() {
        var cards = document.querySelectorAll('.ed-field-card');
        cards.forEach(function (card, idx) {
            if (!entity.fields[idx]) return;
            entity.fields[idx].name = card.querySelector('.ed-field-name').value;
            entity.fields[idx].label = card.querySelector('.ed-field-label').value || null;
            entity.fields[idx].type = card.querySelector('.ed-field-type').value;
            entity.fields[idx].required = card.querySelector('.ed-field-required').checked;
            entity.fields[idx].list = card.querySelector('.ed-field-list').checked;
            var valInput = card.querySelector('.ed-field-values');
            if (valInput) entity.fields[idx].values = valInput.value.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
            var lookupEntity = card.querySelector('.ed-field-lookupEntity');
            if (lookupEntity) entity.fields[idx].lookupEntity = lookupEntity.value;
            var lookupDisplay = card.querySelector('.ed-field-lookupDisplayField');
            if (lookupDisplay) entity.fields[idx].lookupDisplayField = lookupDisplay.value;
        });
    }

    function wireEvents() {
        // Entity property changes
        ['ed-name', 'ed-slug', 'ed-navGroup', 'ed-navOrder', 'ed-idStrategy', 'ed-viewType', 'ed-permissions', 'ed-parentField'].forEach(function (id) {
            var el = document.getElementById(id);
            if (el) el.addEventListener('input', function () { syncEntityFromInputs(); updateJsonPreview(); });
        });
        var showNav = document.getElementById('ed-showOnNav');
        if (showNav) showNav.addEventListener('change', function () { syncEntityFromInputs(); updateJsonPreview(); });

        // Field changes
        document.querySelectorAll('.ed-field-card').forEach(function (card) {
            card.querySelectorAll('input, select').forEach(function (inp) {
                inp.addEventListener('input', function () { syncFieldsFromInputs(); updateJsonPreview(); });
                inp.addEventListener('change', function () {
                    syncFieldsFromInputs();
                    // Re-render if type changed (to show/hide enum values / lookup fields)
                    if (inp.classList.contains('ed-field-type')) render();
                    else updateJsonPreview();
                });
            });
        });

        // Add field
        var addBtn = document.getElementById('ed-add-field');
        if (addBtn) addBtn.addEventListener('click', function () {
            syncEntityFromInputs();
            syncFieldsFromInputs();
            entity.fields.push({
                fieldId: crypto.randomUUID(), name: '', label: null, type: 'string',
                required: false, list: true, view: true, edit: true, create: true, values: null,
                lookupEntity: null, lookupDisplayField: null
            });
            render();
        });

        // Remove field
        document.querySelectorAll('.ed-field-remove').forEach(function (btn) {
            btn.addEventListener('click', function () {
                var idx = parseInt(btn.closest('.ed-field-card').dataset.idx, 10);
                syncEntityFromInputs();
                syncFieldsFromInputs();
                entity.fields.splice(idx, 1);
                render();
            });
        });

        // Download JSON
        var dlBtn = document.getElementById('ed-download');
        if (dlBtn) dlBtn.addEventListener('click', function () {
            syncEntityFromInputs(); syncFieldsFromInputs();
            var blob = new Blob([JSON.stringify({ virtualEntities: [buildJson()] }, null, 2)], { type: 'application/json' });
            var a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = (entity.slug || entity.name || 'entity').toLowerCase().replace(/\s+/g, '-') + '.json';
            a.click();
        });

        // Copy JSON
        var copyBtn = document.getElementById('ed-copy');
        if (copyBtn) copyBtn.addEventListener('click', function () {
            syncEntityFromInputs(); syncFieldsFromInputs();
            navigator.clipboard.writeText(JSON.stringify({ virtualEntities: [buildJson()] }, null, 2));
            copyBtn.innerHTML = '<i class="bi bi-check me-1"></i>Copied!';
            setTimeout(function () { copyBtn.innerHTML = '<i class="bi bi-clipboard me-1"></i>Copy JSON'; }, 2000);
        });

        // Import JSON
        var importInput = document.getElementById('ed-import');
        if (importInput) importInput.addEventListener('change', function (e) {
            var file = e.target.files[0];
            if (!file) return;
            var reader = new FileReader();
            reader.onload = function (ev) {
                try {
                    var data = JSON.parse(ev.target.result);
                    var def = data.virtualEntities ? data.virtualEntities[0] : data;
                    if (def) {
                        entity.entityId = def.entityId || crypto.randomUUID();
                        entity.name = def.name || '';
                        entity.slug = def.slug || '';
                        entity.showOnNav = def.showOnNav !== false;
                        entity.permissions = def.permissions || '';
                        entity.idStrategy = def.idStrategy || 'guid';
                        entity.navGroup = def.navGroup || 'Admin';
                        entity.navOrder = def.navOrder || 0;
                        entity.viewType = def.viewType || null;
                        entity.parentField = def.parentField || null;
                        entity.fields = (def.fields || []).map(function (f) {
                            return {
                                fieldId: f.fieldId || crypto.randomUUID(),
                                name: f.name || '', label: f.label || null, type: f.type || 'string',
                                required: !!f.required, list: f.list !== false,
                                values: f.values || null,
                                lookupEntity: f.lookupEntity || null,
                                lookupDisplayField: f.lookupDisplayField || null
                            };
                        });
                        render();
                    }
                } catch (err) { alert('Invalid JSON: ' + err.message); }
            };
            reader.readAsText(file);
        });

        // Reset
        var resetBtn = document.getElementById('ed-reset');
        if (resetBtn) resetBtn.addEventListener('click', function () {
            if (!confirm('Reset all fields?')) return;
            entity = {
                entityId: crypto.randomUUID(),
                name: '', slug: '', showOnNav: true, permissions: '',
                idStrategy: 'guid', navGroup: 'Admin', navOrder: 0,
                viewType: null, parentField: null, fields: []
            };
            render();
        });
    }

    // Initialize on DOMContentLoaded
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', render);
    } else {
        render();
    }
})();
