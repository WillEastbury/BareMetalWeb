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
        { value: 'lookup', label: 'Lookup (FK)' },
        { value: 'url', label: 'URL' },
        { value: 'phone', label: 'Phone' }
    ];

    var ID_STRATEGIES = ['guid', 'sequential', 'none'];
    var VIEW_TYPES = ['', 'Table', 'TreeView', 'OrgChart', 'Timeline', 'Timetable', 'Sankey', 'Calendar', 'Kanban'];
    var REPORT_TYPES = ['table', 'summary', 'timeline', 'kanban'];
    var PERMISSION_LEVELS = ['read', 'write', 'admin'];

    var SETTINGS_SLUG = 'settings';
    var MODULE_SETTING_PREFIX = 'entity-designer.module.';

    var state = {
        module: createDefaultModule(),
        selectedFieldIndex: -1,
        validation: [],
        status: { kind: 'info', text: 'Edit and Save In Place to persist directly to WAL-backed settings.' }
    };

    function createDefaultModule() {
        return {
            entityId: generateId(),
            name: '',
            slug: '',
            showOnNav: true,
            isComplete: false,
            permissions: '',
            idStrategy: 'guid',
            navGroup: 'Admin',
            navOrder: 0,
            viewType: '',
            parentField: '',
            fields: [],
            reports: [],
            permissionRules: []
        };
    }

    function createDefaultField() {
        return {
            fieldId: generateId(),
            name: '',
            label: '',
            type: 'string',
            required: false,
            list: true,
            view: true,
            edit: true,
            create: true,
            readOnly: false,
            nullable: true,
            multiline: false,
            values: [],
            lookupEntity: '',
            lookupValueField: '',
            lookupDisplayField: '',
            lookupQueryField: '',
            lookupQueryOperator: '',
            placeholder: '',
            minLength: null,
            maxLength: null,
            rangeMin: null,
            rangeMax: null,
            pattern: ''
        };
    }

    function createDefaultReport() {
        return {
            id: generateId(),
            name: '',
            type: 'table',
            sourceField: '',
            aggregation: '',
            visible: true
        };
    }

    function createDefaultPermissionRule() {
        return {
            id: generateId(),
            principal: '',
            level: 'read',
            constraint: ''
        };
    }

    function getCsrfToken() {
        var el = document.querySelector('meta[name="csrf-token"]');
        return el ? el.getAttribute('content') : '';
    }

    function setStatus(kind, text) {
        state.status = { kind: kind, text: text };
        render();
    }

    function generateId() {
        if (typeof crypto !== 'undefined') {
            if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
            if (typeof crypto.getRandomValues === 'function') {
                var bytes = new Uint8Array(16);
                crypto.getRandomValues(bytes);
                bytes[6] = (bytes[6] & 0x0f) | 0x40;
                bytes[8] = (bytes[8] & 0x3f) | 0x80;
                var hex = '';
                for (var i = 0; i < bytes.length; i++) {
                    var h = bytes[i].toString(16);
                    hex += h.length === 1 ? '0' + h : h;
                }
                return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20);
            }
        }

        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            var r = Math.floor(Math.random() * 16);
            var v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

    function escHtml(input) {
        var str = String(input == null ? '' : input);
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function slugify(value) {
        return String(value || '').trim().toLowerCase().replace(/[^a-z0-9\s-]/g, '').replace(/\s+/g, '-').replace(/-+/g, '-');
    }

    function trim(value) { return String(value || '').trim(); }

    function parseNumberOrNull(value) {
        if (value === '' || value == null) return null;
        var n = Number(value);
        return Number.isFinite(n) ? n : null;
    }

    function ensureSelectedFieldIndex() {
        if (!state.module.fields.length) {
            state.selectedFieldIndex = -1;
            return;
        }
        if (state.selectedFieldIndex < 0) {
            state.selectedFieldIndex = 0;
            return;
        }
        if (state.selectedFieldIndex >= state.module.fields.length) state.selectedFieldIndex = state.module.fields.length - 1;
    }

    function getSettingIdForModule() {
        var slug = slugify(state.module.slug || state.module.name);
        return MODULE_SETTING_PREFIX + (slug || state.module.entityId);
    }

    function buildExportObject() {
        var moduleDef = state.module;
        var out = {
            entityId: moduleDef.entityId,
            name: moduleDef.name,
            showOnNav: !!moduleDef.showOnNav,
            isComplete: !!moduleDef.isComplete,
            idStrategy: moduleDef.idStrategy || 'guid',
            navGroup: moduleDef.navGroup || 'Admin',
            navOrder: Number(moduleDef.navOrder) || 0,
            fields: moduleDef.fields.map(function (field, index) {
                var def = {
                    fieldId: field.fieldId,
                    name: field.name,
                    type: field.type,
                    order: index + 1,
                    required: !!field.required,
                    list: field.list !== false,
                    view: field.view !== false,
                    edit: field.edit !== false,
                    create: field.create !== false,
                    readOnly: !!field.readOnly,
                    nullable: field.nullable !== false
                };
                if (field.label) def.label = field.label;
                if (field.multiline) def.multiline = true;
                if (field.placeholder) def.placeholder = field.placeholder;
                if (field.type === 'enum' && field.values && field.values.length) def.values = field.values.slice();
                if (field.type === 'lookup') {
                    if (field.lookupEntity) def.lookupEntity = field.lookupEntity;
                    if (field.lookupValueField) def.lookupValueField = field.lookupValueField;
                    if (field.lookupDisplayField) def.lookupDisplayField = field.lookupDisplayField;
                    if (field.lookupQueryField) def.lookupQueryField = field.lookupQueryField;
                    if (field.lookupQueryOperator) def.lookupQueryOperator = field.lookupQueryOperator;
                }
                if (field.minLength != null) def.minLength = field.minLength;
                if (field.maxLength != null) def.maxLength = field.maxLength;
                if (field.rangeMin != null) def.rangeMin = field.rangeMin;
                if (field.rangeMax != null) def.rangeMax = field.rangeMax;
                if (field.pattern) def.pattern = field.pattern;
                return def;
            }),
            reports: moduleDef.reports.map(function (report) {
                return {
                    id: report.id,
                    name: report.name,
                    type: report.type,
                    sourceField: report.sourceField,
                    aggregation: report.aggregation,
                    visible: report.visible !== false
                };
            }),
            permissionRules: moduleDef.permissionRules.map(function (rule) {
                return {
                    id: rule.id,
                    principal: rule.principal,
                    level: rule.level,
                    constraint: rule.constraint
                };
            })
        };

        if (moduleDef.slug) out.slug = moduleDef.slug;
        if (moduleDef.viewType) out.viewType = moduleDef.viewType;
        if (moduleDef.parentField) out.parentField = moduleDef.parentField;

        var tokenSet = {};
        var tokens = [];
        if (moduleDef.permissions) {
            moduleDef.permissions.split(/[\s,]+/).map(trim).filter(Boolean).forEach(function (token) {
                if (!tokenSet[token]) {
                    tokenSet[token] = true;
                    tokens.push(token);
                }
            });
        }
        moduleDef.permissionRules.forEach(function (rule) {
            var principal = trim(rule.principal);
            if (principal && !tokenSet[principal]) {
                tokenSet[principal] = true;
                tokens.push(principal);
            }
        });
        if (tokens.length) out.permissions = tokens.join(' ');

        return out;
    }

    function validate() {
        var errors = [];
        var moduleDef = state.module;

        if (!trim(moduleDef.name)) errors.push('Entity name is required.');
        if (!trim(moduleDef.slug)) errors.push('Slug is required for in-place save.');

        var seen = {};
        moduleDef.fields.forEach(function (field, index) {
            var row = index + 1;
            var fieldName = trim(field.name);
            if (!fieldName) {
                errors.push('Field #' + row + ' is missing a name.');
            } else {
                var key = fieldName.toLowerCase();
                if (seen[key]) errors.push('Duplicate field name: ' + fieldName + '.');
                seen[key] = true;
            }

            if (field.type === 'enum' && (!field.values || !field.values.length)) errors.push('Field "' + (fieldName || ('#' + row)) + '" is enum but has no values.');
            if (field.type === 'lookup') {
                if (!trim(field.lookupEntity)) errors.push('Field "' + (fieldName || ('#' + row)) + '" is lookup but has no target entity slug.');
                if (!trim(field.lookupDisplayField)) errors.push('Field "' + (fieldName || ('#' + row)) + '" is lookup but has no display field.');
            }
            if (field.minLength != null && field.maxLength != null && field.minLength > field.maxLength) errors.push('Field "' + (fieldName || ('#' + row)) + '" has minLength greater than maxLength.');
            if (field.rangeMin != null && field.rangeMax != null && field.rangeMin > field.rangeMax) errors.push('Field "' + (fieldName || ('#' + row)) + '" has rangeMin greater than rangeMax.');
        });

        if ((moduleDef.viewType === 'TreeView' || moduleDef.viewType === 'OrgChart') && !trim(moduleDef.parentField)) errors.push(moduleDef.viewType + ' view requires Parent Field.');
        moduleDef.permissionRules.forEach(function (rule, index) { if (!trim(rule.principal)) errors.push('Permission rule #' + (index + 1) + ' is missing principal.'); });
        moduleDef.reports.forEach(function (report, index) { if (!trim(report.name)) errors.push('Report #' + (index + 1) + ' is missing name.'); });

        state.validation = errors;
    }

    function render() {
        ensureSelectedFieldIndex();
        validate();

        var root = document.getElementById('designer-root');
        if (!root) return;

        var moduleDef = state.module;
        var selectedField = state.selectedFieldIndex >= 0 ? moduleDef.fields[state.selectedFieldIndex] : null;
        var settingId = getSettingIdForModule();

        var statusClass = state.status.kind === 'error' ? 'danger' : (state.status.kind === 'success' ? 'success' : (state.status.kind === 'warning' ? 'warning' : 'info'));
        var canExportBinary = moduleDef.isComplete && state.validation.length === 0;

        var html = '';
        html += '<div class="row g-3">';
        html += '  <div class="col-xl-8">';
        html += '    <div class="card bm-page-card mb-3">';
        html += '      <div class="card-header d-flex justify-content-between align-items-center">';
        html += '        <h5 class="mb-0"><i class="bi bi-box-seam me-2"></i>Module Editor</h5>';
        html += '        <button class="btn btn-sm btn-outline-secondary" data-action="auto-slug"><i class="bi bi-magic me-1"></i>Auto Slug</button>';
        html += '      </div>';
        html += '      <div class="card-body">';
        html += '        <div class="alert alert-info py-2 small mb-3">Single-screen integrated module editor. Save writes directly to WAL-backed settings in-place.</div>';
        html += '        <div class="row g-2">';
        html += '          <div class="col-md-4"><label class="form-label">Name <span class="text-danger">*</span></label><input class="form-control form-control-sm" data-section="entity" data-prop="name" value="' + escHtml(moduleDef.name) + '" placeholder="e.g. TelemetryModule"></div>';
        html += '          <div class="col-md-4"><label class="form-label">Slug <span class="text-danger">*</span></label><input class="form-control form-control-sm" data-section="entity" data-prop="slug" value="' + escHtml(moduleDef.slug) + '" placeholder="telemetry-module"></div>';
        html += '          <div class="col-md-4"><label class="form-label">Storage Key</label><input class="form-control form-control-sm" value="' + escHtml(settingId) + '" disabled></div>';
        html += '          <div class="col-md-3"><label class="form-label">Nav Group</label><input class="form-control form-control-sm" data-section="entity" data-prop="navGroup" value="' + escHtml(moduleDef.navGroup) + '"></div>';
        html += '          <div class="col-md-2"><label class="form-label">Nav Order</label><input type="number" class="form-control form-control-sm" data-section="entity" data-prop="navOrder" value="' + escHtml(moduleDef.navOrder) + '"></div>';
        html += '          <div class="col-md-2"><label class="form-label">ID Strategy</label><select class="form-select form-select-sm" data-section="entity" data-prop="idStrategy">';
        ID_STRATEGIES.forEach(function (s) { html += '<option value="' + s + '"' + (moduleDef.idStrategy === s ? ' selected' : '') + '>' + s + '</option>'; });
        html += '          </select></div>';
        html += '          <div class="col-md-2"><label class="form-label">View Type</label><select class="form-select form-select-sm" data-section="entity" data-prop="viewType">';
        VIEW_TYPES.forEach(function (s) {
            var label = s || 'Table (default)';
            html += '<option value="' + escHtml(s) + '"' + (moduleDef.viewType === s ? ' selected' : '') + '>' + escHtml(label) + '</option>';
        });
        html += '          </select></div>';
        html += '          <div class="col-md-3"><label class="form-label">Parent Field</label><input class="form-control form-control-sm" data-section="entity" data-prop="parentField" value="' + escHtml(moduleDef.parentField) + '"></div>';
        html += '          <div class="col-md-9"><label class="form-label">Permissions (tokens)</label><input class="form-control form-control-sm" data-section="entity" data-prop="permissions" value="' + escHtml(moduleDef.permissions) + '" placeholder="e.g. admin deploy-agent"></div>';
        html += '          <div class="col-md-3 d-flex align-items-end gap-3">';
        html += '            <div class="form-check"><input type="checkbox" class="form-check-input" id="showOnNav" data-section="entity" data-prop="showOnNav"' + (moduleDef.showOnNav ? ' checked' : '') + '><label class="form-check-label" for="showOnNav">Show in Nav</label></div>';
        html += '            <div class="form-check"><input type="checkbox" class="form-check-input" id="isComplete" data-section="entity" data-prop="isComplete"' + (moduleDef.isComplete ? ' checked' : '') + '><label class="form-check-label" for="isComplete">Module Complete</label></div>';
        html += '          </div>';
        html += '        </div>';
        html += '      </div>';
        html += '    </div>';

        html += '    <div class="card bm-page-card mb-3">';
        html += '      <div class="card-header d-flex justify-content-between align-items-center">';
        html += '        <h6 class="mb-0"><i class="bi bi-list-columns-reverse me-2"></i>Properties (Fields)</h6>';
        html += '        <button class="btn btn-sm btn-outline-primary" data-action="add-field"><i class="bi bi-plus"></i> Add Property</button>';
        html += '      </div>';
        html += '      <div class="card-body p-0">';
        html += '        <div class="table-responsive">';
        html += '          <table class="table table-sm mb-0">';
        html += '            <thead><tr><th style="width:36px"></th><th>Name</th><th>Type</th><th>Req</th><th>List</th><th style="width:150px"></th></tr></thead><tbody>';

        if (!moduleDef.fields.length) {
            html += '<tr><td colspan="6" class="text-muted p-3">No properties yet.</td></tr>';
        } else {
            moduleDef.fields.forEach(function (field, idx) {
                html += '<tr' + (idx === state.selectedFieldIndex ? ' class="table-primary"' : '') + '>';
                html += '<td class="text-muted">' + (idx + 1) + '</td>';
                html += '<td><input class="form-control form-control-sm" data-section="field-row" data-index="' + idx + '" data-prop="name" value="' + escHtml(field.name) + '" placeholder="fieldName"></td>';
                html += '<td><select class="form-select form-select-sm" data-section="field-row" data-index="' + idx + '" data-prop="type">';
                FIELD_TYPES.forEach(function (ft) { html += '<option value="' + ft.value + '"' + (field.type === ft.value ? ' selected' : '') + '>' + ft.label + '</option>'; });
                html += '</select></td>';
                html += '<td><input type="checkbox" data-section="field-row" data-index="' + idx + '" data-prop="required"' + (field.required ? ' checked' : '') + '></td>';
                html += '<td><input type="checkbox" data-section="field-row" data-index="' + idx + '" data-prop="list"' + (field.list !== false ? ' checked' : '') + '></td>';
                html += '<td class="text-end">';
                html += '<button class="btn btn-sm btn-outline-secondary me-1" data-action="select-field" data-index="' + idx + '">Edit</button>';
                html += '<button class="btn btn-sm btn-outline-secondary me-1" data-action="move-field-up" data-index="' + idx + '"><i class="bi bi-arrow-up"></i></button>';
                html += '<button class="btn btn-sm btn-outline-secondary me-1" data-action="move-field-down" data-index="' + idx + '"><i class="bi bi-arrow-down"></i></button>';
                html += '<button class="btn btn-sm btn-outline-danger" data-action="remove-field" data-index="' + idx + '"><i class="bi bi-trash"></i></button>';
                html += '</td></tr>';
            });
        }

        html += '            </tbody></table></div></div></div>';

        html += '    <div class="card bm-page-card mb-3"><div class="card-header"><h6 class="mb-0"><i class="bi bi-sliders2 me-2"></i>Selected Property Details</h6></div><div class="card-body">';
        html += selectedField ? renderSelectedFieldEditor(selectedField, state.selectedFieldIndex) : '<div class="text-muted small">Select a property to edit detailed metadata.</div>';
        html += '    </div></div>';

        html += '    <div class="card bm-page-card mb-3"><div class="card-header d-flex justify-content-between align-items-center"><h6 class="mb-0"><i class="bi bi-bar-chart-line me-2"></i>Reports</h6><button class="btn btn-sm btn-outline-primary" data-action="add-report"><i class="bi bi-plus"></i> Add Report</button></div><div class="card-body p-0">';
        html += renderReportsTable(moduleDef.reports);
        html += '    </div></div>';

        html += '    <div class="card bm-page-card mb-3"><div class="card-header d-flex justify-content-between align-items-center"><h6 class="mb-0"><i class="bi bi-shield-lock me-2"></i>Permission Rules</h6><button class="btn btn-sm btn-outline-primary" data-action="add-permission"><i class="bi bi-plus"></i> Add Rule</button></div><div class="card-body p-0">';
        html += renderPermissionsTable(moduleDef.permissionRules);
        html += '    </div></div>';

        html += '  </div>';
        html += '  <div class="col-xl-4">';
        html += '    <div class="d-flex gap-2 mb-3">';
        html += '      <button class="btn btn-primary" data-action="save-in-place"><i class="bi bi-save me-1"></i>Save In Place</button>';
        html += '      <button class="btn btn-outline-secondary" data-action="load-in-place"><i class="bi bi-arrow-repeat me-1"></i>Load Saved</button>';
        html += '      <button class="btn btn-outline-success" data-action="export-binary"' + (canExportBinary ? '' : ' disabled') + '><i class="bi bi-box-arrow-down me-1"></i>Export Binary</button>';
        html += '      <button class="btn btn-outline-secondary" data-action="import-binary"><i class="bi bi-box-arrow-in-down me-1"></i>Import Binary</button>';
        html += '      <input type="file" id="import-binary-input" class="d-none" accept=".bmwmod,application/octet-stream">';
        html += '      <button class="btn btn-outline-danger ms-auto" data-action="reset"><i class="bi bi-arrow-counterclockwise me-1"></i>Reset</button>';
        html += '    </div>';

        html += '    <div class="alert alert-' + statusClass + ' small">' + escHtml(state.status.text) + '</div>';

        html += '    <div class="card bm-page-card mb-3"><div class="card-header"><h6 class="mb-0"><i class="bi bi-check2-circle me-2"></i>Validation</h6></div><div class="card-body">';
        if (!state.validation.length) {
            html += '<div class="text-success small"><i class="bi bi-check-circle me-1"></i>No validation issues.</div>';
        } else {
            html += '<ul class="small text-danger mb-0 ps-3">';
            state.validation.forEach(function (error) { html += '<li>' + escHtml(error) + '</li>'; });
            html += '</ul>';
        }
        html += '    </div></div>';

        html += '    <div class="card bm-page-card"><div class="card-header"><h6 class="mb-0"><i class="bi bi-journal-check me-2"></i>Module Summary</h6></div><div class="card-body small">';
        html += '<div><strong>Fields:</strong> ' + moduleDef.fields.length + '</div>';
        html += '<div><strong>Reports:</strong> ' + moduleDef.reports.length + '</div>';
        html += '<div><strong>Permission Rules:</strong> ' + moduleDef.permissionRules.length + '</div>';
        html += '<div><strong>Complete:</strong> ' + (moduleDef.isComplete ? 'Yes' : 'No') + '</div>';
        html += '<div class="mt-2 text-muted">Binary export is available only when module is complete and validation passes.</div>';
        html += '    </div></div>';

        html += '  </div></div>';

        root.innerHTML = html;
    }

    function renderReportsTable(reports) {
        var html = '<div class="table-responsive"><table class="table table-sm mb-0"><thead><tr><th>Name</th><th>Type</th><th>Source Field</th><th>Aggregation</th><th>Visible</th><th style="width:60px"></th></tr></thead><tbody>';
        if (!reports.length) html += '<tr><td colspan="6" class="text-muted p-3">No reports yet.</td></tr>';
        else reports.forEach(function (report, idx) {
            html += '<tr>';
            html += '<td><input class="form-control form-control-sm" data-section="report" data-index="' + idx + '" data-prop="name" value="' + escHtml(report.name) + '"></td>';
            html += '<td><select class="form-select form-select-sm" data-section="report" data-index="' + idx + '" data-prop="type">';
            REPORT_TYPES.forEach(function (type) { html += '<option value="' + type + '"' + (report.type === type ? ' selected' : '') + '>' + type + '</option>'; });
            html += '</select></td>';
            html += '<td><input class="form-control form-control-sm" data-section="report" data-index="' + idx + '" data-prop="sourceField" value="' + escHtml(report.sourceField) + '"></td>';
            html += '<td><input class="form-control form-control-sm" data-section="report" data-index="' + idx + '" data-prop="aggregation" value="' + escHtml(report.aggregation) + '"></td>';
            html += '<td><input type="checkbox" data-section="report" data-index="' + idx + '" data-prop="visible"' + (report.visible !== false ? ' checked' : '') + '></td>';
            html += '<td><button class="btn btn-sm btn-outline-danger" data-action="remove-report" data-index="' + idx + '"><i class="bi bi-trash"></i></button></td></tr>';
        });
        html += '</tbody></table></div>';
        return html;
    }

    function renderPermissionsTable(rules) {
        var html = '<div class="table-responsive"><table class="table table-sm mb-0"><thead><tr><th>Principal</th><th>Level</th><th>Constraint</th><th style="width:60px"></th></tr></thead><tbody>';
        if (!rules.length) html += '<tr><td colspan="4" class="text-muted p-3">No permission rules yet.</td></tr>';
        else rules.forEach(function (rule, idx) {
            html += '<tr>';
            html += '<td><input class="form-control form-control-sm" data-section="permission" data-index="' + idx + '" data-prop="principal" value="' + escHtml(rule.principal) + '" placeholder="deploy-agent"></td>';
            html += '<td><select class="form-select form-select-sm" data-section="permission" data-index="' + idx + '" data-prop="level">';
            PERMISSION_LEVELS.forEach(function (level) { html += '<option value="' + level + '"' + (rule.level === level ? ' selected' : '') + '>' + level + '</option>'; });
            html += '</select></td>';
            html += '<td><input class="form-control form-control-sm" data-section="permission" data-index="' + idx + '" data-prop="constraint" value="' + escHtml(rule.constraint) + '" placeholder="OwnRecordOnly"></td>';
            html += '<td><button class="btn btn-sm btn-outline-danger" data-action="remove-permission" data-index="' + idx + '"><i class="bi bi-trash"></i></button></td></tr>';
        });
        html += '</tbody></table></div>';
        return html;
    }

    function renderSelectedFieldEditor(field, index) {
        var html = '';
        html += '<div class="row g-2">';
        html += '<div class="col-md-4"><label class="form-label small">Label</label><input class="form-control form-control-sm" data-section="selected-field" data-index="' + index + '" data-prop="label" value="' + escHtml(field.label) + '"></div>';
        html += '<div class="col-md-4"><label class="form-label small">Placeholder</label><input class="form-control form-control-sm" data-section="selected-field" data-index="' + index + '" data-prop="placeholder" value="' + escHtml(field.placeholder) + '"></div>';
        html += '<div class="col-md-4"><label class="form-label small">Pattern</label><input class="form-control form-control-sm" data-section="selected-field" data-index="' + index + '" data-prop="pattern" value="' + escHtml(field.pattern) + '"></div>';
        html += '<div class="col-md-2"><label class="form-label small">Min Length</label><input type="number" class="form-control form-control-sm" data-section="selected-field" data-index="' + index + '" data-prop="minLength" value="' + escHtml(field.minLength == null ? '' : field.minLength) + '"></div>';
        html += '<div class="col-md-2"><label class="form-label small">Max Length</label><input type="number" class="form-control form-control-sm" data-section="selected-field" data-index="' + index + '" data-prop="maxLength" value="' + escHtml(field.maxLength == null ? '' : field.maxLength) + '"></div>';
        html += '<div class="col-md-2"><label class="form-label small">Range Min</label><input type="number" step="any" class="form-control form-control-sm" data-section="selected-field" data-index="' + index + '" data-prop="rangeMin" value="' + escHtml(field.rangeMin == null ? '' : field.rangeMin) + '"></div>';
        html += '<div class="col-md-2"><label class="form-label small">Range Max</label><input type="number" step="any" class="form-control form-control-sm" data-section="selected-field" data-index="' + index + '" data-prop="rangeMax" value="' + escHtml(field.rangeMax == null ? '' : field.rangeMax) + '"></div>';
        html += '<div class="col-md-4 d-flex align-items-end gap-3">';
        html += '<div class="form-check"><input type="checkbox" class="form-check-input" id="f-view-' + index + '" data-section="selected-field" data-index="' + index + '" data-prop="view"' + (field.view !== false ? ' checked' : '') + '><label class="form-check-label" for="f-view-' + index + '">View</label></div>';
        html += '<div class="form-check"><input type="checkbox" class="form-check-input" id="f-edit-' + index + '" data-section="selected-field" data-index="' + index + '" data-prop="edit"' + (field.edit !== false ? ' checked' : '') + '><label class="form-check-label" for="f-edit-' + index + '">Edit</label></div>';
        html += '<div class="form-check"><input type="checkbox" class="form-check-input" id="f-create-' + index + '" data-section="selected-field" data-index="' + index + '" data-prop="create"' + (field.create !== false ? ' checked' : '') + '><label class="form-check-label" for="f-create-' + index + '">Create</label></div>';
        html += '</div>';
        html += '<div class="col-md-8 d-flex align-items-end gap-3">';
        html += '<div class="form-check"><input type="checkbox" class="form-check-input" id="f-readonly-' + index + '" data-section="selected-field" data-index="' + index + '" data-prop="readOnly"' + (field.readOnly ? ' checked' : '') + '><label class="form-check-label" for="f-readonly-' + index + '">Read Only</label></div>';
        html += '<div class="form-check"><input type="checkbox" class="form-check-input" id="f-nullable-' + index + '" data-section="selected-field" data-index="' + index + '" data-prop="nullable"' + (field.nullable !== false ? ' checked' : '') + '><label class="form-check-label" for="f-nullable-' + index + '">Nullable</label></div>';
        html += '<div class="form-check"><input type="checkbox" class="form-check-input" id="f-multiline-' + index + '" data-section="selected-field" data-index="' + index + '" data-prop="multiline"' + (field.multiline ? ' checked' : '') + '><label class="form-check-label" for="f-multiline-' + index + '">Multiline</label></div>';
        html += '</div>';

        if (field.type === 'enum') html += '<div class="col-12"><label class="form-label small">Enum Values (pipe-separated)</label><input class="form-control form-control-sm" data-section="selected-field" data-index="' + index + '" data-prop="valuesPipe" value="' + escHtml((field.values || []).join('|')) + '" placeholder="Open|In Progress|Closed"></div>';
        if (field.type === 'lookup') {
            html += '<div class="col-md-3"><label class="form-label small">Lookup Entity</label><input class="form-control form-control-sm" data-section="selected-field" data-index="' + index + '" data-prop="lookupEntity" value="' + escHtml(field.lookupEntity) + '"></div>';
            html += '<div class="col-md-3"><label class="form-label small">Lookup Value Field</label><input class="form-control form-control-sm" data-section="selected-field" data-index="' + index + '" data-prop="lookupValueField" value="' + escHtml(field.lookupValueField) + '" placeholder="Id"></div>';
            html += '<div class="col-md-3"><label class="form-label small">Lookup Display Field</label><input class="form-control form-control-sm" data-section="selected-field" data-index="' + index + '" data-prop="lookupDisplayField" value="' + escHtml(field.lookupDisplayField) + '"></div>';
            html += '<div class="col-md-3"><label class="form-label small">Lookup Query Field</label><input class="form-control form-control-sm" data-section="selected-field" data-index="' + index + '" data-prop="lookupQueryField" value="' + escHtml(field.lookupQueryField) + '"></div>';
            html += '<div class="col-md-3"><label class="form-label small">Lookup Query Operator</label><input class="form-control form-control-sm" data-section="selected-field" data-index="' + index + '" data-prop="lookupQueryOperator" value="' + escHtml(field.lookupQueryOperator) + '" placeholder="equals"></div>';
        }

        html += '</div>';
        return html;
    }

    function wireRootEvents() {
        var root = document.getElementById('designer-root');
        if (!root) return;

        root.addEventListener('click', function (event) {
            var actionEl = event.target.closest('[data-action]');
            if (actionEl) {
                handleAction(actionEl.getAttribute('data-action'), actionEl.getAttribute('data-index'));
            }
        });

        root.addEventListener('input', handleInputChange);
        root.addEventListener('change', handleInputChange);
        root.addEventListener('change', function (event) {
            var target = event.target;
            if (target && target.id === 'import-binary-input' && target.files && target.files[0]) {
                importBinaryFile(target.files[0]);
                target.value = '';
            }
        });
    }

    function handleInputChange(event) {
        var target = event.target;
        if (!target || !target.dataset) return;

        var section = target.dataset.section;
        if (!section) return;

        var prop = target.dataset.prop;
        var index = target.dataset.index != null ? parseInt(target.dataset.index, 10) : -1;

        if (section === 'entity') {
            updateObjectProperty(state.module, prop, target);
            render();
            return;
        }
        if (section === 'field-row' && index >= 0 && state.module.fields[index]) {
            updateFieldProperty(state.module.fields[index], prop, target);
            render();
            return;
        }
        if (section === 'selected-field' && index >= 0 && state.module.fields[index]) {
            updateFieldProperty(state.module.fields[index], prop, target);
            render();
            return;
        }
        if (section === 'report' && index >= 0 && state.module.reports[index]) {
            updateObjectProperty(state.module.reports[index], prop, target);
            render();
            return;
        }
        if (section === 'permission' && index >= 0 && state.module.permissionRules[index]) {
            updateObjectProperty(state.module.permissionRules[index], prop, target);
            render();
        }
    }

    function updateFieldProperty(field, prop, target) {
        if (prop === 'valuesPipe') {
            field.values = String(target.value || '').split('|').map(trim).filter(Boolean);
            return;
        }

        if (prop === 'minLength' || prop === 'maxLength' || prop === 'rangeMin' || prop === 'rangeMax') {
            field[prop] = parseNumberOrNull(target.value);
            return;
        }

        updateObjectProperty(field, prop, target);

        if (prop === 'type') {
            if (field.type !== 'enum') field.values = [];
            if (field.type !== 'lookup') {
                field.lookupEntity = '';
                field.lookupValueField = '';
                field.lookupDisplayField = '';
                field.lookupQueryField = '';
                field.lookupQueryOperator = '';
            }
        }
    }

    function updateObjectProperty(obj, prop, target) {
        if (!obj || !prop) return;
        if (target.type === 'checkbox') { obj[prop] = !!target.checked; return; }
        if (prop === 'navOrder') { obj[prop] = parseInt(target.value, 10) || 0; return; }
        obj[prop] = target.value;
    }

    async function handleAction(action, indexValue) {
        var index = indexValue != null ? parseInt(indexValue, 10) : -1;

        if (action === 'auto-slug') { state.module.slug = slugify(state.module.slug || state.module.name); render(); return; }
        if (action === 'add-field') { state.module.fields.push(createDefaultField()); state.selectedFieldIndex = state.module.fields.length - 1; render(); return; }
        if (action === 'select-field' && index >= 0) { state.selectedFieldIndex = index; render(); return; }
        if (action === 'remove-field' && index >= 0) { state.module.fields.splice(index, 1); if (state.selectedFieldIndex === index) state.selectedFieldIndex = -1; render(); return; }
        if (action === 'move-field-up' && index > 0) { var up = state.module.fields[index - 1]; state.module.fields[index - 1] = state.module.fields[index]; state.module.fields[index] = up; state.selectedFieldIndex = index - 1; render(); return; }
        if (action === 'move-field-down' && index >= 0 && index < state.module.fields.length - 1) { var down = state.module.fields[index + 1]; state.module.fields[index + 1] = state.module.fields[index]; state.module.fields[index] = down; state.selectedFieldIndex = index + 1; render(); return; }
        if (action === 'add-report') { state.module.reports.push(createDefaultReport()); render(); return; }
        if (action === 'remove-report' && index >= 0) { state.module.reports.splice(index, 1); render(); return; }
        if (action === 'add-permission') { state.module.permissionRules.push(createDefaultPermissionRule()); render(); return; }
        if (action === 'remove-permission' && index >= 0) { state.module.permissionRules.splice(index, 1); render(); return; }

        if (action === 'reset') {
            if (!confirm('Reset this module editor?')) return;
            state.module = createDefaultModule();
            state.selectedFieldIndex = -1;
            setStatus('info', 'Reset complete.');
            return;
        }

        if (action === 'save-in-place') {
            await saveModuleInPlace();
            return;
        }

        if (action === 'load-in-place') {
            await loadModuleInPlace();
            return;
        }

        if (action === 'import-binary') {
            var importInput = document.getElementById('import-binary-input');
            if (importInput) importInput.click();
            return;
        }

        if (action === 'export-binary') {
            exportBinary();
        }
    }

    function parseJsonList(payload) {
        if (Array.isArray(payload)) return payload;
        if (payload && Array.isArray(payload.items)) return payload.items;
        return [];
    }

    function normalizeSettingItem(item) {
        return {
            key: item.key || item.Key || 0,
            settingId: item.settingId || item.SettingId || '',
            value: item.value || item.Value || '',
            description: item.description || item.Description || ''
        };
    }

    async function findSettingById(settingId) {
        var resp = await fetch('/api/_binary/' + SETTINGS_SLUG + '?f_settingId=' + encodeURIComponent(settingId), {
            method: 'GET',
            headers: { 'Accept': 'application/json' }
        });
        if (!resp.ok) {
            throw new Error('Lookup failed (' + resp.status + ')');
        }

        var data = await resp.json();
        var list = parseJsonList(data);
        if (!list.length) return null;
        return normalizeSettingItem(list[0]);
    }

    async function saveModuleInPlace() {
        validate();
        if (state.validation.length) {
            setStatus('error', 'Fix validation errors before saving in place.');
            return;
        }

        var settingId = getSettingIdForModule();
        var payload = {
            SettingId: settingId,
            Value: JSON.stringify(buildExportObject()),
            Description: 'Entity Designer module state (single-object).'
        };

        try {
            var existing = await findSettingById(settingId);
            var url = '/api/_binary/' + SETTINGS_SLUG;
            var method = 'POST';
            if (existing && existing.key) {
                method = 'PUT';
                url += '/' + existing.key;
                payload.Key = existing.key;
            }

            var resp = await fetch(url, {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-CSRF-Token': getCsrfToken(),
                    'X-Requested-With': 'BareMetalWeb'
                },
                body: JSON.stringify(payload)
            });

            if (!resp.ok) {
                throw new Error('Save failed (' + resp.status + ')');
            }

            setStatus('success', 'Saved in place to ' + settingId + '.');
        } catch (error) {
            setStatus('error', error && error.message ? error.message : 'Save failed.');
        }
    }

    async function loadModuleInPlace() {
        var settingId = getSettingIdForModule();
        try {
            var existing = await findSettingById(settingId);
            if (!existing || !existing.value) {
                setStatus('warning', 'No saved module found for ' + settingId + '.');
                return;
            }

            var parsed = JSON.parse(existing.value);
            state.module = normalizeImportedModule(parsed);
            state.selectedFieldIndex = state.module.fields.length ? 0 : -1;
            setStatus('success', 'Loaded saved module from ' + settingId + '.');
        } catch (error) {
            setStatus('error', error && error.message ? error.message : 'Load failed.');
        }
    }

    function exportBinary() {
        validate();
        if (!state.module.isComplete || state.validation.length) {
            setStatus('warning', 'Mark module complete and clear validation errors before binary export.');
            return;
        }

        var obj = buildExportObject();
        var bytes = new TextEncoder().encode(JSON.stringify(obj));
        var blob = new Blob([bytes], { type: 'application/octet-stream' });
        var name = slugify(state.module.slug || state.module.name || 'module') || 'module';

        var anchor = document.createElement('a');
        anchor.href = URL.createObjectURL(blob);
        anchor.download = name + '.bmwmod';
        anchor.click();
        setStatus('success', 'Binary module export downloaded (' + name + '.bmwmod).');
    }

    async function importBinaryFile(file) {
        try {
            var buffer = await file.arrayBuffer();
            var parsed = parseBinaryModule(buffer);
            state.module = normalizeImportedModule(parsed);
            state.selectedFieldIndex = state.module.fields.length ? 0 : -1;
            setStatus('success', 'Imported binary module from ' + file.name + '.');
        } catch (error) {
            setStatus('error', error && error.message ? error.message : 'Binary import failed.');
        }
    }

    function parseBinaryModule(buffer) {
        var text = new TextDecoder('utf-8').decode(new Uint8Array(buffer));
        return JSON.parse(text);
    }

    function normalizeImportedModule(input) {
        var obj = input;

        var moduleDef = createDefaultModule();
        moduleDef.entityId = trim(obj.entityId) || generateId();
        moduleDef.name = trim(obj.name);
        moduleDef.slug = trim(obj.slug) || slugify(moduleDef.name);
        moduleDef.showOnNav = obj.showOnNav !== false;
        moduleDef.isComplete = !!obj.isComplete;
        moduleDef.permissions = trim(obj.permissions);
        moduleDef.idStrategy = trim(obj.idStrategy) || 'guid';
        moduleDef.navGroup = trim(obj.navGroup) || 'Admin';
        moduleDef.navOrder = Number(obj.navOrder) || 0;
        moduleDef.viewType = trim(obj.viewType);
        moduleDef.parentField = trim(obj.parentField);

        moduleDef.fields = Array.isArray(obj.fields) ? obj.fields.map(function (field) {
            var out = createDefaultField();
            out.fieldId = trim(field.fieldId) || generateId();
            out.name = trim(field.name);
            out.label = trim(field.label);
            out.type = trim(field.type) || 'string';
            out.required = !!field.required;
            out.list = field.list !== false;
            out.view = field.view !== false;
            out.edit = field.edit !== false;
            out.create = field.create !== false;
            out.readOnly = !!field.readOnly;
            out.nullable = field.nullable !== false;
            out.multiline = !!field.multiline;
            out.values = Array.isArray(field.values) ? field.values.map(trim).filter(Boolean) : [];
            out.lookupEntity = trim(field.lookupEntity);
            out.lookupValueField = trim(field.lookupValueField);
            out.lookupDisplayField = trim(field.lookupDisplayField);
            out.lookupQueryField = trim(field.lookupQueryField);
            out.lookupQueryOperator = trim(field.lookupQueryOperator);
            out.placeholder = trim(field.placeholder);
            out.minLength = parseNumberOrNull(field.minLength);
            out.maxLength = parseNumberOrNull(field.maxLength);
            out.rangeMin = parseNumberOrNull(field.rangeMin);
            out.rangeMax = parseNumberOrNull(field.rangeMax);
            out.pattern = trim(field.pattern);
            return out;
        }) : [];

        moduleDef.reports = Array.isArray(obj.reports) ? obj.reports.map(function (report) {
            var out = createDefaultReport();
            out.id = trim(report.id) || generateId();
            out.name = trim(report.name);
            out.type = trim(report.type) || 'table';
            out.sourceField = trim(report.sourceField);
            out.aggregation = trim(report.aggregation);
            out.visible = report.visible !== false;
            return out;
        }) : [];

        moduleDef.permissionRules = Array.isArray(obj.permissionRules) ? obj.permissionRules.map(function (rule) {
            var out = createDefaultPermissionRule();
            out.id = trim(rule.id) || generateId();
            out.principal = trim(rule.principal);
            out.level = trim(rule.level) || 'read';
            out.constraint = trim(rule.constraint);
            return out;
        }) : [];

        return moduleDef;
    }

    function init() {
        wireRootEvents();
        render();
    }

    if (typeof window !== 'undefined') {
        window.__entityDesignerTestHooks = {
            normalizeImportedModule: normalizeImportedModule,
            parseBinaryModule: parseBinaryModule,
            buildExportObject: function () { return buildExportObject(); },
            setModule: function (moduleDef) {
                state.module = normalizeImportedModule(moduleDef);
                state.selectedFieldIndex = state.module.fields.length ? 0 : -1;
                render();
            }
        };
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
