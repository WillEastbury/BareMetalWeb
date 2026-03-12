# Entity Designer

The Entity Designer is a visual tool for creating **virtual entity** definitions without writing code.
Navigate to **System → Entity Designer** in the admin nav (or go to `/admin/entity-designer`) to open it.

Virtual entities are fully functioning CRUD entities backed by WAL storage.
The rebuilt designer now uses a **single integrated module object** (entity + properties + reports + permission rules) and saves it **in place**.

---

## Quick Start

1. Fill in the **Entity Properties** section (at minimum, the **Name**).
2. Click **Add Field** to add fields to the entity.
3. Add optional **Reports** and **Permission Rules** in the same editor screen.
4. Click **Save In Place** to persist directly to WAL-backed settings.
5. Mark **Module Complete** when ready.
6. Use **Export Binary** only for complete modules.
7. Use **Import Binary** (`.bmwmod`) to load a module package into the editor.

---

## Entity Properties

| Field | Required | Description |
|-------|----------|-------------|
| **Name** | ✅ | The entity type name shown in the admin UI, e.g. `Ticket` or `Product`. |
| **Slug** | | URL-safe identifier used in API paths and routes, e.g. `tickets`. Auto-derived from Name (lowercased, spaces → hyphens) if left blank. |
| **Nav Group** | | Navigation menu group. Entities in the same group appear together in the sidebar. Defaults to `Admin`. Examples: `Admin`, `System`, `Sales`. |
| **Nav Order** | | Sort order within the Nav Group (ascending). Lower numbers appear higher in the menu. Defaults to `0`. |
| **ID Strategy** | | How new record IDs are generated: `guid` (random UUID, recommended default), `sequential` (auto-increment integer), or `none` (caller must supply the ID). |
| **View Type** | | Default view layout for the entity list page. Options: `Table` (default), `TreeView`, `OrgChart`, `Timeline`, `Timetable`, `Sankey`, `Calendar`, `Kanban`. See notes below. |
| **Permissions** | | Space-separated role names required to access this entity. Leave blank to allow any authenticated user. Example: `admin manager`. |
| **Show in Nav** | | When checked, the entity appears as a link in the navigation sidebar. |
| **Parent Field** | | Field name that links a child record back to its parent in the same entity. Required for `TreeView` and `OrgChart` view types. Example: `ParentId`. |

### View Type Notes

- **Table** — Default grid view. Works for all entities.
- **TreeView** — Explorer-style collapsible tree. Requires a **Parent Field** that references another record in the same entity.
- **OrgChart** — Visual hierarchy chart. Also requires a **Parent Field**.
- **Timeline** — Chronological timeline grouped by date. Requires at least one `date` or `datetime` field.
- **Timetable** — Schedule/calendar view. Requires `date`/`datetime` fields.
- **Sankey** — Document pipeline / flow visualisation. Requires `[RelatedDocument]` fields.
- **Calendar** — Monthly calendar view. Requires at least one `date` or `datetime` field.
- **Kanban** — Drag-and-drop Kanban board with WIP limits and automation hooks. Requires at least one `Enum` field (columns are the enum values). Cards can be dragged between columns; the enum field value is updated via PATCH. Configure WIP limits and per-column automation hooks via the **Board settings** toolbar.

---

## Fields

Click **Add Field** to add a field row. Each field row has the following columns:

| Column | Description |
|--------|-------------|
| **Field Name** | Internal code name. Use camelCase or PascalCase with no spaces, e.g. `firstName`, `IsActive`, `OrderDate`. |
| **Label** | Human-readable label shown in forms and column headers. Auto-derived from the field name if left blank. |
| **Type** | Data type — see the [Field Types](#field-types) table below. |
| **Req** | (Required) When checked, a value must be provided before a record can be saved. |
| **List** | When checked, this field appears as a column in the entity list/table view. |
| 🗑️ | Removes the field from the entity. |

---

## Reports

The single-screen editor includes a **Reports** section. Reports are stored as sub-records on the same module object.

| Field | Description |
|-------|-------------|
| **Name** | Report identifier shown in the editor. |
| **Type** | Report style (for example `table`, `summary`, `timeline`, `kanban`). |
| **Source Field** | Optional source field used by the report. |
| **Aggregation** | Optional aggregation expression (for example `count`, `sum`). |
| **Visible** | Whether the report is enabled by default. |

---

## Permission Rules

The single-screen editor also includes **Permission Rules** sub-records.

| Field | Description |
|-------|-------------|
| **Principal** | Role/agent/service principal token. |
| **Level** | Access level (`read`, `write`, `admin`). |
| **Constraint** | Optional scope hint, such as `OwnRecordOnly`. |

### Field Types

| Type | Description |
|------|-------------|
| **String** | Single-line text input. |
| **Text Area** | Multi-line text input. |
| **Email** | Single-line text input validated as an email address. |
| **Integer** | Whole number (no decimals). |
| **Decimal** | Number with decimal places. |
| **Yes/No** | Boolean checkbox. |
| **Date** | Date-only picker (no time component). |
| **Time** | Time-only picker. |
| **DateTime** | Combined date and time picker. |
| **Enum (dropdown)** | Fixed-choice dropdown. When selected, an **Enum Values** row appears — enter the allowed values separated by `|`, e.g. `Open|In Progress|Closed`. |
| **Lookup (FK)** | Foreign-key reference to another entity. When selected, two extra inputs appear: **Target entity slug** (the slug of the entity being referenced) and **Display field** (the field on that entity to show as the label). |

### Enum Values

When a field type is **Enum (dropdown)**, a text input labeled **Enum Values (pipe-separated)** appears below the field row. Enter the allowed values separated by `|`, for example:

```
Open|In Progress|Resolved|Closed
```

### Lookup Fields

When a field type is **Lookup (FK)**, two extra inputs appear:

- **Target entity slug** — the `slug` of the entity being referenced (e.g. `customers`, `products`).
- **Display field** — the field on the target entity whose value is shown in dropdowns and read-only views (e.g. `Name`, `Email`).

---

## Action Buttons

| Button | Description |
|--------|-------------|
| **Save In Place** | Persists the module directly in WAL-backed settings using a deterministic module key. |
| **Load Saved** | Loads the existing persisted module for the current slug/key. |
| **Export Binary** | Downloads a binary module package (`.bmwmod`) only when the module is marked complete and passes validation. |
| **Import Binary** | Loads a binary module package (`.bmwmod`) into the editor. This is the primary module import format. |
| **Reset** | Clears all fields and starts a new entity definition (asks for confirmation first). |

---

## Deploying a Virtual Entity

1. Open **System → Entity Designer**.
2. Edit the module on one screen and click **Save In Place**.
3. Restart the server when you want runtime metadata recompiled and visible across admin routes.

```json
{
  "entityId": "...",
  "name": "TelemetryModule",
  "slug": "telemetry-module",
  "showOnNav": true,
  "idStrategy": "guid",
  "navGroup": "System",
  "navOrder": 10,
  "permissions": "admin deploy-agent",
  "fields": [
    { "fieldId": "...", "name": "HostName", "type": "string", "order": 1, "required": true, "list": true },
    { "fieldId": "...", "name": "Status", "type": "enum", "order": 2, "values": ["Healthy", "Degraded", "Offline"] }
  ],
  "reports": [
    { "id": "...", "name": "ErrorsByType", "type": "summary", "sourceField": "ErrorType", "aggregation": "count", "visible": true }
  ],
  "permissionRules": [
    { "id": "...", "principal": "deploy-agent", "level": "write", "constraint": "OwnRecordOnly" }
  ]
}
```

> **Tip:** Keep `slug` stable over time so the same in-place module key is reused.

---

## Tips & Gotchas

- **Slug must be unique** across all entities (both code-defined and virtual).
- **Field names must be unique** within an entity. Duplicate names will cause errors at startup.
- **Field IDs (`fieldId`) are stable GUIDs** that identify fields across renames. The designer generates them automatically. Do not change them once data has been stored against that field, or existing records will lose those field values.
- **Order** controls the field's position in forms. The designer assigns order by field position (top to bottom).
- To **reorder fields**, remove and re-add them in the desired order. (Drag handles are visual only in this version.)
- The **Entity ID (`entityId`)** is a stable GUID for the entity. Do not change it once data has been stored.
- Saving in place updates the WAL-backed module payload immediately; a **server restart** applies runtime metadata compilation changes.
