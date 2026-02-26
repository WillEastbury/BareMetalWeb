# Entity Designer

The Entity Designer is a visual tool for creating **virtual entity** definitions without writing code.
Navigate to **System → Entity Designer** in the admin nav (or go to `/admin/entity-designer`) to open it.

Virtual entities are fully functioning CRUD entities backed by JSON files on disk.
The designer produces a JSON snippet ready to drop into your `virtualEntities.json` configuration file.

---

## Quick Start

1. Fill in the **Entity Properties** section (at minimum, the **Name**).
2. Click **Add Field** to add fields to the entity.
3. The **JSON Preview** on the right updates live as you type.
4. When done, click **Download JSON** to save the file, or **Copy JSON** to paste it elsewhere.
5. Place the downloaded JSON block inside the `virtualEntities` array in your `virtualEntities.json` file and restart the server.

---

## Entity Properties

| Field | Required | Description |
|-------|----------|-------------|
| **Name** | ✅ | The entity type name shown in the admin UI, e.g. `Ticket` or `Product`. |
| **Slug** | | URL-safe identifier used in API paths and routes, e.g. `tickets`. Auto-derived from Name (lowercased, spaces → hyphens) if left blank. |
| **Nav Group** | | Navigation menu group. Entities in the same group appear together in the sidebar. Defaults to `Admin`. Examples: `Admin`, `System`, `Sales`. |
| **Nav Order** | | Sort order within the Nav Group (ascending). Lower numbers appear higher in the menu. Defaults to `0`. |
| **ID Strategy** | | How new record IDs are generated: `guid` (random UUID, recommended default), `sequential` (auto-increment integer), or `none` (caller must supply the ID). |
| **View Type** | | Default view layout for the entity list page. Options: `Table` (default), `TreeView`, `OrgChart`, `Timeline`, `Timetable`. See notes below. |
| **Permissions** | | Space-separated role names required to access this entity. Leave blank to allow any authenticated user. Example: `admin manager`. |
| **Show in Nav** | | When checked, the entity appears as a link in the navigation sidebar. |
| **Parent Field** | | Field name that links a child record back to its parent in the same entity. Required for `TreeView` and `OrgChart` view types. Example: `ParentId`. |

### View Type Notes

- **Table** — Default grid view. Works for all entities.
- **TreeView** — Explorer-style collapsible tree. Requires a **Parent Field** that references another record in the same entity.
- **OrgChart** — Visual hierarchy chart. Also requires a **Parent Field**.
- **Timeline** — Chronological timeline grouped by date. Requires at least one `date` or `datetime` field.
- **Timetable** — Schedule/calendar view. Requires `date`/`datetime` fields.

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
| **Download JSON** | Downloads the entity definition as a `.json` file ready to place in `virtualEntities.json`. |
| **Copy JSON** | Copies the JSON to the clipboard. |
| **Import JSON** | Loads an existing entity definition JSON file for editing. Accepts `.json` files in the same format as the output. |
| **Reset** | Clears all fields and starts a new entity definition (asks for confirmation first). |

---

## Deploying a Virtual Entity

1. Open `virtualEntities.json` at the root of your data store (or create it if it does not exist).
2. Ensure the file has the structure below. If the file already has entities, add the new object to the array.
3. Restart the server; the entity will be compiled and appear in the admin UI automatically.

```json
{
  "virtualEntities": [
    {
      "entityId": "...",
      "name": "Ticket",
      "slug": "tickets",
      "showOnNav": true,
      "idStrategy": "guid",
      "navGroup": "Support",
      "navOrder": 10,
      "fields": [
        { "fieldId": "...", "name": "Title",    "type": "string",   "order": 1, "required": true,  "list": true  },
        { "fieldId": "...", "name": "Status",   "type": "enum",     "order": 2, "required": true,  "list": true,  "values": ["Open", "In Progress", "Closed"] },
        { "fieldId": "...", "name": "AssignedTo","type": "lookup",   "order": 3, "required": false, "list": true,  "lookupEntity": "users", "lookupDisplayField": "UserName" },
        { "fieldId": "...", "name": "Body",     "type": "multiline","order": 4, "required": false, "list": false }
      ]
    }
  ]
}
```

> **Tip:** Use **Import JSON** to reload any existing `virtualEntities.json` entry back into the designer for editing. The designer reads the first item in the `virtualEntities` array.

---

## Tips & Gotchas

- **Slug must be unique** across all entities (both code-defined and virtual).
- **Field names must be unique** within an entity. Duplicate names will cause errors at startup.
- **Field IDs (`fieldId`) are stable GUIDs** that identify fields across renames. The designer generates them automatically. Do not change them once data has been stored against that field, or existing records will lose those field values.
- **Order** controls the field's position in forms. The designer assigns order by field position (top to bottom).
- To **reorder fields**, remove and re-add them in the desired order. (Drag handles are visual only in this version.)
- The **Entity ID (`entityId`)** is a stable GUID for the entity. Do not change it once data has been stored.
- Adding the entity to `virtualEntities.json` requires a **server restart** to take effect.
