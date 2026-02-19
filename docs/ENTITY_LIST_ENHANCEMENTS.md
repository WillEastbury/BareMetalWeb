# Entity List View Enhancements

This document describes the search, filtering, sorting, and pagination features added to entity list views in BareMetalWeb.

## Features

### 1. Global Search
A search box appears above entity list tables, allowing users to search across all visible fields.

**Usage:**
- Type search terms in the search box
- Click "Search" or press Enter
- Search queries across all list fields using OR logic
- URL parameter: `?q=search+term`

**Example:**
```
/admin/data/user?q=john
```
Searches for "john" in Name, Email, and other list fields of the User entity.

### 2. Configurable Page Size
Users can select how many records to display per page.

**Options:**
- 10 items per page
- 25 items per page (default)
- 50 items per page
- 100 items per page

**URL parameter:** `?size=50`

**Example:**
```
/admin/data/user?size=100
```
Shows 100 users per page.

### 3. Enhanced Pagination
Numbered pagination with smart page range display.

**Features:**
- Shows current page and +/- 2 pages
- First/Last page links when appropriate
- Ellipsis (...) for skipped pages
- Previous/Next buttons
- Record count display ("Records 26 to 50 of 237 total")

**URL parameter:** `?page=3`

**Example:**
```
/admin/data/user?page=3&size=25
```
Shows page 3 with 25 users per page (records 51-75).

### 4. Sortable Column Headers
Click any column header to sort by that field.

**Features:**
- Click once to sort ascending (↑)
- Click again to sort descending (↓)
- Visual indicator shows current sort column and direction
- Inactive columns show a faint sort icon (⇅)

**URL parameters:** `?sort=FieldName&dir=asc` or `?sort=FieldName&dir=desc`

**Example:**
```
/admin/data/user?sort=Email&dir=asc
```
Sorts users by Email in ascending order.

### 5. Per-Field Filtering (Backend Support)
Filter by specific fields using URL parameters.

**URL pattern:** `?f_{FieldName}=value&op_{FieldName}=operator`

**Supported operators:**
- `contains` - Text contains value (default for strings)
- `startswith` - Text starts with value
- `endswith` - Text ends with value
- `eq` or `equals` - Exact match (default for numbers/dates)
- `ne` or `notequals` - Not equal
- `gt` - Greater than
- `lt` - Less than
- `gte` - Greater than or equal
- `lte` - Less than or equal
- `in` - Value in list (comma-separated)
- `notin` - Value not in list

**Examples:**
```
# Filter users with emails containing @example.com
/admin/data/user?f_Email=@example.com

# Filter users older than 30
/admin/data/user?f_Age=30&op_Age=gt

# Filter users with specific role (exact match)
/admin/data/user?f_Role=Admin&op_Role=eq

# Multiple filters (AND logic)
/admin/data/user?f_Email=@example.com&f_IsActive=true
```

### 6. Combined Filtering
All filter types can be combined.

**Example:**
```
/admin/data/user?q=john&f_IsActive=true&sort=CreatedDate&dir=desc&page=2&size=50
```

This query:
- Searches for "john" across all fields
- Filters to only active users
- Sorts by creation date (newest first)
- Shows page 2 with 50 results per page

## Implementation Details

### Backend Changes (DataScaffold.cs)

**BuildQueryDefinition** method now supports:
- Multiple field filters via `f_{field}=value` pattern
- Custom operators via `op_{field}=operator` pattern
- Auto-selection of default operators based on field type
- Backward compatibility with legacy `field=&value=&op=` pattern

### Frontend Changes (RouteHandlers.cs)

New helper methods:
- `BuildSearchBox` - Renders search input form
- `BuildPageSizeSelector` - Renders page size dropdown
- `BuildEnhancedPagination` - Renders numbered pagination controls
- `BuildSortableColumnHeaders` - Renders clickable headers with sort icons
- `BuildTableWithSortableHeaders` - Builds complete sortable table
- `BuildUrlWithParam` - Helper for URL construction with query params

Updated `DataListHandler`:
- Configurable page size (default 25, max 100)
- Integrated search box UI
- Integrated page size selector
- Integrated numbered pagination
- Integrated sortable table headers

## Future Enhancements

### Potential additions:
1. **Column filter UI in table headers** - Dropdown/input for each column
2. **Date range pickers** - For date/datetime fields
3. **Numeric range inputs** - For numeric fields with min/max
4. **Saved filter presets** - Save and reuse common filter combinations
5. **Export with filters** - CSV/HTML export respects current filters
6. **Filter panel for mobile** - Collapsible panel with all filter options
7. **Client-side debouncing** - Reduce server requests while typing
8. **Filter count badges** - Show number of active filters

## Testing

All features have been validated:
- ✅ Build succeeds with no errors
- ✅ All unit tests pass (436 tests total)
- ✅ Backward compatibility maintained
- ✅ URL state is bookmarkable and shareable
- ✅ Mobile responsive (existing Bootstrap features maintained)

## Code Quality

- Minimal changes to existing code
- No breaking changes to existing APIs
- Follows BareMetalWeb patterns (no middleware, explicit routing)
- Performance-focused (server-side filtering/sorting/pagination)
- Zero allocation where possible (existing patterns maintained)
