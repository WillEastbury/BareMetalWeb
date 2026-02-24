# Lookup Field Refresh and Add Buttons

## Overview

This feature adds convenient "Refresh" and "Add" buttons to lookup fields in forms, allowing users to update cached lookup values and quickly add new entries to referenced entities without leaving the current form.

## What Problem Does This Solve?

When working with forms that have lookup fields (dropdowns that reference other entities), users often encounter these scenarios:

1. **Stale cached data**: After adding a new employee/product/etc., the newly created item doesn't appear in lookup dropdowns on other forms because the lookup values are cached.

2. **Need to add missing entries**: Users want to reference an entity that doesn't exist yet, requiring them to navigate away from the current form, create the new entry, and then return.

This feature solves both problems by adding buttons directly next to lookup fields.

## How It Works

### Refresh Button (↻)
- **Purpose**: Clears the cached lookup values and reloads the form with fresh data
- **Behavior**: Reloads the current page with a cache-busting parameter, forcing the server to regenerate the form with updated lookup options
- **When to use**: After adding/editing entries in a related entity, click refresh to see the changes

### Add Button (+)
- **Purpose**: Opens a new window/tab to create a new entry in the referenced entity
- **Behavior**: 
  - Opens the create form for the target entity in a new browser window
  - When the new window is closed, automatically refreshes the lookup field
  - Falls back to same-window navigation if popups are blocked
- **When to use**: When you need to reference an entity that doesn't exist yet

## Implementation Details

### Changes Made

1. **FormField Model** (`BareMetalWeb.Core/FormField.cs`)
   - Added `LookupTargetType` property: The type name of the entity being looked up (e.g., "Employee")
   - Added `LookupTargetSlug` property: The URL slug for the entity (e.g., "employees")

2. **DataScaffold** (`BareMetalWeb.Data/DataScaffold.cs`)
   - Updated `BuildFormFields` to populate lookup metadata when building form fields with `[DataLookup]` attributes
   - Metadata is only added for actual lookup fields, not enum fields

3. **HTML Templates** (`BareMetalWeb.Core/wwwroot/templates/fragments/`)
   - `LookupGroupStart.html`: Opens a Bootstrap input-group wrapper
   - `LookupGroupEnd.html`: Closes the input-group wrapper
   - `LookupRefreshButton.html`: Refresh button template with icon
   - `LookupAddButton.html`: Add button template with icon

4. **Rendering Logic** (`BareMetalWeb.Rendering/StaticHTMLFragments.cs`)
   - Updated `RenderLookupSelect` to wrap lookup fields in input-group when metadata is present
   - Added button templates for refresh and add functionality
   - Buttons are only rendered for true lookup fields (not enums)

5. **JavaScript** (`BareMetalWeb.Core/wwwroot/static/js/lookup-helper.js`)
   - `refreshLookup(fieldName)`: Reloads the page with cache-busting parameters
   - `addLookupItem(targetSlug, fieldName)`: Opens create form in new window and auto-refreshes on close

6. **Tests** (`BareMetalWeb.Data.Tests/LookupFieldButtonTests.cs`)
   - Tests verify that lookup metadata is correctly populated for lookup fields
   - Tests verify that non-lookup fields do not get lookup metadata

## Example Usage

### Employee Form with Manager Lookup

When creating or editing an employee with a "Manager" lookup field:

```csharp
[DataField(Order = 5, Label = "Manager", List = true, View = true, Edit = true, Create = true)]
[DataLookup(typeof(Employee), DisplayField = nameof(Name), 
    QueryField = nameof(Id), QueryOperator = QueryOperator.NotEquals)]
public string? ManagerId { get; set; }
```

The rendered HTML will include:

```html
<div class="input-group">
    <select class="form-select" id="ManagerId" name="ManagerId">
        <option value="guid-1">John Doe</option>
        <option value="guid-2">Jane Smith</option>
    </select>
    <button class="btn btn-outline-secondary btn-sm" type="button" 
            onclick="refreshLookup('ManagerId')" title="Refresh lookup values">↻</button>
    <button class="btn btn-outline-primary btn-sm" type="button" 
            onclick="addLookupItem('employees', 'ManagerId')" title="Add new Employee">+</button>
</div>
```

### User Workflow

1. User is creating Employee A who reports to Employee B
2. Employee B doesn't exist yet, so user clicks the "+" button next to Manager field
3. New window opens with the Employee create form
4. User creates Employee B in the new window
5. User closes the new window
6. The Manager dropdown automatically refreshes and now includes Employee B
7. User selects Employee B as the manager and completes the form

## Technical Notes

### Caching
- Lookup values are cached for performance (default: 60 seconds via `DataLookupAttribute.CacheSeconds`)
- Refresh button bypasses cache by reloading the page with a timestamp parameter
- Cache behavior is managed by `DataScaffold.GetLookupOptions`

### Security
- Buttons respect existing permission model - users can only add entries if they have permission to access that entity's create route
- JavaScript is loaded with proper CSP nonce for Content Security Policy compliance

### Performance
- Minimal overhead: Only adds two small buttons to lookup fields
- No additional API calls unless buttons are clicked
- Uses Bootstrap's existing input-group styling, no additional CSS needed

### Browser Compatibility
- Works in all modern browsers
- Graceful degradation if popups are blocked (falls back to same-window navigation with user notification)

## Future Enhancements

Potential improvements for future versions:

1. **Inline creation**: Add modal dialog option instead of new window
2. **Selective refresh**: Refresh only the specific lookup field instead of reloading entire page
3. **Auto-select**: Automatically select newly created item after adding
4. **Configurable**: Add attribute option to hide buttons on specific fields
5. **Quick edit**: Add edit button to quickly modify existing lookup entries

## Testing

Run the tests with:
```bash
dotnet test BareMetalWeb.Data.Tests --filter "FullyQualifiedName~LookupFieldButtonTests"
```

Tests verify:
- Lookup fields receive the correct metadata (target type and slug)
- Non-lookup fields (strings, enums, etc.) do not receive lookup metadata
- Metadata is used correctly during form rendering
