# Tree View and Org Chart Implementation Guide

## Overview

This implementation adds two new view types for data scaffolding to visualize hierarchical/self-referencing relationships:

1. **Tree View** - Explorer-style sidebar navigation with detail panel
2. **Org Chart** - Top-down organization chart layout

## Features

### Tree View
- **Left Panel**: Collapsible tree hierarchy
  - Click any node to view details
  - Auto-expands to show selected node's ancestry
  - Recursive rendering with depth limit (10 levels)
  - Circular reference detection
  
- **Right Panel**: Selected entity details
  - Full field display using existing view row logic
  - Edit and Delete action buttons
  - Falls back to "Select an item" when nothing selected

### Org Chart
- **Hierarchical Card Layout**
  - Cards for each entity with name and title/role
  - Auto-detects title field (Title, Role, Position properties)
  - Visual connectors between parent/child levels
  - Depth limit of 5 levels for readability
  
- **Interactive Actions per Node**
  - View: Navigate to detail page
  - Edit: Navigate to edit page  
  - Focus: Re-root the chart on this node

### View Switching
- **Button Group**: Table | Tree | Org Chart
  - Only shows Tree/Org Chart for self-referencing entities
  - Active state highlights current view
  - Query parameter override: `?view=tree`, `?view=orgchart`, `?view=table`
  
- **Entity Default**: Use `[DataViewType(ViewType.TreeView)]` attribute
  - Falls back to Table view if not specified

## Self-Referencing Detection

The system automatically detects self-referencing entities:

1. During metadata build, scans all fields for lookup attributes
2. If `lookup.TargetType == entityType`, stores as `ParentField`
3. Only entities with `ParentField != null` show Tree/Org Chart options

## Usage

### Define a Self-Referencing Entity

```csharp
[DataEntity("Employees", ShowOnNav = true, NavGroup = "Organization")]
[DataViewType(ViewType.TreeView)]  // Optional: sets default view
public class Employee : BaseDataObject
{
    [DataField(Label = "Name", List = true, View = true, Required = true)]
    public string Name { get; set; } = string.Empty;
    
    [DataField(Label = "Title", List = true, View = true)]
    public string? Title { get; set; }
    
    [DataField(Label = "Manager", List = true, View = true)]
    [DataLookup(typeof(Employee), DisplayField = nameof(Name))]
    public string? ManagerId { get; set; }  // Self-reference!
}
```

### URL Examples

```
/admin/data/employees              # Default view (TreeView from attribute)
/admin/data/employees?view=table   # Override to table view
/admin/data/employees?view=tree    # Tree view
/admin/data/employees?view=tree&selected=abc123  # Tree view with node selected
/admin/data/employees?view=orgchart&selected=abc123  # Org chart rooted at node
```

## CSS Classes

### Tree View Classes
- `.bm-data-tree-layout` - Flex container for sidebar + content
- `.bm-data-tree-sidebar` - Left sidebar with tree
- `.bm-data-tree-content` - Right content panel
- `.bm-data-tree-list` - Nested list for tree nodes
- `.bm-data-tree-link` - Link for each tree node
- `.bm-data-tree-active` - Active/selected node highlight

### Org Chart Classes
- `.bm-orgchart-container` - Main container with scrolling
- `.bm-orgchart-level` - Flex container for each hierarchy level
- `.bm-orgchart-node` - Wrapper for each entity
- `.bm-orgchart-card` - Card displaying entity info
- `.bm-orgchart-card-selected` - Highlight for root/selected node
- `.bm-orgchart-name` - Entity name display
- `.bm-orgchart-title` - Title/role display (if field exists)
- `.bm-orgchart-connector` - Visual line between levels

## Architecture Notes

### DataScaffold.cs Methods

**BuildTreeViewHtml()**
- Accepts: metadata, all items, selectedId, basePath, permissions callback
- Returns: Complete HTML with sidebar tree + content panel
- Logic: Finds roots, recursively renders children, handles selection

**BuildOrgChartHtml()**
- Accepts: metadata, all items, selectedId, basePath, permissions callback
- Returns: Complete HTML with hierarchical card layout
- Logic: Starts from selected/first root, renders descendants recursively

**Helper Methods:**
- `RenderTreeNode()` - Recursive tree node rendering
- `RenderOrgChartNode()` - Recursive org chart node rendering
- `IsAncestorSelected()` - Determines if node should be expanded
- `GetDisplayValue()` - Finds best display field (Name/Title/DisplayName/ID)

### RouteHandlers.cs Updates

**DataListHandler changes:**
1. Extract `?view` and `?selected` query parameters
2. Determine effective view type (query param > entity attribute > Table default)
3. For Tree/Org Chart: Load all items (no pagination)
4. For Table: Use existing pagination logic
5. Render view switcher buttons if entity has parent field

## Performance Considerations

- **Tree/Org Chart views load all entities** (no pagination)
  - Acceptable for most org structures (<10,000 employees)
  - Consider adding lazy loading for very large hierarchies
  
- **Depth limits prevent runaway recursion**
  - Tree: 10 levels
  - Org Chart: 5 levels
  
- **Circular reference detection** prevents infinite loops
  - Uses visited set in ancestry checking

## Future Enhancements

Potential improvements:
1. Lazy-load tree branches (AJAX expand on click)
2. Search/filter within tree view
3. Drag-and-drop to reassign managers
4. Export org chart as image/PDF
5. Collapse/expand all buttons
6. Breadcrumb navigation in org chart
7. Different layout options (horizontal, radial)
