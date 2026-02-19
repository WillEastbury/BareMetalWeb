# Timetable View Feature

## Overview

The Timetable view is a specialized view type for entities that have both a Day (DayOfWeek enum) field and a Time field (TimeOnly or DateTime). It automatically groups items by day of the week and sorts them by time within each day, making it perfect for schedules, class timetables, and other time-based data.

## When to Use

The Timetable view is automatically available for any entity that has:
1. A field of type `DayOfWeek` (typically named "Day")
2. A field of type `TimeOnly` or `DateTime` (representing the time)

If both conditions are met, a "Timetable" button will appear in the view switcher alongside Table, Tree, and Org Chart views.

## Example Entity

```csharp
[DataEntity("Time Table Plans", ShowOnNav = true, NavGroup = "School", NavOrder = 20)]
public class TimeTablePlan : RenderableDataObject
{
    [DataLookup(typeof(Subject), DisplayField = "Name")]
    [DataField(Label = "Subject Id", Order = 1, Required = true, List = true)]
    public string SubjectId { get; set; } = string.Empty;

    [DataField(Label = "Notes", Order = 2, List = true)]
    public string Notes { get; set; } = string.Empty;

    [DataField(Label = "Day", Order = 3, Required = true, List = true)]
    public DayOfWeek Day { get; set; }

    [DataField(Label = "Start Time", Order = 4, Required = true, List = true)]
    public TimeOnly StartTime { get; set; }

    [DataField(Label = "Minutes", Order = 5, List = true)]
    public int Minutes { get; set; } = 30;
}
```

## Features

### Grouping by Day
- Items are automatically grouped by day of the week (Sunday through Saturday)
- Each day is displayed in its own section with a clear header
- Days are sorted in chronological order (Sunday first)

### Sorting by Time
- Within each day, items are sorted by time (earliest first)
- Time formatting is automatic (HH:mm format)
- Supports both TimeOnly and DateTime fields

### All List Fields Displayed
- The Timetable view displays all fields marked with `List = true`
- Excludes the Day field (used for grouping)
- The Time field is prominently displayed as the first data column

### Full CRUD Actions
- View, Edit, Clone, and Delete buttons for each item
- Consistent with other view types
- Actions are displayed in the first column of each row

## Usage

### Accessing the View

Navigate to the entity list page and click the "Timetable" button in the view switcher:

```
/admin/data/{entity-slug}?view=timetable
```

For example:
```
/admin/data/time-table-plans?view=timetable
```

### View Switcher

The view switcher appears at the top of the list page with buttons for:
- Table (always available)
- Tree (if entity has parent field)
- Org Chart (if entity has parent field)
- **Timetable (if entity has Day and Time fields)**

## Implementation Details

### Detection Logic

The system automatically detects if an entity can show Timetable view using:

```csharp
public static bool CanShowTimetableView(DataEntityMetadata metadata)
{
    var dayField = metadata.Fields.FirstOrDefault(f =>
        f.FieldType == FormFieldType.Enum &&
        f.Property.PropertyType == typeof(DayOfWeek));

    var timeField = metadata.Fields.FirstOrDefault(f =>
        f.FieldType == FormFieldType.TimeOnly ||
        f.FieldType == FormFieldType.DateTime);

    return dayField != null && timeField != null;
}
```

### Rendering

The BuildTimetableHtml method:
1. Loads all items (no pagination, like Tree and Org Chart views)
2. Groups items by DayOfWeek field
3. Sorts items within each group by Time field
4. Renders each day as a separate section with its own table
5. Includes action buttons and all List fields

### Styling

The view uses Bootstrap table classes with custom CSS:
- `.bm-timetable-container` - Main container
- `.bm-timetable-day-section` - Each day section with border and padding
- `.bm-timetable-day-header` - Day name header with primary color accent

## Query Parameter

Like other view types, you can specify the timetable view via query parameter:

```
?view=timetable
```

This overrides the entity's default view type.

## Comparison with Other Views

| Feature | Table | Tree | Org Chart | **Timetable** |
|---------|-------|------|-----------|---------------|
| Pagination | Yes | No | No | **No** |
| Requires parent field | No | Yes | Yes | **No** |
| Requires Day + Time | No | No | No | **Yes** |
| Grouping | No | By hierarchy | By hierarchy | **By Day** |
| Sorting | Configurable | Alphabetical | Hierarchical | **By Time** |

## Benefits

1. **Automatic Organization**: No manual sorting or grouping needed
2. **Clear Visual Structure**: Day-based sections make it easy to scan the schedule
3. **Time-Ordered**: Items are always sorted by time within each day
4. **Consistent UI**: Uses the same action buttons and styling as other views
5. **Zero Configuration**: If your entity has Day and Time fields, the view is automatically available

## Notes

- The Timetable view loads all items at once (no pagination) to ensure complete daily schedules
- Best suited for entities with a reasonable number of items (similar to Tree and Org Chart views)
- For very large datasets, consider using the Table view with filtering instead
