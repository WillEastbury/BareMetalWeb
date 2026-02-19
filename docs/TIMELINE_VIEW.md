# Timeline View Feature

## Overview

The Timeline View is a new view type added to BareMetalWeb that displays entities in a chronological timeline format, grouped by date. This view is particularly useful for audit trails, activity logs, and any data that has a temporal component.

## Features

- **Automatic Detection**: Timeline view button appears automatically for any entity that has a `DateOnly` or `DateTime` field
- **Date Grouping**: Items are grouped by date and displayed vertically (most recent first)
- **Rich Display**: Shows key fields from each entity along with action buttons (View, Edit, Clone)
- **Responsive Design**: Built with Bootstrap styling for consistent UI
- **No Configuration Required**: Works out of the box with existing entities

## Usage

### Viewing Timeline

Navigate to any data entity list page (e.g., `/admin/data/employees`). If the entity has a `DateOnly` or `DateTime` field, you'll see a "Timeline" button in the view switcher alongside Table, Tree, and Org Chart options.

Click the Timeline button to switch to timeline view. The URL will include `?view=timeline`.

### Supported Field Types

The timeline view looks for fields with these types:
- `FormFieldType.DateOnly` (e.g., Employee HireDate, Invoice Date)
- `FormFieldType.DateTime` (e.g., SessionLog StartedAt, LastActivity)

The first date/datetime field found is used for grouping.

### Display Format

Timeline view displays:
1. **Date Headers**: Each date group shows the date in a readable format (e.g., "Friday, December 20, 2024") with a count badge
2. **Item Cards**: Each item within a date group shows:
   - The primary display value (typically the first string field)
   - Up to 5 key fields from the entity (those marked as List = true)
   - Action buttons: View, Edit, and Clone (if enabled)

## Implementation

### Files Modified

1. **BareMetalWeb.Data/DataViewTypeAttribute.cs**
   - Added `Timeline = 3` to `ViewType` enum

2. **BareMetalWeb.Host/RouteHandlers.cs**
   - Added `BuildTimelineViewHtml` method to render timeline view
   - Updated `BuildViewSwitcher` to show timeline button for date-enabled entities
   - Updated `GetViewTypeName` to include Timeline
   - Modified `DataListHandler` to handle timeline view routing
   - Added helper methods: `GetDisplayValue` and `FormatFieldValue`

### New Test

**BareMetalWeb.Data.Tests/ViewTypeTests.cs**
- Verifies Timeline is added to ViewType enum
- Ensures all enum values are unique

## Examples

### Employee Timeline (HireDate)

When viewing employees in timeline view, they are grouped by hire date:

```
December 20, 2024 [2]
  - John Doe
    Title: Senior Developer
    Department: Engineering
    [View] [Edit] [Clone]
  
  - Jane Smith
    Title: Product Manager
    Department: Product
    [View] [Edit] [Clone]

December 15, 2024 [1]
  - Bob Johnson
    Title: Designer
    Department: Design
    [View] [Edit] [Clone]
```

### Invoice Timeline (InvoiceDate)

Invoices grouped by invoice date show:
- Invoice number
- Customer
- Amount
- Status
- Action buttons

### Session Log Timeline (StartedAt)

Session logs grouped by start time show:
- Username
- IP Address
- Activity status
- Action buttons

## Styling

Timeline view includes embedded CSS for:
- Clean vertical timeline layout
- Date headers with blue accent color
- Item cards with hover effects
- Responsive spacing and typography
- Bootstrap icon integration

## Future Enhancements

Potential improvements:
- Date range filtering in the UI
- Multiple date field selection
- Export timeline to PDF/HTML
- Customizable field display in timeline items
- Search within timeline
- Pagination for large datasets
