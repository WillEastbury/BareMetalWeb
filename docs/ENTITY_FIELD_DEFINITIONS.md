# Entity & Field Definitions Guide

This guide covers how to define data entities, fields, relationships, validation, indexing, and commands in BareMetalWeb.

## Table of Contents

- [Quick Start](#quick-start)
- [Entity Definition](#entity-definition)
- [Field Definition](#field-definition)
- [Lookup Fields (Foreign Keys)](#lookup-fields-foreign-keys)
- [Validation](#validation)
- [Indexing](#indexing)
- [Calculated Fields](#calculated-fields)
- [Computed Fields](#computed-fields)
- [Remote Commands](#remote-commands)
- [ID Generation](#id-generation)
- [File & Image Fields](#file--image-fields)
- [Copy From Parent](#copy-from-parent)
- [Base Classes](#base-classes)
- [Complete Example](#complete-example)

---

## Quick Start

A minimal entity with two fields:

```csharp
using BareMetalWeb.Data;

[DataEntity("Products", ShowOnNav = true, NavGroup = "Inventory")]
public class Product : RenderableDataObject
{
    [DataField(Label = "Name", Order = 1, Required = true)]
    public string Name { get; set; } = string.Empty;

    [DataField(Label = "Price", Order = 2)]
    public decimal Price { get; set; }
}
```

Place the file in `BareMetalWeb.UserClasses/DataObjects/`. It will be auto-discovered at startup.

---

## Entity Definition

The `[DataEntity]` attribute marks a class as a data entity.

```csharp
[DataEntity("Display Name",
    Slug = "url-slug",              // URL path segment (auto-generated if omitted)
    Permissions = "Admin",          // Required permission (default: entity name)
    ShowOnNav = true,               // Show in navigation bar
    NavGroup = "Sales",             // Navigation dropdown group
    NavOrder = 10)]                 // Sort order within group (lower = first)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `Name` | string | *required* | Display name (plural, e.g. "Customers") |
| `Slug` | string | auto | URL slug (e.g. "customers") |
| `Permissions` | string | entity name | Permission required to access |
| `ShowOnNav` | bool | false | Show in the navigation bar |
| `NavGroup` | string | null | Groups entities under a dropdown |
| `NavOrder` | int | 0 | Sort order in navigation |
| `IdGeneration` | AutoIdStrategy | Guid | How IDs are generated |

---

## Field Definition

The `[DataField]` attribute configures how a property appears in forms, lists, and detail views.

```csharp
[DataField(
    Label = "Email Address",        // Display label
    Order = 3,                      // Sort order on forms
    Required = true,                // Require a value
    FieldType = FormFieldType.Email, // Override auto-detected type
    List = true,                    // Show in list/table view
    View = true,                    // Show in detail view
    Edit = true,                    // Editable on edit form
    Create = true,                  // Shown on create form
    ReadOnly = false,               // Read-only display
    Placeholder = "user@example.com")]
```

### Auto-detected field types

| C# Type | FormFieldType | Rendered As |
|---------|--------------|-------------|
| `string` | String | Text input |
| `int`, `long`, `decimal`, `double` | Number | Number input |
| `bool` | Boolean | Checkbox |
| `DateTime` | DateTime | DateTime picker |
| `DateOnly` | Date | Date picker |
| `TimeOnly` | Time | Time picker |
| `enum` | Select | Dropdown |
| `List<T>` | ChildList | Inline editor |

Override with `FieldType = FormFieldType.TextArea`, `FormFieldType.Email`, `FormFieldType.Url`, etc.

---

## Lookup Fields (Foreign Keys)

The `[DataLookup]` attribute creates a dropdown that loads options from another entity.

```csharp
[DataField(Label = "Customer", Order = 2, Required = true)]
[DataLookup(typeof(Customer),
    DisplayField = "Name",          // Field shown in dropdown (default: "Name")
    ValueField = "Id",              // Field stored as value (default: "Id")
    SortField = "Name",             // Sort dropdown options
    SortDirection = SortDirection.Asc,
    CacheSeconds = 120,             // Cache duration for options
    QueryField = "IsActive",        // Filter: only show active customers
    QueryOperator = QueryOperator.Equals,
    QueryValue = "true",
    CopyFields = "Discount->DiscountPercent")]  // Auto-copy fields on selection
public string CustomerId { get; set; } = string.Empty;
```

### CopyFields

When a lookup value is selected, automatically copy fields from the selected entity:

```csharp
// Copies Product.Price to OrderLine.UnitPrice when product is selected
[DataLookup(typeof(Product), DisplayField = "Name", CopyFields = "Price->UnitPrice")]
public string ProductId { get; set; } = string.Empty;
```

Multiple copies: `CopyFields = "Price->UnitPrice,Sku->ProductSku"`

---

## Validation

Add validation attributes to enforce data integrity. Server-side validation blocks save; client-side shows inline errors.

```csharp
// String length
[MinLength(2, ErrorMessage = "Name must be at least 2 characters")]
[MaxLength(100)]

// Numeric range
[Range(0.01, 99999.99, ErrorMessage = "Price must be between 0.01 and 99,999.99")]

// Format
[EmailAddress]
[Url]
[Phone]

// Pattern
[RegexPattern(@"^[A-Z]{2}\d{4}$", ErrorMessage = "Must match format: AB1234")]
```

### Cross-field validation

Apply `[ValidationRule]` at the entity level:

```csharp
[ValidationRule("EndDate > StartDate", "End date must be after start date")]
[DataEntity("Events")]
public class Event : RenderableDataObject
{
    [DataField(Label = "Start")] public DateTime StartDate { get; set; }
    [DataField(Label = "End")]   public DateTime EndDate { get; set; }
}
```

See [VALIDATION.md](VALIDATION.md) for full details.

---

## Indexing

The `[DataIndex]` attribute enables search indexes on frequently queried fields.

```csharp
[DataField(Label = "Email")]
[DataIndex]                                // Inverted index (default) — full-text search
public string Email { get; set; }

[DataField(Label = "Order Date")]
[DataIndex(IndexKind.BTree)]              // Sorted index — range queries
public DateOnly OrderDate { get; set; }
```

| IndexKind | Use Case | Performance |
|-----------|----------|-------------|
| `Inverted` | Full-text search, keyword matching | O(1) exact, O(k) prefix |
| `BTree` | Range queries, sorted access | O(log n) |
| `Treap` | Balanced insert/delete workloads | O(log n) expected |
| `Bloom` | Fast "does not exist" checks | O(1), false positives possible |

Indexes are built lazily on first query and persisted as binary `.idx` files.

See [SEARCH_INDEX_TYPES.md](SEARCH_INDEX_TYPES.md) for implementation details.

---

## Calculated Fields

Client-side expressions evaluated in real-time as the user edits the form.

```csharp
[CalculatedField(Expression = "Quantity * UnitPrice")]
[DataField(Label = "Subtotal", Order = 5, ReadOnly = true)]
public decimal Subtotal { get; set; }

[CalculatedField(Expression = "Subtotal * (1 - DiscountPercent / 100)")]
[DataField(Label = "Line Total", Order = 6, ReadOnly = true)]
public decimal LineTotal { get; set; }
```

Expressions support: `+`, `-`, `*`, `/`, `%`, `If(condition, trueVal, falseVal)`, comparisons, and field references.

---

## Computed Fields

Server-side fields populated from related entities. Three strategies control freshness vs performance.

```csharp
// Snapshot: frozen at creation time (e.g. price at order time)
[ComputedField(
    SourceEntity = typeof(Product),
    SourceField = "Price",
    ForeignKeyField = "ProductId",
    Strategy = ComputedStrategy.Snapshot,
    Trigger = ComputedTrigger.OnCreate)]
[DataField(Label = "Unit Price at Order")]
public decimal UnitPriceSnapshot { get; set; }

// CachedLive: refreshed periodically
[ComputedField(
    SourceEntity = typeof(Product),
    SourceField = "Price",
    ForeignKeyField = "ProductId",
    Strategy = ComputedStrategy.CachedLive,
    CacheSeconds = 60)]
[DataField(Label = "Current Price")]
public decimal CurrentPrice { get; set; }

// Aggregation: sum/count/min/max/avg over child collection
[ComputedField(
    ChildCollectionProperty = "OrderLines",
    SourceField = "LineTotal",
    Aggregate = AggregateFunction.Sum,
    Strategy = ComputedStrategy.AlwaysLive)]
[DataField(Label = "Order Total")]
public decimal OrderTotal { get; set; }
```

See [COMPUTED_FIELDS.md](COMPUTED_FIELDS.md) for full details.

---

## Remote Commands

Add action buttons to entity detail views that execute server-side logic.

```csharp
[RemoteCommand(
    Label = "Approve",
    Icon = "bi-check-circle",           // Bootstrap icon
    ConfirmMessage = "Approve this order?",
    Order = 1)]
public RemoteCommandResult Approve()
{
    if (Status == "Approved")
        return RemoteCommandResult.Fail("Already approved.");

    Status = "Approved";
    IsOpen = false;
    return RemoteCommandResult.Ok("Order approved successfully.");
}

[RemoteCommand(
    Label = "Cancel",
    Icon = "bi-x-circle",
    Destructive = true,                  // Red button styling
    ConfirmMessage = "Cancel this order? This cannot be undone.",
    Permission = "Admin",                // Requires Admin permission
    Order = 2)]
public RemoteCommandResult Cancel()
{
    Status = "Cancelled";
    IsOpen = false;
    return RemoteCommandResult.Ok("Order cancelled.");
}
```

Commands must return `RemoteCommandResult`. Use `.Ok(message)` or `.Fail(message)`.

---

## ID Generation

Control how entity IDs are assigned.

```csharp
// Default: GUID (32-char hex string)
// No attribute needed — BaseDataObject generates GUIDs automatically.

// Sequential integers (1, 2, 3...)
[IdGeneration(IdGenerationStrategy.SequentialLong)]
[DataField(Label = "Invoice #", Order = 0, ReadOnly = true)]
public new string Id { get => base.Id; set => base.Id = value; }
```

| Strategy | Example IDs | Use Case |
|----------|------------|----------|
| `Guid` (default) | `a1b2c3d4...` | General purpose, globally unique |
| `SequentialLong` | `1`, `2`, `3` | Human-readable sequential IDs |

---

## File & Image Fields

Upload files and images as entity fields.

```csharp
// File upload
[FileField(Label = "Attachment", Order = 10,
    MaxFileSizeBytes = 10 * 1024 * 1024,    // 10 MB
    AllowedMimeTypes = new[] { "application/pdf", "text/plain" })]
public StoredFileData? Attachment { get; set; }

// Image upload with constraints
[ImageField(Label = "Photo", Order = 5,
    MaxFileSizeBytes = 5 * 1024 * 1024,     // 5 MB
    MaxWidth = 1920, MaxHeight = 1080,
    GenerateThumbnail = true)]
public StoredFileData? Photo { get; set; }
```

Files are stored as binary data via the data provider. Use `StoredFileData` as the property type.

---

## Copy From Parent

Auto-populate fields from a parent entity when creating sub-entity records in a modal.

```csharp
[DataField(Label = "Discount %", Order = 4)]
[CopyFromParent("CustomerId", "customers", "DiscountPercent")]
public decimal DiscountPercent { get; set; }
```

Parameters: `CopyFromParent(parentFieldName, entitySlug, sourceFieldName)`

- `parentFieldName` — The lookup field on the parent form (e.g. "CustomerId")
- `entitySlug` — The entity to fetch the parent from (e.g. "customers")
- `sourceFieldName` — The field to copy from the parent record (e.g. "DiscountPercent")

---

## Base Classes

| Class | Use |
|-------|-----|
| `RenderableDataObject` | Standard entities with full UI (forms, lists, detail views) |
| `BaseDataObject` | Internal/system entities without direct UI rendering |

Both provide: `Id`, `CreatedOnUtc`, `UpdatedOnUtc`, `CreatedBy`, `UpdatedBy`, `ETag`.

```csharp
// Standard entity — use this for most cases
[DataEntity("Customers", ShowOnNav = true)]
public class Customer : RenderableDataObject { ... }

// System entity — no auto-generated UI
public class AuditEntry : BaseDataObject { ... }
```

---

## Complete Example

A full entity with lookups, validation, calculated fields, indexing, and commands:

```csharp
using BareMetalWeb.Data;

[DataEntity("Orders", ShowOnNav = true, NavGroup = "Sales", NavOrder = 40)]
public class Order : RenderableDataObject
{
    [DataField(Label = "Order Number", Order = 1, Required = true)]
    [MinLength(3)]
    [DataIndex]
    public string OrderNumber { get; set; } = string.Empty;

    [DataField(Label = "Customer", Order = 2, Required = true)]
    [DataLookup(typeof(Customer), DisplayField = "Name",
        SortField = "Name", CacheSeconds = 120)]
    [DataIndex]
    public string CustomerId { get; set; } = string.Empty;

    [DataField(Label = "Order Date", Order = 3, Required = true)]
    [DataIndex(IndexKind.BTree)]
    public DateOnly OrderDate { get; set; } = DateOnly.FromDateTime(DateTime.UtcNow);

    [DataField(Label = "Currency", Order = 4, Required = true)]
    [DataLookup(typeof(Currency), DisplayField = "Name")]
    public string CurrencyId { get; set; } = string.Empty;

    [DataField(Label = "Status", Order = 5)]
    [DataIndex]
    public string Status { get; set; } = "Open";

    [DataField(Label = "Is Open", Order = 6)]
    public bool IsOpen { get; set; } = true;

    [DataField(Label = "Notes", Order = 7, FieldType = FormFieldType.TextArea)]
    public string Notes { get; set; } = string.Empty;

    [DataField(Label = "Order Rows", Order = 8)]
    public List<OrderLine> OrderRows { get; set; } = new();

    [RemoteCommand(Label = "Approve", Icon = "bi-check-circle",
        ConfirmMessage = "Approve this order?", Order = 1)]
    public RemoteCommandResult Approve()
    {
        if (Status == "Approved")
            return RemoteCommandResult.Fail("Already approved.");
        Status = "Approved";
        IsOpen = false;
        return RemoteCommandResult.Ok("Order approved.");
    }

    [RemoteCommand(Label = "Cancel", Icon = "bi-x-circle",
        Destructive = true, ConfirmMessage = "Cancel this order?", Order = 2)]
    public RemoteCommandResult Cancel()
    {
        Status = "Cancelled";
        IsOpen = false;
        return RemoteCommandResult.Ok("Order cancelled.");
    }
}
```

---

## Related Documentation

- [VALIDATION.md](VALIDATION.md) — Validation attribute reference
- [COMPUTED_FIELDS.md](COMPUTED_FIELDS.md) — Computed field strategies
- [SEARCH_INDEX_TYPES.md](SEARCH_INDEX_TYPES.md) — Index implementation details
- [LOOKUP_API.md](LOOKUP_API.md) — Lookup REST API endpoints
- [BULK_OPERATIONS.md](BULK_OPERATIONS.md) — Bulk create/update/delete
