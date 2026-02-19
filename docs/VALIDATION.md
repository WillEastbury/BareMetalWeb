# Field Validation Framework

BareMetalWeb includes a comprehensive field validation framework with server-side enforcement, client-side HTML5 attributes, and expression-based cross-field validation powered by the ExpressionParser engine.

## Validation Attributes

Apply validation attributes to entity properties alongside `[DataField]`:

```csharp
[DataEntity("Products", Slug = "products")]
public class Product : BaseDataObject
{
    [DataField(Label = "Name", Required = true)]
    [MinLength(2)]
    [MaxLength(100)]
    public string Name { get; set; } = string.Empty;

    [DataField(Label = "Price", FieldType = FormFieldType.Decimal)]
    [Range(0.01, 99999.99)]
    public decimal Price { get; set; }

    [DataField(Label = "SKU")]
    [RegexPattern(@"^[A-Z]{3}-\d{4}$", ErrorMessage = "SKU must be in format XXX-0000")]
    public string? SKU { get; set; }

    [DataField(Label = "Email")]
    [EmailAddress]
    public string? ContactEmail { get; set; }

    [DataField(Label = "Website")]
    [Url]
    public string? Website { get; set; }

    [DataField(Label = "Phone")]
    [Phone]
    public string? Phone { get; set; }
}
```

### Available Attributes

| Attribute | Description | HTML5 Output |
|-----------|-------------|--------------|
| `[MinLength(n)]` | Minimum string length | `minlength="n"` |
| `[MaxLength(n)]` | Maximum string length | `maxlength="n"` |
| `[Range(min, max)]` | Numeric range | `min="min" max="max"` |
| `[RegexPattern(pattern)]` | Regex validation | `pattern="..."` |
| `[EmailAddress]` | Email format | Built-in email type |
| `[Url]` | URL format (http/https) | — |
| `[Phone]` | Phone number format | — |

All attributes support an optional `ErrorMessage` property for custom error messages.

## Cross-Field Validation (Expression Rules)

Use `[ValidationRule]` for cross-field validation. Expressions are evaluated using the same ExpressionParser used for calculated fields, supporting comparison operators (`>`, `<`, `>=`, `<=`, `==`, `!=`), arithmetic, and functions (`If()`, `Min()`, `Max()`, etc.).

### Property-Level Expression Rules

```csharp
[DataField(Label = "Discount")]
[ValidationRule("Discount <= Price", "Discount cannot exceed price")]
public decimal Discount { get; set; }
```

### Entity-Level Expression Rules

Apply to the class for rules spanning multiple fields:

```csharp
[DataEntity("Events")]
[ValidationRule("EndDate > StartDate", "End date must be after start date")]
[ValidationRule("MaxAttendees > 0", "Must allow at least one attendee")]
public class Event : BaseDataObject
{
    [DataField(Label = "Start Date")] public DateTime StartDate { get; set; }
    [DataField(Label = "End Date")] public DateTime EndDate { get; set; }
    [DataField(Label = "Max Attendees")] public int MaxAttendees { get; set; }
}
```

## How It Works

### Server-Side Flow

1. **Form submission** → `ApplyValuesFromForm()` validates Required + type parsing + runs attribute validators per field
2. **Entity validation** → `ValidateEntity()` runs expression-based cross-field rules
3. **If errors** → form re-renders with per-field error messages (Bootstrap `is-invalid` + `invalid-feedback`)
4. **API routes** → return HTTP 400 with error messages

### Client-Side

- HTML5 validation attributes (`minlength`, `maxlength`, `min`, `max`, `pattern`, `required`) emitted automatically
- `form-validation.js` provides real-time validation on input/change events
- Bootstrap `is-invalid` / `invalid-feedback` styling for server-side errors
- Form submission prevented if client-side validation fails

### Skipped Fields

- **Computed fields** (auto-populated from lookups/aggregations) — skipped
- **Calculated fields** (expression-based) — skipped
- **Read-only fields** — skipped

## Architecture

- `ValidationAttributes.cs` — Attribute definitions
- `ValidationService.cs` — Server-side validation engine
- `ValidationConfig` record — Per-field validation configuration (built from attributes at registration)
- `DataFieldMetadata.Validation` — Validation config attached to field metadata
- `ExpressionParser` — Reused from calculated fields for expression-based rules
- `form-validation.js` — Client-side real-time validation
