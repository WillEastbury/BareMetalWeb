using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// A per-user shopping basket that persists items across sessions.
/// Each user has at most one open basket; completing checkout closes it.
/// </summary>
[DataEntity("Baskets", ShowOnNav = false, Permissions = "Public")]
public class Basket : RenderableDataObject
{
    [DataField(Label = "User ID", Order = 1, Required = true)]
    public string UserId { get; set; } = string.Empty;

    [DataField(Label = "Status", Order = 2)]
    public BasketStatus Status { get; set; } = BasketStatus.Open;

    [DataField(Label = "Item Count", Order = 3, ReadOnly = true)]
    public int ItemCount { get; set; }

    [DataField(Label = "Total", Order = 4, ReadOnly = true, FieldType = Rendering.Models.FormFieldType.Money)]
    public decimal Total { get; set; }

    [DataField(Label = "Created", Order = 5, ReadOnly = true)]
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;

    public override string ToString() => $"Basket ({UserId}) — {Status}";
}

public enum BasketStatus
{
    Open = 0,
    CheckedOut = 1,
    Abandoned = 2
}

/// <summary>
/// A line item within a shopping basket.
/// </summary>
[DataEntity("Basket Items", ShowOnNav = false, Permissions = "Public")]
public class BasketItem : RenderableDataObject
{
    /// <summary>FK to the parent Basket.</summary>
    [DataField(Label = "Basket ID", Order = 1, Required = true)]
    public string BasketId { get; set; } = string.Empty;

    /// <summary>FK to the product entity (by key).</summary>
    [DataField(Label = "Product ID", Order = 2, Required = true)]
    public string ProductId { get; set; } = string.Empty;

    [DataField(Label = "Product Name", Order = 3)]
    public string ProductName { get; set; } = string.Empty;

    [DataField(Label = "Quantity", Order = 4, Required = true)]
    public int Quantity { get; set; } = 1;

    [DataField(Label = "Unit Price", Order = 5, FieldType = Rendering.Models.FormFieldType.Money)]
    public decimal UnitPrice { get; set; }

    [DataField(Label = "Line Total", Order = 6, ReadOnly = true, FieldType = Rendering.Models.FormFieldType.Money)]
    public decimal LineTotal { get; set; }

    public override string ToString() => $"{ProductName} x{Quantity}";
}
