using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// A per-user shopping basket that persists items across sessions.
/// Each user has at most one open basket; completing checkout closes it.
/// </summary>
[DataEntity("Baskets", ShowOnNav = false, Permissions = "Public")]
public class Basket : BaseDataObject
{
    private const int Ord_UserId = BaseFieldCount + 0;
    private const int Ord_Status = BaseFieldCount + 1;
    private const int Ord_ItemCount = BaseFieldCount + 2;
    private const int Ord_Total = BaseFieldCount + 3;
    private const int Ord_CreatedUtc = BaseFieldCount + 4;
    internal const int TotalFieldCount = BaseFieldCount + 5;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("CreatedUtc", Ord_CreatedUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("ItemCount", Ord_ItemCount),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("Status", Ord_Status),
        new FieldSlot("Total", Ord_Total),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("UserId", Ord_UserId),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public Basket() : base(TotalFieldCount) { }
    public Basket(string createdBy) : base(TotalFieldCount, createdBy) { }

    [DataField(Label = "User ID", Order = 1, Required = true)]
    public string UserId
    {
        get => (string?)_values[Ord_UserId] ?? string.Empty;
        set => _values[Ord_UserId] = value;
    }

    [DataField(Label = "Status", Order = 2)]
    public BasketStatus Status
    {
        get => _values[Ord_Status] is BasketStatus v ? v : default;
        set => _values[Ord_Status] = value;
    }

    [DataField(Label = "Item Count", Order = 3, ReadOnly = true)]
    public int ItemCount
    {
        get => (int)(_values[Ord_ItemCount] ?? 0);
        set => _values[Ord_ItemCount] = value;
    }

    [DataField(Label = "Total", Order = 4, ReadOnly = true, FieldType = Rendering.Models.FormFieldType.Money)]
    public decimal Total
    {
        get => (decimal)(_values[Ord_Total] ?? 0m);
        set => _values[Ord_Total] = value;
    }

    [DataField(Label = "Created", Order = 5, ReadOnly = true)]
    public DateTime CreatedUtc
    {
        get => _values[Ord_CreatedUtc] is DateTime dt ? dt : default;
        set => _values[Ord_CreatedUtc] = value;
    }

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
public class BasketItem : BaseDataObject
{
    private const int Ord_BasketId = BaseFieldCount + 0;
    private const int Ord_ProductId = BaseFieldCount + 1;
    private const int Ord_ProductName = BaseFieldCount + 2;
    private const int Ord_Quantity = BaseFieldCount + 3;
    private const int Ord_UnitPrice = BaseFieldCount + 4;
    private const int Ord_LineTotal = BaseFieldCount + 5;
    internal const int TotalFieldCount = BaseFieldCount + 6;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("BasketId", Ord_BasketId),
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("LineTotal", Ord_LineTotal),
        new FieldSlot("ProductId", Ord_ProductId),
        new FieldSlot("ProductName", Ord_ProductName),
        new FieldSlot("Quantity", Ord_Quantity),
        new FieldSlot("UnitPrice", Ord_UnitPrice),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public BasketItem() : base(TotalFieldCount) { }
    public BasketItem(string createdBy) : base(TotalFieldCount, createdBy) { }

    /// <summary>FK to the parent Basket.</summary>
    [DataField(Label = "Basket ID", Order = 1, Required = true)]
    public string BasketId
    {
        get => (string?)_values[Ord_BasketId] ?? string.Empty;
        set => _values[Ord_BasketId] = value;
    }

    /// <summary>FK to the product entity (by key).</summary>
    [DataField(Label = "Product ID", Order = 2, Required = true)]
    public string ProductId
    {
        get => (string?)_values[Ord_ProductId] ?? string.Empty;
        set => _values[Ord_ProductId] = value;
    }

    [DataField(Label = "Product Name", Order = 3)]
    public string ProductName
    {
        get => (string?)_values[Ord_ProductName] ?? string.Empty;
        set => _values[Ord_ProductName] = value;
    }

    [DataField(Label = "Quantity", Order = 4, Required = true)]
    public int Quantity
    {
        get => (int)(_values[Ord_Quantity] ?? 1);
        set => _values[Ord_Quantity] = value;
    }

    [DataField(Label = "Unit Price", Order = 5, FieldType = Rendering.Models.FormFieldType.Money)]
    public decimal UnitPrice
    {
        get => (decimal)(_values[Ord_UnitPrice] ?? 0m);
        set => _values[Ord_UnitPrice] = value;
    }

    [DataField(Label = "Line Total", Order = 6, ReadOnly = true, FieldType = Rendering.Models.FormFieldType.Money)]
    public decimal LineTotal
    {
        get => (decimal)(_values[Ord_LineTotal] ?? 0m);
        set => _values[Ord_LineTotal] = value;
    }

    public override string ToString() => $"{ProductName} x{Quantity}";
}
