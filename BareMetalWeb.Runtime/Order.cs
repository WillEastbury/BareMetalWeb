using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Completed order created during checkout. Records the basket snapshot,
/// payment method, and fulfilment status.
/// </summary>
[DataEntity("Orders", ShowOnNav = true, NavGroup = "Sales", NavOrder = 500)]
public class Order : BaseDataObject
{
    public override string EntityTypeName => "Order";
    private const int Ord_OrderNumber = BaseFieldCount + 0;
    private const int Ord_UserId = BaseFieldCount + 1;
    private const int Ord_Status = BaseFieldCount + 2;
    private const int Ord_PaymentMethod = BaseFieldCount + 3;
    private const int Ord_PaymentReference = BaseFieldCount + 4;
    private const int Ord_Subtotal = BaseFieldCount + 5;
    private const int Ord_Tax = BaseFieldCount + 6;
    private const int Ord_Total = BaseFieldCount + 7;
    private const int Ord_ItemCount = BaseFieldCount + 8;
    private const int Ord_ItemsJson = BaseFieldCount + 9;
    private const int Ord_ShippingAddress = BaseFieldCount + 10;
    private const int Ord_Email = BaseFieldCount + 11;
    private const int Ord_PlacedAtUtc = BaseFieldCount + 12;
    internal const int TotalFieldCount = BaseFieldCount + 13;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Email", Ord_Email),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("ItemCount", Ord_ItemCount),
        new FieldSlot("ItemsJson", Ord_ItemsJson),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("OrderNumber", Ord_OrderNumber),
        new FieldSlot("PaymentMethod", Ord_PaymentMethod),
        new FieldSlot("PaymentReference", Ord_PaymentReference),
        new FieldSlot("PlacedAtUtc", Ord_PlacedAtUtc),
        new FieldSlot("ShippingAddress", Ord_ShippingAddress),
        new FieldSlot("Status", Ord_Status),
        new FieldSlot("Subtotal", Ord_Subtotal),
        new FieldSlot("Tax", Ord_Tax),
        new FieldSlot("Total", Ord_Total),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("UserId", Ord_UserId),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public Order() : base(TotalFieldCount) { }
    public Order(string createdBy) : base(TotalFieldCount, createdBy) { }

    [DataField(Label = "Order Number", Order = 1, ReadOnly = true)]
    public string OrderNumber
    {
        get => (string?)_values[Ord_OrderNumber] ?? string.Empty;
        set => _values[Ord_OrderNumber] = value;
    }

    [DataField(Label = "User ID", Order = 2)]
    public string UserId
    {
        get => (string?)_values[Ord_UserId] ?? string.Empty;
        set => _values[Ord_UserId] = value;
    }

    [DataField(Label = "Status", Order = 3)]
    public OrderStatus Status
    {
        get => _values[Ord_Status] is OrderStatus v ? v : default;
        set => _values[Ord_Status] = value;
    }

    [DataField(Label = "Payment Method", Order = 4)]
    public PaymentMethod PaymentMethod
    {
        get => _values[Ord_PaymentMethod] is PaymentMethod v ? v : default;
        set => _values[Ord_PaymentMethod] = value;
    }

    [DataField(Label = "Payment Reference", Order = 5)]
    public string PaymentReference
    {
        get => (string?)_values[Ord_PaymentReference] ?? string.Empty;
        set => _values[Ord_PaymentReference] = value;
    }

    [DataField(Label = "Subtotal", Order = 6, ReadOnly = true, FieldType = Rendering.Models.FormFieldType.Money)]
    public decimal Subtotal
    {
        get => (decimal)(_values[Ord_Subtotal] ?? 0m);
        set => _values[Ord_Subtotal] = value;
    }

    [DataField(Label = "Tax", Order = 7, ReadOnly = true, FieldType = Rendering.Models.FormFieldType.Money)]
    public decimal Tax
    {
        get => (decimal)(_values[Ord_Tax] ?? 0m);
        set => _values[Ord_Tax] = value;
    }

    [DataField(Label = "Total", Order = 8, ReadOnly = true, FieldType = Rendering.Models.FormFieldType.Money)]
    public decimal Total
    {
        get => (decimal)(_values[Ord_Total] ?? 0m);
        set => _values[Ord_Total] = value;
    }

    [DataField(Label = "Item Count", Order = 9, ReadOnly = true)]
    public int ItemCount
    {
        get => (int)(_values[Ord_ItemCount] ?? 0);
        set => _values[Ord_ItemCount] = value;
    }

    [DataField(Label = "Items JSON", Order = 10, FieldType = Rendering.Models.FormFieldType.TextArea, ReadOnly = true)]
    public string ItemsJson
    {
        get => (string?)_values[Ord_ItemsJson] ?? "[]";
        set => _values[Ord_ItemsJson] = value;
    }

    [DataField(Label = "Shipping Address", Order = 11, FieldType = Rendering.Models.FormFieldType.TextArea)]
    public string ShippingAddress
    {
        get => (string?)_values[Ord_ShippingAddress] ?? string.Empty;
        set => _values[Ord_ShippingAddress] = value;
    }

    [DataField(Label = "Email", Order = 12, FieldType = Rendering.Models.FormFieldType.Email)]
    public string Email
    {
        get => (string?)_values[Ord_Email] ?? string.Empty;
        set => _values[Ord_Email] = value;
    }

    [DataField(Label = "Placed At", Order = 13, ReadOnly = true)]
    public DateTime PlacedAtUtc
    {
        get => _values[Ord_PlacedAtUtc] is DateTime dt ? dt : default;
        set => _values[Ord_PlacedAtUtc] = value;
    }

    public override string ToString() => $"Order {OrderNumber} — {Status}";
}

public enum OrderStatus
{
    Pending = 0,
    Paid = 1,
    Processing = 2,
    Shipped = 3,
    Delivered = 4,
    Cancelled = 5,
    Refunded = 6
}

public enum PaymentMethod
{
    Stripe = 0,
    PayPal = 1,
    Manual = 2
}
