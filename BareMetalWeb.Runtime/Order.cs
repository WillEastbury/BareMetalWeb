using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Completed order created during checkout. Records the basket snapshot,
/// payment method, and fulfilment status.
/// </summary>
[DataEntity("Orders", ShowOnNav = true, NavGroup = "Sales", NavOrder = 500)]
public class Order : RenderableDataObject
{
    [DataField(Label = "Order Number", Order = 1, ReadOnly = true)]
    public string OrderNumber { get; set; } = string.Empty;

    [DataField(Label = "User ID", Order = 2)]
    public string UserId { get; set; } = string.Empty;

    [DataField(Label = "Status", Order = 3)]
    public OrderStatus Status { get; set; } = OrderStatus.Pending;

    [DataField(Label = "Payment Method", Order = 4)]
    public PaymentMethod PaymentMethod { get; set; } = PaymentMethod.Stripe;

    [DataField(Label = "Payment Reference", Order = 5)]
    public string PaymentReference { get; set; } = string.Empty;

    [DataField(Label = "Subtotal", Order = 6, ReadOnly = true, FieldType = Rendering.Models.FormFieldType.Money)]
    public decimal Subtotal { get; set; }

    [DataField(Label = "Tax", Order = 7, ReadOnly = true, FieldType = Rendering.Models.FormFieldType.Money)]
    public decimal Tax { get; set; }

    [DataField(Label = "Total", Order = 8, ReadOnly = true, FieldType = Rendering.Models.FormFieldType.Money)]
    public decimal Total { get; set; }

    [DataField(Label = "Item Count", Order = 9, ReadOnly = true)]
    public int ItemCount { get; set; }

    [DataField(Label = "Items JSON", Order = 10, FieldType = Rendering.Models.FormFieldType.TextArea, ReadOnly = true)]
    public string ItemsJson { get; set; } = "[]";

    [DataField(Label = "Shipping Address", Order = 11, FieldType = Rendering.Models.FormFieldType.TextArea)]
    public string ShippingAddress { get; set; } = string.Empty;

    [DataField(Label = "Email", Order = 12, FieldType = Rendering.Models.FormFieldType.Email)]
    public string Email { get; set; } = string.Empty;

    [DataField(Label = "Placed At", Order = 13, ReadOnly = true)]
    public DateTime PlacedAtUtc { get; set; } = DateTime.UtcNow;

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
