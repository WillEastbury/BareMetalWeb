using System.Text.Json;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Runtime;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Checkout API handlers.
/// POST /api/checkout — create an order from the current basket
/// POST /api/checkout/confirm — confirm payment and finalize order
/// </summary>
public static class CheckoutApiHandlers
{
    private static readonly Dictionary<string, PaymentMethod> PaymentMethodLookup = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Stripe"] = PaymentMethod.Stripe,
        ["PayPal"] = PaymentMethod.PayPal,
        ["Manual"] = PaymentMethod.Manual,
    };

    private static long _orderSeq = DateTime.UtcNow.Ticks % 100_000;

    // SECURITY: Per-basket locks to prevent double-checkout race condition (see #1217)
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<uint, SemaphoreSlim> _checkoutLocks = new();

    /// <summary>
    /// POST /api/checkout
    /// Body: { email, shippingAddress, paymentMethod }
    /// Creates an Order from the user's open basket and marks the basket as CheckedOut.
    /// </summary>
    public static async ValueTask CheckoutHandler(BmwContext context)
    {
        var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted);
        var userId = user?.Key.ToString() ?? GetAnonymousId(context);

        if (!DataScaffold.TryGetEntity("baskets", out var basketMeta) ||
            !DataScaffold.TryGetEntity("basket-items", out var itemMeta) ||
            !DataScaffold.TryGetEntity("orders", out var orderMeta))
        {
            context.Response.StatusCode = 500;
            await context.Response.WriteAsync("{\"error\":\"Shop entities not registered.\"}");
            return;
        }

        // Find open basket
        var bqd = new QueryDefinition();
        bqd.Clauses.Add(new QueryClause { Field = "UserId", Operator = QueryOperator.Equals, Value = userId });
        bqd.Clauses.Add(new QueryClause { Field = "Status", Operator = QueryOperator.Equals, Value = "Open" });
        var baskets = await basketMeta.Handlers.QueryAsync(bqd, context.RequestAborted);
        Basket? basket = null;
        foreach (var obj in baskets)
        {
            basket = (Basket)obj;
            break;
        }
        if (basket == null)
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("{\"error\":\"No open basket.\"}");
            return;
        }

        // SECURITY: Acquire per-basket lock to prevent double-checkout race condition (see #1217)
        var basketLock = _checkoutLocks.GetOrAdd(basket.Key, _ => new SemaphoreSlim(1, 1));
        if (!await basketLock.WaitAsync(TimeSpan.FromSeconds(5), context.RequestAborted))
        {
            context.Response.StatusCode = 409;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"Checkout already in progress for this basket.\"}");
            return;
        }
        try
        {
        // Re-check basket status under lock
        if (basket.Status != BasketStatus.Open)
        {
            context.Response.StatusCode = 409;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"Basket was already checked out.\"}");
            return;
        }

        // Load items
        var iqd = new QueryDefinition();
        iqd.Clauses.Add(new QueryClause { Field = "BasketId", Operator = QueryOperator.Equals, Value = basket.Key.ToString() });
        var itemResults = await itemMeta.Handlers.QueryAsync(iqd, context.RequestAborted);
        var items = new List<BasketItem>();
        foreach (var obj in itemResults)
            items.Add((BasketItem)obj);
        if (items.Count == 0)
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("{\"error\":\"Basket is empty.\"}");
            return;
        }

        // Parse request
        using var doc = await JsonDocument.ParseAsync(context.HttpRequest.Body, cancellationToken: context.RequestAborted);
        var root = doc.RootElement;
        var email = root.TryGetProperty("email", out var e) ? e.GetString() ?? "" : "";
        var address = root.TryGetProperty("shippingAddress", out var a) ? a.GetString() ?? "" : "";
        var method = root.TryGetProperty("paymentMethod", out var pm) ? pm.GetString() ?? "Stripe" : "Stripe";

        // Create order
        var order = (Order)orderMeta.Handlers.Create();
        await DataScaffold.ApplyAutoIdAsync(orderMeta, order, context.RequestAborted);
        var seq = Interlocked.Increment(ref _orderSeq);
        order.OrderNumber = $"ORD-{DateTime.UtcNow:yyyyMMdd}-{seq:D5}";
        order.UserId = userId;
        order.Email = email;
        order.ShippingAddress = address;
        order.PaymentMethod = PaymentMethodLookup.TryGetValue(method, out var pmEnum) ? pmEnum : PaymentMethod.Stripe;
        decimal subtotal = 0;
        foreach (var i in items) subtotal += i.LineTotal;
        order.Subtotal = subtotal;
        order.Tax = Math.Round(order.Subtotal * 0.20m, 2); // 20% tax (configurable in future)
        order.Total = order.Subtotal + order.Tax;
        order.ItemCount = items.Count;
        using var ms = new MemoryStream();
        using (var itemWriter = new Utf8JsonWriter(ms))
        {
            itemWriter.WriteStartArray();
            foreach (var i in items)
            {
                itemWriter.WriteStartObject();
                itemWriter.WriteString("ProductId", i.ProductId);
                itemWriter.WriteString("ProductName", i.ProductName);
                itemWriter.WriteNumber("Quantity", i.Quantity);
                itemWriter.WriteNumber("UnitPrice", i.UnitPrice);
                itemWriter.WriteNumber("LineTotal", i.LineTotal);
                itemWriter.WriteEndObject();
            }
            itemWriter.WriteEndArray();
        }
        order.ItemsJson = System.Text.Encoding.UTF8.GetString(ms.ToArray());
        order.PlacedAtUtc = DateTime.UtcNow;
        order.Status = OrderStatus.Pending;
        await orderMeta.Handlers.SaveAsync(order, context.RequestAborted);

        // Mark basket as checked out
        basket.Status = BasketStatus.CheckedOut;
        await basketMeta.Handlers.SaveAsync(basket, context.RequestAborted);

        context.Response.ContentType = "application/json";
        await using var writer = new Utf8JsonWriter(context.Response.Body);
        writer.WriteStartObject();
        writer.WriteBoolean("ok", true);
        writer.WriteString("orderNumber", order.OrderNumber);
        writer.WriteNumber("orderKey", order.Key);
        writer.WriteNumber("total", order.Total);
        writer.WriteString("status", order.Status.ToString());
        writer.WriteEndObject();
        await writer.FlushAsync(context.RequestAborted);
        } // end try
        finally
        {
            basketLock.Release();
            _checkoutLocks.TryRemove(basket.Key, out _);
        }
    }

    /// <summary>
    /// POST /api/checkout/confirm
    /// Body: { orderKey, paymentReference }
    /// Confirms payment and updates order status to Paid.
    /// </summary>
    public static async ValueTask ConfirmPaymentHandler(BmwContext context)
    {
        if (!DataScaffold.TryGetEntity("orders", out var orderMeta))
        {
            context.Response.StatusCode = 500;
            await context.Response.WriteAsync("{\"error\":\"Orders entity not registered.\"}");
            return;
        }

        using var doc = await JsonDocument.ParseAsync(context.HttpRequest.Body, cancellationToken: context.RequestAborted);
        var root = doc.RootElement;
        var orderKey = root.TryGetProperty("orderKey", out var ok) ? ok.GetUInt32() : 0u;
        var paymentRef = root.TryGetProperty("paymentReference", out var pr) ? pr.GetString() ?? "" : "";

        if (orderKey == 0)
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("{\"error\":\"orderKey required.\"}");
            return;
        }

        var obj = await orderMeta.Handlers.LoadAsync(orderKey, context.RequestAborted);
        if (obj is not Order order)
        {
            context.Response.StatusCode = 404;
            await context.Response.WriteAsync("{\"error\":\"Order not found.\"}");
            return;
        }

        order.PaymentReference = paymentRef;
        order.Status = OrderStatus.Paid;
        await orderMeta.Handlers.SaveAsync(order, context.RequestAborted);

        context.Response.ContentType = "application/json";
        await using var writer = new Utf8JsonWriter(context.Response.Body);
        writer.WriteStartObject();
        writer.WriteBoolean("ok", true);
        writer.WriteString("orderNumber", order.OrderNumber);
        writer.WriteString("status", order.Status.ToString());
        writer.WriteEndObject();
        await writer.FlushAsync(context.RequestAborted);
    }

    private static string GetAnonymousId(BmwContext context)
    {
        const string cookieName = "bm-anon-id";
        if (context.HttpRequest.Cookies.TryGetValue(cookieName, out var id) && !string.IsNullOrEmpty(id))
            return id;
        id = Guid.NewGuid().ToString("N")[..12];
        context.Response.Cookies.Append(cookieName, id, new CookieOptions
        {
            HttpOnly = true,
            Secure = context.HttpRequest.IsHttps,
            SameSite = SameSiteMode.Lax,
            MaxAge = TimeSpan.FromDays(365),
            Path = "/"
        });
        return id;
    }
}
