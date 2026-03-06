using System.Text.Json;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Runtime;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// API handlers for the shopping basket.
/// GET  /api/basket         — get current user's open basket with items
/// POST /api/basket/add     — add item to basket { productId, productName, quantity, unitPrice }
/// POST /api/basket/remove  — remove item { itemKey }
/// POST /api/basket/clear   — clear all items
/// </summary>
public static class BasketApiHandlers
{
    public static async ValueTask GetBasketHandler(BmwContext context)
    {
        var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted);
        var userId = user?.Key.ToString() ?? GetAnonymousId(context);

        var basket = await FindOrCreateBasket(userId, context.RequestAborted);
        var items = await LoadBasketItems(basket.Key.ToString(), context.RequestAborted);

        context.Response.ContentType = "application/json";
        decimal basketTotal = 0;
        foreach (var i in items) basketTotal += i.LineTotal;

        await using var writer = new Utf8JsonWriter(context.Response.Body);
        writer.WriteStartObject();
        writer.WriteNumber("basketKey", basket.Key);
        writer.WriteString("userId", userId);
        writer.WriteString("status", basket.Status.ToString());
        writer.WriteNumber("itemCount", items.Count);
        writer.WriteNumber("total", basketTotal);
        writer.WriteStartArray("items");
        foreach (var i in items)
        {
            writer.WriteStartObject();
            writer.WriteNumber("key", i.Key);
            writer.WriteString("productId", i.ProductId);
            writer.WriteString("productName", i.ProductName);
            writer.WriteNumber("quantity", i.Quantity);
            writer.WriteNumber("unitPrice", i.UnitPrice);
            writer.WriteNumber("lineTotal", i.LineTotal);
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
        writer.WriteEndObject();
        await writer.FlushAsync(context.RequestAborted);
    }

    public static async ValueTask AddItemHandler(BmwContext context)
    {
        var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted);
        var userId = user?.Key.ToString() ?? GetAnonymousId(context);

        using var doc = await JsonDocument.ParseAsync(context.HttpRequest.Body, cancellationToken: context.RequestAborted);
        var root = doc.RootElement;
        var productId = root.TryGetProperty("productId", out var pid) ? pid.GetString() ?? "" : "";
        var productName = root.TryGetProperty("productName", out var pn) ? pn.GetString() ?? "" : "";
        var quantity = root.TryGetProperty("quantity", out var q) ? q.GetInt32() : 1;
        var unitPrice = root.TryGetProperty("unitPrice", out var up) ? up.GetDecimal() : 0m;

        var basket = await FindOrCreateBasket(userId, context.RequestAborted);

        if (!DataScaffold.TryGetEntity("basket-items", out var itemMeta))
        {
            context.Response.StatusCode = 500;
            await context.Response.WriteAsync("{\"error\":\"Basket items entity not registered.\"}");
            return;
        }

        // Check if product already in basket — update quantity
        var existing = await LoadBasketItems(basket.Key.ToString(), context.RequestAborted);
        BasketItem? existingItem = null;
        foreach (var i in existing)
        {
            if (i.ProductId == productId)
            {
                existingItem = i;
                break;
            }
        }
        if (existingItem != null)
        {
            existingItem.Quantity += quantity;
            existingItem.LineTotal = existingItem.Quantity * existingItem.UnitPrice;
            await itemMeta.Handlers.SaveAsync(existingItem, context.RequestAborted);
        }
        else
        {
            var item = (BasketItem)itemMeta.Handlers.Create();
            await DataScaffold.ApplyAutoIdAsync(itemMeta, item, context.RequestAborted);
            item.BasketId = basket.Key.ToString();
            item.ProductId = productId;
            item.ProductName = productName;
            item.Quantity = quantity;
            item.UnitPrice = unitPrice;
            item.LineTotal = quantity * unitPrice;
            await itemMeta.Handlers.SaveAsync(item, context.RequestAborted);
        }

        // Update basket totals
        var allItems = await LoadBasketItems(basket.Key.ToString(), context.RequestAborted);
        basket.ItemCount = allItems.Count;
        decimal allItemsTotal = 0;
        foreach (var i in allItems) allItemsTotal += i.LineTotal;
        basket.Total = allItemsTotal;
        if (DataScaffold.TryGetEntity("baskets", out var basketMeta))
            await basketMeta.Handlers.SaveAsync(basket, context.RequestAborted);

        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync("{\"ok\":true,\"itemCount\":" + basket.ItemCount + ",\"total\":" + basket.Total + "}");
    }

    public static async ValueTask RemoveItemHandler(BmwContext context)
    {
        using var doc = await JsonDocument.ParseAsync(context.HttpRequest.Body, cancellationToken: context.RequestAborted);
        var itemKey = doc.RootElement.TryGetProperty("itemKey", out var ik) ? ik.GetUInt32() : 0u;
        if (itemKey == 0)
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("{\"error\":\"itemKey required.\"}");
            return;
        }

        if (DataScaffold.TryGetEntity("basket-items", out var itemMeta))
            await itemMeta.Handlers.DeleteAsync(itemKey, context.RequestAborted);

        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync("{\"ok\":true}");
    }

    public static async ValueTask ClearBasketHandler(BmwContext context)
    {
        var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted);
        var userId = user?.Key.ToString() ?? GetAnonymousId(context);

        var basket = await FindOrCreateBasket(userId, context.RequestAborted);
        var items = await LoadBasketItems(basket.Key.ToString(), context.RequestAborted);

        if (DataScaffold.TryGetEntity("basket-items", out var itemMeta))
        {
            foreach (var item in items)
                await itemMeta.Handlers.DeleteAsync(item.Key, context.RequestAborted);
        }

        basket.ItemCount = 0;
        basket.Total = 0;
        if (DataScaffold.TryGetEntity("baskets", out var basketMeta))
            await basketMeta.Handlers.SaveAsync(basket, context.RequestAborted);

        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync("{\"ok\":true}");
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private static async Task<Basket> FindOrCreateBasket(string userId, CancellationToken ct)
    {
        if (!DataScaffold.TryGetEntity("baskets", out var meta))
            throw new InvalidOperationException("Baskets entity not registered.");

        var qd = new QueryDefinition();
        qd.Clauses.Add(new QueryClause { Field = "UserId", Operator = QueryOperator.Equals, Value = userId });
        qd.Clauses.Add(new QueryClause { Field = "Status", Operator = QueryOperator.Equals, Value = "Open" });
        var results = await meta.Handlers.QueryAsync(qd, ct);
        Basket? existing = null;
        foreach (var obj in results)
        {
            existing = (Basket)obj;
            break;
        }
        if (existing != null) return existing;

        var basket = (Basket)meta.Handlers.Create();
        await DataScaffold.ApplyAutoIdAsync(meta, basket, ct);
        basket.UserId = userId;
        basket.Status = BasketStatus.Open;
        basket.CreatedUtc = DateTime.UtcNow;
        await meta.Handlers.SaveAsync(basket, ct);
        return basket;
    }

    private static async Task<List<BasketItem>> LoadBasketItems(string basketKey, CancellationToken ct)
    {
        if (!DataScaffold.TryGetEntity("basket-items", out var meta))
            return new List<BasketItem>();

        var qd = new QueryDefinition();
        qd.Clauses.Add(new QueryClause { Field = "BasketId", Operator = QueryOperator.Equals, Value = basketKey });
        var results = await meta.Handlers.QueryAsync(qd, ct);
        var list = new List<BasketItem>();
        foreach (var obj in results)
            list.Add((BasketItem)obj);
        return list;
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
            SameSite = SameSiteMode.Lax,
            MaxAge = TimeSpan.FromDays(365),
            Path = "/"
        });
        return id;
    }
}
