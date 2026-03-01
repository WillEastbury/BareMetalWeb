using System.Text;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Renders product category browse and product grid views.
/// GET /products — category listing
/// GET /products/{category} — product grid with filtering
/// </summary>
public static class ProductRenderer
{
    /// <summary>GET /products — render category browse page.</summary>
    public static async ValueTask CategoryBrowseHandler(HttpContext context)
    {
        if (!DataScaffold.TryGetEntity("product-categories", out var catMeta))
        {
            context.Response.StatusCode = 500;
            await context.Response.WriteAsync("Product categories not configured.");
            return;
        }

        var categories = await catMeta.Handlers.QueryAsync(null, context.RequestAborted);
        var catList = new List<(string Slug, string Name, string Desc, string Icon, int Order)>();

        foreach (var c in categories)
        {
            catList.Add((
                GetField(c, catMeta, "Slug"),
                GetField(c, catMeta, "Name"),
                GetField(c, catMeta, "Description"),
                GetField(c, catMeta, "Icon"),
                int.TryParse(GetField(c, catMeta, "DisplayOrder"), out var o) ? o : 100));
        }
        catList.Sort((a, b) => a.Order.CompareTo(b.Order));

        context.Response.StatusCode = 200;
        context.Response.ContentType = "text/html; charset=utf-8";

        var sb = new StringBuilder(4096);
        AppendHead(sb, "Products");
        AppendNavbar(sb, "Products", null);

        sb.AppendLine("""<div class="container py-4">""");
        sb.AppendLine("""<h2 class="mb-4">Browse Categories</h2>""");
        sb.AppendLine("""<div class="row row-cols-1 row-cols-md-3 row-cols-lg-4 g-4">""");

        foreach (var (slug, name, desc, icon, _) in catList)
        {
            sb.AppendLine("""<div class="col">""");
            sb.AppendLine($"""<a href="/products/{Enc(slug)}" class="text-decoration-none">""");
            sb.AppendLine("""<div class="card h-100 shadow-sm">""");
            sb.AppendLine("""<div class="card-body text-center">""");
            if (!string.IsNullOrEmpty(icon))
                sb.AppendLine($"""<i class="bi {Enc(icon)} fs-1 text-primary mb-3"></i>""");
            sb.AppendLine($"""<h5 class="card-title">{Enc(name)}</h5>""");
            if (!string.IsNullOrEmpty(desc))
                sb.AppendLine($"""<p class="card-text text-muted small">{Enc(desc)}</p>""");
            sb.AppendLine("</div></div></a></div>");
        }

        sb.AppendLine("</div></div>");
        AppendFooter(sb);

        await context.Response.WriteAsync(sb.ToString(), context.RequestAborted);
    }

    /// <summary>GET /products/{category} — render product grid for a category.</summary>
    public static async ValueTask ProductGridHandler(HttpContext context)
    {
        var categorySlug = BinaryApiHandlers.GetRouteValue(context, "category") ?? string.Empty;

        if (!DataScaffold.TryGetEntity("products", out var prodMeta) ||
            !DataScaffold.TryGetEntity("product-categories", out var catMeta))
        {
            context.Response.StatusCode = 500;
            await context.Response.WriteAsync("Product entities not configured.");
            return;
        }

        // Find category name
        string categoryName = categorySlug;
        uint categoryKey = 0;
        var cats = await catMeta.Handlers.QueryAsync(null, context.RequestAborted);
        foreach (var c in cats)
        {
            if (string.Equals(GetField(c, catMeta, "Slug"), categorySlug, StringComparison.OrdinalIgnoreCase))
            {
                categoryName = GetField(c, catMeta, "Name");
                categoryKey = c.Key;
                break;
            }
        }

        // Load products, filter by category
        var products = await prodMeta.Handlers.QueryAsync(null, context.RequestAborted);
        var filtered = new List<ProductView>();

        // Parse query filter
        var searchQuery = context.Request.Query.TryGetValue("q", out var q) ? q.ToString() : null;
        var tagFilter = context.Request.Query.TryGetValue("tag", out var t) ? t.ToString() : null;

        foreach (var p in products)
        {
            var available = GetField(p, prodMeta, "IsActive");
            if (string.Equals(available, "False", StringComparison.OrdinalIgnoreCase)) continue;

            var pCategory = GetField(p, prodMeta, "Category");
            if (!string.IsNullOrEmpty(categorySlug) &&
                !string.Equals(pCategory, categoryName, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(pCategory, categorySlug, StringComparison.OrdinalIgnoreCase))
                continue;

            var name = GetField(p, prodMeta, "Name");
            var desc = GetField(p, prodMeta, "Description");
            var tags = GetField(p, prodMeta, "Tags");

            // Search filter
            if (!string.IsNullOrEmpty(searchQuery) &&
                !name.Contains(searchQuery, StringComparison.OrdinalIgnoreCase) &&
                !desc.Contains(searchQuery, StringComparison.OrdinalIgnoreCase))
                continue;

            // Tag filter
            if (!string.IsNullOrEmpty(tagFilter) &&
                !tags.Contains(tagFilter, StringComparison.OrdinalIgnoreCase))
                continue;

            filtered.Add(new ProductView(
                Name: name,
                Description: desc,
                Price: GetField(p, prodMeta, "Price"),
                ImageUrl: GetField(p, prodMeta, "ImageUrl"),
                Sku: GetField(p, prodMeta, "Sku"),
                Tags: tags));
        }

        context.Response.StatusCode = 200;
        context.Response.ContentType = "text/html; charset=utf-8";

        var sb = new StringBuilder(8192);
        AppendHead(sb, categoryName);
        AppendNavbar(sb, categoryName, "/products");

        sb.AppendLine("""<div class="container py-4">""");

        // Filter bar
        sb.AppendLine("""<div class="card shadow-sm mb-4"><div class="card-body">""");
        sb.AppendLine($"""<form method="get" action="/products/{Enc(categorySlug)}" class="row g-2 align-items-end">""");
        sb.AppendLine("""<div class="col-md-6">""");
        sb.AppendLine("""<label class="form-label">Search</label>""");
        sb.AppendLine($"""<input type="text" name="q" class="form-control" placeholder="Search products..." value="{Enc(searchQuery ?? "")}"/>""");
        sb.AppendLine("</div>");
        sb.AppendLine("""<div class="col-md-4">""");
        sb.AppendLine("""<label class="form-label">Tag</label>""");
        sb.AppendLine($"""<input type="text" name="tag" class="form-control" placeholder="Filter by tag..." value="{Enc(tagFilter ?? "")}"/>""");
        sb.AppendLine("</div>");
        sb.AppendLine("""<div class="col-md-2"><button type="submit" class="btn btn-primary w-100">Filter</button></div>""");
        sb.AppendLine("</form></div></div>");

        // Product grid
        sb.AppendLine($"""<p class="text-muted">{filtered.Count} product(s)</p>""");
        sb.AppendLine("""<div class="row row-cols-1 row-cols-sm-2 row-cols-md-3 row-cols-lg-4 g-4">""");

        foreach (var p in filtered)
        {
            sb.AppendLine("""<div class="col">""");
            sb.AppendLine("""<div class="card h-100 shadow-sm">""");

            // Product image
            if (!string.IsNullOrEmpty(p.ImageUrl))
                sb.AppendLine($"""<img src="{Enc(p.ImageUrl)}" class="card-img-top" alt="{Enc(p.Name)}" style="height:200px;object-fit:cover;"/>""");
            else
                sb.AppendLine("""<div class="card-img-top bg-light d-flex align-items-center justify-content-center" style="height:200px;"><i class="bi bi-image fs-1 text-muted"></i></div>""");

            sb.AppendLine("""<div class="card-body d-flex flex-column">""");
            sb.AppendLine($"""<h6 class="card-title">{Enc(p.Name)}</h6>""");

            if (!string.IsNullOrEmpty(p.Description))
            {
                var shortDesc = p.Description.Length > 100 ? p.Description[..100] + "..." : p.Description;
                sb.AppendLine($"""<p class="card-text text-muted small flex-grow-1">{Enc(shortDesc)}</p>""");
            }

            // Price
            if (decimal.TryParse(p.Price, out var price))
                sb.AppendLine($"""<p class="fw-bold text-success mb-1">£{price:F2}</p>""");

            // SKU
            if (!string.IsNullOrEmpty(p.Sku))
                sb.AppendLine($"""<small class="text-muted">SKU: {Enc(p.Sku)}</small>""");

            // Tags
            if (!string.IsNullOrEmpty(p.Tags))
            {
                sb.Append("""<div class="mt-2">""");
                foreach (var tag in p.Tags.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    sb.Append($"""<span class="badge bg-secondary me-1">{Enc(tag)}</span>""");
                sb.AppendLine("</div>");
            }

            sb.AppendLine("</div></div></div>");
        }

        sb.AppendLine("</div></div>");
        AppendFooter(sb);

        await context.Response.WriteAsync(sb.ToString(), context.RequestAborted);
    }

    // ── Chrome ──────────────────────────────────────────────────────────────

    private static void AppendHead(StringBuilder sb, string title)
    {
        sb.AppendLine("<!DOCTYPE html><html lang=\"en\"><head>");
        sb.AppendLine("<meta charset=\"utf-8\"/><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>");
        sb.AppendLine($"<title>{Enc(title)} — BareMetalWeb</title>");
        sb.AppendLine("""<link rel="stylesheet" href="/static/css/bootstrap.min.css"/>""");
        sb.AppendLine("""<link rel="stylesheet" href="/static/css/bootstrap-icons.min.css"/>""");
        sb.AppendLine("</head><body class=\"bg-light\">");
    }

    private static void AppendNavbar(StringBuilder sb, string title, string? backUrl)
    {
        sb.AppendLine("""<nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-0">""");
        sb.AppendLine("""<div class="container-fluid">""");
        sb.AppendLine("""<a class="navbar-brand" href="/">BareMetalWeb</a>""");
        if (backUrl != null)
            sb.AppendLine($"""<a href="{backUrl}" class="btn btn-outline-light btn-sm me-2"><i class="bi bi-arrow-left"></i> Back</a>""");
        sb.AppendLine($"""<span class="navbar-text text-light">{Enc(title)}</span>""");
        sb.AppendLine("</div></nav>");
    }

    private static void AppendFooter(StringBuilder sb)
    {
        sb.AppendLine("""<script src="/static/js/bootstrap.bundle.min.js"></script>""");
        sb.AppendLine("</body></html>");
    }

    private static string Enc(string s) => System.Net.WebUtility.HtmlEncode(s);

    private static string GetField(BaseDataObject obj, DataEntityMetadata meta, string fieldName)
    {
        var field = meta.Fields.FirstOrDefault(f =>
            string.Equals(f.Name, fieldName, StringComparison.OrdinalIgnoreCase));
        return field?.GetValueFn?.Invoke(obj)?.ToString() ?? string.Empty;
    }

    private sealed record ProductView(
        string Name, string Description, string Price,
        string ImageUrl, string Sku, string Tags);
}
