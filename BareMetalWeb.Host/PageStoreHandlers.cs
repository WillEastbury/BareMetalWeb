using System.Text;
using Microsoft.AspNetCore.Http;
using BareMetalWeb.Data.PageStore;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Core;

namespace BareMetalWeb.Host;

/// <summary>
/// HTTP handlers for the page store API endpoints.
/// </summary>
public sealed class PageStoreHandlers
{
    private readonly PagedFileStore _pageStore;
    private readonly IBufferedLogger? _logger;

    public PageStoreHandlers(PagedFileStore pageStore, IBufferedLogger? logger = null)
    {
        _pageStore = pageStore ?? throw new ArgumentNullException(nameof(pageStore));
        _logger = logger;
    }

    /// <summary>
    /// GET /pages/{id} - Read a page and return its content with ETag.
    /// </summary>
    public async ValueTask GetPageAsync(HttpContext context)
    {
        if (!TryGetPageIdFromRoute(context, out var pageId))
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Invalid page ID");
            return;
        }

        var (data, metadata) = await _pageStore.ReadPageAsync(pageId, context.RequestAborted);

        if (!metadata.Exists || data == null)
        {
            context.Response.StatusCode = 404;
            await context.Response.WriteAsync("Page not found");
            return;
        }

        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/octet-stream";
        context.Response.Headers["ETag"] = $"\"{metadata.Version}\"";
        context.Response.ContentLength = data.Length;
        await context.Response.Body.WriteAsync(data, context.RequestAborted);
    }

    /// <summary>
    /// HEAD /pages/{id} - Get page metadata only (ETag).
    /// </summary>
    public async ValueTask HeadPageAsync(HttpContext context)
    {
        if (!TryGetPageIdFromRoute(context, out var pageId))
        {
            context.Response.StatusCode = 400;
            return;
        }

        var metadata = await _pageStore.HeadPageAsync(pageId, context.RequestAborted);

        if (!metadata.Exists)
        {
            context.Response.StatusCode = 404;
            return;
        }

        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/octet-stream";
        context.Response.Headers["ETag"] = $"\"{metadata.Version}\"";
        context.Response.ContentLength = metadata.Size;
    }

    /// <summary>
    /// POST /pages - Create a new page.
    /// </summary>
    public async ValueTask PostPageAsync(HttpContext context)
    {
        if (context.Request.ContentLength == null || context.Request.ContentLength == 0)
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Request body cannot be empty");
            return;
        }

        var data = new byte[context.Request.ContentLength.Value];
        var totalBytesRead = 0;
        while (totalBytesRead < data.Length)
        {
            var read = await context.Request.Body.ReadAsync(data.AsMemory(totalBytesRead), context.RequestAborted);
            if (read == 0) break;
            totalBytesRead += read;
        }

        var result = await _pageStore.AddPageAsync(data, context.RequestAborted);

        if (!result.Success)
        {
            if (result.ErrorMessage?.Contains("backpressure") == true)
            {
                context.Response.StatusCode = 503; // Service Unavailable
            }
            else
            {
                context.Response.StatusCode = 400;
            }
            await context.Response.WriteAsync(result.ErrorMessage ?? "Failed to create page");
            return;
        }

        context.Response.StatusCode = 201; // Created
        context.Response.ContentType = "application/json";
        context.Response.Headers["ETag"] = $"\"{result.Version}\"";
        context.Response.Headers["Location"] = $"/pages/{result.PageId}";
        
        var response = System.Text.Json.JsonSerializer.Serialize(new
        {
            pageId = result.PageId,
            version = result.Version
        });
        await context.Response.WriteAsync(response);
    }

    /// <summary>
    /// PUT /pages/{id} - Update an existing page with optional If-Match header for optimistic concurrency.
    /// </summary>
    public async ValueTask PutPageAsync(HttpContext context)
    {
        if (!TryGetPageIdFromRoute(context, out var pageId))
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Invalid page ID");
            return;
        }

        if (context.Request.ContentLength == null || context.Request.ContentLength == 0)
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Request body cannot be empty");
            return;
        }

        var data = new byte[context.Request.ContentLength.Value];
        var bytesRead = 0;
        while (bytesRead < data.Length)
        {
            var read = await context.Request.Body.ReadAsync(data.AsMemory(bytesRead), context.RequestAborted);
            if (read == 0) break;
            bytesRead += read;
        }

        // Check for If-Match header (optimistic concurrency)
        long? expectedVersion = null;
        if (context.Request.Headers.TryGetValue("If-Match", out var ifMatchValue))
        {
            var etag = ifMatchValue.ToString().Trim('"');
            if (long.TryParse(etag, out var version))
            {
                expectedVersion = version;
            }
        }

        var result = await _pageStore.WritePageAsync(pageId, data, expectedVersion, context.RequestAborted);

        if (!result.Success)
        {
            if (result.ErrorMessage?.Contains("Version mismatch") == true)
            {
                context.Response.StatusCode = 412; // Precondition Failed
            }
            else if (result.ErrorMessage?.Contains("backpressure") == true)
            {
                context.Response.StatusCode = 503; // Service Unavailable
            }
            else if (result.ErrorMessage?.Contains("does not exist") == true)
            {
                context.Response.StatusCode = 404;
            }
            else
            {
                context.Response.StatusCode = 400;
            }
            await context.Response.WriteAsync(result.ErrorMessage ?? "Failed to update page");
            return;
        }

        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/json";
        context.Response.Headers["ETag"] = $"\"{result.NewVersion}\"";
        
        var response = System.Text.Json.JsonSerializer.Serialize(new
        {
            pageId = pageId,
            version = result.NewVersion
        });
        await context.Response.WriteAsync(response);
    }

    private static bool TryGetPageIdFromRoute(HttpContext context, out long pageId)
    {
        pageId = 0;
        
        var pageContext = context.GetPageContext();
        if (pageContext == null)
            return false;

        for (int i = 0; i < pageContext.PageMetaDataKeys.Length; i++)
        {
            if (string.Equals(pageContext.PageMetaDataKeys[i], "id", StringComparison.OrdinalIgnoreCase))
            {
                var idString = pageContext.PageMetaDataValues[i];
                return long.TryParse(idString, out pageId) && pageId > 0;
            }
        }

        return false;
    }
}
