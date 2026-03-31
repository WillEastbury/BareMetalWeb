using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// RFC 7807-inspired API error envelope.
/// Used by <see cref="ApiErrorWriter"/> to produce consistent JSON error responses.
/// </summary>
internal readonly struct ApiError
{
    /// <summary>
    /// URI reference identifying the error type.
    /// Example: <c>https://baremetalweb.dev/errors/validation</c>.
    /// </summary>
    public string? Type { get; init; }

    /// <summary>Short, human-readable summary of the error.</summary>
    public string Title { get; init; }

    /// <summary>HTTP status code (mirrored in body for easy parsing).</summary>
    public int Status { get; init; }

    /// <summary>Detailed human-readable explanation specific to this occurrence.</summary>
    public string? Detail { get; init; }

    /// <summary>Correlation ID for server-side log lookup (typically set on 5xx).</summary>
    public string? ErrorId { get; init; }

    /// <summary>
    /// URI reference identifying the specific resource that triggered the error (RFC 7807 "instance").
    /// Typically the request path, e.g. <c>/api/_meta</c> or <c>/setup</c>.
    /// </summary>
    public string? Instance { get; init; }

    /// <summary>Optional field-level validation errors.</summary>
    public FieldError[]? Errors { get; init; }
}

/// <summary>Single field-level validation error.</summary>
internal readonly struct FieldError
{
    public string Field { get; init; }
    public string Message { get; init; }
}

/// <summary>
/// Well-known error type URIs for <see cref="ApiError.Type"/>.
/// </summary>
internal static class ApiErrorTypes
{
    private const string Base = "https://baremetalweb.dev/errors/";
    public const string Validation      = Base + "validation";
    public const string NotFound        = Base + "not-found";
    public const string Forbidden       = Base + "forbidden";
    public const string Unauthorized    = Base + "unauthorized";
    public const string RateLimited     = Base + "rate-limited";
    public const string Conflict        = Base + "conflict";
    public const string UnsupportedMedia = Base + "unsupported-media-type";
    public const string InternalError   = Base + "internal";
    public const string ServiceUnavailable = Base + "service-unavailable";
}

/// <summary>
/// Centralized writer for <see cref="ApiError"/> responses.
/// <list type="bullet">
///   <item>Writes <c>application/problem+json</c> (RFC 7807) for API/AJAX requests.</item>
///   <item>Sets <c>X-Error-Id</c> header when <see cref="ApiError.ErrorId"/> is present.</item>
///   <item>Uses <see cref="Utf8JsonWriter"/> directly — no allocations beyond the response buffer.</item>
/// </list>
/// </summary>
internal static class ApiErrorWriter
{
    private static readonly JsonWriterOptions WriterOptions = new() { Indented = false };

    /// <summary>
    /// Write an <see cref="ApiError"/> directly to a <see cref="BmwContext"/>.
    /// Uses PipeWriter (IBufferWriter) — zero intermediate allocation.
    /// </summary>
    internal static async ValueTask WriteAsync(BareMetalWeb.Core.BmwContext context, ApiError error, CancellationToken ct = default)
    {
        context.StatusCode = error.Status;
        context.ContentType = "application/problem+json";

        if (error.ErrorId is not null)
        {
            context.ResponseHeaders["X-Error-Id"] = error.ErrorId;
        }

        // Utf8JsonWriter accepts IBufferWriter<byte> — PipeWriter implements it
        await using var writer = new Utf8JsonWriter(context.ResponseBody, WriterOptions);
        WriteErrorBody(writer, error);
        await writer.FlushAsync(ct);
        // Flush the PipeWriter to push buffered bytes to the underlying transport/stream
        await context.ResponseBody.FlushAsync(ct);
    }

    /// <summary>
    /// Write an <see cref="ApiError"/> as a JSON response (HttpResponse bridge).
    /// Sets status code, content type, and <c>X-Error-Id</c> header.
    /// </summary>
    internal static async ValueTask WriteAsync(HttpResponse response, ApiError error, CancellationToken ct = default)
    {
        response.StatusCode = error.Status;
        response.ContentType = "application/problem+json";

        if (error.ErrorId is not null)
        {
            response.Headers["X-Error-Id"] = error.ErrorId;
        }

        await using var writer = new Utf8JsonWriter(response.Body, WriterOptions);
        WriteErrorBody(writer, error);
        await writer.FlushAsync(ct);
    }

    private static void WriteErrorBody(Utf8JsonWriter writer, ApiError error)
    {
        writer.WriteStartObject();

        if (error.Type is not null)
        {
            writer.WriteString("type"u8, error.Type);
        }

        writer.WriteString("title"u8, error.Title);
        writer.WriteNumber("status"u8, error.Status);

        if (error.Detail is not null)
        {
            writer.WriteString("detail"u8, error.Detail);
        }

        if (error.ErrorId is not null)
        {
            writer.WriteString("errorId"u8, error.ErrorId);
        }

        if (error.Instance is not null)
        {
            writer.WriteString("instance"u8, error.Instance);
        }

        if (error.Errors is { Length: > 0 } fieldErrors)
        {
            writer.WriteStartArray("errors"u8);
            for (int i = 0; i < fieldErrors.Length; i++)
            {
                writer.WriteStartObject();
                writer.WriteString("field"u8, fieldErrors[i].Field);
                writer.WriteString("message"u8, fieldErrors[i].Message);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
        }

        writer.WriteEndObject();
    }

    // ── Convenience factories for common errors ─────────────────────────

    internal static ApiError BadRequest(string detail, FieldError[]? errors = null) => new()
    {
        Type = ApiErrorTypes.Validation,
        Title = "Bad Request",
        Status = StatusCodes.Status400BadRequest,
        Detail = detail,
        Errors = errors,
    };

    internal static ApiError Unauthorized(string? detail = null, string? instance = null) => new()
    {
        Type = ApiErrorTypes.Unauthorized,
        Title = "Unauthorized",
        Status = StatusCodes.Status401Unauthorized,
        Detail = detail ?? "Authentication is required.",
        Instance = instance,
    };

    internal static ApiError Forbidden(string? detail = null, string? instance = null) => new()
    {
        Type = ApiErrorTypes.Forbidden,
        Title = "Forbidden",
        Status = StatusCodes.Status403Forbidden,
        Detail = detail ?? "Access denied.",
        Instance = instance,
    };

    internal static ApiError NotFound(string? detail = null) => new()
    {
        Type = ApiErrorTypes.NotFound,
        Title = "Not Found",
        Status = StatusCodes.Status404NotFound,
        Detail = detail,
    };

    internal static ApiError RateLimited(string? detail = null, int? retryAfterSeconds = null) => new()
    {
        Type = ApiErrorTypes.RateLimited,
        Title = "Too Many Requests",
        Status = StatusCodes.Status429TooManyRequests,
        Detail = detail ?? (retryAfterSeconds.HasValue
            ? $"Rate limit exceeded. Retry after {retryAfterSeconds.Value}s."
            : "Rate limit exceeded."),
    };

    internal static ApiError UnsupportedMediaType(string? detail = null) => new()
    {
        Type = ApiErrorTypes.UnsupportedMedia,
        Title = "Unsupported Media Type",
        Status = StatusCodes.Status415UnsupportedMediaType,
        Detail = detail ?? "Content-Type must be application/json.",
    };

    internal static ApiError Conflict(string? detail = null, string? instance = null) => new()
    {
        Type = ApiErrorTypes.Conflict,
        Title = "Conflict",
        Status = StatusCodes.Status409Conflict,
        Detail = detail,
        Instance = instance,
    };

    internal static ApiError InternalError(string errorId, string? detail = null) => new()
    {
        Type = ApiErrorTypes.InternalError,
        Title = "Internal Server Error",
        Status = StatusCodes.Status500InternalServerError,
        Detail = detail ?? "An unexpected error occurred.",
        ErrorId = errorId,
    };

    internal static ApiError ServiceUnavailable(string? detail = null) => new()
    {
        Type = ApiErrorTypes.ServiceUnavailable,
        Title = "Service Unavailable",
        Status = StatusCodes.Status503ServiceUnavailable,
        Detail = detail,
    };
}
