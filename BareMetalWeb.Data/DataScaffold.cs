using System;
using System.Collections;
using System.Globalization;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Core;

public sealed record DataFieldMetadata(
    PropertyInfo Property,
    string Name,
    string Label,
    FormFieldType FieldType,
    int Order,
    bool Required,
    bool List,
    bool View,
    bool Edit,
    bool Create,
    bool ReadOnly,
    string? Placeholder,
    DataLookupConfig? Lookup
);

public sealed record DataEntityMetadata(
    Type Type,
    string Name,
    string Slug,
    string Permissions,
    bool ShowOnNav,
    string? NavGroup,
    int NavOrder,
    IReadOnlyList<DataFieldMetadata> Fields,
    DataEntityHandlers Handlers
);

public sealed record DataEntityHandlers(
    Func<BaseDataObject> Create,
    Func<string, CancellationToken, ValueTask<BaseDataObject?>> LoadAsync,
    Func<BaseDataObject, CancellationToken, ValueTask> SaveAsync,
    Func<string, CancellationToken, ValueTask> DeleteAsync,
    Func<QueryDefinition?, CancellationToken, ValueTask<IEnumerable<BaseDataObject>>> QueryAsync,
    Func<QueryDefinition?, CancellationToken, ValueTask<int>> CountAsync
);

public static class DataScaffold
{
    private static readonly object Sync = new();
    private static readonly Dictionary<string, DataEntityMetadata> EntitiesBySlug = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<Type, DataEntityMetadata> EntitiesByType = new();
    private static readonly NullabilityInfoContext NullabilityContext = new();
    private static readonly object LookupCacheSync = new();
    private static readonly Dictionary<string, LookupCacheEntry> LookupCache = new(StringComparer.OrdinalIgnoreCase);

    private sealed record LookupCacheEntry(IReadOnlyList<KeyValuePair<string, string>> Options, DateTime ExpiresUtc);

    internal static class DataEntityMetadataCache<T> where T : BaseDataObject, new()
    {
        public static readonly DataEntityMetadata? Metadata = Build();

        private static DataEntityMetadata? Build()
        {
            return BuildEntityMetadata<T>();
        }
    }

    public static IReadOnlyList<DataEntityMetadata> Entities
    {
        get
        {
            lock (Sync)
            {
                return EntitiesBySlug.Values.OrderBy(e => e.NavOrder).ThenBy(e => e.Name).ToList();
            }
        }
    }

    public static bool RegisterEntity<T>() where T : BaseDataObject, new()
    {
        var type = typeof(T);
        var metadata = DataEntityMetadataCache<T>.Metadata;
        if (metadata == null)
            return false;

        lock (Sync)
        {
            EntitiesBySlug[metadata.Slug] = metadata;
            EntitiesByType[type] = metadata;
        }

        return true;
    }

    public static async ValueTask<object?> LoadAsync(DataEntityMetadata metadata, string id, CancellationToken cancellationToken = default)
    {
        return await metadata.Handlers.LoadAsync(id, cancellationToken);
    }

    public static async ValueTask SaveAsync(DataEntityMetadata metadata, object instance, CancellationToken cancellationToken = default)
    {
        await metadata.Handlers.SaveAsync((BaseDataObject)instance, cancellationToken);
    }

    public static async ValueTask DeleteAsync(DataEntityMetadata metadata, string id, CancellationToken cancellationToken = default)
    {
        await metadata.Handlers.DeleteAsync(id, cancellationToken);
    }

    public static async ValueTask<IEnumerable> QueryAsync(DataEntityMetadata metadata, QueryDefinition? query = null, CancellationToken cancellationToken = default)
    {
        var payload = await metadata.Handlers.QueryAsync(query, cancellationToken);
        return payload;
    }

    public static async ValueTask<int> CountAsync(DataEntityMetadata metadata, QueryDefinition? query = null, CancellationToken cancellationToken = default)
    {
        return await metadata.Handlers.CountAsync(query, cancellationToken);
    }

    public static bool TryGetEntity(string slug, out DataEntityMetadata metadata)
    {
        lock (Sync)
        {
            return EntitiesBySlug.TryGetValue(slug, out metadata!);
        }
    }

    public static DataEntityMetadata? GetEntityByType(Type type)
    {
        lock (Sync)
        {
            return EntitiesByType.TryGetValue(type, out var metadata) ? metadata : null;
        }
    }

    public static QueryDefinition BuildQueryDefinition(IDictionary<string, string?> query, DataEntityMetadata metadata)
    {
        var definition = new QueryDefinition();

        if (query.TryGetValue("q", out var queryText) && !string.IsNullOrWhiteSpace(queryText))
        {
            var group = new QueryGroup { Logic = QueryGroupLogic.Or };
            foreach (var field in metadata.Fields.Where(f => f.List))
            {
                group.Clauses.Add(new QueryClause
                {
                    Field = field.Name,
                    Operator = QueryOperator.Contains,
                    Value = queryText
                });
            }
            definition.Groups.Add(group);
        }

        if (query.TryGetValue("field", out var fieldName) && query.TryGetValue("value", out var value) && !string.IsNullOrWhiteSpace(fieldName))
        {
            var op = QueryOperator.Equals;
            if (query.TryGetValue("op", out var opValue) && !string.IsNullOrWhiteSpace(opValue))
            {
                op = opValue.Trim().ToLowerInvariant() switch
                {
                    "contains" => QueryOperator.Contains,
                    "startswith" => QueryOperator.StartsWith,
                    "endswith" => QueryOperator.EndsWith,
                    "in" => QueryOperator.In,
                    "notin" => QueryOperator.NotIn,
                    "nin" => QueryOperator.NotIn,
                    "gt" => QueryOperator.GreaterThan,
                    "lt" => QueryOperator.LessThan,
                    "gte" => QueryOperator.GreaterThanOrEqual,
                    "lte" => QueryOperator.LessThanOrEqual,
                    "ne" => QueryOperator.NotEquals,
                    "neq" => QueryOperator.NotEquals,
                    "notequals" => QueryOperator.NotEquals,
                    "eq" => QueryOperator.Equals,
                    _ => QueryOperator.Equals
                };
            }

            definition.Clauses.Add(new QueryClause
            {
                Field = fieldName,
                Operator = op,
                Value = value
            });
        }

        if (query.TryGetValue("sort", out var sortField) && !string.IsNullOrWhiteSpace(sortField))
        {
            var direction = SortDirection.Asc;
            if (query.TryGetValue("dir", out var dir) && string.Equals(dir, "desc", StringComparison.OrdinalIgnoreCase))
                direction = SortDirection.Desc;

            definition.Sorts.Add(new SortClause
            {
                Field = sortField,
                Direction = direction
            });
        }

        if (query.TryGetValue("skip", out var skipStr) && int.TryParse(skipStr, out var skipVal))
            definition.Skip = skipVal;

        if (query.TryGetValue("top", out var topStr) && int.TryParse(topStr, out var topVal))
            definition.Top = topVal;

        return definition;
    }

    public static IReadOnlyList<FormField> BuildFormFields(DataEntityMetadata metadata, object? instance, bool forCreate)
    {
        var fields = new List<FormField>();
        foreach (var field in metadata.Fields.OrderBy(f => f.Order))
        {
            if (forCreate && !field.Create)
                continue;
            if (!forCreate && !field.Edit)
                continue;

            var value = instance != null ? field.Property.GetValue(instance) : null;
            if (IsChildListType(field.Property.PropertyType, out var childType))
            {
                var html = BuildChildListEditorHtml(field, childType, value as IEnumerable);
                fields.Add(new FormField(
                    FormFieldType.CustomHtml,
                    field.Name,
                    field.Label,
                    field.Required,
                    Html: html));
                continue;
            }

            if (IsDictionaryType(field.Property.PropertyType, out var valueType))
            {
                var html = BuildDictionaryEditorHtml(field, valueType, value as IEnumerable);
                fields.Add(new FormField(
                    FormFieldType.CustomHtml,
                    field.Name,
                    field.Label,
                    field.Required,
                    Html: html));
                continue;
            }
            var effectiveType = Nullable.GetUnderlyingType(field.Property.PropertyType) ?? field.Property.PropertyType;
            var effectiveFieldType = effectiveType == typeof(DateOnly) && field.FieldType == FormFieldType.DateTime
                ? FormFieldType.DateOnly
                : field.FieldType;
            var lookupOptions = field.Lookup != null
                ? GetLookupOptions(field.Lookup)
                : null;
            if (lookupOptions != null)
                effectiveFieldType = FormFieldType.LookupList;
            var stringValue = ToInputString(value, field.Property.PropertyType, effectiveFieldType);
            if (metadata.Type == typeof(SystemPrincipal)
                && string.Equals(field.Name, nameof(SystemPrincipal.ApiKeyHashes), StringComparison.OrdinalIgnoreCase))
            {
                if (forCreate)
                {
                    stringValue = SystemPrincipal.GenerateRawApiKey();
                }
                else
                {
                    stringValue = string.Empty;
                }
            }
            if (forCreate && IsDefaultValue(value, field.Property.PropertyType))
            {
                var defaultValue = GetCreateDefaultInputString(field.Property.PropertyType, effectiveFieldType);
                if (defaultValue != null)
                    stringValue = defaultValue;
            }
            var selectedValue = effectiveFieldType == FormFieldType.YesNo
                ? (IsTruthy(value) ? "true" : "false")
                : effectiveFieldType == FormFieldType.Enum ? value?.ToString() : null;

            lookupOptions ??= effectiveFieldType == FormFieldType.Enum
                ? BuildEnumOptions(field.Property.PropertyType)
                : null;

            fields.Add(new FormField(
                effectiveFieldType,
                field.Name,
                field.Label,
                field.Required,
                field.Placeholder,
                Value: stringValue,
                SelectedValue: selectedValue,
                LookupOptions: lookupOptions
            ));
        }

        return fields;
    }

    public static IReadOnlyList<(string Label, string Value)> BuildViewRows(DataEntityMetadata metadata, object instance)
    {
        var rows = new List<(string Label, string Value)>();
        foreach (var field in metadata.Fields.Where(f => f.View).OrderBy(f => f.Order))
        {
            var value = field.Property.GetValue(instance);
            if (field.Lookup != null)
            {
                var lookupOptions = GetLookupOptions(field.Lookup);
                var lookupMap = lookupOptions.ToDictionary(k => k.Key, v => v.Value, StringComparer.OrdinalIgnoreCase);
                var key = value?.ToString() ?? string.Empty;
                var display = lookupMap.TryGetValue(key, out var resolved) ? resolved : key;
                rows.Add((field.Label, FormatLookupDisplay(key, display)));
                continue;
            }

            rows.Add((field.Label, ToDisplayString(value, field.Property.PropertyType)));
        }

        return rows;
    }

    public static IReadOnlyList<(string Label, string Value, bool IsHtml)> BuildViewRowsHtml(DataEntityMetadata metadata, object instance, Func<DataEntityMetadata, bool>? canRenderLookupLink = null)
    {
        var rows = new List<(string Label, string Value, bool IsHtml)>();
        foreach (var field in metadata.Fields.Where(f => f.View).OrderBy(f => f.Order))
        {
            var value = field.Property.GetValue(instance);
            if (field.Lookup != null)
            {
                var lookupOptions = GetLookupOptions(field.Lookup);
                var lookupMap = lookupOptions.ToDictionary(k => k.Key, v => v.Value, StringComparer.OrdinalIgnoreCase);
                var key = value?.ToString() ?? string.Empty;
                var display = lookupMap.TryGetValue(key, out var resolved) ? resolved : key;
                var relatedUrl = TryBuildLookupUrl(field.Lookup, key, canRenderLookupLink);
                rows.Add((field.Label, BuildLookupHtml(key, display, relatedUrl), true));
                continue;
            }

            if (IsChildListType(field.Property.PropertyType, out var childType))
            {
                var html = BuildChildListViewHtml(field, childType, value as IEnumerable);
                rows.Add((field.Label, html, true));
                continue;
            }

            if (IsDictionaryType(field.Property.PropertyType, out var valueType))
            {
                var html = BuildDictionaryViewHtml(field, valueType, value as IEnumerable);
                rows.Add((field.Label, html, true));
                continue;
            }

            rows.Add((field.Label, ToDisplayString(value, field.Property.PropertyType), false));
        }

        return rows;
    }

    public static IReadOnlyList<string> BuildListHeaders(DataEntityMetadata metadata, bool includeActions)
    {
        var headers = metadata.Fields
            .Where(f => f.List)
            .OrderBy(f => f.Order)
            .Select(f => f.Label)
            .ToList();

        if (includeActions)
            headers.Insert(0, "Actions");

        return headers;
    }

    public static TableRowActions? BuildRowActionsMetadata(BaseDataObject? dataObject, string rowBasePath, string? cloneToken = null, string? cloneReturnUrl = null)
    {
        if (dataObject == null)
            return null;

        var id = GetIdValue(dataObject);
        var safeId = Uri.EscapeDataString(id ?? string.Empty);
        var actionBasePath = $"{rowBasePath}/{safeId}";
        var actions = new List<TableRowAction>
        {
            new TableRowAction(actionBasePath, "Open", "bi-search", "btn-outline-info"),
            new TableRowAction($"{actionBasePath}/edit", "Edit", "bi-pencil", "btn-outline-warning"),
        };

        if (!string.IsNullOrWhiteSpace(cloneToken))
        {
            actions.Add(new TableRowAction($"{actionBasePath}/clone", "Clone row", "bi-files", "btn-outline-primary", RequiresCsrf: true, CsrfReturnUrl: cloneReturnUrl));
            actions.Add(new TableRowAction($"{actionBasePath}/clone-edit", "Clone and edit", "bi-pencil-square", "btn-outline-warning", RequiresCsrf: true, CsrfReturnUrl: cloneReturnUrl));
        }

        actions.Add(new TableRowAction($"{actionBasePath}/delete", "Delete", "bi-x-lg", "btn-outline-danger"));

        return new TableRowActions(actions);
    }

    public static IReadOnlyList<string[]> BuildListRows(DataEntityMetadata metadata, IEnumerable items, string basePath, bool includeActions, Func<DataEntityMetadata, bool>? canRenderLookupLink = null, string? cloneToken = null, string? cloneReturnUrl = null)
    {
        var rows = new List<string[]>();
        foreach (var item in items)
        {
            if (item == null)
                continue;

            var values = new List<string>();
            foreach (var field in metadata.Fields.Where(f => f.List).OrderBy(f => f.Order))
            {
                var rawValue = field.Property.GetValue(item);
                if (field.Lookup != null)
                {
                    var lookupOptions = GetLookupOptions(field.Lookup);
                    var lookupMap = lookupOptions.ToDictionary(k => k.Key, v => v.Value, StringComparer.OrdinalIgnoreCase);
                    var key = rawValue?.ToString() ?? string.Empty;
                    var display = lookupMap.TryGetValue(key, out var resolved) ? resolved : key;
                    var relatedUrl = TryBuildLookupUrl(field.Lookup, key, canRenderLookupLink);
                    var safeKey = WebUtility.HtmlEncode(key);
                    var safeDisplay = WebUtility.HtmlEncode(FormatLookupDisplay(key, display));
                    var linkHtml = BuildLookupLinkHtml(relatedUrl);
                    values.Add($"<span title=\"{safeKey}\">{safeDisplay}</span>{linkHtml}");
                    continue;
                }

                values.Add(WebUtility.HtmlEncode(ToDisplayString(rawValue, field.Property.PropertyType)));
            }

            if (includeActions && item is BaseDataObject dataObject)
            {
                var id = GetIdValue(dataObject);
                var safeId = Uri.EscapeDataString(id ?? string.Empty);
                var viewUrl = $"{basePath}/{safeId}";
                var editUrl = $"{basePath}/{safeId}/edit";
                var deleteUrl = $"{basePath}/{safeId}/delete";
                var cloneHtml = string.Empty;
                if (!string.IsNullOrWhiteSpace(cloneToken))
                {
                    cloneHtml = "<form class=\"d-inline\" method=\"post\" action=\"" + WebUtility.HtmlEncode($"{basePath}/{safeId}/clone") + "\"><input type=\"hidden\" name=\"csrf_token\" value=\"" + WebUtility.HtmlEncode(cloneToken) + "\" /><input type=\"hidden\" name=\"returnUrl\" value=\"" + WebUtility.HtmlEncode(cloneReturnUrl ?? string.Empty) + "\" /><button type=\"submit\" class=\"btn btn-sm btn-outline-primary me-1\" title=\"Clone row\" aria-label=\"Clone row\"><i class=\"bi bi-files\" aria-hidden=\"true\"></i></button></form>"
                        + "<form class=\"d-inline\" method=\"post\" action=\"" + WebUtility.HtmlEncode($"{basePath}/{safeId}/clone-edit") + "\"><input type=\"hidden\" name=\"csrf_token\" value=\"" + WebUtility.HtmlEncode(cloneToken) + "\" /><input type=\"hidden\" name=\"returnUrl\" value=\"" + WebUtility.HtmlEncode(cloneReturnUrl ?? string.Empty) + "\" /><button type=\"submit\" class=\"btn btn-sm btn-outline-warning me-1\" title=\"Clone and edit\" aria-label=\"Clone and edit\"><i class=\"bi bi-pencil-square\" aria-hidden=\"true\"></i></button></form>";
                }

                values.Insert(0, $"<a class=\"btn btn-sm btn-outline-info me-1\" href=\"{viewUrl}\" title=\"Open\" aria-label=\"Open\"><i class=\"bi bi-search\" aria-hidden=\"true\"></i></a><a class=\"btn btn-sm btn-outline-warning me-1\" href=\"{editUrl}\" title=\"Edit\" aria-label=\"Edit\"><i class=\"bi bi-pencil\" aria-hidden=\"true\"></i></a>{cloneHtml}<a class=\"btn btn-sm btn-outline-danger\" href=\"{deleteUrl}\" title=\"Delete\" aria-label=\"Delete\"><i class=\"bi bi-x-lg\" aria-hidden=\"true\"></i></a>");
            }

            rows.Add(values.ToArray());
        }

        return rows;
    }

    private static string FormatLookupDisplay(string key, string display)
    {
        if (string.IsNullOrWhiteSpace(key))
            return display;

        if (string.IsNullOrWhiteSpace(display) || string.Equals(key, display, StringComparison.OrdinalIgnoreCase))
            return key;

        return $"{display} ({key})";
    }

    private static string BuildLookupHtml(string key, string display, string? relatedUrl)
    {
        var safeKey = WebUtility.HtmlEncode(key);
        var safeDisplay = WebUtility.HtmlEncode(FormatLookupDisplay(key, display));
        var linkHtml = BuildLookupLinkHtml(relatedUrl);
        return $"<span title=\"{safeKey}\">{safeDisplay}</span>{linkHtml}";
    }

    private static string BuildLookupLinkHtml(string? relatedUrl)
    {
        if (string.IsNullOrWhiteSpace(relatedUrl))
            return string.Empty;

        return $"<a class=\"btn btn-sm btn-outline-info ms-1\" href=\"{relatedUrl}\" title=\"Open related\" aria-label=\"Open related\"><i class=\"bi bi-search\" aria-hidden=\"true\"></i></a>";
    }

    private static string? TryBuildLookupUrl(DataLookupConfig lookup, string key, Func<DataEntityMetadata, bool>? canRenderLookupLink)
    {
        if (string.IsNullOrWhiteSpace(key))
            return null;

        var targetMeta = GetEntityByType(lookup.TargetType);
        if (targetMeta == null)
            return null;

        if (!targetMeta.ShowOnNav)
            return null;

        if (canRenderLookupLink != null && !canRenderLookupLink(targetMeta))
            return null;

        var safeId = Uri.EscapeDataString(key);
        return $"/admin/data/{targetMeta.Slug}/{safeId}";
    }



    public static List<string> ApplyValuesFromForm(DataEntityMetadata metadata, object instance, IDictionary<string, string?> values, bool forCreate)
    {
        var errors = new List<string>();
        foreach (var field in metadata.Fields.OrderBy(f => f.Order))
        {
            if (field.ReadOnly)
                continue;
            if (forCreate && !field.Create)
                continue;
            if (!forCreate && !field.Edit)
                continue;

            if (IsChildListType(field.Property.PropertyType, out var childType))
            {
                if (!TryGetFormValue(values, field.Name, out var rawList) || rawList == null)
                {
                    if (field.Required)
                        errors.Add($"{field.Label} is required.");
                    continue;
                }

                if (!TryParseChildList(rawList, childType, out var listValue) || listValue == null)
                {
                    errors.Add($"{field.Label} is invalid.");
                    continue;
                }

                field.Property.SetValue(instance, listValue);
                continue;
            }

            if (IsDictionaryType(field.Property.PropertyType, out var dictValueType))
            {
                if (!TryGetFormValue(values, field.Name, out var rawDict) || rawDict == null)
                {
                    if (field.Required)
                        errors.Add($"{field.Label} is required.");
                    continue;
                }

                if (!TryParseDictionary(rawDict, dictValueType, out var dictValue) || dictValue == null)
                {
                    errors.Add($"{field.Label} is invalid.");
                    continue;
                }

                field.Property.SetValue(instance, dictValue);
                continue;
            }

            if (!TryGetFormValue(values, field.Name, out var rawValue) || rawValue == null)
            {
                if (IsBooleanField(field, field.Property.PropertyType))
                {
                    field.Property.SetValue(instance, false);
                    if (field.Required)
                        errors.Add($"{field.Label} is required.");
                    continue;
                }

                if (field.Required)
                    errors.Add($"{field.Label} is required.");
                continue;
            }

            if (field.Required && string.IsNullOrWhiteSpace(rawValue))
            {
                errors.Add($"{field.Label} is required.");
                continue;
            }

            if (!TryConvertValue(rawValue, field.Property.PropertyType, out var converted))
            {
                if (!TryFallbackConvert(rawValue, field.Property.PropertyType, out converted))
                {
                    errors.Add($"{field.Label} is invalid.");
                    continue;
                }
            }

            field.Property.SetValue(instance, converted);
        }

        return errors;
    }

    public static List<string> ApplyValuesFromJson(DataEntityMetadata metadata, object instance, IDictionary<string, JsonElement> values, bool forCreate, bool allowMissing)
    {
        var errors = new List<string>();
        foreach (var field in metadata.Fields.OrderBy(f => f.Order))
        {
            if (field.ReadOnly)
                continue;
            if (forCreate && !field.Create)
                continue;
            if (!forCreate && !field.Edit)
                continue;

            if (!values.TryGetValue(field.Name, out var rawElement))
            {
                if (!allowMissing && field.Required)
                    errors.Add($"{field.Label} is required.");
                continue;
            }

            if (!TryConvertJson(rawElement, field.Property.PropertyType, out var converted))
            {
                errors.Add($"{field.Label} is invalid.");
                continue;
            }

            field.Property.SetValue(instance, converted);
        }

        return errors;
    }

    public static string ToDisplayString(object? value, Type type)
    {
        if (value == null)
            return string.Empty;

        if (value is DateTime dateTime)
            return dateTime.ToString("u", CultureInfo.InvariantCulture);

        if (value is DateTimeOffset dateTimeOffset)
            return dateTimeOffset.ToString("u", CultureInfo.InvariantCulture);

        if (value is DateOnly dateOnly)
            return dateOnly.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

        if (value is TimeOnly timeOnly)
            return timeOnly.ToString("HH:mm", CultureInfo.InvariantCulture);

        if (value is IEnumerable enumerable && value is not string)
        {
            var parts = new List<string>();
            foreach (var item in enumerable)
            {
                if (item == null)
                    continue;
                parts.Add(item.ToString() ?? string.Empty);
            }
            return string.Join(", ", parts);
        }

        return value.ToString() ?? string.Empty;
    }

    private static string ToInputString(object? value, Type type, FormFieldType fieldType)
    {
        if (value == null)
            return string.Empty;

        if (IsStringListType(type))
        {
            if (value is IEnumerable enumerable && value is not string)
            {
                var parts = new List<string>();
                foreach (var item in enumerable)
                {
                    if (item == null)
                        continue;
                    parts.Add(item.ToString() ?? string.Empty);
                }
                return string.Join(Environment.NewLine, parts);
            }
        }

        switch (fieldType)
        {
            case FormFieldType.DateOnly:
                if (value is DateOnly dateOnly)
                    return dateOnly.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
                break;
            case FormFieldType.TimeOnly:
                if (value is TimeOnly timeOnly)
                    return timeOnly.ToString("HH:mm", CultureInfo.InvariantCulture);
                break;
            case FormFieldType.DateTime:
                if (value is DateTime dateTime)
                {
                    var local = dateTime.Kind == DateTimeKind.Utc ? dateTime.ToLocalTime() : dateTime;
                    return local.ToString("yyyy-MM-dd'T'HH:mm", CultureInfo.InvariantCulture);
                }
                if (value is DateTimeOffset dateTimeOffset)
                {
                    var local = dateTimeOffset.ToLocalTime();
                    return local.ToString("yyyy-MM-dd'T'HH:mm", CultureInfo.InvariantCulture);
                }
                break;
        }

        return ToDisplayString(value, type);
    }

    private static IReadOnlyList<KeyValuePair<string, string>> BuildEnumOptions(Type type)
    {
        var effectiveType = Nullable.GetUnderlyingType(type) ?? type;
        if (!effectiveType.IsEnum)
            return Array.Empty<KeyValuePair<string, string>>();

        return Enum.GetNames(effectiveType)
            .Select(name => new KeyValuePair<string, string>(name, DeCamelcaseWithId(name)))
            .ToArray();
    }

    private static IReadOnlyList<KeyValuePair<string, string>> GetLookupOptions(DataLookupConfig lookup)
    {
        var cacheKey = BuildLookupCacheKey(lookup);
        lock (LookupCacheSync)
        {
            if (LookupCache.TryGetValue(cacheKey, out var cached) && cached.ExpiresUtc > DateTime.UtcNow)
                return cached.Options;
        }

        var query = BuildLookupQuery(lookup);
        var items = QueryByType(lookup.TargetType, query);
        var options = BuildLookupOptions(items, lookup.ValueField, lookup.DisplayField);

        lock (LookupCacheSync)
        {
            LookupCache[cacheKey] = new LookupCacheEntry(options, DateTime.UtcNow.Add(lookup.CacheTtl));
        }

        return options;
    }

    private static string BuildLookupCacheKey(DataLookupConfig lookup)
    {
        return string.Join('|',
            lookup.TargetType.FullName ?? lookup.TargetType.Name,
            lookup.ValueField,
            lookup.DisplayField,
            lookup.QueryField ?? string.Empty,
            lookup.QueryOperator,
            lookup.QueryValue ?? string.Empty,
            lookup.SortField ?? string.Empty,
            lookup.SortDirection,
            lookup.CacheTtl.TotalSeconds.ToString(CultureInfo.InvariantCulture));
    }

    private static QueryDefinition? BuildLookupQuery(DataLookupConfig lookup)
    {
        var query = new QueryDefinition();
        if (!string.IsNullOrWhiteSpace(lookup.QueryField) && !string.IsNullOrWhiteSpace(lookup.QueryValue))
        {
            query.Clauses.Add(new QueryClause
            {
                Field = lookup.QueryField!,
                Operator = lookup.QueryOperator,
                Value = lookup.QueryValue
            });
        }

        if (!string.IsNullOrWhiteSpace(lookup.SortField))
        {
            query.Sorts.Add(new SortClause
            {
                Field = lookup.SortField!,
                Direction = lookup.SortDirection
            });
        }

        return query.Clauses.Count == 0 && query.Sorts.Count == 0 ? null : query;
    }

    private static IEnumerable QueryByType(Type type, QueryDefinition? query)
    {
        var method = typeof(IDataObjectStore).GetMethod(nameof(IDataObjectStore.Query))!;
        var generic = method.MakeGenericMethod(type);
        return (IEnumerable)generic.Invoke(DataStoreProvider.Current, new object?[] { query })!;
    }

    private static IReadOnlyList<KeyValuePair<string, string>> BuildLookupOptions(IEnumerable items, string valueField, string displayField)
    {
        var options = new List<KeyValuePair<string, string>>();
        foreach (var item in items)
        {
            if (item == null)
                continue;

            var valueProp = item.GetType().GetProperty(valueField, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
            var displayProp = item.GetType().GetProperty(displayField, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
            if (valueProp == null || displayProp == null)
                continue;

            var value = valueProp.GetValue(item);
            if (value == null)
                continue;

            var display = displayProp.GetValue(item);
            var displayText = display != null
                ? ToDisplayString(display, displayProp.PropertyType)
                : value.ToString() ?? string.Empty;

            options.Add(new KeyValuePair<string, string>(value.ToString() ?? string.Empty, displayText));
        }

        return options;
    }

    private static bool IsDefaultValue(object? value, Type type)
    {
        if (value == null)
            return true;

        var effectiveType = Nullable.GetUnderlyingType(type) ?? type;
        if (!effectiveType.IsValueType)
            return false;

        var defaultValue = Activator.CreateInstance(effectiveType);
        return Equals(value, defaultValue);
    }

    private static string? GetCreateDefaultInputString(Type type, FormFieldType fieldType)
    {
        var effectiveType = Nullable.GetUnderlyingType(type) ?? type;
        switch (fieldType)
        {
            case FormFieldType.DateOnly:
                if (effectiveType == typeof(DateOnly))
                    return DateOnly.FromDateTime(DateTime.Today).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
                break;
            case FormFieldType.TimeOnly:
                if (effectiveType == typeof(TimeOnly))
                    return TimeOnly.FromDateTime(DateTime.Now).ToString("HH:mm", CultureInfo.InvariantCulture);
                break;
            case FormFieldType.DateTime:
                if (effectiveType == typeof(DateTime))
                    return DateTime.Now.ToString("yyyy-MM-dd'T'HH:mm", CultureInfo.InvariantCulture);
                if (effectiveType == typeof(DateTimeOffset))
                    return DateTimeOffset.Now.ToString("yyyy-MM-dd'T'HH:mm", CultureInfo.InvariantCulture);
                break;
        }

        return null;
    }

    public static string? GetIdValue(BaseDataObject instance)
        => instance.Id;

    public static bool IsTruthy(object? value)
    {
        if (value == null)
            return false;

        if (value is bool b)
            return b;

        if (value is string s)
            return string.Equals(s, "true", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "on", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "yes", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "1", StringComparison.OrdinalIgnoreCase);

        if (value is int i)
            return i != 0;

        return false;
    }

    private static bool IsBooleanField(DataFieldMetadata field, Type propertyType)
    {
        if (field.FieldType == FormFieldType.YesNo)
            return true;

        var effectiveType = Nullable.GetUnderlyingType(propertyType) ?? propertyType;
        return effectiveType == typeof(bool);
    }

    private static bool TryGetFormValue(IDictionary<string, string?> values, string name, out string? rawValue)
    {
        if (values.TryGetValue(name, out rawValue))
            return true;

        var camel = ToCamelCase(name);
        if (!string.Equals(camel, name, StringComparison.Ordinal) && values.TryGetValue(camel, out rawValue))
            return true;

        var lower = name.ToLowerInvariant();
        if (!string.Equals(lower, name, StringComparison.Ordinal) && values.TryGetValue(lower, out rawValue))
            return true;

        rawValue = null;
        return false;
    }

    private sealed record ChildFieldMeta(
        string Name,
        string Label,
        Type FieldType,
        bool Required,
        FormFieldType FormFieldType,
        IReadOnlyList<KeyValuePair<string, string>>? LookupOptions
    );

    private static bool IsChildListType(Type type, out Type childType)
    {
        childType = typeof(object);
        if (!type.IsGenericType || type.GetGenericTypeDefinition() != typeof(List<>))
            return false;

        childType = type.GetGenericArguments()[0];
        return childType.IsClass && childType != typeof(string);
    }

    private static IReadOnlyList<ChildFieldMeta> GetChildFieldMetadata(Type childType)
    {
        var fields = new List<ChildFieldMeta>();
        var properties = childType.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .OrderBy(p => p.MetadataToken)
            .ToArray();

        foreach (var prop in properties)
        {
            if (!prop.CanRead || !prop.CanWrite)
                continue;

            var fieldAttribute = prop.GetCustomAttribute<DataFieldAttribute>();
            var lookupAttribute = prop.GetCustomAttribute<DataLookupAttribute>();
            if (fieldAttribute == null)
                continue;

            if (!fieldAttribute.Create && !fieldAttribute.Edit)
                continue;

            var label = fieldAttribute.Label ?? DeCamelcaseWithId(prop.Name);
            var required = fieldAttribute.Required;
            var effectiveFieldType = fieldAttribute.FieldType == FormFieldType.Unknown
                ? MapFieldType(prop.PropertyType)
                : fieldAttribute.FieldType;

            IReadOnlyList<KeyValuePair<string, string>>? lookupOptions = null;
            if (lookupAttribute != null)
            {
                var lookup = new DataLookupConfig(
                    lookupAttribute.TargetType,
                    lookupAttribute.ValueField,
                    lookupAttribute.DisplayField,
                    lookupAttribute.QueryField,
                    lookupAttribute.QueryOperator,
                    lookupAttribute.QueryValue,
                    lookupAttribute.SortField,
                    lookupAttribute.SortDirection,
                    TimeSpan.FromSeconds(Math.Max(0, lookupAttribute.CacheSeconds))
                );
                lookupOptions = GetLookupOptions(lookup);
                effectiveFieldType = FormFieldType.LookupList;
            }
            else if (effectiveFieldType == FormFieldType.Enum)
            {
                lookupOptions = BuildEnumOptions(prop.PropertyType);
            }

            fields.Add(new ChildFieldMeta(prop.Name, label, prop.PropertyType, required, effectiveFieldType, lookupOptions));
        }

        return fields;
    }

    private static string BuildChildListEditorHtml(DataFieldMetadata field, Type childType, IEnumerable? listValue)
    {
        var fieldId = WebUtility.HtmlEncode(field.Name);
        var rows = new List<Dictionary<string, string>>();
        var childFields = GetChildFieldMetadata(childType);

        if (listValue != null)
        {
            foreach (var item in listValue)
            {
                if (item == null)
                    continue;
                var row = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var child in childFields)
                {
                    var prop = childType.GetProperty(child.Name, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
                    if (prop == null)
                        continue;
                    var value = prop.GetValue(item);
                    row[child.Name] = ToDisplayString(value, prop.PropertyType);
                }
                rows.Add(row);
            }
        }

        var json = JsonSerializer.Serialize(rows);
        var modalId = $"modal_{field.Name}";
        var tableId = $"table_{field.Name}";
        var formId = $"form_{field.Name}";

        var sb = new StringBuilder();
        sb.Append($"<textarea class=\"d-none\" id=\"{fieldId}\" name=\"{fieldId}\">{WebUtility.HtmlEncode(json)}</textarea>");
        sb.Append("<div class=\"mb-3\">");
        sb.Append("<div class=\"d-flex align-items-center justify-content-between mb-2\">");
        sb.Append($"<label class=\"form-label mb-0\">{WebUtility.HtmlEncode(field.Label)}</label>");
        sb.Append($"<button type=\"button\" class=\"btn btn-sm btn-outline-success\" data-bs-toggle=\"modal\" data-bs-target=\"#{WebUtility.HtmlEncode(modalId)}\" data-action=\"add\"><i class=\"bi bi-plus-lg\" aria-hidden=\"true\"></i> Add</button>");
        sb.Append("</div>");
        sb.Append($"<div class=\"table-responsive\"><table class=\"table table-striped table-sm align-middle mb-0 bm-table\" id=\"{WebUtility.HtmlEncode(tableId)}\"><thead><tr>");
        sb.Append("<th>Actions</th>");
        foreach (var child in childFields)
        {
            sb.Append($"<th>{WebUtility.HtmlEncode(child.Label)}</th>");
        }
        sb.Append("</tr></thead><tbody></tbody></table></div>");
        sb.Append("</div>");

        sb.Append($"<div class=\"modal fade\" id=\"{WebUtility.HtmlEncode(modalId)}\" tabindex=\"-1\" aria-hidden=\"true\">");
        sb.Append("<div class=\"modal-dialog modal-lg modal-dialog-scrollable\"><div class=\"modal-content\">");
        sb.Append("<div class=\"modal-header\"><h5 class=\"modal-title\">Edit Row</h5>");
        sb.Append("<button type=\"button\" class=\"btn-close\" data-bs-dismiss=\"modal\" aria-label=\"Close\"></button></div>");
        sb.Append($"<div class=\"modal-body\"><form id=\"{WebUtility.HtmlEncode(formId)}\">\n");
        sb.Append("<input type=\"hidden\" name=\"_rowIndex\" value=\"-1\" />");

        foreach (var child in childFields)
        {
            var inputType = MapChildInputType(child.FieldType, out var step);
            sb.Append("<div class=\"mb-3\">");
            sb.Append($"<label class=\"form-label\">{WebUtility.HtmlEncode(child.Label)}</label>");
            if (child.LookupOptions != null)
            {
                sb.Append($"<select class=\"form-select\" data-field=\"{WebUtility.HtmlEncode(child.Name)}\">");
                sb.Append("<option value=\"\"></option>");
                foreach (var option in child.LookupOptions)
                {
                    var optKey = WebUtility.HtmlEncode(option.Key);
                    var optLabel = WebUtility.HtmlEncode(option.Value);
                    sb.Append($"<option value=\"{optKey}\">{optLabel}</option>");
                }
                sb.Append("</select>");
            }
            else if (inputType == "checkbox")
            {
                sb.Append($"<div class=\"form-check\"><input class=\"form-check-input\" type=\"checkbox\" data-field=\"{WebUtility.HtmlEncode(child.Name)}\" /></div>");
            }
            else
            {
                var stepAttr = string.IsNullOrWhiteSpace(step) ? string.Empty : $" step=\"{step}\"";
                sb.Append($"<input class=\"form-control\" type=\"{inputType}\" data-field=\"{WebUtility.HtmlEncode(child.Name)}\"{stepAttr} />");
            }
            sb.Append("</div>");
        }

        sb.Append("</form></div>");
        sb.Append("<div class=\"modal-footer\">");
        sb.Append("<button type=\"button\" class=\"btn btn-secondary\" data-bs-dismiss=\"modal\">Cancel</button>");
        sb.Append("<button type=\"button\" class=\"btn btn-primary\" data-action=\"save\">Save</button>");
        sb.Append("</div></div></div></div>");

        sb.Append("<script>");
        sb.Append("document.addEventListener('DOMContentLoaded',function(){");
        sb.Append($"var input=document.getElementById('{EscapeJs(field.Name)}');");
        sb.Append($"var table=document.getElementById('{EscapeJs(tableId)}');");
        sb.Append($"var modal=document.getElementById('{EscapeJs(modalId)}');");
        sb.Append($"var form=document.getElementById('{EscapeJs(formId)}');");
        sb.Append("if(!input||!table||!modal||!form){return;}" );
        sb.Append("var data=[]; try{data=JSON.parse(input.value||'[]');}catch(e){data=[];}" );
        sb.Append("var tbody=table.querySelector('tbody');" );
        sb.Append("var lookupMaps=");
        var lookupMaps = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var child in childFields.Where(child => child.LookupOptions != null))
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var option in child.LookupOptions!)
            {
                if (string.IsNullOrWhiteSpace(option.Key))
                    continue;
                map[option.Key] = option.Value;
            }
            lookupMaps[child.Name] = map;
        }
        sb.Append(JsonSerializer.Serialize(lookupMaps));
        sb.Append(";" );

        sb.Append("function render(){tbody.innerHTML='';data.forEach(function(row,idx){var tr=document.createElement('tr');" );
        sb.Append("var actions=document.createElement('td');actions.setAttribute('data-label','Actions');" );
        sb.Append("actions.innerHTML='<button type=\\\"button\\\" class=\\\"btn btn-sm btn-outline-info me-1\\\" data-action=\\\"edit\\\" data-index=\\\"'+idx+'\\\"><i class=\\\"bi bi-pencil\\\" aria-hidden=\\\"true\\\"></i></button>'+");
        sb.Append("'<button type=\\\"button\\\" class=\\\"btn btn-sm btn-outline-danger\\\" data-action=\\\"delete\\\" data-index=\\\"'+idx+'\\\"><i class=\\\"bi bi-x-lg\\\" aria-hidden=\\\"true\\\"></i></button>';" );
        sb.Append("tr.appendChild(actions);" );
        foreach (var child in childFields)
        {
            var label = WebUtility.HtmlEncode(child.Label);
            var name = WebUtility.HtmlEncode(child.Name);
            sb.Append($"var td_{name}=document.createElement('td');td_{name}.setAttribute('data-label','{label}');var raw_{name}=(row['{name}']||'');var map_{name}=lookupMaps && lookupMaps['{name}'];td_{name}.textContent=(map_{name} && map_{name}[raw_{name}] ? map_{name}[raw_{name}] : raw_{name});tr.appendChild(td_{name});");
        }
        sb.Append("tbody.appendChild(tr);});input.value=JSON.stringify(data);}" );
        sb.Append("render();" );
        sb.Append("modal.addEventListener('show.bs.modal',function(ev){var btn=ev.relatedTarget;" );
        sb.Append("if(!btn){return;}var idx=btn.getAttribute('data-index');" );
        sb.Append("form.querySelector('[name=_rowIndex]').value=(idx===null?'-1':idx);" );
        sb.Append("var fields=form.querySelectorAll('[data-field]');fields.forEach(function(f){var name=f.getAttribute('data-field');if(idx===null){if(f.type==='checkbox'){f.checked=false;}else{f.value='';}}else{var row=data[parseInt(idx,10)]||{};if(f.type==='checkbox'){f.checked=(row[name]==='true');}else{f.value=(row[name]||'');}}});});" );
        sb.Append("modal.addEventListener('click',function(ev){var saveBtn=ev.target.closest('[data-action=save]');if(!saveBtn){return;}ev.preventDefault();" );
        sb.Append("var idx=parseInt(form.querySelector('[name=_rowIndex]').value,10);" );
        sb.Append("var row={};form.querySelectorAll('[data-field]').forEach(function(f){var name=f.getAttribute('data-field');if(f.type==='checkbox'){row[name]=f.checked?'true':'false';}else{row[name]=f.value||'';}});" );
        sb.Append("if(isNaN(idx)||idx<0){data.push(row);}else{data[idx]=row;}render();var modalInstance=(window.bootstrap&&bootstrap.Modal?bootstrap.Modal.getOrCreateInstance(modal):null);if(modalInstance){modalInstance.hide();}});");
        sb.Append("tbody.addEventListener('click',function(ev){var btn=ev.target.closest('button');if(!btn){return;}var action=btn.getAttribute('data-action');var idx=parseInt(btn.getAttribute('data-index'),10);if(action==='delete'){if(!isNaN(idx)){data.splice(idx,1);render();}}if(action==='edit'){btn.setAttribute('data-bs-toggle','modal');btn.setAttribute('data-bs-target','#'+modal.id);}});");
        sb.Append("});");
        sb.Append("</script>");

        return sb.ToString();
    }

    private static string BuildChildListViewHtml(DataFieldMetadata field, Type childType, IEnumerable? listValue)
    {
        var childFields = GetChildFieldMetadata(childType);
        var sb = new StringBuilder();
        sb.Append("<div class=\"mt-3\">");
        sb.Append($"<h2 class=\"h6\">{WebUtility.HtmlEncode(field.Label)}</h2>");
        sb.Append("<div class=\"table-responsive\"><table class=\"table table-striped table-sm align-middle mb-0 bm-table\">");
        sb.Append("<thead><tr>");
        foreach (var child in childFields)
        {
            sb.Append($"<th>{WebUtility.HtmlEncode(child.Label)}</th>");
        }
        sb.Append("</tr></thead><tbody>");

        if (listValue != null)
        {
            foreach (var item in listValue)
            {
                if (item == null)
                    continue;
                sb.Append("<tr>");
                foreach (var child in childFields)
                {
                    var prop = childType.GetProperty(child.Name, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
                    var value = prop?.GetValue(item);
                    var displayText = ToDisplayString(value, prop?.PropertyType ?? typeof(string));
                    if (child.LookupOptions != null)
                    {
                        var map = child.LookupOptions.ToDictionary(k => k.Key, v => v.Value, StringComparer.OrdinalIgnoreCase);
                        var key = value?.ToString() ?? string.Empty;
                        displayText = map.TryGetValue(key, out var resolved) ? resolved : key;
                    }
                    var display = WebUtility.HtmlEncode(displayText);
                    sb.Append($"<td data-label=\"{WebUtility.HtmlEncode(child.Label)}\">{display}</td>");
                }
                sb.Append("</tr>");
            }
        }

        sb.Append("</tbody></table></div></div>");
        return sb.ToString();
    }

    private static bool TryParseChildList(string rawValue, Type childType, out object? list)
    {
        list = null;
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            list = Activator.CreateInstance(typeof(List<>).MakeGenericType(childType));
            return true;
        }

        try
        {
            var rows = JsonSerializer.Deserialize<List<Dictionary<string, string>>>(rawValue)
                ?? new List<Dictionary<string, string>>();
            var listType = typeof(List<>).MakeGenericType(childType);
            var typedList = (IList)Activator.CreateInstance(listType)!;
            var childFields = GetChildFieldMetadata(childType);

            foreach (var row in rows)
            {
                var instance = Activator.CreateInstance(childType);
                if (instance == null)
                    continue;

                foreach (var child in childFields)
                {
                    if (!row.TryGetValue(child.Name, out var raw))
                        continue;

                    var prop = childType.GetProperty(child.Name, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
                    if (prop == null)
                        continue;

                    if (TryConvertValue(raw, prop.PropertyType, out var converted) && converted != null)
                    {
                        prop.SetValue(instance, converted);
                    }
                    else if ((Nullable.GetUnderlyingType(prop.PropertyType) ?? prop.PropertyType) == typeof(string))
                    {
                        prop.SetValue(instance, raw);
                    }
                }

                typedList.Add(instance);
            }

            list = typedList;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string MapChildInputType(Type type, out string step)
    {
        step = string.Empty;
        var effectiveType = Nullable.GetUnderlyingType(type) ?? type;
        if (effectiveType == typeof(bool))
            return "checkbox";
        if (effectiveType == typeof(int) || effectiveType == typeof(long) || effectiveType == typeof(short))
            return "number";
        if (effectiveType == typeof(decimal) || effectiveType == typeof(double) || effectiveType == typeof(float))
        {
            step = "0.01";
            return "number";
        }
        if (effectiveType == typeof(DateOnly))
            return "date";
        if (effectiveType == typeof(TimeOnly))
            return "time";
        if (effectiveType == typeof(DateTime) || effectiveType == typeof(DateTimeOffset))
            return "datetime-local";
        return "text";
    }

    private static string EscapeJs(string value)
    {
        return value.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("'", "\\'");
    }

    private static bool IsDictionaryType(Type type, out Type valueType)
    {
        valueType = typeof(string);
        var effectiveType = Nullable.GetUnderlyingType(type) ?? type;
        if (effectiveType.IsGenericType)
        {
            var generic = effectiveType.GetGenericTypeDefinition();
            if (generic == typeof(Dictionary<,>) || generic == typeof(IDictionary<,>) || generic == typeof(IReadOnlyDictionary<,>))
            {
                var args = effectiveType.GetGenericArguments();
                if (args.Length == 2 && args[0] == typeof(string))
                {
                    valueType = args[1];
                    return true;
                }
            }
        }

        foreach (var iface in effectiveType.GetInterfaces())
        {
            if (!iface.IsGenericType)
                continue;
            var generic = iface.GetGenericTypeDefinition();
            if (generic != typeof(IDictionary<,>) && generic != typeof(IReadOnlyDictionary<,>))
                continue;
            var args = iface.GetGenericArguments();
            if (args.Length == 2 && args[0] == typeof(string))
            {
                valueType = args[1];
                return true;
            }
        }

        return false;
    }

    private static string BuildDictionaryEditorHtml(DataFieldMetadata field, Type valueType, IEnumerable? dictValue)
    {
        var rows = new List<Dictionary<string, string>>();
        if (dictValue is IDictionary dictionary)
        {
            foreach (DictionaryEntry entry in dictionary)
            {
                var key = entry.Key?.ToString() ?? string.Empty;
                var value = ToDisplayString(entry.Value, valueType);
                rows.Add(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["key"] = key,
                    ["value"] = value
                });
            }
        }

        var json = JsonSerializer.Serialize(rows);
        var modalId = $"modal_{field.Name}";
        var tableId = $"table_{field.Name}";
        var formId = $"form_{field.Name}";
        var inputType = MapChildInputType(valueType, out var step);
        var stepAttr = string.IsNullOrWhiteSpace(step) ? string.Empty : $" step=\"{step}\"";

        var sb = new StringBuilder();
        sb.Append($"<textarea class=\"d-none\" id=\"{WebUtility.HtmlEncode(field.Name)}\" name=\"{WebUtility.HtmlEncode(field.Name)}\">{WebUtility.HtmlEncode(json)}</textarea>");
        sb.Append("<div class=\"mb-3\">");
        sb.Append("<div class=\"d-flex align-items-center justify-content-between mb-2\">");
        sb.Append($"<label class=\"form-label mb-0\">{WebUtility.HtmlEncode(field.Label)}</label>");
        sb.Append($"<button type=\"button\" class=\"btn btn-sm btn-outline-success\" data-bs-toggle=\"modal\" data-bs-target=\"#{WebUtility.HtmlEncode(modalId)}\" data-action=\"add\"><i class=\"bi bi-plus-lg\" aria-hidden=\"true\"></i> Add</button>");
        sb.Append("</div>");
        sb.Append($"<div class=\"table-responsive\"><table class=\"table table-striped table-sm align-middle mb-0 bm-table\" id=\"{WebUtility.HtmlEncode(tableId)}\"><thead><tr><th>Actions</th><th>Key</th><th>Value</th></tr></thead><tbody></tbody></table></div>");
        sb.Append("</div>");

        sb.Append($"<div class=\"modal fade\" id=\"{WebUtility.HtmlEncode(modalId)}\" tabindex=\"-1\" aria-hidden=\"true\"><div class=\"modal-dialog\"><div class=\"modal-content\">");
        sb.Append($"<div class=\"modal-header\"><h5 class=\"modal-title\">Edit {WebUtility.HtmlEncode(field.Label)}</h5><button type=\"button\" class=\"btn-close\" data-bs-dismiss=\"modal\" aria-label=\"Close\"></button></div>");
        sb.Append($"<div class=\"modal-body\"><form id=\"{WebUtility.HtmlEncode(formId)}\" onsubmit=\"return false;\">" );
        sb.Append("<input type=\"hidden\" name=\"_rowIndex\" value=\"-1\" />");
        sb.Append("<div class=\"mb-3\"><label class=\"form-label\">Key</label><input class=\"form-control\" type=\"text\" data-field=\"key\" /></div>");
        sb.Append($"<div class=\"mb-3\"><label class=\"form-label\">Value</label><input class=\"form-control\" type=\"{inputType}\" data-field=\"value\"{stepAttr} /></div>");
        sb.Append("</form></div>");
        sb.Append("<div class=\"modal-footer\"><button type=\"button\" class=\"btn btn-secondary\" data-bs-dismiss=\"modal\">Cancel</button><button type=\"button\" class=\"btn btn-primary\" data-action=\"save\">Save</button></div>");
        sb.Append("</div></div></div>");

        sb.Append("<script>");
        sb.Append("document.addEventListener('DOMContentLoaded',function(){");
        sb.Append($"var input=document.getElementById('{EscapeJs(field.Name)}');");
        sb.Append($"var table=document.getElementById('{EscapeJs(tableId)}');");
        sb.Append($"var modal=document.getElementById('{EscapeJs(modalId)}');");
        sb.Append($"var form=document.getElementById('{EscapeJs(formId)}');");
        sb.Append("if(!input||!table||!modal||!form){return;}");
        sb.Append("var data=[]; try{data=JSON.parse(input.value||'[]');}catch(e){data=[];}");
        sb.Append("var tbody=table.querySelector('tbody');");
        sb.Append("function render(){tbody.innerHTML='';data.forEach(function(row,idx){var tr=document.createElement('tr');");
        sb.Append("var actions=document.createElement('td');actions.setAttribute('data-label','Actions');");
        sb.Append(@"actions.innerHTML='<button type=""button"" class=""btn btn-sm btn-outline-info me-1"" data-action=""edit"" data-index=""'+idx+'""><i class=""bi bi-pencil"" aria-hidden=""true""></i></button>'+");
        sb.Append(@"'<button type=""button"" class=""btn btn-sm btn-outline-danger"" data-action=""delete"" data-index=""'+idx+'""><i class=""bi bi-x-lg"" aria-hidden=""true""></i></button>';");
        sb.Append("tr.appendChild(actions);");
        sb.Append("var keyCell=document.createElement('td');keyCell.setAttribute('data-label','Key');keyCell.textContent=(row['key']||'');tr.appendChild(keyCell);");
        sb.Append("var valCell=document.createElement('td');valCell.setAttribute('data-label','Value');valCell.textContent=(row['value']||'');tr.appendChild(valCell);");
        sb.Append("tbody.appendChild(tr);});input.value=JSON.stringify(data);}");
        sb.Append("render();");
        sb.Append("modal.addEventListener('show.bs.modal',function(ev){var btn=ev.relatedTarget; if(!btn){return;}var idx=btn.getAttribute('data-index');");
        sb.Append("form.querySelector('[name=_rowIndex]').value=(idx===null?'-1':idx);");
        sb.Append("var fields=form.querySelectorAll('[data-field]');fields.forEach(function(f){var name=f.getAttribute('data-field');if(idx===null){f.value='';}else{var row=data[parseInt(idx,10)]||{};f.value=(row[name]||'');}});});");
        sb.Append("modal.addEventListener('click',function(ev){var saveBtn=ev.target.closest('[data-action=save]');if(!saveBtn){return;}ev.preventDefault();");
        sb.Append("var idx=parseInt(form.querySelector('[name=_rowIndex]').value,10);var row={};form.querySelectorAll('[data-field]').forEach(function(f){var name=f.getAttribute('data-field');row[name]=f.value||'';});");
        sb.Append("if(isNaN(idx)||idx<0){data.push(row);}else{data[idx]=row;}render();var modalInstance=(window.bootstrap&&bootstrap.Modal?bootstrap.Modal.getOrCreateInstance(modal):null);if(modalInstance){modalInstance.hide();}});");
        sb.Append("tbody.addEventListener('click',function(ev){var btn=ev.target.closest('button');if(!btn){return;}var action=btn.getAttribute('data-action');var idx=parseInt(btn.getAttribute('data-index'),10);if(action==='delete'){if(!isNaN(idx)){data.splice(idx,1);render();}}if(action==='edit'){btn.setAttribute('data-bs-toggle','modal');btn.setAttribute('data-bs-target','#'+modal.id);}});");
        sb.Append("});");
        sb.Append("</script>");

        return sb.ToString();
    }

    private static string BuildDictionaryViewHtml(DataFieldMetadata field, Type valueType, IEnumerable? dictValue)
    {
        var sb = new StringBuilder();
        sb.Append("<div class=\"mt-3\">");
        sb.Append($"<h2 class=\"h6\">{WebUtility.HtmlEncode(field.Label)}</h2>");
        sb.Append("<div class=\"table-responsive\"><table class=\"table table-striped table-sm align-middle mb-0 bm-table\"><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>");

        if (dictValue is IDictionary dictionary)
        {
            foreach (DictionaryEntry entry in dictionary)
            {
                var key = WebUtility.HtmlEncode(entry.Key?.ToString() ?? string.Empty);
                var value = WebUtility.HtmlEncode(ToDisplayString(entry.Value, valueType));
                sb.Append($"<tr><td data-label=\"Key\">{key}</td><td data-label=\"Value\">{value}</td></tr>");
            }
        }

        sb.Append("</tbody></table></div></div>");
        return sb.ToString();
    }

    private static bool TryParseDictionary(string rawValue, Type valueType, out object? dictionary)
    {
        dictionary = null;
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            dictionary = Activator.CreateInstance(typeof(Dictionary<,>).MakeGenericType(typeof(string), valueType));
            return true;
        }

        try
        {
            var list = JsonSerializer.Deserialize<List<Dictionary<string, string>>>(rawValue)
                ?? new List<Dictionary<string, string>>();
            var dictType = typeof(Dictionary<,>).MakeGenericType(typeof(string), valueType);
            var result = (IDictionary)Activator.CreateInstance(dictType)!;

            foreach (var row in list)
            {
                if (!row.TryGetValue("key", out var key) || string.IsNullOrWhiteSpace(key))
                    continue;
                row.TryGetValue("value", out var raw);
                if (!TryConvertValue(raw ?? string.Empty, valueType, out var converted))
                {
                    if ((Nullable.GetUnderlyingType(valueType) ?? valueType) == typeof(string))
                    {
                        converted = raw ?? string.Empty;
                    }
                    else
                    {
                        continue;
                    }
                }

                result[key] = converted ?? string.Empty;
            }

            dictionary = result;
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static string[] ParseStringList(string rawValue)
    {
        return rawValue.Split(new[] { '\r', '\n', ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static bool IsStringListType(Type type)
    {
        if (type == typeof(string[]))
            return true;

        return type.IsGenericType
            && type.GetGenericTypeDefinition() == typeof(List<>)
            && type.GetGenericArguments()[0] == typeof(string);
    }

    private static string ToCamelCase(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return input;
        if (input.Length == 1)
            return input.ToLowerInvariant();
        return char.ToLowerInvariant(input[0]) + input[1..];
    }

    private static bool TryFallbackConvert(string rawValue, Type targetType, out object? converted)
    {
        converted = null;
        var effectiveType = Nullable.GetUnderlyingType(targetType) ?? targetType;

        if (effectiveType == typeof(string))
        {
            converted = rawValue;
            return true;
        }

        if (effectiveType == typeof(bool))
        {
            converted = IsTruthy(rawValue);
            return true;
        }

        if (effectiveType == typeof(string[]))
        {
            converted = ParseStringList(rawValue);
            return true;
        }

        if (effectiveType == typeof(List<string>))
        {
            converted = new List<string>(ParseStringList(rawValue));
            return true;
        }

        return false;
    }

    public static bool TryConvertValue(string rawValue, Type targetType, out object? converted)
    {
        converted = null;
        var effectiveType = Nullable.GetUnderlyingType(targetType) ?? targetType;

        if (IsStringListType(effectiveType))
        {
            var list = ParseStringList(rawValue);
            converted = effectiveType == typeof(string[])
                ? list
                : new List<string>(list);
            return true;
        }

        if (effectiveType == typeof(int))
        {
            if (int.TryParse(rawValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var intValue))
            {
                converted = intValue;
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(long))
        {
            if (long.TryParse(rawValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var longValue))
            {
                converted = longValue;
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(decimal))
        {
            if (decimal.TryParse(rawValue, NumberStyles.Number, CultureInfo.InvariantCulture, out var decValue))
            {
                converted = decValue;
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(double))
        {
            if (double.TryParse(rawValue, NumberStyles.Number, CultureInfo.InvariantCulture, out var dblValue))
            {
                converted = dblValue;
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(float))
        {
            if (float.TryParse(rawValue, NumberStyles.Number, CultureInfo.InvariantCulture, out var fltValue))
            {
                converted = fltValue;
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(DateTime))
        {
            if (DateTime.TryParse(rawValue, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal, out var dateValue))
            {
                converted = DateTime.SpecifyKind(dateValue, DateTimeKind.Utc);
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(DateTimeOffset))
        {
            if (DateTimeOffset.TryParse(rawValue, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal, out var dateValue))
            {
                converted = dateValue.ToUniversalTime();
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(DateOnly))
        {
            if (DateOnly.TryParse(rawValue, CultureInfo.InvariantCulture, DateTimeStyles.None, out var dateOnly))
            {
                converted = dateOnly;
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(TimeOnly))
        {
            if (TimeOnly.TryParse(rawValue, CultureInfo.InvariantCulture, DateTimeStyles.None, out var timeOnly))
            {
                converted = timeOnly;
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(int))
        {
            if (int.TryParse(rawValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var intValue))
            {
                converted = intValue;
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(long))
        {
            if (long.TryParse(rawValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var longValue))
            {
                converted = longValue;
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(decimal))
        {
            if (decimal.TryParse(rawValue, NumberStyles.Number, CultureInfo.InvariantCulture, out var decimalValue))
            {
                converted = decimalValue;
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(double))
        {
            if (double.TryParse(rawValue, NumberStyles.Number, CultureInfo.InvariantCulture, out var doubleValue))
            {
                converted = doubleValue;
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(float))
        {
            if (float.TryParse(rawValue, NumberStyles.Number, CultureInfo.InvariantCulture, out var floatValue))
            {
                converted = floatValue;
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(DateTime))
        {
            if (DateTime.TryParse(rawValue, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal, out var dateValue))
            {
                converted = DateTime.SpecifyKind(dateValue, DateTimeKind.Utc);
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(DateTimeOffset))
        {
            if (DateTimeOffset.TryParse(rawValue, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal, out var dateValue))
            {
                converted = dateValue.ToUniversalTime();
                return true;
            }
            return false;
        }

        if (effectiveType == typeof(string[]))
        {
            converted = ParseStringList(rawValue);
            return true;
        }

        if (effectiveType.IsEnum)
        {
            try
            {
                converted = Enum.Parse(effectiveType, rawValue, ignoreCase: true);
                return true;
            }
            catch
            {
                return false;
            }
        }

        return false;
    }

    public static bool TryConvertJson(JsonElement element, Type targetType, out object? converted)
    {
        converted = null;
        var effectiveType = Nullable.GetUnderlyingType(targetType) ?? targetType;

        try
        {
            if (effectiveType == typeof(string))
            {
                converted = element.ValueKind == JsonValueKind.Null ? null : element.ToString();
                return true;
            }

            if (effectiveType == typeof(bool))
            {
                converted = element.ValueKind switch
                {
                    JsonValueKind.True => true,
                    JsonValueKind.False => false,
                    JsonValueKind.String => IsTruthy(element.GetString()),
                    _ => false
                };
                return true;
            }

            if (effectiveType == typeof(int) && element.TryGetInt32(out var intValue))
            {
                converted = intValue;
                return true;
            }

            if (effectiveType == typeof(long) && element.TryGetInt64(out var longValue))
            {
                converted = longValue;
                return true;
            }

            if (effectiveType == typeof(decimal) && element.TryGetDecimal(out var decValue))
            {
                converted = decValue;
                return true;
            }

            if (effectiveType == typeof(double) && element.TryGetDouble(out var dblValue))
            {
                converted = dblValue;
                return true;
            }

            if (effectiveType == typeof(DateTime) && element.ValueKind == JsonValueKind.String && DateTime.TryParse(element.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal, out var dateValue))
            {
                converted = DateTime.SpecifyKind(dateValue, DateTimeKind.Utc);
                return true;
            }

            if (effectiveType == typeof(DateTimeOffset) && element.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(element.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal, out var dateValue2))
            {
                converted = dateValue2.ToUniversalTime();
                return true;
            }

            if (effectiveType == typeof(DateOnly) && element.ValueKind == JsonValueKind.String && DateOnly.TryParse(element.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.None, out var dateOnly))
            {
                converted = dateOnly;
                return true;
            }

            if (effectiveType == typeof(TimeOnly) && element.ValueKind == JsonValueKind.String && TimeOnly.TryParse(element.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.None, out var timeOnly))
            {
                converted = timeOnly;
                return true;
            }

            if (effectiveType == typeof(string[]) && element.ValueKind == JsonValueKind.Array)
            {
                var list = new List<string>();
                foreach (var item in element.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String)
                        list.Add(item.GetString() ?? string.Empty);
                }
                converted = list.ToArray();
                return true;
            }

            if (effectiveType == typeof(List<string>) && element.ValueKind == JsonValueKind.Array)
            {
                var list = new List<string>();
                foreach (var item in element.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String)
                        list.Add(item.GetString() ?? string.Empty);
                }
                converted = list;
                return true;
            }

            if (effectiveType.IsEnum && element.ValueKind == JsonValueKind.String)
            {
                converted = Enum.Parse(effectiveType, element.GetString() ?? string.Empty, ignoreCase: true);
                return true;
            }
        }
        catch
        {
            return false;
        }

        return false;
    }

    public static FormFieldType MapFieldType(Type type)
    {
        var effectiveType = Nullable.GetUnderlyingType(type) ?? type;

        if (IsStringListType(effectiveType))
            return FormFieldType.TextArea;
        if (effectiveType == typeof(bool))
            return FormFieldType.YesNo;
        if (effectiveType.IsEnum)
            return FormFieldType.Enum;
        if (effectiveType == typeof(DateOnly))
            return FormFieldType.DateOnly;
        if (effectiveType == typeof(TimeOnly))
            return FormFieldType.TimeOnly;
        if (effectiveType == typeof(DateTime) || effectiveType == typeof(DateTimeOffset))
            return FormFieldType.DateTime;
        if (effectiveType == typeof(int) || effectiveType == typeof(long) || effectiveType == typeof(short))
            return FormFieldType.Integer;
        if (effectiveType == typeof(decimal) || effectiveType == typeof(double) || effectiveType == typeof(float))
            return FormFieldType.Decimal;
        if (effectiveType == typeof(string))
            return FormFieldType.String;

        return FormFieldType.String;
    }

    private static DataEntityMetadata? BuildEntityMetadata<T>() where T : BaseDataObject, new()
    {
        var type = typeof(T);
        if (type.IsAbstract)
            return null;

        var entityAttribute = type.GetCustomAttribute<DataEntityAttribute>();
        var useConvention = typeof(RenderableDataObject).IsAssignableFrom(type);
        if (entityAttribute == null && !useConvention)
            return null;

        var fields = new List<DataFieldMetadata>();
        var properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .OrderBy(p => p.MetadataToken)
            .ToArray();
        for (int i = 0; i < properties.Length; i++)
        {
            var prop = properties[i];
            if (!prop.CanRead || !prop.CanWrite)
                continue;

            if (IsCoreDataObjectProperty(prop))
                continue;

            var fieldAttribute = prop.GetCustomAttribute<DataFieldAttribute>();
            var lookupAttribute = prop.GetCustomAttribute<DataLookupAttribute>();
            if (fieldAttribute == null && !useConvention)
                continue;

            var fieldType = fieldAttribute?.FieldType == FormFieldType.Unknown || fieldAttribute == null
                ? MapFieldType(prop.PropertyType)
                : fieldAttribute.FieldType;
            var label = fieldAttribute?.Label ?? DeCamelcaseWithId(prop.Name);
            var required = fieldAttribute?.Required ?? (!IsNullable(prop) || !HasDefaultValue(type, prop));
            var order = fieldAttribute?.Order ?? (i + 1);
            DataLookupConfig? lookup = null;
            if (lookupAttribute != null)
            {
                lookup = new DataLookupConfig(
                    lookupAttribute.TargetType,
                    lookupAttribute.ValueField,
                    lookupAttribute.DisplayField,
                    lookupAttribute.QueryField,
                    lookupAttribute.QueryOperator,
                    lookupAttribute.QueryValue,
                    lookupAttribute.SortField,
                    lookupAttribute.SortDirection,
                    TimeSpan.FromSeconds(Math.Max(0, lookupAttribute.CacheSeconds))
                );
            }

            fields.Add(new DataFieldMetadata(
                prop,
                prop.Name,
                label,
                fieldType,
                order,
                required,
                fieldAttribute?.List ?? true,
                fieldAttribute?.View ?? true,
                fieldAttribute?.Edit ?? true,
                fieldAttribute?.Create ?? true,
                fieldAttribute?.ReadOnly ?? false,
                fieldAttribute?.Placeholder,
                lookup
            ));
        }

        var name = entityAttribute?.Name ?? Pluralize(DeCamelcaseWithId(type.Name));
        var slug = string.IsNullOrWhiteSpace(entityAttribute?.Slug)
            ? ToSlug(name)
            : entityAttribute!.Slug!.Trim().ToLowerInvariant();
        var permissions = string.IsNullOrWhiteSpace(entityAttribute?.Permissions)
            ? name
            : entityAttribute!.Permissions;
        var showOnNav = entityAttribute?.ShowOnNav ?? true;
        var navGroup = entityAttribute?.NavGroup ?? "Admin";
        var navOrder = entityAttribute?.NavOrder ?? 0;

        var handlers = new DataEntityHandlers(
            static () => new T(),
            LoadTypedAsync<T>,
            SaveTypedAsync<T>,
            DeleteTypedAsync<T>,
            QueryTypedAsync<T>,
            CountTypedAsync<T>
        );

        return new DataEntityMetadata(
            type,
            name,
            slug,
            permissions,
            showOnNav,
            navGroup,
            navOrder,
            fields.OrderBy(f => f.Order).ToList(),
            handlers
        );
    }

    private static bool IsCoreDataObjectProperty(PropertyInfo property)
    {
        return property.DeclaringType == typeof(BaseDataObject)
            || property.Name == nameof(BaseDataObject.Id)
            || property.Name == nameof(BaseDataObject.CreatedOnUtc)
            || property.Name == nameof(BaseDataObject.UpdatedOnUtc)
            || property.Name == nameof(BaseDataObject.CreatedBy)
            || property.Name == nameof(BaseDataObject.UpdatedBy)
            || property.Name == nameof(BaseDataObject.ETag);
    }

    private static bool IsNullable(PropertyInfo property)
    {
        if (Nullable.GetUnderlyingType(property.PropertyType) != null)
            return true;
        if (property.PropertyType.IsValueType)
            return false;

        var nullability = NullabilityContext.Create(property);
        return nullability.ReadState == NullabilityState.Nullable
            || nullability.WriteState == NullabilityState.Nullable;
    }

    private static bool HasDefaultValue(Type declaringType, PropertyInfo property)
    {
        object? instance = null;
        try
        {
            instance = Activator.CreateInstance(declaringType);
        }
        catch
        {
            return false;
        }

        if (instance is null)
            return false;

        var value = property.GetValue(instance);
        var defaultValue = property.PropertyType.IsValueType
            ? Activator.CreateInstance(property.PropertyType)
            : null;
        return !Equals(value, defaultValue);
    }

    private static string DeCamelcaseWithId(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return string.Empty;

        var words = new List<string>();
        var buffer = new List<char>();
        for (int i = 0; i < name.Length; i++)
        {
            var c = name[i];
            var isBoundary = i > 0
                && char.IsUpper(c)
                && (char.IsLower(name[i - 1]) || (i + 1 < name.Length && char.IsLower(name[i + 1])));
            if (isBoundary)
            {
                words.Add(new string(buffer.ToArray()));
                buffer.Clear();
            }
            buffer.Add(c);
        }

        if (buffer.Count > 0)
            words.Add(new string(buffer.ToArray()));

        for (int i = 0; i < words.Count; i++)
        {
            if (string.Equals(words[i], "Id", StringComparison.OrdinalIgnoreCase))
                words[i] = "ID";
        }

        return string.Join(" ", words);
    }

    private static string Pluralize(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return string.Empty;

        if (name.EndsWith("y", StringComparison.OrdinalIgnoreCase) && name.Length > 1)
        {
            var before = name[^2];
            if (!"aeiou".Contains(char.ToLowerInvariant(before)))
                return name[..^1] + "ies";
        }

        if (name.EndsWith("s", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith("x", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith("z", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith("ch", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith("sh", StringComparison.OrdinalIgnoreCase))
        {
            return name + "es";
        }

        return name + "s";
    }

    private static string ToSlug(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return string.Empty;

        var chars = new List<char>();
        foreach (var c in name)
        {
            if (char.IsLetterOrDigit(c))
                chars.Add(char.ToLowerInvariant(c));
            else if (char.IsWhiteSpace(c) || c == '_' || c == '-')
                chars.Add('-');
        }

        var slug = new string(chars.ToArray());
        while (slug.Contains("--", StringComparison.Ordinal))
            slug = slug.Replace("--", "-", StringComparison.Ordinal);

        return slug.Trim('-');
    }

    private static async ValueTask<BaseDataObject?> LoadTypedAsync<T>(string id, CancellationToken cancellationToken) where T : BaseDataObject
        => await DataStoreProvider.Current.LoadAsync<T>(id, cancellationToken);

    private static async ValueTask SaveTypedAsync<T>(BaseDataObject instance, CancellationToken cancellationToken) where T : BaseDataObject
        => await DataStoreProvider.Current.SaveAsync((T)instance, cancellationToken);

    private static async ValueTask DeleteTypedAsync<T>(string id, CancellationToken cancellationToken) where T : BaseDataObject
        => await DataStoreProvider.Current.DeleteAsync<T>(id, cancellationToken);

    private static async ValueTask<IEnumerable<BaseDataObject>> QueryTypedAsync<T>(QueryDefinition? query, CancellationToken cancellationToken) where T : BaseDataObject
    {
        var results = await DataStoreProvider.Current.QueryAsync<T>(query, cancellationToken);
        return results.Cast<BaseDataObject>().ToList();
    }

    private static async ValueTask<int> CountTypedAsync<T>(QueryDefinition? query, CancellationToken cancellationToken) where T : BaseDataObject
        => await DataStoreProvider.Current.CountAsync<T>(query, cancellationToken);
}


