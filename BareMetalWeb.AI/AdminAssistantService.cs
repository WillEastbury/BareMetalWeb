using System.ComponentModel;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Microsoft.Extensions.AI;

namespace BareMetalWeb.AI;

/// <summary>
/// Admin assistant service that registers all BareMetalWeb domain tools
/// with an <see cref="IChatClient"/> for AI-assisted administration.
/// </summary>
public sealed class AdminAssistantService
{
    private readonly IChatClient _chatClient;

    public AdminAssistantService(IChatClient chatClient)
    {
        _chatClient = chatClient ?? throw new ArgumentNullException(nameof(chatClient));
    }

    /// <summary>
    /// Builds the system prompt with context about registered entities.
    /// </summary>
    public static string BuildSystemPrompt()
    {
        var entities = DataScaffold.Entities;
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < entities.Count; i++)
        {
            var e = entities[i];
            if (i > 0) sb.Append('\n');
            sb.Append($"  - {e.Name} (slug: {e.Slug}, {e.Fields.Count} fields)");
        }
        var entityList = sb.ToString();

        return $"""
            You are an AI assistant for a BareMetalWeb application.
            You help administrators manage entities, run queries, build reports, and configure the system.

            Available entities:
            {entityList}

            Use the provided tools to:
            - List and inspect entity schemas
            - Query, load, create, update, and delete entity records
            - Build reports and analyze data
            - Manage application settings

            Always confirm destructive operations (delete, bulk update) before executing.
            Respect user permissions — if a tool returns an error, explain it clearly.
            """;
    }

    /// <summary>
    /// Returns all AI function tools for registration with the Copilot SDK.
    /// </summary>
    public static IReadOnlyList<AIFunction> GetTools()
    {
        return
        [
            // Entity designer tools
            AIFunctionFactory.Create(EntityDesignerTools.ListEntities),
            AIFunctionFactory.Create(EntityDesignerTools.ListFieldTypes),
            AIFunctionFactory.Create(EntityDesignerTools.GetEntitySchema),
            AIFunctionFactory.Create(EntityDesignerTools.CreateEntitySchema),

            // Query tools
            AIFunctionFactory.Create(QueryTools.ListEntityFields),
            AIFunctionFactory.Create(QueryTools.GetOperators),
            AIFunctionFactory.Create(QueryTools.QueryEntities),
            AIFunctionFactory.Create(QueryTools.CountEntities),
            AIFunctionFactory.Create(QueryTools.LoadEntity),
            AIFunctionFactory.Create(QueryTools.SearchByName),

            // CRUD tools
            AIFunctionFactory.Create(CrudTools.SaveEntity),
            AIFunctionFactory.Create(CrudTools.DeleteEntity),

            // System tools
            AIFunctionFactory.Create(SystemTools.GetAppSetting),
            AIFunctionFactory.Create(SystemTools.ListAppSettings),
        ];
    }

    /// <summary>
    /// Sends a user message and returns the assistant's streamed response.
    /// </summary>
    public async IAsyncEnumerable<string> ChatAsync(
        string userMessage,
        IList<ChatMessage>? history = null)
    {
        history ??= new List<ChatMessage>();

        if (history.Count == 0)
        {
            history.Add(new ChatMessage(ChatRole.System, BuildSystemPrompt()));
        }

        history.Add(new ChatMessage(ChatRole.User, userMessage));

        var options = new ChatOptions
        {
            Tools = new List<AITool>()
        };
        foreach (var tool in GetTools())
            options.Tools.Add((AITool)tool);

        await foreach (var update in _chatClient.GetStreamingResponseAsync(history, options)
            .ConfigureAwait(false))
        {
            if (update.Text is { Length: > 0 } text)
                yield return text;
        }
    }
}

/// <summary>
/// CRUD tools for the admin assistant.
/// </summary>
public static class CrudTools
{
    [Description("Save (create or update) an entity record. Pass the entity slug, an optional key (0 for new), and a dictionary of field values.")]
    public static async Task<string> SaveEntity(
        string entitySlug, uint key, Dictionary<string, string?> fieldValues)
    {
        if (!DataScaffold.TryGetEntity(entitySlug, out var meta))
            return $"Entity '{entitySlug}' not found.";

        BaseDataObject instance;
        if (key > 0)
        {
            var existing = await meta.Handlers.LoadAsync(key, CancellationToken.None)
                .ConfigureAwait(false);
            instance = existing ?? meta.Handlers.Create();
            instance.Key = key;
        }
        else
        {
            instance = meta.Handlers.Create();
        }

        var layout = EntityLayoutCompiler.GetOrCompile(meta);
        foreach (var (fieldName, value) in fieldValues)
        {
            var field = layout.FieldByName(fieldName);
            if (field != null && value != null)
            {
                try
                {
                    object? converted = null;
                    var clrType = Nullable.GetUnderlyingType(field.ClrType) ?? field.ClrType;
                    if (clrType.IsEnum && value is string es)
                    {
                        // Reuse the cached AOT-safe name→value lookup from DataScaffold.
                        var lookup = DataScaffold.GetEnumLookup(clrType);
                        converted = lookup.TryGetValue(es, out var found) ? found : null;
                        if (converted == null) continue;
                    }
                    else if (clrType.IsEnum && value is IConvertible eic)
                        converted = EnumHelper.FromInt32(clrType, eic.ToInt32(null));
                    else if (value is IConvertible ic)
                    {
                        var code = Type.GetTypeCode(clrType);
                        converted = code switch
                        {
                            TypeCode.Int32   => (object)ic.ToInt32(null),
                            TypeCode.Int64   => ic.ToInt64(null),
                            TypeCode.Double  => ic.ToDouble(null),
                            TypeCode.Single  => ic.ToSingle(null),
                            TypeCode.Decimal => ic.ToDecimal(null),
                            TypeCode.Boolean => ic.ToBoolean(null),
                            TypeCode.String  => ic.ToString(null),
                            TypeCode.Byte    => ic.ToByte(null),
                            TypeCode.SByte   => ic.ToSByte(null),
                            TypeCode.Int16   => ic.ToInt16(null),
                            TypeCode.UInt16  => ic.ToUInt16(null),
                            TypeCode.UInt32  => ic.ToUInt32(null),
                            TypeCode.UInt64  => ic.ToUInt64(null),
                            TypeCode.DateTime => ic.ToDateTime(null),
                            _                => value,
                        };
                    }
                    if (converted != null)
                        field.Setter(instance, converted);
                }
                catch (Exception) { /* skip invalid values */ }
            }
        }

        await meta.Handlers.SaveAsync(instance, CancellationToken.None).ConfigureAwait(false);
        return $"Saved {entitySlug} with key {instance.Key}.";
    }

    [Description("Delete an entity record by slug and key.")]
    public static async Task<string> DeleteEntity(string entitySlug, uint key)
    {
        if (!DataScaffold.TryGetEntity(entitySlug, out var meta))
            return $"Entity '{entitySlug}' not found.";

        await meta.Handlers.DeleteAsync(key, CancellationToken.None).ConfigureAwait(false);
        return $"Deleted {entitySlug} key {key}.";
    }
}

/// <summary>
/// System administration tools.
/// </summary>
public static class SystemTools
{
    [Description("Get the value of an application setting by its setting ID.")]
    public static string GetAppSetting(string settingId)
    {
        return SettingsService.GetValue(settingId);
    }

    [Description("List all application settings. Returns an array of setting IDs.")]
    public static async Task<IReadOnlyList<SettingSummary>> ListAppSettings()
    {
        if (!DataScaffold.TryGetEntity("app-setting", out var meta))
            return Array.Empty<SettingSummary>();

        var items = await meta.Handlers.QueryAsync(null, CancellationToken.None)
            .ConfigureAwait(false);

        var layout = EntityLayoutCompiler.GetOrCompile(meta);
        var idField = layout.FieldByName("SettingId");
        var valueField = layout.FieldByName("Value");
        if (idField == null || valueField == null)
            return Array.Empty<SettingSummary>();

        var result = new List<SettingSummary>();
        foreach (var e in items)
        {
            result.Add(new SettingSummary(
                idField.Getter(e)?.ToString() ?? "",
                valueField.Getter(e)?.ToString() ?? ""
            ));
        }
        return result.ToArray();
    }
}

public sealed record SettingSummary(string SettingId, string Value);
