using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Low-allocation reader for <see cref="SamplePackage"/> JSON without
/// <c>JsonSerializer</c>. Uses <see cref="JsonDocument"/> with manual
/// property extraction. Handles both camelCase and PascalCase property
/// names for backward compatibility.
/// </summary>
public static class SamplePackageReader
{
    public static SamplePackage? ReadSamplePackage(Stream stream)
    {
        using var doc = JsonDocument.Parse(stream);
        return ReadPackage(doc.RootElement);
    }

    public static SamplePackage? ReadSamplePackage(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return ReadPackage(doc.RootElement);
    }

    // ── Top-level package ────────────────────────────────────────────────────

    private static SamplePackage ReadPackage(JsonElement el)
    {
        var pkg = new SamplePackage
        {
            Name        = Str(el, "name", "Name"),
            Slug        = Str(el, "slug", "Slug"),
            Description = Str(el, "description", "Description"),
            Icon        = Str(el, "icon", "Icon", "bi-box"),
            Version     = Str(el, "version", "Version", "1.0"),
        };

        if (TryArr(el, "entities", "Entities", out var entities))
            foreach (var e in entities) pkg.Entities.Add(ReadEntity(e));

        if (TryArr(el, "fields", "Fields", out var fields))
            foreach (var e in fields) pkg.Fields.Add(ReadField(e));

        if (TryArr(el, "indexes", "Indexes", out var indexes))
            foreach (var e in indexes) pkg.Indexes.Add(ReadIndex(e));

        if (TryArr(el, "actions", "Actions", out var actions))
            foreach (var e in actions) pkg.Actions.Add(ReadAction(e));

        if (TryArr(el, "actionCommands", "ActionCommands", out var cmds))
            foreach (var e in cmds) pkg.ActionCommands.Add(ReadActionCommand(e));

        if (TryArr(el, "reports", "Reports", out var reports))
            foreach (var e in reports) pkg.Reports.Add(ReadReport(e));

        if (TryArr(el, "roles", "Roles", out var roles))
            foreach (var e in roles) pkg.Roles.Add(ReadRole(e));

        if (TryArr(el, "permissions", "Permissions", out var perms))
            foreach (var e in perms) pkg.Permissions.Add(ReadPermission(e));

        if (TryArr(el, "aggregations", "Aggregations", out var aggs))
            foreach (var e in aggs) pkg.Aggregations.Add(ReadAggregation(e));

        if (TryArr(el, "scheduledActions", "ScheduledActions", out var sched))
            foreach (var e in sched) pkg.ScheduledActions.Add(ReadScheduledAction(e));

        if (TryArr(el, "workflowRules", "WorkflowRules", out var rules))
            foreach (var e in rules) pkg.WorkflowRules.Add(ReadWorkflowRule(e));

        return pkg;
    }

    // ── Entity types ─────────────────────────────────────────────────────────

    private static EntityDefinition ReadEntity(JsonElement el)
    {
        var e = new EntityDefinition
        {
            EntityId    = Str(el, "entityId", "EntityId"),
            Name        = Str(el, "name", "Name"),
            Slug        = NStr(el, "slug", "Slug"),
            Version     = Int(el, "version", "Version", 1),
            IdStrategy  = Str(el, "idStrategy", "IdStrategy", "guid"),
            ShowOnNav   = Bool(el, "showOnNav", "ShowOnNav"),
            Permissions = Str(el, "permissions", "Permissions"),
            NavGroup    = Str(el, "navGroup", "NavGroup", "Admin"),
            NavOrder    = Int(el, "navOrder", "NavOrder"),
            SchemaHash  = Str(el, "schemaHash", "SchemaHash"),
            FormLayout  = Str(el, "formLayout", "FormLayout", "Standard"),
        };
        return e;
    }

    private static FieldDefinition ReadField(JsonElement el)
    {
        return new FieldDefinition
        {
            FieldId                    = Str(el, "fieldId", "FieldId"),
            EntityId                   = Str(el, "entityId", "EntityId"),
            Name                       = Str(el, "name", "Name"),
            Label                      = NStr(el, "label", "Label"),
            Ordinal                    = Int(el, "ordinal", "Ordinal"),
            Type                       = Str(el, "type", "Type", "string"),
            IsNullable                 = Bool(el, "isNullable", "IsNullable", true),
            Required                   = Bool(el, "required", "Required"),
            List                       = Bool(el, "list", "List", true),
            View                       = Bool(el, "view", "View", true),
            Edit                       = Bool(el, "edit", "Edit", true),
            Create                     = Bool(el, "create", "Create", true),
            ReadOnly                   = Bool(el, "readOnly", "ReadOnly"),
            DefaultValue               = NStr(el, "defaultValue", "DefaultValue"),
            Placeholder                = NStr(el, "placeholder", "Placeholder"),
            MinLength                  = NInt(el, "minLength", "MinLength"),
            MaxLength                  = NInt(el, "maxLength", "MaxLength"),
            RangeMin                   = NDouble(el, "rangeMin", "RangeMin"),
            RangeMax                   = NDouble(el, "rangeMax", "RangeMax"),
            Pattern                    = NStr(el, "pattern", "Pattern"),
            EnumValues                 = NStr(el, "enumValues", "EnumValues"),
            LookupEntitySlug           = NStr(el, "lookupEntitySlug", "LookupEntitySlug"),
            LookupValueField           = NStr(el, "lookupValueField", "LookupValueField"),
            LookupDisplayField         = NStr(el, "lookupDisplayField", "LookupDisplayField"),
            Multiline                  = Bool(el, "multiline", "Multiline"),
            ChildEntitySlug            = NStr(el, "childEntitySlug", "ChildEntitySlug"),
            LookupCopyFields           = NStr(el, "lookupCopyFields", "LookupCopyFields"),
            CalculatedExpression       = NStr(el, "calculatedExpression", "CalculatedExpression"),
            CalculatedDisplayFormat    = NStr(el, "calculatedDisplayFormat", "CalculatedDisplayFormat"),
            CopyFromParentField        = NStr(el, "copyFromParentField", "CopyFromParentField"),
            CopyFromParentSlug         = NStr(el, "copyFromParentSlug", "CopyFromParentSlug"),
            CopyFromParentSourceField  = NStr(el, "copyFromParentSourceField", "CopyFromParentSourceField"),
            RelatedDocumentSlug        = NStr(el, "relatedDocumentSlug", "RelatedDocumentSlug"),
            RelatedDocumentDisplayField = NStr(el, "relatedDocumentDisplayField", "RelatedDocumentDisplayField"),
            CascadeFromField           = NStr(el, "cascadeFromField", "CascadeFromField"),
            CascadeFilterField         = NStr(el, "cascadeFilterField", "CascadeFilterField"),
            FieldGroup                 = NStr(el, "fieldGroup", "FieldGroup"),
            ColumnSpan                 = Int(el, "columnSpan", "ColumnSpan", 12),
        };
    }

    private static IndexDefinition ReadIndex(JsonElement el)
    {
        return new IndexDefinition
        {
            EntityId   = Str(el, "entityId", "EntityId"),
            FieldNames = Str(el, "fieldNames", "FieldNames"),
            Type       = Str(el, "type", "Type", "inverted"),
        };
    }

    private static ActionDefinition ReadAction(JsonElement el)
    {
        return new ActionDefinition
        {
            EntityId    = Str(el, "entityId", "EntityId"),
            Name        = Str(el, "name", "Name"),
            Label       = NStr(el, "label", "Label"),
            Icon        = NStr(el, "icon", "Icon"),
            Permission  = NStr(el, "permission", "Permission"),
            EnabledWhen = NStr(el, "enabledWhen", "EnabledWhen"),
            Operations  = NStr(el, "operations", "Operations"),
            Version     = Int(el, "version", "Version", 1),
        };
    }

    private static ActionCommandDefinition ReadActionCommand(JsonElement el)
    {
        return new ActionCommandDefinition
        {
            ActionId         = Str(el, "actionId", "ActionId"),
            CommandType      = Str(el, "commandType", "CommandType", "SetIf"),
            Order            = Int(el, "order", "Order"),
            ParentCommandId  = NStr(el, "parentCommandId", "ParentCommandId"),
            Condition        = NStr(el, "condition", "Condition"),
            FieldId          = NStr(el, "fieldId", "FieldId"),
            ValueExpression  = NStr(el, "valueExpression", "ValueExpression"),
            ListFieldId      = NStr(el, "listFieldId", "ListFieldId"),
            Severity         = NStr(el, "severity", "Severity"),
            ErrorCode        = NStr(el, "errorCode", "ErrorCode"),
            Message          = NStr(el, "message", "Message"),
            TargetEntityType = NStr(el, "targetEntityType", "TargetEntityType"),
            TargetActionId   = NStr(el, "targetActionId", "TargetActionId"),
            ParameterMap     = NStr(el, "parameterMap", "ParameterMap"),
        };
    }

    private static SampleReport ReadReport(JsonElement el)
    {
        return new SampleReport
        {
            Name           = Str(el, "name", "Name"),
            Description    = Str(el, "description", "Description"),
            RootEntity     = Str(el, "rootEntity", "RootEntity"),
            ColumnsJson    = Str(el, "columnsJson", "ColumnsJson", "[]"),
            FiltersJson    = Str(el, "filtersJson", "FiltersJson", "[]"),
            ParametersJson = Str(el, "parametersJson", "ParametersJson", "[]"),
            SortField      = Str(el, "sortField", "SortField"),
            SortDescending = Bool(el, "sortDescending", "SortDescending"),
            Permission     = NStr(el, "permission", "Permission"),
        };
    }

    private static SampleRole ReadRole(JsonElement el)
    {
        return new SampleRole
        {
            RoleName        = Str(el, "roleName", "RoleName"),
            Description     = Str(el, "description", "Description"),
            PermissionCodes = Str(el, "permissionCodes", "PermissionCodes"),
        };
    }

    private static SamplePermission ReadPermission(JsonElement el)
    {
        return new SamplePermission
        {
            Code              = Str(el, "code", "Code"),
            Description       = Str(el, "description", "Description"),
            TargetEntity      = Str(el, "targetEntity", "TargetEntity", "*"),
            Actions           = Str(el, "actions", "Actions", "*"),
            RequiresElevation = Bool(el, "requiresElevation", "RequiresElevation"),
        };
    }

    private static AggregationDefinition ReadAggregation(JsonElement el)
    {
        return new AggregationDefinition
        {
            EntityId      = Str(el, "entityId", "EntityId"),
            Name          = Str(el, "name", "Name"),
            GroupByFields = Str(el, "groupByFields", "GroupByFields"),
            Measures      = Str(el, "measures", "Measures"),
        };
    }

    private static ScheduledActionDefinition ReadScheduledAction(JsonElement el)
    {
        return new ScheduledActionDefinition
        {
            EntityId         = Str(el, "entityId", "EntityId"),
            Name             = Str(el, "name", "Name"),
            ActionName       = Str(el, "actionName", "ActionName"),
            Schedule         = Str(el, "schedule", "Schedule", "daily"),
            FilterExpression = NStr(el, "filterExpression", "FilterExpression"),
            Enabled          = Bool(el, "enabled", "Enabled", true),
            LastRunUtc       = NDateTime(el, "lastRunUtc", "LastRunUtc"),
            LastRunCount     = Int(el, "lastRunCount", "LastRunCount"),
        };
    }

    private static DomainEventSubscription ReadWorkflowRule(JsonElement el)
    {
        return new DomainEventSubscription
        {
            Name             = Str(el, "name", "Name"),
            SourceEntity     = Str(el, "sourceEntity", "SourceEntity"),
            WatchField       = NStr(el, "watchField", "WatchField"),
            FromValue        = NStr(el, "fromValue", "FromValue"),
            TriggerValue     = NStr(el, "triggerValue", "TriggerValue"),
            TargetAction     = Str(el, "targetAction", "TargetAction"),
            TargetResolution = Str(el, "targetResolution", "TargetResolution", "self"),
            Priority         = Int(el, "priority", "Priority", 100),
            Enabled          = Bool(el, "enabled", "Enabled", true),
        };
    }

    // ── Property-reading helpers (case-insensitive: try camelCase then PascalCase) ─

    private static bool TryGet(JsonElement el, string camel, string pascal, out JsonElement value)
    {
        return el.TryGetProperty(camel, out value) || el.TryGetProperty(pascal, out value);
    }

    private static string Str(JsonElement el, string camel, string pascal, string fallback = "")
    {
        return TryGet(el, camel, pascal, out var v) ? v.GetString() ?? fallback : fallback;
    }

    private static string? NStr(JsonElement el, string camel, string pascal)
    {
        return TryGet(el, camel, pascal, out var v) ? v.GetString() : null;
    }

    private static int Int(JsonElement el, string camel, string pascal, int fallback = 0)
    {
        return TryGet(el, camel, pascal, out var v) && v.ValueKind == JsonValueKind.Number
            ? v.GetInt32() : fallback;
    }

    private static int? NInt(JsonElement el, string camel, string pascal)
    {
        return TryGet(el, camel, pascal, out var v) && v.ValueKind == JsonValueKind.Number
            ? v.GetInt32() : null;
    }

    private static double? NDouble(JsonElement el, string camel, string pascal)
    {
        return TryGet(el, camel, pascal, out var v) && v.ValueKind == JsonValueKind.Number
            ? v.GetDouble() : null;
    }

    private static bool Bool(JsonElement el, string camel, string pascal, bool fallback = false)
    {
        if (!TryGet(el, camel, pascal, out var v)) return fallback;
        return v.ValueKind switch
        {
            JsonValueKind.True  => true,
            JsonValueKind.False => false,
            _                   => fallback
        };
    }

    private static DateTime? NDateTime(JsonElement el, string camel, string pascal)
    {
        if (!TryGet(el, camel, pascal, out var v) || v.ValueKind != JsonValueKind.String)
            return null;
        return DateTime.TryParse(v.GetString(), out var dt) ? dt : null;
    }

    private static bool TryArr(JsonElement el, string camel, string pascal, out JsonElement.ArrayEnumerator arr)
    {
        if (TryGet(el, camel, pascal, out var v) && v.ValueKind == JsonValueKind.Array)
        {
            arr = v.EnumerateArray();
            return true;
        }
        arr = default;
        return false;
    }
}
