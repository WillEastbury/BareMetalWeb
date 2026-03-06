using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Represents a shipped metadata sample package that can be deployed via the gallery page.
/// Each package bundles <see cref="EntityDefinition"/>, <see cref="FieldDefinition"/>, and
/// <see cref="IndexDefinition"/> records for a logical group of related entities.
/// </summary>
public sealed class SamplePackage
{
    /// <summary>Human-readable display name, e.g. "Sales Module".</summary>
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>Identifier that also matches the JSON file name, e.g. "sales".</summary>
    [JsonPropertyName("slug")]
    public string Slug { get; set; } = string.Empty;

    /// <summary>Short description shown on the gallery card.</summary>
    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    /// <summary>Bootstrap icon class, e.g. "bi-cart-check".</summary>
    [JsonPropertyName("icon")]
    public string Icon { get; set; } = "bi-box";

    /// <summary>Schema version of this sample file.</summary>
    [JsonPropertyName("version")]
    public string Version { get; set; } = "1.0";

    [JsonPropertyName("entities")]
    public List<EntityDefinition> Entities { get; set; } = new();

    [JsonPropertyName("fields")]
    public List<FieldDefinition> Fields { get; set; } = new();

    [JsonPropertyName("indexes")]
    public List<IndexDefinition> Indexes { get; set; } = new();

    [JsonPropertyName("actions")]
    public List<ActionDefinition> Actions { get; set; } = new();

    [JsonPropertyName("actionCommands")]
    public List<ActionCommandDefinition> ActionCommands { get; set; } = new();

    [JsonPropertyName("reports")]
    public List<SampleReport> Reports { get; set; } = new();

    /// <summary>Role definitions to create when deploying this package.</summary>
    [JsonPropertyName("roles")]
    public List<SampleRole> Roles { get; set; } = new();

    /// <summary>Permission definitions to create when deploying this package.</summary>
    [JsonPropertyName("permissions")]
    public List<SamplePermission> Permissions { get; set; } = new();

    [JsonPropertyName("aggregations")]
    public List<AggregationDefinition> Aggregations { get; set; } = new();

    [JsonPropertyName("scheduledActions")]
    public List<ScheduledActionDefinition> ScheduledActions { get; set; } = new();

    /// <summary>Workflow / automation rules to create when deploying this package.</summary>
    [JsonPropertyName("workflowRules")]
    public List<DomainEventSubscription> WorkflowRules { get; set; } = new();
}

/// <summary>
/// Lightweight report definition within a sample package.
/// Converted to <see cref="BareMetalWeb.Data.ReportDefinition"/> on deploy.
/// </summary>
public sealed class SampleReport
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    /// <summary>Slug of the root entity (resolved at deploy time).</summary>
    [JsonPropertyName("rootEntity")]
    public string RootEntity { get; set; } = string.Empty;

    [JsonPropertyName("columnsJson")]
    public string ColumnsJson { get; set; } = "[]";

    [JsonPropertyName("filtersJson")]
    public string FiltersJson { get; set; } = "[]";

    [JsonPropertyName("parametersJson")]
    public string ParametersJson { get; set; } = "[]";

    [JsonPropertyName("sortField")]
    public string SortField { get; set; } = string.Empty;

    [JsonPropertyName("sortDescending")]
    public bool SortDescending { get; set; }

    /// <summary>Permission token required to view the report.</summary>
    [JsonPropertyName("permission")]
    public string? Permission { get; set; }
}

/// <summary>
/// A role definition shipped with a sample package.
/// Stored as a DataRecord in the "roles" entity on deploy.
/// </summary>
public sealed class SampleRole
{
    [JsonPropertyName("roleName")]
    public string RoleName { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    /// <summary>Comma-separated permission codes granted by this role.</summary>
    [JsonPropertyName("permissionCodes")]
    public string PermissionCodes { get; set; } = string.Empty;
}

/// <summary>
/// A permission definition shipped with a sample package.
/// Stored as a DataRecord in the "permissions" entity on deploy.
/// </summary>
public sealed class SamplePermission
{
    /// <summary>Machine-readable permission code, e.g. "todo.read".</summary>
    [JsonPropertyName("code")]
    public string Code { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    /// <summary>Slug of the target entity, or "*" for global.</summary>
    [JsonPropertyName("targetEntity")]
    public string TargetEntity { get; set; } = "*";

    /// <summary>Comma-separated allowed actions: Read, Create, Update, Delete, Execute, *.</summary>
    [JsonPropertyName("actions")]
    public string Actions { get; set; } = "*";

    /// <summary>Whether this permission requires elevation (step-up auth).</summary>
    [JsonPropertyName("requiresElevation")]
    public bool RequiresElevation { get; set; }
}
