using System.Collections.Generic;
using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Represents a shipped metadata sample package that can be deployed via the gallery page.
/// Each package bundles <see cref="EntityDefinition"/>, <see cref="FieldDefinition"/>, and
/// <see cref="IndexDefinition"/> records for a logical group of related entities.
/// Deserialized manually via <see cref="SamplePackageJson"/> — no attribute-based serialization.
/// </summary>
public sealed class SamplePackage
{
    /// <summary>Human-readable display name, e.g. "Sales Module".</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Identifier that also matches the JSON file name, e.g. "sales".</summary>
    public string Slug { get; set; } = string.Empty;

    /// <summary>Short description shown on the gallery card.</summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>Bootstrap icon class, e.g. "bi-cart-check".</summary>
    public string Icon { get; set; } = "bi-box";

    /// <summary>Schema version of this sample file.</summary>
    public string Version { get; set; } = "1.0";

    public List<EntityDefinition> Entities { get; set; } = new();

    public List<FieldDefinition> Fields { get; set; } = new();

    public List<IndexDefinition> Indexes { get; set; } = new();

    /// <summary>Action definitions — stored as DataRecord via "action-definitions" slug.</summary>
    public List<DataRecord> Actions { get; set; } = new();

    /// <summary>Action commands — stored as DataRecord via "action-commands" slug.</summary>
    public List<DataRecord> ActionCommands { get; set; } = new();

    public List<SampleReport> Reports { get; set; } = new();

    /// <summary>Role definitions to create when deploying this package.</summary>
    public List<SampleRole> Roles { get; set; } = new();

    /// <summary>Permission definitions to create when deploying this package.</summary>
    public List<SamplePermission> Permissions { get; set; } = new();

    /// <summary>Aggregation definitions — stored as DataRecord via "aggregation-definitions" slug.</summary>
    public List<DataRecord> Aggregations { get; set; } = new();

    /// <summary>Scheduled actions — stored as DataRecord via "scheduled-actions" slug.</summary>
    public List<DataRecord> ScheduledActions { get; set; } = new();

    /// <summary>Workflow / automation rules — stored as DataRecord via "domain-event-subscriptions" slug.</summary>
    public List<DataRecord> WorkflowRules { get; set; } = new();
}

/// <summary>
/// Lightweight report definition within a sample package.
/// Converted to <see cref="BareMetalWeb.Data.ReportDefinition"/> on deploy.
/// </summary>
public sealed class SampleReport
{
    public string Name { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    /// <summary>Slug of the root entity (resolved at deploy time).</summary>
    public string RootEntity { get; set; } = string.Empty;

    public string ColumnsJson { get; set; } = "[]";

    public string FiltersJson { get; set; } = "[]";

    public string ParametersJson { get; set; } = "[]";

    public string SortField { get; set; } = string.Empty;

    public bool SortDescending { get; set; }

    /// <summary>Permission token required to view the report.</summary>
    public string? Permission { get; set; }
}

/// <summary>
/// A role definition shipped with a sample package.
/// Stored as a DataRecord in the "roles" entity on deploy.
/// </summary>
public sealed class SampleRole
{
    public string RoleName { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    /// <summary>Comma-separated permission codes granted by this role.</summary>
    public string PermissionCodes { get; set; } = string.Empty;
}

/// <summary>
/// A permission definition shipped with a sample package.
/// Stored as a DataRecord in the "permissions" entity on deploy.
/// </summary>
public sealed class SamplePermission
{
    /// <summary>Machine-readable permission code, e.g. "todo.read".</summary>
    public string Code { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    /// <summary>Slug of the target entity, or "*" for global.</summary>
    public string TargetEntity { get; set; } = "*";

    /// <summary>Comma-separated allowed actions: Read, Create, Update, Delete, Execute, *.</summary>
    public string Actions { get; set; } = "*";

    /// <summary>Whether this permission requires elevation (step-up auth).</summary>
    public bool RequiresElevation { get; set; }
}
