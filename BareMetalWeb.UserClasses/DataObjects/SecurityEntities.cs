using BareMetalWeb.Data;

namespace BareMetalWeb.Data.DataObjects;

/// <summary>
/// A named permission that can be assigned to roles.
/// Permissions can contain expressions for dynamic evaluation.
/// </summary>
[DataEntity("Permissions", ShowOnNav = true, NavGroup = "Admin", NavOrder = 10, Permissions = "admin")]
public class Permission : RenderableDataObject
{
    [DataField(Label = "Permission Code", Order = 1, Required = true)]
    [DataIndex]
    public string Code { get; set; } = string.Empty;

    [DataField(Label = "Description", Order = 2)]
    public string Description { get; set; } = string.Empty;

    /// <summary>Target entity slug this permission applies to, or "*" for global.</summary>
    [DataField(Label = "Target Entity", Order = 3)]
    public string TargetEntity { get; set; } = "*";

    /// <summary>CRUD action mask: Read, Create, Update, Delete, Execute, or * for all.</summary>
    [DataField(Label = "Actions", Order = 4, Required = true)]
    public string Actions { get; set; } = "Read";

    /// <summary>
    /// Optional expression evaluated at runtime to determine if permission applies.
    /// Empty = always granted. Example: "entity.OwnerId == user.Key"
    /// </summary>
    [DataField(Label = "Condition Expression", Order = 5)]
    public string ConditionExpression { get; set; } = string.Empty;

    /// <summary>When true, user must activate superuser/elevation mode to use this permission.</summary>
    [DataField(Label = "Requires Elevation", Order = 6)]
    public bool RequiresElevation { get; set; }

    public override string ToString() => Code;
}

/// <summary>
/// A role is a named collection of permissions.
/// Roles are assigned to groups.
/// </summary>
[DataEntity("Roles", ShowOnNav = true, NavGroup = "Admin", NavOrder = 20, Permissions = "admin")]
public class SecurityRole : RenderableDataObject
{
    [DataField(Label = "Role Name", Order = 1, Required = true)]
    [DataIndex]
    public string RoleName { get; set; } = string.Empty;

    [DataField(Label = "Description", Order = 2)]
    public string Description { get; set; } = string.Empty;

    /// <summary>Comma-separated permission codes assigned to this role.</summary>
    [DataField(Label = "Permission Codes", Order = 3)]
    public string PermissionCodes { get; set; } = string.Empty;

    public override string ToString() => RoleName;
}

/// <summary>
/// A security group containing principals (users/service principals).
/// Groups can have roles assigned and can nest other groups.
/// </summary>
[DataEntity("Security Groups", ShowOnNav = true, NavGroup = "Admin", NavOrder = 30, Permissions = "admin")]
public class SecurityGroup : RenderableDataObject
{
    [DataField(Label = "Group Name", Order = 1, Required = true)]
    [DataIndex]
    public string GroupName { get; set; } = string.Empty;

    [DataField(Label = "Description", Order = 2)]
    public string Description { get; set; } = string.Empty;

    /// <summary>Comma-separated role names assigned to this group.</summary>
    [DataField(Label = "Role Names", Order = 3)]
    public string RoleNames { get; set; } = string.Empty;

    /// <summary>Comma-separated member principal keys (User or SystemPrincipal uint keys).</summary>
    [DataField(Label = "Member Keys", Order = 4)]
    public string MemberKeys { get; set; } = string.Empty;

    /// <summary>Comma-separated nested group keys for group-in-group nesting.</summary>
    [DataField(Label = "Nested Group Keys", Order = 5)]
    public string NestedGroupKeys { get; set; } = string.Empty;

    public override string ToString() => GroupName;
}
