using System.Collections.Generic;

namespace BareMetalWeb.Data;

/// <summary>
/// Embedded <see cref="EntitySchema"/> definitions for all system entity types.
/// Built once at startup; provides the metadata foundation for AOT-safe field
/// access via ordinal constants in the <c>*Fields</c> companion classes.
/// </summary>
public static class SystemEntitySchemas
{
    public static EntitySchema User { get; } = new EntitySchema.Builder("User", "users")
        .AddField("UserName", FieldType.StringUtf8, typeof(string), required: true, indexed: true)
        .AddField("DisplayName", FieldType.StringUtf8, typeof(string), required: true)
        .AddField("Email", FieldType.StringUtf8, typeof(string), required: true, indexed: true)
        .AddField("PasswordHash", FieldType.StringUtf8, typeof(string))
        .AddField("PasswordSalt", FieldType.StringUtf8, typeof(string))
        .AddField("PasswordIterations", FieldType.Int32, typeof(int))
        .AddField("Permissions", FieldType.StringUtf8, typeof(string))
        .AddField("IsActive", FieldType.Bool, typeof(bool))
        .AddField("LastLoginUtc", FieldType.DateTime, typeof(DateTime?), nullable: true)
        .AddField("FailedLoginCount", FieldType.Int32, typeof(int))
        .AddField("LockoutUntilUtc", FieldType.DateTime, typeof(DateTime?), nullable: true)
        .AddField("MfaEnabled", FieldType.Bool, typeof(bool))
        .AddField("MfaSecret", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("MfaLastVerifiedStep", FieldType.Int64, typeof(long))
        .AddField("MfaSecretEncrypted", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("MfaPendingSecret", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("MfaPendingExpiresUtc", FieldType.DateTime, typeof(DateTime?), nullable: true)
        .AddField("MfaPendingFailedAttempts", FieldType.Int32, typeof(int))
        .AddField("MfaPendingSecretEncrypted", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("MfaBackupCodeHashes", FieldType.StringUtf8, typeof(string))
        .AddField("MfaBackupCodesGeneratedUtc", FieldType.DateTime, typeof(DateTime?), nullable: true)
        .Build();

    public static EntitySchema UserSession { get; } = new EntitySchema.Builder("UserSession", "user-sessions")
        .AddField("UserId", FieldType.StringUtf8, typeof(string), indexed: true)
        .AddField("UserName", FieldType.StringUtf8, typeof(string))
        .AddField("DisplayName", FieldType.StringUtf8, typeof(string))
        .AddField("Permissions", FieldType.StringUtf8, typeof(string))
        .AddField("IssuedUtc", FieldType.DateTime, typeof(DateTime))
        .AddField("ExpiresUtc", FieldType.DateTime, typeof(DateTime))
        .AddField("LastSeenUtc", FieldType.DateTime, typeof(DateTime))
        .AddField("RememberMe", FieldType.Bool, typeof(bool))
        .AddField("IsRevoked", FieldType.Bool, typeof(bool))
        .Build();

    public static EntitySchema AuditEntry { get; } = new EntitySchema.Builder("AuditEntry", "auditentry")
        .AddField("EntityType", FieldType.StringUtf8, typeof(string), required: true, indexed: true)
        .AddField("EntityKey", FieldType.UInt32, typeof(uint), required: true, indexed: true)
        .AddField("Operation", FieldType.Int32, typeof(int), required: true, indexed: true)
        .AddField("TimestampUtc", FieldType.DateTime, typeof(DateTime), required: true, indexed: true)
        .AddField("UserName", FieldType.StringUtf8, typeof(string), required: true, indexed: true)
        .AddField("FieldChangesJson", FieldType.StringUtf8, typeof(string))
        .AddField("CommandName", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("CommandParameters", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("CommandResult", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("Notes", FieldType.StringUtf8, typeof(string), nullable: true)
        .Build();

    public static EntitySchema AppSetting { get; } = new EntitySchema.Builder("AppSetting", "settings")
        .AddField("SettingId", FieldType.StringUtf8, typeof(string), required: true, indexed: true)
        .AddField("Value", FieldType.StringUtf8, typeof(string))
        .AddField("Description", FieldType.StringUtf8, typeof(string))
        .Build();

    public static EntitySchema ReportDefinition { get; } = new EntitySchema.Builder("ReportDefinition", "report-definitions")
        .AddField("Name", FieldType.StringUtf8, typeof(string), required: true)
        .AddField("Description", FieldType.StringUtf8, typeof(string))
        .AddField("RootEntity", FieldType.StringUtf8, typeof(string), required: true)
        .AddField("JoinsJson", FieldType.StringUtf8, typeof(string))
        .AddField("ColumnsJson", FieldType.StringUtf8, typeof(string))
        .AddField("FiltersJson", FieldType.StringUtf8, typeof(string))
        .AddField("ParametersJson", FieldType.StringUtf8, typeof(string))
        .AddField("SortField", FieldType.StringUtf8, typeof(string))
        .AddField("SortDescending", FieldType.Bool, typeof(bool))
        .Build();

    public static EntitySchema Permission { get; } = new EntitySchema.Builder("Permission", "permissions")
        .AddField("Code", FieldType.StringUtf8, typeof(string), required: true, indexed: true)
        .AddField("Description", FieldType.StringUtf8, typeof(string))
        .AddField("TargetEntity", FieldType.StringUtf8, typeof(string))
        .AddField("Actions", FieldType.StringUtf8, typeof(string), required: true)
        .AddField("ConditionExpression", FieldType.StringUtf8, typeof(string))
        .AddField("RequiresElevation", FieldType.Bool, typeof(bool))
        .Build();

    public static EntitySchema SecurityRole { get; } = new EntitySchema.Builder("SecurityRole", "roles")
        .AddField("RoleName", FieldType.StringUtf8, typeof(string), required: true, indexed: true)
        .AddField("Description", FieldType.StringUtf8, typeof(string))
        .AddField("PermissionCodes", FieldType.StringUtf8, typeof(string))
        .Build();

    public static EntitySchema SecurityGroup { get; } = new EntitySchema.Builder("SecurityGroup", "security-groups")
        .AddField("GroupName", FieldType.StringUtf8, typeof(string), required: true, indexed: true)
        .AddField("Description", FieldType.StringUtf8, typeof(string))
        .AddField("RoleNames", FieldType.StringUtf8, typeof(string))
        .AddField("MemberKeys", FieldType.StringUtf8, typeof(string))
        .AddField("NestedGroupKeys", FieldType.StringUtf8, typeof(string))
        .Build();

    public static EntitySchema MfaChallenge { get; } = new EntitySchema.Builder("MfaChallenge", "mfa-challenges")
        .AddField("UserId", FieldType.StringUtf8, typeof(string))
        .AddField("RememberMe", FieldType.Bool, typeof(bool))
        .AddField("ExpiresUtc", FieldType.DateTime, typeof(DateTime))
        .AddField("IsUsed", FieldType.Bool, typeof(bool))
        .Build();

    public static EntitySchema DeviceCodeAuth { get; } = new EntitySchema.Builder("DeviceCodeAuth", "device-code-auth")
        .AddField("UserCode", FieldType.StringUtf8, typeof(string))
        .AddField("DeviceCode", FieldType.StringUtf8, typeof(string))
        .AddField("ExpiresUtc", FieldType.DateTime, typeof(DateTime))
        .AddField("Status", FieldType.StringUtf8, typeof(string))
        .AddField("UserId", FieldType.StringUtf8, typeof(string))
        .AddField("ClientDescription", FieldType.StringUtf8, typeof(string))
        .Build();

    public static EntitySchema EntityDefinition { get; } = new EntitySchema.Builder("EntityDefinition", "entity-definitions")
        .AddField("EntityId", FieldType.StringUtf8, typeof(string))
        .AddField("Name", FieldType.StringUtf8, typeof(string), required: true)
        .AddField("Slug", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("Version", FieldType.Int32, typeof(int))
        .AddField("IdStrategy", FieldType.StringUtf8, typeof(string))
        .AddField("ShowOnNav", FieldType.Bool, typeof(bool))
        .AddField("Permissions", FieldType.StringUtf8, typeof(string))
        .AddField("NavGroup", FieldType.StringUtf8, typeof(string))
        .AddField("NavOrder", FieldType.Int32, typeof(int))
        .AddField("SchemaHash", FieldType.StringUtf8, typeof(string))
        .Build();

    public static EntitySchema FieldDefinition { get; } = new EntitySchema.Builder("FieldDefinition", "field-definitions")
        .AddField("FieldId", FieldType.StringUtf8, typeof(string))
        .AddField("EntityId", FieldType.StringUtf8, typeof(string), required: true)
        .AddField("Name", FieldType.StringUtf8, typeof(string), required: true)
        .AddField("Label", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("Ordinal", FieldType.Int32, typeof(int))
        .AddField("Type", FieldType.StringUtf8, typeof(string), required: true)
        .AddField("IsNullable", FieldType.Bool, typeof(bool))
        .AddField("Required", FieldType.Bool, typeof(bool))
        .AddField("List", FieldType.Bool, typeof(bool))
        .AddField("View", FieldType.Bool, typeof(bool))
        .AddField("Edit", FieldType.Bool, typeof(bool))
        .AddField("Create", FieldType.Bool, typeof(bool))
        .AddField("ReadOnly", FieldType.Bool, typeof(bool))
        .AddField("DefaultValue", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("Placeholder", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("MinLength", FieldType.Int32, typeof(int?), nullable: true)
        .AddField("MaxLength", FieldType.Int32, typeof(int?), nullable: true)
        .AddField("RangeMin", FieldType.Decimal, typeof(double?), nullable: true)
        .AddField("RangeMax", FieldType.Decimal, typeof(double?), nullable: true)
        .AddField("Pattern", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("EnumValues", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("LookupEntitySlug", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("LookupValueField", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("LookupDisplayField", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("Multiline", FieldType.Bool, typeof(bool))
        .Build();

    public static EntitySchema IndexDefinition { get; } = new EntitySchema.Builder("IndexDefinition", "index-definitions")
        .AddField("EntityId", FieldType.StringUtf8, typeof(string), required: true)
        .AddField("FieldNames", FieldType.StringUtf8, typeof(string), required: true)
        .AddField("Type", FieldType.StringUtf8, typeof(string))
        .Build();

    public static EntitySchema ActionDefinition { get; } = new EntitySchema.Builder("ActionDefinition", "action-definitions")
        .AddField("EntityId", FieldType.StringUtf8, typeof(string), required: true)
        .AddField("Name", FieldType.StringUtf8, typeof(string), required: true)
        .AddField("Label", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("Icon", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("Permission", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("EnabledWhen", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("Operations", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("Version", FieldType.Int32, typeof(int))
        .Build();

    public static EntitySchema ActionCommandDefinition { get; } = new EntitySchema.Builder("ActionCommandDefinition", "action-commands")
        .AddField("ActionId", FieldType.StringUtf8, typeof(string), required: true)
        .AddField("CommandType", FieldType.StringUtf8, typeof(string), required: true)
        .AddField("Order", FieldType.Int32, typeof(int))
        .AddField("ParentCommandId", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("Condition", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("FieldId", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("ValueExpression", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("ListFieldId", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("Severity", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("ErrorCode", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("Message", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("TargetEntityType", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("TargetActionId", FieldType.StringUtf8, typeof(string), nullable: true)
        .AddField("ParameterMap", FieldType.StringUtf8, typeof(string), nullable: true)
        .Build();

    public static EntitySchema SessionLog { get; } = new EntitySchema.Builder("SessionLog", "sessions")
        .AddField("UserName", FieldType.StringUtf8, typeof(string), indexed: true)
        .AddField("LoginUtc", FieldType.DateTime, typeof(DateTime))
        .AddField("LogoutUtc", FieldType.DateTime, typeof(DateTime?), nullable: true)
        .AddField("IpAddress", FieldType.StringUtf8, typeof(string))
        .AddField("UserAgent", FieldType.StringUtf8, typeof(string))
        .Build();

    public static EntitySchema RecordComment { get; } = new EntitySchema.Builder("RecordComment", "recordcomment")
        .AddField("RecordType", FieldType.StringUtf8, typeof(string), required: true, indexed: true)
        .AddField("RecordKey", FieldType.UInt32, typeof(uint), required: true, indexed: true)
        .AddField("Text", FieldType.StringUtf8, typeof(string), required: true)
        .Build();

    public static EntitySchema Module { get; } = new EntitySchema.Builder("Module", "modules")
        .AddField("ModuleId", FieldType.StringUtf8, typeof(string), required: true, indexed: true)
        .AddField("Name", FieldType.StringUtf8, typeof(string), required: true)
        .AddField("Version", FieldType.StringUtf8, typeof(string))
        .AddField("EntitySlugs", FieldType.StringUtf8, typeof(string))
        .AddField("ActionKeys", FieldType.StringUtf8, typeof(string))
        .AddField("ReportSlugs", FieldType.StringUtf8, typeof(string))
        .AddField("RequiredPermissions", FieldType.StringUtf8, typeof(string))
        .AddField("NavGroup", FieldType.StringUtf8, typeof(string))
        .AddField("Dependencies", FieldType.StringUtf8, typeof(string))
        .AddField("Isolation", FieldType.StringUtf8, typeof(string))
        .AddField("Enabled", FieldType.Bool, typeof(bool))
        .Build();

    public static EntitySchema ChatSession { get; } = new EntitySchema.Builder("ChatSession", "chat-sessions")
        .AddField("UserName", FieldType.StringUtf8, typeof(string), required: true, indexed: true)
        .AddField("Title", FieldType.StringUtf8, typeof(string), required: true)
        .AddField("CreatedAtUtc", FieldType.DateTime, typeof(DateTime))
        .AddField("UpdatedAtUtc", FieldType.DateTime, typeof(DateTime))
        .AddField("MessageCount", FieldType.Int32, typeof(int))
        .AddField("Status", FieldType.StringUtf8, typeof(string))
        .Build();

    public static EntitySchema ChatMessage { get; } = new EntitySchema.Builder("ChatMessage", "chat-messages")
        .AddField("SessionId", FieldType.UInt32, typeof(uint), required: true, indexed: true)
        .AddField("Role", FieldType.StringUtf8, typeof(string), required: true)
        .AddField("Content", FieldType.StringUtf8, typeof(string), required: true)
        .AddField("TimestampUtc", FieldType.DateTime, typeof(DateTime))
        .AddField("TokenCount", FieldType.Int32, typeof(int))
        .AddField("LatencyMs", FieldType.Int32, typeof(int))
        .AddField("ResolvedIntent", FieldType.StringUtf8, typeof(string))
        .AddField("Confidence", FieldType.Decimal, typeof(decimal))
        .Build();

    public static EntitySchema RuntimeRelease { get; } = new EntitySchema.Builder("RuntimeRelease", "runtime-releases")
        .AddField("Version", FieldType.StringUtf8, typeof(string), required: true, indexed: true)
        .AddField("Architecture", FieldType.StringUtf8, typeof(string), required: true, indexed: true)
        .AddField("Sha256", FieldType.StringUtf8, typeof(string), required: true)
        .AddField("FileSizeBytes", FieldType.Int64, typeof(long))
        .AddField("PublishedAtUtc", FieldType.DateTime, typeof(DateTime))
        .AddField("TargetRing", FieldType.StringUtf8, typeof(string), required: true, indexed: true)
        .AddField("IsActive", FieldType.Bool, typeof(bool))
        .AddField("Notes", FieldType.StringUtf8, typeof(string))
        .Build();

    public static EntitySchema DeploymentNode { get; } = new EntitySchema.Builder("DeploymentNode", "deployment-nodes")
        .AddField("NodeId", FieldType.StringUtf8, typeof(string), required: true, indexed: true)
        .AddField("SecretHash", FieldType.StringUtf8, typeof(string), required: true)
        .AddField("Ring", FieldType.StringUtf8, typeof(string), required: true, indexed: true)
        .AddField("Architecture", FieldType.StringUtf8, typeof(string))
        .AddField("CurrentVersion", FieldType.StringUtf8, typeof(string))
        .AddField("LastHeartbeatUtc", FieldType.DateTime, typeof(DateTime))
        .AddField("PollIntervalSeconds", FieldType.Int32, typeof(int))
        .AddField("IsEnabled", FieldType.Bool, typeof(bool))
        .AddField("DisplayName", FieldType.StringUtf8, typeof(string))
        .AddField("ClusterEndpoint", FieldType.StringUtf8, typeof(string))
        .Build();

    /// <summary>All system entity schemas, for bulk registration.</summary>
    public static IReadOnlyList<EntitySchema> All { get; } = new[]
    {
        User, UserSession, AuditEntry, AppSetting, ReportDefinition,
        Permission, SecurityRole, SecurityGroup,
        MfaChallenge, DeviceCodeAuth,
        EntityDefinition, FieldDefinition, IndexDefinition,
        ActionDefinition, ActionCommandDefinition,
        SessionLog,
        RecordComment,
        Module,
        ChatSession,
        ChatMessage,
        RuntimeRelease,
        DeploymentNode
    };

    // ── Name-based lookup ────────────────────────────────────────────────────

    private static readonly Dictionary<string, EntitySchema> s_byName = BuildByNameLookup();

    private static Dictionary<string, EntitySchema> BuildByNameLookup()
    {
        var dict = new Dictionary<string, EntitySchema>(All.Count, System.StringComparer.OrdinalIgnoreCase);
        foreach (var s in All)
            dict[s.EntityName] = s;
        return dict;
    }

    /// <summary>
    /// Returns the system <see cref="EntitySchema"/> whose <see cref="EntitySchema.EntityName"/>
    /// matches <paramref name="entityTypeName"/> (case-insensitive), or <c>null</c> if no match.
    /// </summary>
    public static EntitySchema? GetByName(string entityTypeName)
        => s_byName.TryGetValue(entityTypeName, out var schema) ? schema : null;
}
