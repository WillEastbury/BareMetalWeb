namespace BareMetalWeb.Data;

/// <summary>
/// Ordinal constants for <see cref="User"/> fields.
/// Use with <see cref="DataRecord.GetValue(int)"/> / <see cref="DataRecord.SetValue(int, object?)"/>
/// for ~1–2 ns field access — no dictionary lookup, no reflection.
/// </summary>
public static class UserFields
{
    public const int UserName = 0;
    public const int DisplayName = 1;
    public const int Email = 2;
    public const int PasswordHash = 3;
    public const int PasswordSalt = 4;
    public const int PasswordIterations = 5;
    public const int Permissions = 6;
    public const int IsActive = 7;
    public const int LastLoginUtc = 8;
    public const int FailedLoginCount = 9;
    public const int LockoutUntilUtc = 10;
    public const int MfaEnabled = 11;
    public const int MfaSecret = 12;
    public const int MfaLastVerifiedStep = 13;
    public const int MfaSecretEncrypted = 14;
    public const int MfaPendingSecret = 15;
    public const int MfaPendingExpiresUtc = 16;
    public const int MfaPendingFailedAttempts = 17;
    public const int MfaPendingSecretEncrypted = 18;
    public const int MfaBackupCodeHashes = 19;
    public const int MfaBackupCodesGeneratedUtc = 20;
}

/// <summary>Ordinal constants for <see cref="UserSession"/> fields.</summary>
public static class UserSessionFields
{
    public const int UserId = 0;
    public const int UserName = 1;
    public const int DisplayName = 2;
    public const int Permissions = 3;
    public const int IssuedUtc = 4;
    public const int ExpiresUtc = 5;
    public const int LastSeenUtc = 6;
    public const int RememberMe = 7;
    public const int IsRevoked = 8;
}

/// <summary>Ordinal constants for <see cref="AuditEntry"/> fields.</summary>
public static class AuditEntryFields
{
    public const int EntityType = 0;
    public const int EntityKey = 1;
    public const int Operation = 2;
    public const int TimestampUtc = 3;
    public const int UserName = 4;
    public const int FieldChangesJson = 5;
    public const int CommandName = 6;
    public const int CommandParameters = 7;
    public const int CommandResult = 8;
    public const int Notes = 9;
}

/// <summary>Ordinal constants for <see cref="AppSetting"/> fields.</summary>
public static class AppSettingFields
{
    public const int SettingId = 0;
    public const int Value = 1;
    public const int Description = 2;
}

/// <summary>Ordinal constants for <see cref="ReportDefinition"/> fields.</summary>
public static class ReportDefinitionFields
{
    public const int Name = 0;
    public const int Description = 1;
    public const int RootEntity = 2;
    public const int JoinsJson = 3;
    public const int ColumnsJson = 4;
    public const int FiltersJson = 5;
    public const int ParametersJson = 6;
    public const int SortField = 7;
    public const int SortDescending = 8;
}

/// <summary>Ordinal constants for Permission fields.</summary>
public static class PermissionFields
{
    public const int Code = 0;
    public const int Description = 1;
    public const int TargetEntity = 2;
    public const int Actions = 3;
    public const int ConditionExpression = 4;
    public const int RequiresElevation = 5;
}

/// <summary>Ordinal constants for SecurityRole fields.</summary>
public static class SecurityRoleFields
{
    public const int RoleName = 0;
    public const int Description = 1;
    public const int PermissionCodes = 2;
}

/// <summary>Ordinal constants for SecurityGroup fields.</summary>
public static class SecurityGroupFields
{
    public const int GroupName = 0;
    public const int Description = 1;
    public const int RoleNames = 2;
    public const int MemberKeys = 3;
    public const int NestedGroupKeys = 4;
}

/// <summary>Ordinal constants for <see cref="MfaChallenge"/> fields.</summary>
public static class MfaChallengeFields
{
    public const int UserId = 0;
    public const int RememberMe = 1;
    public const int ExpiresUtc = 2;
    public const int IsUsed = 3;
}

/// <summary>Ordinal constants for <see cref="DeviceCodeAuth"/> fields.</summary>
public static class DeviceCodeAuthFields
{
    public const int UserCode = 0;
    public const int DeviceCode = 1;
    public const int ExpiresUtc = 2;
    public const int Status = 3;
    public const int UserId = 4;
    public const int ClientDescription = 5;
}

/// <summary>Ordinal constants for EntityDefinition fields.</summary>
public static class EntityDefinitionFields
{
    public const int EntityId = 0;
    public const int Name = 1;
    public const int Slug = 2;
    public const int Version = 3;
    public const int IdStrategy = 4;
    public const int ShowOnNav = 5;
    public const int Permissions = 6;
    public const int NavGroup = 7;
    public const int NavOrder = 8;
    public const int SchemaHash = 9;
}

/// <summary>Ordinal constants for FieldDefinition fields.</summary>
public static class FieldDefinitionFields
{
    public const int FieldId = 0;
    public const int EntityId = 1;
    public const int Name = 2;
    public const int Label = 3;
    public const int Ordinal = 4;
    public const int Type = 5;
    public const int IsNullable = 6;
    public const int Required = 7;
    public const int List = 8;
    public const int View = 9;
    public const int Edit = 10;
    public const int Create = 11;
    public const int ReadOnly = 12;
    public const int DefaultValue = 13;
    public const int Placeholder = 14;
    public const int MinLength = 15;
    public const int MaxLength = 16;
    public const int RangeMin = 17;
    public const int RangeMax = 18;
    public const int Pattern = 19;
    public const int EnumValues = 20;
    public const int LookupEntitySlug = 21;
    public const int LookupValueField = 22;
    public const int LookupDisplayField = 23;
    public const int Multiline = 24;
}

/// <summary>Ordinal constants for IndexDefinition fields.</summary>
public static class IndexDefinitionFields
{
    public const int EntityId = 0;
    public const int FieldNames = 1;
    public const int Type = 2;
}

/// <summary>Ordinal constants for ActionDefinition fields.</summary>
public static class ActionDefinitionFields
{
    public const int EntityId = 0;
    public const int Name = 1;
    public const int Label = 2;
    public const int Icon = 3;
    public const int Permission = 4;
    public const int EnabledWhen = 5;
    public const int Operations = 6;
    public const int Version = 7;
}

/// <summary>Ordinal constants for ActionCommandDefinition fields.</summary>
public static class ActionCommandDefinitionFields
{
    public const int ActionId = 0;
    public const int CommandType = 1;
    public const int Order = 2;
    public const int ParentCommandId = 3;
    public const int Condition = 4;
    public const int FieldId = 5;
    public const int ValueExpression = 6;
    public const int ListFieldId = 7;
    public const int Severity = 8;
    public const int ErrorCode = 9;
    public const int Message = 10;
    public const int TargetEntityType = 11;
    public const int TargetActionId = 12;
    public const int ParameterMap = 13;
}

/// <summary>Ordinal constants for SessionLog fields.</summary>
public static class SessionLogFields
{
    public const int UserName = 0;
    public const int LoginUtc = 1;
    public const int LogoutUtc = 2;
    public const int IpAddress = 3;
    public const int UserAgent = 4;
}
