namespace BareMetalWeb.Data;

/// <summary>
/// Ordinal constants for <see cref="User"/> fields.
/// Use with <see cref="DataRecord.GetValue(int)"/> / <see cref="DataRecord.SetValue(int, object?)"/>
/// for ~1–2 ns field access — no dictionary lookup, no reflection.
/// </summary>
public static class UserFields
{
    public const int UserName = DataRecord.BaseFieldCount + 0;
    public const int DisplayName = DataRecord.BaseFieldCount + 1;
    public const int Email = DataRecord.BaseFieldCount + 2;
    public const int PasswordHash = DataRecord.BaseFieldCount + 3;
    public const int PasswordSalt = DataRecord.BaseFieldCount + 4;
    public const int PasswordIterations = DataRecord.BaseFieldCount + 5;
    public const int Permissions = DataRecord.BaseFieldCount + 6;
    public const int IsActive = DataRecord.BaseFieldCount + 7;
    public const int LastLoginUtc = DataRecord.BaseFieldCount + 8;
    public const int FailedLoginCount = DataRecord.BaseFieldCount + 9;
    public const int LockoutUntilUtc = DataRecord.BaseFieldCount + 10;
    public const int MfaEnabled = DataRecord.BaseFieldCount + 11;
    public const int MfaSecret = DataRecord.BaseFieldCount + 12;
    public const int MfaLastVerifiedStep = DataRecord.BaseFieldCount + 13;
    public const int MfaSecretEncrypted = DataRecord.BaseFieldCount + 14;
    public const int MfaPendingSecret = DataRecord.BaseFieldCount + 15;
    public const int MfaPendingExpiresUtc = DataRecord.BaseFieldCount + 16;
    public const int MfaPendingFailedAttempts = DataRecord.BaseFieldCount + 17;
    public const int MfaPendingSecretEncrypted = DataRecord.BaseFieldCount + 18;
    public const int MfaBackupCodeHashes = DataRecord.BaseFieldCount + 19;
    public const int MfaBackupCodesGeneratedUtc = DataRecord.BaseFieldCount + 20;
}

/// <summary>Ordinal constants for <see cref="UserSession"/> fields.</summary>
public static class UserSessionFields
{
    public const int UserId = DataRecord.BaseFieldCount + 0;
    public const int UserName = DataRecord.BaseFieldCount + 1;
    public const int DisplayName = DataRecord.BaseFieldCount + 2;
    public const int Permissions = DataRecord.BaseFieldCount + 3;
    public const int IssuedUtc = DataRecord.BaseFieldCount + 4;
    public const int ExpiresUtc = DataRecord.BaseFieldCount + 5;
    public const int LastSeenUtc = DataRecord.BaseFieldCount + 6;
    public const int RememberMe = DataRecord.BaseFieldCount + 7;
    public const int IsRevoked = DataRecord.BaseFieldCount + 8;
}

/// <summary>Ordinal constants for <see cref="AuditEntry"/> fields.</summary>
public static class AuditEntryFields
{
    public const int EntityType = DataRecord.BaseFieldCount + 0;
    public const int EntityKey = DataRecord.BaseFieldCount + 1;
    public const int Operation = DataRecord.BaseFieldCount + 2;
    public const int TimestampUtc = DataRecord.BaseFieldCount + 3;
    public const int UserName = DataRecord.BaseFieldCount + 4;
    public const int FieldChangesJson = DataRecord.BaseFieldCount + 5;
    public const int CommandName = DataRecord.BaseFieldCount + 6;
    public const int CommandParameters = DataRecord.BaseFieldCount + 7;
    public const int CommandResult = DataRecord.BaseFieldCount + 8;
    public const int Notes = DataRecord.BaseFieldCount + 9;
}

/// <summary>Ordinal constants for <see cref="AppSetting"/> fields.</summary>
public static class AppSettingFields
{
    public const int SettingId = DataRecord.BaseFieldCount + 0;
    public const int Value = DataRecord.BaseFieldCount + 1;
    public const int Description = DataRecord.BaseFieldCount + 2;
}

/// <summary>Ordinal constants for <see cref="ReportDefinition"/> fields.</summary>
public static class ReportDefinitionFields
{
    public const int Name = DataRecord.BaseFieldCount + 0;
    public const int Description = DataRecord.BaseFieldCount + 1;
    public const int RootEntity = DataRecord.BaseFieldCount + 2;
    public const int JoinsJson = DataRecord.BaseFieldCount + 3;
    public const int ColumnsJson = DataRecord.BaseFieldCount + 4;
    public const int FiltersJson = DataRecord.BaseFieldCount + 5;
    public const int ParametersJson = DataRecord.BaseFieldCount + 6;
    public const int SortField = DataRecord.BaseFieldCount + 7;
    public const int SortDescending = DataRecord.BaseFieldCount + 8;
}

/// <summary>Ordinal constants for Permission fields.</summary>
public static class PermissionFields
{
    public const int Code = DataRecord.BaseFieldCount + 0;
    public const int Description = DataRecord.BaseFieldCount + 1;
    public const int TargetEntity = DataRecord.BaseFieldCount + 2;
    public const int Actions = DataRecord.BaseFieldCount + 3;
    public const int ConditionExpression = DataRecord.BaseFieldCount + 4;
    public const int RequiresElevation = DataRecord.BaseFieldCount + 5;
}

/// <summary>Ordinal constants for SecurityRole fields.</summary>
public static class SecurityRoleFields
{
    public const int RoleName = DataRecord.BaseFieldCount + 0;
    public const int Description = DataRecord.BaseFieldCount + 1;
    public const int PermissionCodes = DataRecord.BaseFieldCount + 2;
}

/// <summary>Ordinal constants for SecurityGroup fields.</summary>
public static class SecurityGroupFields
{
    public const int GroupName = DataRecord.BaseFieldCount + 0;
    public const int Description = DataRecord.BaseFieldCount + 1;
    public const int RoleNames = DataRecord.BaseFieldCount + 2;
    public const int MemberKeys = DataRecord.BaseFieldCount + 3;
    public const int NestedGroupKeys = DataRecord.BaseFieldCount + 4;
}

/// <summary>Ordinal constants for <see cref="MfaChallenge"/> fields.</summary>
public static class MfaChallengeFields
{
    public const int UserId = DataRecord.BaseFieldCount + 0;
    public const int RememberMe = DataRecord.BaseFieldCount + 1;
    public const int ExpiresUtc = DataRecord.BaseFieldCount + 2;
    public const int IsUsed = DataRecord.BaseFieldCount + 3;
}

/// <summary>Ordinal constants for <see cref="DeviceCodeAuth"/> fields.</summary>
public static class DeviceCodeAuthFields
{
    public const int UserCode = DataRecord.BaseFieldCount + 0;
    public const int DeviceCode = DataRecord.BaseFieldCount + 1;
    public const int ExpiresUtc = DataRecord.BaseFieldCount + 2;
    public const int Status = DataRecord.BaseFieldCount + 3;
    public const int UserId = DataRecord.BaseFieldCount + 4;
    public const int ClientDescription = DataRecord.BaseFieldCount + 5;
}

/// <summary>Ordinal constants for EntityDefinition fields.</summary>
public static class EntityDefinitionFields
{
    public const int EntityId = DataRecord.BaseFieldCount + 0;
    public const int Name = DataRecord.BaseFieldCount + 1;
    public const int Slug = DataRecord.BaseFieldCount + 2;
    public const int Version = DataRecord.BaseFieldCount + 3;
    public const int IdStrategy = DataRecord.BaseFieldCount + 4;
    public const int ShowOnNav = DataRecord.BaseFieldCount + 5;
    public const int Permissions = DataRecord.BaseFieldCount + 6;
    public const int NavGroup = DataRecord.BaseFieldCount + 7;
    public const int NavOrder = DataRecord.BaseFieldCount + 8;
    public const int SchemaHash = DataRecord.BaseFieldCount + 9;
}

/// <summary>Ordinal constants for FieldDefinition fields.</summary>
public static class FieldDefinitionFields
{
    public const int FieldId = DataRecord.BaseFieldCount + 0;
    public const int EntityId = DataRecord.BaseFieldCount + 1;
    public const int Name = DataRecord.BaseFieldCount + 2;
    public const int Label = DataRecord.BaseFieldCount + 3;
    public const int Ordinal = DataRecord.BaseFieldCount + 4;
    public const int Type = DataRecord.BaseFieldCount + 5;
    public const int IsNullable = DataRecord.BaseFieldCount + 6;
    public const int Required = DataRecord.BaseFieldCount + 7;
    public const int List = DataRecord.BaseFieldCount + 8;
    public const int View = DataRecord.BaseFieldCount + 9;
    public const int Edit = DataRecord.BaseFieldCount + 10;
    public const int Create = DataRecord.BaseFieldCount + 11;
    public const int ReadOnly = DataRecord.BaseFieldCount + 12;
    public const int DefaultValue = DataRecord.BaseFieldCount + 13;
    public const int Placeholder = DataRecord.BaseFieldCount + 14;
    public const int MinLength = DataRecord.BaseFieldCount + 15;
    public const int MaxLength = DataRecord.BaseFieldCount + 16;
    public const int RangeMin = DataRecord.BaseFieldCount + 17;
    public const int RangeMax = DataRecord.BaseFieldCount + 18;
    public const int Pattern = DataRecord.BaseFieldCount + 19;
    public const int EnumValues = DataRecord.BaseFieldCount + 20;
    public const int LookupEntitySlug = DataRecord.BaseFieldCount + 21;
    public const int LookupValueField = DataRecord.BaseFieldCount + 22;
    public const int LookupDisplayField = DataRecord.BaseFieldCount + 23;
    public const int Multiline = DataRecord.BaseFieldCount + 24;
    public const int ChildEntitySlug = DataRecord.BaseFieldCount + 25;
    public const int LookupCopyFields = DataRecord.BaseFieldCount + 26;
    public const int CalculatedExpression = DataRecord.BaseFieldCount + 27;
    public const int CalculatedDisplayFormat = DataRecord.BaseFieldCount + 28;
    public const int CopyFromParentField = DataRecord.BaseFieldCount + 29;
    public const int CopyFromParentSlug = DataRecord.BaseFieldCount + 30;
    public const int CopyFromParentSourceField = DataRecord.BaseFieldCount + 31;
    public const int RelatedDocumentSlug = DataRecord.BaseFieldCount + 32;
    public const int RelatedDocumentDisplayField = DataRecord.BaseFieldCount + 33;
    public const int CascadeFromField = DataRecord.BaseFieldCount + 34;
    public const int CascadeFilterField = DataRecord.BaseFieldCount + 35;
    public const int FieldGroup = DataRecord.BaseFieldCount + 36;
    public const int ColumnSpan = DataRecord.BaseFieldCount + 37;
}

/// <summary>Ordinal constants for IndexDefinition fields.</summary>
public static class IndexDefinitionFields
{
    public const int EntityId = DataRecord.BaseFieldCount + 0;
    public const int FieldNames = DataRecord.BaseFieldCount + 1;
    public const int Type = DataRecord.BaseFieldCount + 2;
}

/// <summary>Ordinal constants for ActionDefinition fields.</summary>
public static class ActionDefinitionFields
{
    public const int EntityId = DataRecord.BaseFieldCount + 0;
    public const int Name = DataRecord.BaseFieldCount + 1;
    public const int Label = DataRecord.BaseFieldCount + 2;
    public const int Icon = DataRecord.BaseFieldCount + 3;
    public const int Permission = DataRecord.BaseFieldCount + 4;
    public const int EnabledWhen = DataRecord.BaseFieldCount + 5;
    public const int Operations = DataRecord.BaseFieldCount + 6;
    public const int Version = DataRecord.BaseFieldCount + 7;
}

/// <summary>Ordinal constants for ActionCommandDefinition fields.</summary>
public static class ActionCommandDefinitionFields
{
    public const int ActionId = DataRecord.BaseFieldCount + 0;
    public const int CommandType = DataRecord.BaseFieldCount + 1;
    public const int Order = DataRecord.BaseFieldCount + 2;
    public const int ParentCommandId = DataRecord.BaseFieldCount + 3;
    public const int Condition = DataRecord.BaseFieldCount + 4;
    public const int FieldId = DataRecord.BaseFieldCount + 5;
    public const int ValueExpression = DataRecord.BaseFieldCount + 6;
    public const int ListFieldId = DataRecord.BaseFieldCount + 7;
    public const int Severity = DataRecord.BaseFieldCount + 8;
    public const int ErrorCode = DataRecord.BaseFieldCount + 9;
    public const int Message = DataRecord.BaseFieldCount + 10;
    public const int TargetEntityType = DataRecord.BaseFieldCount + 11;
    public const int TargetActionId = DataRecord.BaseFieldCount + 12;
    public const int ParameterMap = DataRecord.BaseFieldCount + 13;
}

/// <summary>Ordinal constants for SessionLog fields.</summary>
public static class SessionLogFields
{
    public const int UserName = DataRecord.BaseFieldCount + 0;
    public const int LoginUtc = DataRecord.BaseFieldCount + 1;
    public const int LogoutUtc = DataRecord.BaseFieldCount + 2;
    public const int IpAddress = DataRecord.BaseFieldCount + 3;
    public const int UserAgent = DataRecord.BaseFieldCount + 4;
}
