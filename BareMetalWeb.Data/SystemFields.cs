namespace BareMetalWeb.Data;

/// <summary>
/// Ordinal constants for <see cref="User"/> fields.
/// Use with <see cref="DataRecord.GetValue(int)"/> / <see cref="DataRecord.SetValue(int, object?)"/>
/// for ~1–2 ns field access — no dictionary lookup, no reflection.
/// </summary>
public static class UserFields
{
    public const int UserName = BaseDataObject.BaseFieldCount + 0;
    public const int DisplayName = BaseDataObject.BaseFieldCount + 1;
    public const int Email = BaseDataObject.BaseFieldCount + 2;
    public const int PasswordHash = BaseDataObject.BaseFieldCount + 3;
    public const int PasswordSalt = BaseDataObject.BaseFieldCount + 4;
    public const int PasswordIterations = BaseDataObject.BaseFieldCount + 5;
    public const int Permissions = BaseDataObject.BaseFieldCount + 6;
    public const int IsActive = BaseDataObject.BaseFieldCount + 7;
    public const int LastLoginUtc = BaseDataObject.BaseFieldCount + 8;
    public const int FailedLoginCount = BaseDataObject.BaseFieldCount + 9;
    public const int LockoutUntilUtc = BaseDataObject.BaseFieldCount + 10;
    public const int MfaEnabled = BaseDataObject.BaseFieldCount + 11;
    public const int MfaSecret = BaseDataObject.BaseFieldCount + 12;
    public const int MfaLastVerifiedStep = BaseDataObject.BaseFieldCount + 13;
    public const int MfaSecretEncrypted = BaseDataObject.BaseFieldCount + 14;
    public const int MfaPendingSecret = BaseDataObject.BaseFieldCount + 15;
    public const int MfaPendingExpiresUtc = BaseDataObject.BaseFieldCount + 16;
    public const int MfaPendingFailedAttempts = BaseDataObject.BaseFieldCount + 17;
    public const int MfaPendingSecretEncrypted = BaseDataObject.BaseFieldCount + 18;
    public const int MfaBackupCodeHashes = BaseDataObject.BaseFieldCount + 19;
    public const int MfaBackupCodesGeneratedUtc = BaseDataObject.BaseFieldCount + 20;
}

/// <summary>Ordinal constants for <see cref="UserSession"/> fields.</summary>
public static class UserSessionFields
{
    public const int UserId = BaseDataObject.BaseFieldCount + 0;
    public const int UserName = BaseDataObject.BaseFieldCount + 1;
    public const int DisplayName = BaseDataObject.BaseFieldCount + 2;
    public const int Permissions = BaseDataObject.BaseFieldCount + 3;
    public const int IssuedUtc = BaseDataObject.BaseFieldCount + 4;
    public const int ExpiresUtc = BaseDataObject.BaseFieldCount + 5;
    public const int LastSeenUtc = BaseDataObject.BaseFieldCount + 6;
    public const int RememberMe = BaseDataObject.BaseFieldCount + 7;
    public const int IsRevoked = BaseDataObject.BaseFieldCount + 8;
}

/// <summary>Ordinal constants for <see cref="AuditEntry"/> fields.</summary>
public static class AuditEntryFields
{
    public const int EntityType = BaseDataObject.BaseFieldCount + 0;
    public const int EntityKey = BaseDataObject.BaseFieldCount + 1;
    public const int Operation = BaseDataObject.BaseFieldCount + 2;
    public const int TimestampUtc = BaseDataObject.BaseFieldCount + 3;
    public const int UserName = BaseDataObject.BaseFieldCount + 4;
    public const int FieldChangesJson = BaseDataObject.BaseFieldCount + 5;
    public const int CommandName = BaseDataObject.BaseFieldCount + 6;
    public const int CommandParameters = BaseDataObject.BaseFieldCount + 7;
    public const int CommandResult = BaseDataObject.BaseFieldCount + 8;
    public const int Notes = BaseDataObject.BaseFieldCount + 9;
}

/// <summary>Ordinal constants for <see cref="AppSetting"/> fields.</summary>
public static class AppSettingFields
{
    public const int SettingId = BaseDataObject.BaseFieldCount + 0;
    public const int Value = BaseDataObject.BaseFieldCount + 1;
    public const int Description = BaseDataObject.BaseFieldCount + 2;
}

/// <summary>Ordinal constants for <see cref="ReportDefinition"/> fields.</summary>
public static class ReportDefinitionFields
{
    public const int Name = BaseDataObject.BaseFieldCount + 0;
    public const int Description = BaseDataObject.BaseFieldCount + 1;
    public const int RootEntity = BaseDataObject.BaseFieldCount + 2;
    public const int JoinsJson = BaseDataObject.BaseFieldCount + 3;
    public const int ColumnsJson = BaseDataObject.BaseFieldCount + 4;
    public const int FiltersJson = BaseDataObject.BaseFieldCount + 5;
    public const int ParametersJson = BaseDataObject.BaseFieldCount + 6;
    public const int SortField = BaseDataObject.BaseFieldCount + 7;
    public const int SortDescending = BaseDataObject.BaseFieldCount + 8;
}

/// <summary>Ordinal constants for Permission fields.</summary>
public static class PermissionFields
{
    public const int Code = BaseDataObject.BaseFieldCount + 0;
    public const int Description = BaseDataObject.BaseFieldCount + 1;
    public const int TargetEntity = BaseDataObject.BaseFieldCount + 2;
    public const int Actions = BaseDataObject.BaseFieldCount + 3;
    public const int ConditionExpression = BaseDataObject.BaseFieldCount + 4;
    public const int RequiresElevation = BaseDataObject.BaseFieldCount + 5;
}

/// <summary>Ordinal constants for SecurityRole fields.</summary>
public static class SecurityRoleFields
{
    public const int RoleName = BaseDataObject.BaseFieldCount + 0;
    public const int Description = BaseDataObject.BaseFieldCount + 1;
    public const int PermissionCodes = BaseDataObject.BaseFieldCount + 2;
}

/// <summary>Ordinal constants for SecurityGroup fields.</summary>
public static class SecurityGroupFields
{
    public const int GroupName = BaseDataObject.BaseFieldCount + 0;
    public const int Description = BaseDataObject.BaseFieldCount + 1;
    public const int RoleNames = BaseDataObject.BaseFieldCount + 2;
    public const int MemberKeys = BaseDataObject.BaseFieldCount + 3;
    public const int NestedGroupKeys = BaseDataObject.BaseFieldCount + 4;
}

/// <summary>Ordinal constants for <see cref="MfaChallenge"/> fields.</summary>
public static class MfaChallengeFields
{
    public const int UserId = BaseDataObject.BaseFieldCount + 0;
    public const int RememberMe = BaseDataObject.BaseFieldCount + 1;
    public const int ExpiresUtc = BaseDataObject.BaseFieldCount + 2;
    public const int IsUsed = BaseDataObject.BaseFieldCount + 3;
}

/// <summary>Ordinal constants for <see cref="DeviceCodeAuth"/> fields.</summary>
public static class DeviceCodeAuthFields
{
    public const int UserCode = BaseDataObject.BaseFieldCount + 0;
    public const int DeviceCode = BaseDataObject.BaseFieldCount + 1;
    public const int ExpiresUtc = BaseDataObject.BaseFieldCount + 2;
    public const int Status = BaseDataObject.BaseFieldCount + 3;
    public const int UserId = BaseDataObject.BaseFieldCount + 4;
    public const int ClientDescription = BaseDataObject.BaseFieldCount + 5;
}

/// <summary>Ordinal constants for EntityDefinition fields.</summary>
public static class EntityDefinitionFields
{
    public const int EntityId = BaseDataObject.BaseFieldCount + 0;
    public const int Name = BaseDataObject.BaseFieldCount + 1;
    public const int Slug = BaseDataObject.BaseFieldCount + 2;
    public const int Version = BaseDataObject.BaseFieldCount + 3;
    public const int IdStrategy = BaseDataObject.BaseFieldCount + 4;
    public const int ShowOnNav = BaseDataObject.BaseFieldCount + 5;
    public const int Permissions = BaseDataObject.BaseFieldCount + 6;
    public const int NavGroup = BaseDataObject.BaseFieldCount + 7;
    public const int NavOrder = BaseDataObject.BaseFieldCount + 8;
    public const int SchemaHash = BaseDataObject.BaseFieldCount + 9;
}

/// <summary>Ordinal constants for FieldDefinition fields.</summary>
public static class FieldDefinitionFields
{
    public const int FieldId = BaseDataObject.BaseFieldCount + 0;
    public const int EntityId = BaseDataObject.BaseFieldCount + 1;
    public const int Name = BaseDataObject.BaseFieldCount + 2;
    public const int Label = BaseDataObject.BaseFieldCount + 3;
    public const int Ordinal = BaseDataObject.BaseFieldCount + 4;
    public const int Type = BaseDataObject.BaseFieldCount + 5;
    public const int IsNullable = BaseDataObject.BaseFieldCount + 6;
    public const int Required = BaseDataObject.BaseFieldCount + 7;
    public const int List = BaseDataObject.BaseFieldCount + 8;
    public const int View = BaseDataObject.BaseFieldCount + 9;
    public const int Edit = BaseDataObject.BaseFieldCount + 10;
    public const int Create = BaseDataObject.BaseFieldCount + 11;
    public const int ReadOnly = BaseDataObject.BaseFieldCount + 12;
    public const int DefaultValue = BaseDataObject.BaseFieldCount + 13;
    public const int Placeholder = BaseDataObject.BaseFieldCount + 14;
    public const int MinLength = BaseDataObject.BaseFieldCount + 15;
    public const int MaxLength = BaseDataObject.BaseFieldCount + 16;
    public const int RangeMin = BaseDataObject.BaseFieldCount + 17;
    public const int RangeMax = BaseDataObject.BaseFieldCount + 18;
    public const int Pattern = BaseDataObject.BaseFieldCount + 19;
    public const int EnumValues = BaseDataObject.BaseFieldCount + 20;
    public const int LookupEntitySlug = BaseDataObject.BaseFieldCount + 21;
    public const int LookupValueField = BaseDataObject.BaseFieldCount + 22;
    public const int LookupDisplayField = BaseDataObject.BaseFieldCount + 23;
    public const int Multiline = BaseDataObject.BaseFieldCount + 24;
    public const int ChildEntitySlug = BaseDataObject.BaseFieldCount + 25;
    public const int LookupCopyFields = BaseDataObject.BaseFieldCount + 26;
    public const int CalculatedExpression = BaseDataObject.BaseFieldCount + 27;
    public const int CalculatedDisplayFormat = BaseDataObject.BaseFieldCount + 28;
    public const int CopyFromParentField = BaseDataObject.BaseFieldCount + 29;
    public const int CopyFromParentSlug = BaseDataObject.BaseFieldCount + 30;
    public const int CopyFromParentSourceField = BaseDataObject.BaseFieldCount + 31;
    public const int RelatedDocumentSlug = BaseDataObject.BaseFieldCount + 32;
    public const int RelatedDocumentDisplayField = BaseDataObject.BaseFieldCount + 33;
    public const int CascadeFromField = BaseDataObject.BaseFieldCount + 34;
    public const int CascadeFilterField = BaseDataObject.BaseFieldCount + 35;
    public const int FieldGroup = BaseDataObject.BaseFieldCount + 36;
    public const int ColumnSpan = BaseDataObject.BaseFieldCount + 37;
}

/// <summary>Ordinal constants for IndexDefinition fields.</summary>
public static class IndexDefinitionFields
{
    public const int EntityId = BaseDataObject.BaseFieldCount + 0;
    public const int FieldNames = BaseDataObject.BaseFieldCount + 1;
    public const int Type = BaseDataObject.BaseFieldCount + 2;
}

/// <summary>Ordinal constants for ActionDefinition fields.</summary>
public static class ActionDefinitionFields
{
    public const int EntityId = BaseDataObject.BaseFieldCount + 0;
    public const int Name = BaseDataObject.BaseFieldCount + 1;
    public const int Label = BaseDataObject.BaseFieldCount + 2;
    public const int Icon = BaseDataObject.BaseFieldCount + 3;
    public const int Permission = BaseDataObject.BaseFieldCount + 4;
    public const int EnabledWhen = BaseDataObject.BaseFieldCount + 5;
    public const int Operations = BaseDataObject.BaseFieldCount + 6;
    public const int Version = BaseDataObject.BaseFieldCount + 7;
}

/// <summary>Ordinal constants for ActionCommandDefinition fields.</summary>
public static class ActionCommandDefinitionFields
{
    public const int ActionId = BaseDataObject.BaseFieldCount + 0;
    public const int CommandType = BaseDataObject.BaseFieldCount + 1;
    public const int Order = BaseDataObject.BaseFieldCount + 2;
    public const int ParentCommandId = BaseDataObject.BaseFieldCount + 3;
    public const int Condition = BaseDataObject.BaseFieldCount + 4;
    public const int FieldId = BaseDataObject.BaseFieldCount + 5;
    public const int ValueExpression = BaseDataObject.BaseFieldCount + 6;
    public const int ListFieldId = BaseDataObject.BaseFieldCount + 7;
    public const int Severity = BaseDataObject.BaseFieldCount + 8;
    public const int ErrorCode = BaseDataObject.BaseFieldCount + 9;
    public const int Message = BaseDataObject.BaseFieldCount + 10;
    public const int TargetEntityType = BaseDataObject.BaseFieldCount + 11;
    public const int TargetActionId = BaseDataObject.BaseFieldCount + 12;
    public const int ParameterMap = BaseDataObject.BaseFieldCount + 13;
}

/// <summary>Ordinal constants for SessionLog fields.</summary>
public static class SessionLogFields
{
    public const int UserName = BaseDataObject.BaseFieldCount + 0;
    public const int LoginUtc = BaseDataObject.BaseFieldCount + 1;
    public const int LogoutUtc = BaseDataObject.BaseFieldCount + 2;
    public const int IpAddress = BaseDataObject.BaseFieldCount + 3;
    public const int UserAgent = BaseDataObject.BaseFieldCount + 4;
}
