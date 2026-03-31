using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Verifies that SystemEntitySchemas and SystemFields ordinal constants
/// are consistent — the ordinal constant matches the schema's NameToOrdinal.
/// </summary>
public class SystemEntitySchemaTests
{
    [Fact]
    public void AllSchemas_AreNonNull()
    {
        Assert.NotNull(SystemEntitySchemas.All);
        Assert.Equal(22, SystemEntitySchemas.All.Count);
        foreach (var schema in SystemEntitySchemas.All)
        {
            Assert.NotNull(schema);
            Assert.True(schema.FieldCount > 0, $"{schema.EntityName} has no fields");
        }
    }

    // ── User ──────────────────────────────────────────────────────────────

    [Fact]
    public void UserSchema_OrdinalsMatchConstants()
    {
        var s = SystemEntitySchemas.User;
        Assert.Equal(21, s.FieldCount);
        Assert.Equal(UserFields.UserName, Ord(s, "UserName"));
        Assert.Equal(UserFields.DisplayName, Ord(s, "DisplayName"));
        Assert.Equal(UserFields.Email, Ord(s, "Email"));
        Assert.Equal(UserFields.PasswordHash, Ord(s, "PasswordHash"));
        Assert.Equal(UserFields.Permissions, Ord(s, "Permissions"));
        Assert.Equal(UserFields.IsActive, Ord(s, "IsActive"));
        Assert.Equal(UserFields.FailedLoginCount, Ord(s, "FailedLoginCount"));
        Assert.Equal(UserFields.MfaEnabled, Ord(s, "MfaEnabled"));
        Assert.Equal(UserFields.MfaBackupCodeHashes, Ord(s, "MfaBackupCodeHashes"));
    }

    // ── UserSession ───────────────────────────────────────────────────────

    [Fact]
    public void UserSessionSchema_OrdinalsMatchConstants()
    {
        var s = SystemEntitySchemas.UserSession;
        Assert.Equal(9, s.FieldCount);
        Assert.Equal(UserSessionFields.UserId, Ord(s, "UserId"));
        Assert.Equal(UserSessionFields.ExpiresUtc, Ord(s, "ExpiresUtc"));
        Assert.Equal(UserSessionFields.IsRevoked, Ord(s, "IsRevoked"));
    }

    // ── AuditEntry ────────────────────────────────────────────────────────

    [Fact]
    public void AuditEntrySchema_OrdinalsMatchConstants()
    {
        var s = SystemEntitySchemas.AuditEntry;
        Assert.Equal(10, s.FieldCount);
        Assert.Equal(AuditEntryFields.EntityType, Ord(s, "EntityType"));
        Assert.Equal(AuditEntryFields.EntityKey, Ord(s, "EntityKey"));
        Assert.Equal(AuditEntryFields.Operation, Ord(s, "Operation"));
        Assert.Equal(AuditEntryFields.Notes, Ord(s, "Notes"));
    }

    // ── AppSetting ────────────────────────────────────────────────────────

    [Fact]
    public void AppSettingSchema_OrdinalsMatchConstants()
    {
        var s = SystemEntitySchemas.AppSetting;
        Assert.Equal(3, s.FieldCount);
        Assert.Equal(AppSettingFields.SettingId, Ord(s, "SettingId"));
        Assert.Equal(AppSettingFields.Value, Ord(s, "Value"));
        Assert.Equal(AppSettingFields.Description, Ord(s, "Description"));
    }

    // ── Permission ────────────────────────────────────────────────────────

    [Fact]
    public void PermissionSchema_OrdinalsMatchConstants()
    {
        var s = SystemEntitySchemas.Permission;
        Assert.Equal(6, s.FieldCount);
        Assert.Equal(PermissionFields.Code, Ord(s, "Code"));
        Assert.Equal(PermissionFields.RequiresElevation, Ord(s, "RequiresElevation"));
    }

    // ── SecurityRole ──────────────────────────────────────────────────────

    [Fact]
    public void SecurityRoleSchema_OrdinalsMatchConstants()
    {
        var s = SystemEntitySchemas.SecurityRole;
        Assert.Equal(3, s.FieldCount);
        Assert.Equal(SecurityRoleFields.RoleName, Ord(s, "RoleName"));
        Assert.Equal(SecurityRoleFields.PermissionCodes, Ord(s, "PermissionCodes"));
    }

    // ── EntityDefinition ──────────────────────────────────────────────────

    [Fact]
    public void EntityDefinitionSchema_OrdinalsMatchConstants()
    {
        var s = SystemEntitySchemas.EntityDefinition;
        Assert.Equal(10, s.FieldCount);
        Assert.Equal(EntityDefinitionFields.EntityId, Ord(s, "EntityId"));
        Assert.Equal(EntityDefinitionFields.Name, Ord(s, "Name"));
        Assert.Equal(EntityDefinitionFields.SchemaHash, Ord(s, "SchemaHash"));
    }

    // ── FieldDefinition ───────────────────────────────────────────────────

    [Fact]
    public void FieldDefinitionSchema_OrdinalsMatchConstants()
    {
        var s = SystemEntitySchemas.FieldDefinition;
        Assert.Equal(38, s.FieldCount);
        Assert.Equal(FieldDefinitionFields.FieldId, Ord(s, "FieldId"));
        Assert.Equal(FieldDefinitionFields.Name, Ord(s, "Name"));
        Assert.Equal(FieldDefinitionFields.Ordinal, Ord(s, "Ordinal"));
        Assert.Equal(FieldDefinitionFields.Multiline, Ord(s, "Multiline"));
        Assert.Equal(FieldDefinitionFields.ChildEntitySlug, Ord(s, "ChildEntitySlug"));
        Assert.Equal(FieldDefinitionFields.ColumnSpan, Ord(s, "ColumnSpan"));
    }

    // ── ActionCommandDefinition ───────────────────────────────────────────

    [Fact]
    public void ActionCommandDefinitionSchema_OrdinalsMatchConstants()
    {
        var s = SystemEntitySchemas.ActionCommandDefinition;
        Assert.Equal(14, s.FieldCount);
        Assert.Equal(ActionCommandDefinitionFields.ActionId, Ord(s, "ActionId"));
        Assert.Equal(ActionCommandDefinitionFields.ParameterMap, Ord(s, "ParameterMap"));
    }

    // ── Round-trip: schema → DataRecord → field access ────────────────────

    [Fact]
    public void UserSchema_CreateRecord_RoundTrip()
    {
        var rec = SystemEntitySchemas.User.CreateRecord();
        rec.SetValue(UserFields.Email, "test@example.com");
        rec.SetValue(UserFields.IsActive, true);
        rec.SetValue(UserFields.FailedLoginCount, 3);

        Assert.Equal("test@example.com", rec.GetValue(UserFields.Email));
        Assert.Equal(true, rec.GetValue(UserFields.IsActive));
        Assert.Equal(3, rec.GetValue(UserFields.FailedLoginCount));
    }

    [Fact]
    public void AppSettingSchema_CreateRecord_RoundTrip()
    {
        var rec = SystemEntitySchemas.AppSetting.CreateRecord();
        rec.SetValue(AppSettingFields.SettingId, "AppName");
        rec.SetValue(AppSettingFields.Value, "BareMetalWeb");

        Assert.Equal("AppName", rec.GetValue(AppSettingFields.SettingId));
        Assert.Equal("BareMetalWeb", rec.GetValue(AppSettingFields.Value));
    }

    // ── Schema hashing is stable ──────────────────────────────────────────

    [Fact]
    public void Schemas_HaveNonZeroHash()
    {
        foreach (var schema in SystemEntitySchemas.All)
            Assert.NotEqual(0UL, schema.SchemaHash);
    }

    [Fact]
    public void Schemas_HaveUniqueHashes()
    {
        var hashes = SystemEntitySchemas.All.Select(s => s.SchemaHash).ToList();
        Assert.Equal(hashes.Count, hashes.Distinct().Count());
    }

    // ── Helper ────────────────────────────────────────────────────────────

    private static int Ord(EntitySchema schema, string name)
    {
        Assert.True(schema.TryGetOrdinal(name, out var ord), $"Field '{name}' not found in {schema.EntityName}");
        return ord;
    }
}
