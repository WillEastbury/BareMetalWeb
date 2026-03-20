using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using Xunit;

namespace BareMetalWeb.Data.Tests;

[Collection("SharedState")]
public sealed class PrincipalAuthorizationPolicyTests : IDisposable
{
    private readonly string _testFolder;
    private readonly IDataObjectStore _store;
    private readonly AuditService _auditService;

    public PrincipalAuthorizationPolicyTests()
    {
        _testFolder = Path.Combine(Path.GetTempPath(), $"principal-auth-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testFolder);

        var provider = new WalDataProvider(_testFolder);
        _store = new DataObjectStore();
        _store.RegisterProvider(provider);
        DataStoreProvider.Current = _store;

        // Register entity metadata so PrincipalAuthorizationPolicy helpers can
        // resolve roles, usernames, and entity types via DataScaffold lookups.
        DataScaffold.RegisterEntity<User>();
        DataScaffold.RegisterEntity<SystemPrincipal>();
        DataScaffold.RegisterEntity<AuditEntry>();

        _auditService = new AuditService(_store) { RunSynchronously = true };
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testFolder))
                Directory.Delete(_testFolder, true);
        }
        catch { }
    }

    // ── AsRestrictedPrincipal ──────────────────────────────────────────

    [Fact]
    public void AsRestrictedPrincipal_RegularUser_ReturnsNull()
    {
        var user = new User { UserName = "alice" };
        Assert.Null(PrincipalAuthorizationPolicy.AsRestrictedPrincipal(user));
    }

    [Fact]
    public void AsRestrictedPrincipal_FullAccessPrincipal_ReturnsNull()
    {
        var sp = new SystemPrincipal { UserName = "deploy-full", Role = PrincipalRole.FullAccess };
        Assert.Null(PrincipalAuthorizationPolicy.AsRestrictedPrincipal(sp));
    }

    [Theory]
    [InlineData(PrincipalRole.DeploymentProcess)]
    [InlineData(PrincipalRole.DeploymentAgent)]
    [InlineData(PrincipalRole.TenantCallback)]
    public void AsRestrictedPrincipal_RestrictedRole_ReturnsPrincipal(PrincipalRole role)
    {
        var sp = new SystemPrincipal { UserName = "sp-test", Role = role };
        var result = PrincipalAuthorizationPolicy.AsRestrictedPrincipal(sp);
        Assert.NotNull(result);
        Assert.Same(sp, result);
    }

    [Fact]
    public void AsRestrictedPrincipal_NullUser_ReturnsNull()
    {
        Assert.Null(PrincipalAuthorizationPolicy.AsRestrictedPrincipal(null));
    }

    // ── DeploymentProcess role ─────────────────────────────────────────

    [Theory]
    [InlineData("orders", "Read")]
    [InlineData("orders", "Create")]
    [InlineData("orders", "Update")]
    public void CheckEntityAction_DeploymentProcess_AllowsReadCreateUpdate(string entity, string action)
    {
        var sp = new SystemPrincipal { Role = PrincipalRole.DeploymentProcess };
        Assert.Null(PrincipalAuthorizationPolicy.CheckEntityAction(sp, entity, action));
    }

    [Fact]
    public void CheckEntityAction_DeploymentProcess_DeniesDelete()
    {
        var sp = new SystemPrincipal { Role = PrincipalRole.DeploymentProcess };
        var result = PrincipalAuthorizationPolicy.CheckEntityAction(sp, "orders", "Delete");
        Assert.NotNull(result);
        Assert.Contains("cannot delete", result, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("Create")]
    [InlineData("Update")]
    public void CheckEntityAction_DeploymentProcess_DeniesSpKeyOperations(string action)
    {
        var sp = new SystemPrincipal { Role = PrincipalRole.DeploymentProcess };
        var result = PrincipalAuthorizationPolicy.CheckEntityAction(sp, "system-principals", action);
        Assert.NotNull(result);
        Assert.Contains("API keys", result, StringComparison.OrdinalIgnoreCase);
    }

    // ── DeploymentAgent role ───────────────────────────────────────────

    [Theory]
    [InlineData("orders", "Read")]
    [InlineData("orders", "Create")]
    public void CheckEntityAction_DeploymentAgent_AllowsReadCreate(string entity, string action)
    {
        var sp = new SystemPrincipal { Role = PrincipalRole.DeploymentAgent };
        Assert.Null(PrincipalAuthorizationPolicy.CheckEntityAction(sp, entity, action));
    }

    [Theory]
    [InlineData("Update")]
    [InlineData("Delete")]
    public void CheckEntityAction_DeploymentAgent_DeniesUpdateDelete(string action)
    {
        var sp = new SystemPrincipal { Role = PrincipalRole.DeploymentAgent };
        var result = PrincipalAuthorizationPolicy.CheckEntityAction(sp, "orders", action);
        Assert.NotNull(result);
    }

    [Theory]
    [InlineData("Create")]
    [InlineData("Update")]
    public void CheckEntityAction_DeploymentAgent_DeniesSpKeyOperations(string action)
    {
        var sp = new SystemPrincipal { Role = PrincipalRole.DeploymentAgent };
        var result = PrincipalAuthorizationPolicy.CheckEntityAction(sp, "system-principals", action);
        Assert.NotNull(result);
        Assert.Contains("API keys", result, StringComparison.OrdinalIgnoreCase);
    }

    // ── TenantCallback role ────────────────────────────────────────────

    [Theory]
    [InlineData("orders", "Read")]
    [InlineData("orders", "Update")]
    public void CheckEntityAction_TenantCallback_AllowsReadUpdate(string entity, string action)
    {
        var sp = new SystemPrincipal { Role = PrincipalRole.TenantCallback };
        Assert.Null(PrincipalAuthorizationPolicy.CheckEntityAction(sp, entity, action));
    }

    [Theory]
    [InlineData("Create")]
    [InlineData("Delete")]
    public void CheckEntityAction_TenantCallback_DeniesCreateDelete(string action)
    {
        var sp = new SystemPrincipal { Role = PrincipalRole.TenantCallback };
        var result = PrincipalAuthorizationPolicy.CheckEntityAction(sp, "orders", action);
        Assert.NotNull(result);
    }

    [Theory]
    [InlineData("Create")]
    [InlineData("Update")]
    public void CheckEntityAction_TenantCallback_DeniesSpKeyOperations(string action)
    {
        var sp = new SystemPrincipal { Role = PrincipalRole.TenantCallback };
        var result = PrincipalAuthorizationPolicy.CheckEntityAction(sp, "system-principals", action);
        Assert.NotNull(result);
        Assert.Contains("API keys", result, StringComparison.OrdinalIgnoreCase);
    }

    // ── FullAccess (unrestricted) ──────────────────────────────────────

    [Theory]
    [InlineData("orders", "Read")]
    [InlineData("orders", "Create")]
    [InlineData("orders", "Update")]
    [InlineData("orders", "Delete")]
    [InlineData("system-principals", "Create")]
    [InlineData("system-principals", "Update")]
    public void CheckEntityAction_FullAccess_AllowsEverything(string entity, string action)
    {
        var sp = new SystemPrincipal { Role = PrincipalRole.FullAccess };
        Assert.Null(PrincipalAuthorizationPolicy.CheckEntityAction(sp, entity, action));
    }

    // ── CanManageApiKeys ───────────────────────────────────────────────

    [Fact]
    public void CanManageApiKeys_FullAccess_ReturnsTrue()
    {
        var sp = new SystemPrincipal { Role = PrincipalRole.FullAccess };
        Assert.True(PrincipalAuthorizationPolicy.CanManageApiKeys(sp));
    }

    [Theory]
    [InlineData(PrincipalRole.DeploymentProcess)]
    [InlineData(PrincipalRole.DeploymentAgent)]
    [InlineData(PrincipalRole.TenantCallback)]
    public void CanManageApiKeys_RestrictedRole_ReturnsFalse(PrincipalRole role)
    {
        var sp = new SystemPrincipal { Role = role };
        Assert.False(PrincipalAuthorizationPolicy.CanManageApiKeys(sp));
    }

    [Fact]
    public void CanManageApiKeys_RegularUser_ReturnsTrue()
    {
        var user = new User { UserName = "admin" };
        Assert.True(PrincipalAuthorizationPolicy.CanManageApiKeys(user));
    }

    [Fact]
    public void CanManageApiKeys_NullUser_ReturnsTrue()
    {
        Assert.True(PrincipalAuthorizationPolicy.CanManageApiKeys(null));
    }

    // ── IsRecordOwner ──────────────────────────────────────────────────

    [Fact]
    public void IsRecordOwner_MatchingCreatedBy_ReturnsTrue()
    {
        var sp = new SystemPrincipal { UserName = "tenant-agent" };
        var record = new User { CreatedBy = "tenant-agent" };
        Assert.True(PrincipalAuthorizationPolicy.IsRecordOwner(sp, record));
    }

    [Fact]
    public void IsRecordOwner_CaseInsensitiveMatch_ReturnsTrue()
    {
        var sp = new SystemPrincipal { UserName = "Tenant-Agent" };
        var record = new User { CreatedBy = "tenant-agent" };
        Assert.True(PrincipalAuthorizationPolicy.IsRecordOwner(sp, record));
    }

    [Fact]
    public void IsRecordOwner_DifferentCreatedBy_ReturnsFalse()
    {
        var sp = new SystemPrincipal { UserName = "tenant-a" };
        var record = new User { CreatedBy = "tenant-b" };
        Assert.False(PrincipalAuthorizationPolicy.IsRecordOwner(sp, record));
    }

    [Fact]
    public void IsRecordOwner_SelfAccess_SystemPrincipal_ReturnsTrue()
    {
        var sp = new SystemPrincipal { Key = 42, UserName = "sp-self" };
        Assert.True(PrincipalAuthorizationPolicy.IsRecordOwner(sp, sp));
    }

    [Fact]
    public void IsRecordOwner_OtherPrincipal_ReturnsFalse()
    {
        var sp = new SystemPrincipal { Key = 42, UserName = "sp-a" };
        var other = new SystemPrincipal { Key = 99, UserName = "sp-b", CreatedBy = "admin" };
        Assert.False(PrincipalAuthorizationPolicy.IsRecordOwner(sp, other));
    }

    // ── FilterOwnedRecords ─────────────────────────────────────────────

    [Fact]
    public void FilterOwnedRecords_ReturnsOnlyOwned()
    {
        var sp = new SystemPrincipal { UserName = "my-agent" };
        var records = new List<User>
        {
            new() { Key = 1, CreatedBy = "my-agent" },
            new() { Key = 2, CreatedBy = "other-agent" },
            new() { Key = 3, CreatedBy = "my-agent" },
        };

        var filtered = PrincipalAuthorizationPolicy.FilterOwnedRecords(sp, records);
        Assert.Equal(2, filtered.Count);
        Assert.All(filtered, r => Assert.Equal("my-agent", r.CreatedBy));
    }

    [Fact]
    public void FilterOwnedRecords_EmptyInput_ReturnsEmpty()
    {
        var sp = new SystemPrincipal { UserName = "my-agent" };
        var filtered = PrincipalAuthorizationPolicy.FilterOwnedRecords(sp, Array.Empty<User>());
        Assert.Empty(filtered);
    }

    // ── Default role for new SystemPrincipal ───────────────────────────

    [Fact]
    public void NewSystemPrincipal_DefaultRole_IsFullAccess()
    {
        var sp = new SystemPrincipal();
        Assert.Equal(PrincipalRole.FullAccess, sp.Role);
    }

    [Fact]
    public void NewSystemPrincipal_DefaultOwnerFields_AreEmpty()
    {
        var sp = new SystemPrincipal();
        Assert.Equal(string.Empty, sp.OwnerTenantId);
        Assert.Equal(string.Empty, sp.OwnerInstanceId);
    }

}
