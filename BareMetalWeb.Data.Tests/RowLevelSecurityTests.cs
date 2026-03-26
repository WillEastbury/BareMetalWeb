using System;
using System.Collections.Generic;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Unit tests for <see cref="RowLevelSecurity"/> — the static RLS enforcement helper.
/// These tests verify filter injection, single-record visibility, and admin bypass semantics.
/// </summary>
public sealed class RowLevelSecurityTests
{
    // ── IsEnabled ──────────────────────────────────────────────────────────

    [Fact]
    public void IsEnabled_NullOwnerField_ReturnsFalse()
    {
        var meta = MakeMeta(rlsOwnerField: null);
        Assert.False(RowLevelSecurity.IsEnabled(meta));
    }

    [Fact]
    public void IsEnabled_EmptyOwnerField_ReturnsFalse()
    {
        var meta = MakeMeta(rlsOwnerField: "");
        Assert.False(RowLevelSecurity.IsEnabled(meta));
    }

    [Fact]
    public void IsEnabled_WhitespaceOwnerField_ReturnsFalse()
    {
        var meta = MakeMeta(rlsOwnerField: "  ");
        Assert.False(RowLevelSecurity.IsEnabled(meta));
    }

    [Fact]
    public void IsEnabled_SetOwnerField_ReturnsTrue()
    {
        var meta = MakeMeta(rlsOwnerField: "CreatedBy");
        Assert.True(RowLevelSecurity.IsEnabled(meta));
    }

    // ── IsAdmin ─────────────────────────────────────────────────────────────

    [Fact]
    public void IsAdmin_WithAdminPermission_ReturnsTrue()
    {
        Assert.True(RowLevelSecurity.IsAdmin(new[] { "admin" }));
    }

    [Fact]
    public void IsAdmin_CaseInsensitive_ReturnsTrue()
    {
        Assert.True(RowLevelSecurity.IsAdmin(new[] { "Admin" }));
        Assert.True(RowLevelSecurity.IsAdmin(new[] { "ADMIN" }));
    }

    [Fact]
    public void IsAdmin_WithoutAdminPermission_ReturnsFalse()
    {
        Assert.False(RowLevelSecurity.IsAdmin(new[] { "users", "reports" }));
    }

    [Fact]
    public void IsAdmin_EmptyPermissions_ReturnsFalse()
    {
        Assert.False(RowLevelSecurity.IsAdmin(Array.Empty<string>()));
    }

    // ── TryApplyFilter ──────────────────────────────────────────────────────

    [Fact]
    public void TryApplyFilter_NoRls_ReturnsTrue_NoClauses()
    {
        var meta = MakeMeta(rlsOwnerField: null);
        var query = new QueryDefinition();

        var result = RowLevelSecurity.TryApplyFilter(query, meta, "alice", new[] { "users" });

        Assert.True(result);
        Assert.Empty(query.Clauses);
    }

    [Fact]
    public void TryApplyFilter_AdminUser_ReturnsTrue_NoClauses()
    {
        var meta = MakeMeta(rlsOwnerField: "CreatedBy");
        var query = new QueryDefinition();

        var result = RowLevelSecurity.TryApplyFilter(query, meta, "alice", new[] { "admin" });

        Assert.True(result);
        Assert.Empty(query.Clauses);
    }

    [Fact]
    public void TryApplyFilter_AuthenticatedUser_InjectsClause()
    {
        var meta = MakeMeta(rlsOwnerField: "CreatedBy");
        var query = new QueryDefinition();

        var result = RowLevelSecurity.TryApplyFilter(query, meta, "bob", new[] { "users" });

        Assert.True(result);
        Assert.Single(query.Clauses);
        Assert.Equal("CreatedBy", query.Clauses[0].Field);
        Assert.Equal(QueryOperator.Equals, query.Clauses[0].Operator);
        Assert.Equal("bob", query.Clauses[0].Value);
    }

    [Fact]
    public void TryApplyFilter_UnauthenticatedUser_ReturnsFalse()
    {
        var meta = MakeMeta(rlsOwnerField: "CreatedBy");
        var query = new QueryDefinition();

        var result = RowLevelSecurity.TryApplyFilter(query, meta, null, Array.Empty<string>());

        Assert.False(result);
    }

    [Fact]
    public void TryApplyFilter_EmptyUserName_ReturnsFalse()
    {
        var meta = MakeMeta(rlsOwnerField: "CreatedBy");
        var query = new QueryDefinition();

        var result = RowLevelSecurity.TryApplyFilter(query, meta, "", Array.Empty<string>());

        Assert.False(result);
    }

    [Fact]
    public void TryApplyFilter_PreservesExistingClauses()
    {
        var meta = MakeMeta(rlsOwnerField: "CreatedBy");
        var query = new QueryDefinition();
        query.Clauses.Add(new QueryClause { Field = "Status", Operator = QueryOperator.Equals, Value = "Active" });

        RowLevelSecurity.TryApplyFilter(query, meta, "carol", new[] { "users" });

        Assert.Equal(2, query.Clauses.Count);
        Assert.Equal("Status", query.Clauses[0].Field);
        Assert.Equal("CreatedBy", query.Clauses[1].Field);
    }

    // ── IsRecordVisible ─────────────────────────────────────────────────────

    [Fact]
    public void IsRecordVisible_NoRls_ReturnsTrue()
    {
        var meta = MakeMeta(rlsOwnerField: null);
        var record = new TestRecord("other-user");

        Assert.True(RowLevelSecurity.IsRecordVisible(record, meta, "alice", new[] { "users" }));
    }

    [Fact]
    public void IsRecordVisible_Admin_ReturnsTrue_Regardless()
    {
        var meta = MakeMeta(rlsOwnerField: "CreatedBy");
        var record = new TestRecord("other-user");

        Assert.True(RowLevelSecurity.IsRecordVisible(record, meta, "alice", new[] { "admin" }));
    }

    [Fact]
    public void IsRecordVisible_OwnerMatch_ReturnsTrue()
    {
        var meta = MakeMeta(rlsOwnerField: "CreatedBy");
        var record = new TestRecord("alice");

        Assert.True(RowLevelSecurity.IsRecordVisible(record, meta, "alice", new[] { "users" }));
    }

    [Fact]
    public void IsRecordVisible_CaseInsensitiveOwnerMatch_ReturnsTrue()
    {
        var meta = MakeMeta(rlsOwnerField: "CreatedBy");
        var record = new TestRecord("Alice");

        Assert.True(RowLevelSecurity.IsRecordVisible(record, meta, "alice", new[] { "users" }));
    }

    [Fact]
    public void IsRecordVisible_DifferentOwner_ReturnsFalse()
    {
        var meta = MakeMeta(rlsOwnerField: "CreatedBy");
        var record = new TestRecord("bob");

        Assert.False(RowLevelSecurity.IsRecordVisible(record, meta, "alice", new[] { "users" }));
    }

    [Fact]
    public void IsRecordVisible_UnauthenticatedUser_ReturnsFalse()
    {
        var meta = MakeMeta(rlsOwnerField: "CreatedBy");
        var record = new TestRecord("bob");

        Assert.False(RowLevelSecurity.IsRecordVisible(record, meta, null, Array.Empty<string>()));
    }

    [Fact]
    public void IsRecordVisible_EmptyUserName_ReturnsFalse()
    {
        var meta = MakeMeta(rlsOwnerField: "CreatedBy");
        var record = new TestRecord("bob");

        Assert.False(RowLevelSecurity.IsRecordVisible(record, meta, "", Array.Empty<string>()));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private sealed class TestRecord : BaseDataObject
    {
        internal new const int TotalFieldCount = BaseFieldCount;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public TestRecord() : base(TotalFieldCount) { }
        public TestRecord(string createdBy) : base(TotalFieldCount, createdBy) { }
    }

    /// <summary>
    /// Creates a minimal <see cref="DataEntityMetadata"/> with the specified RLS owner field.
    /// Uses no-op handlers since the RLS helper doesn't invoke them.
    /// </summary>
    private static DataEntityMetadata MakeMeta(string? rlsOwnerField)
    {
        var handlers = new DataEntityHandlers(
            Create: static () => throw new NotSupportedException(),
            LoadAsync: static (_, _) => throw new NotSupportedException(),
            SaveAsync: static (_, _) => throw new NotSupportedException(),
            DeleteAsync: static (_, _) => throw new NotSupportedException(),
            QueryAsync: static (_, _) => throw new NotSupportedException(),
            CountAsync: static (_, _) => throw new NotSupportedException()
        );

        return new DataEntityMetadata(
            Type: typeof(TestRecord),
            Name: "TestRecords",
            Slug: "test-records",
            Permissions: "Authenticated",
            ShowOnNav: false,
            NavGroup: null,
            NavOrder: 0,
            IdGeneration: AutoIdStrategy.Sequential,
            ViewType: ViewType.Table,
            ParentField: null,
            Fields: Array.Empty<DataFieldMetadata>(),
            Handlers: handlers,
            Commands: Array.Empty<RemoteCommandMetadata>(),
            RlsOwnerField: rlsOwnerField
        );
    }
}
