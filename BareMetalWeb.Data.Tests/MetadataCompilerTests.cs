using System;
using System.Collections.Generic;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;
using Xunit;

namespace BareMetalWeb.Data.Tests;

public class MetadataCompilerTests
{
    // Shared no-op handlers for test metadata
    private static readonly DataEntityHandlers DummyHandlers = new(
        Create: () => throw new NotSupportedException(),
        LoadAsync: (_, _) => ValueTask.FromResult<BaseDataObject?>(null),
        SaveAsync: (_, _) => ValueTask.CompletedTask,
        DeleteAsync: (_, _) => ValueTask.CompletedTask,
        QueryAsync: (_, _) => ValueTask.FromResult<IEnumerable<BaseDataObject>>(Array.Empty<BaseDataObject>()),
        CountAsync: (_, _) => ValueTask.FromResult(0)
    );

    private static DataFieldMetadata MakeField(string name, FormFieldType type = FormFieldType.String, int order = 0,
        bool required = false, bool readOnly = false, int columnSpan = 12) =>
        new(
            Property: typeof(string).GetProperty(nameof(string.Length))!, // dummy PropertyInfo
            Name: name,
            Label: name,
            FieldType: type,
            Order: order,
            Required: required,
            List: true,
            View: true,
            Edit: true,
            Create: true,
            ReadOnly: readOnly,
            Placeholder: null,
            Lookup: null,
            IdGeneration: IdGenerationStrategy.None,
            Computed: null,
            Upload: null,
            Calculated: null,
            Validation: null,
            ColumnSpan: columnSpan
        );

    private static DataEntityMetadata MakeEntity(string slug, params DataFieldMetadata[] fields) =>
        new(
            Type: typeof(object),
            Name: slug,
            Slug: slug,
            Permissions: "",
            ShowOnNav: true,
            NavGroup: null,
            NavOrder: 0,
            IdGeneration: AutoIdStrategy.Sequential,
            ViewType: ViewType.Table,
            ParentField: null,
            Fields: fields,
            Handlers: DummyHandlers,
            Commands: Array.Empty<RemoteCommandMetadata>()
        );

    [Fact]
    public void Compile_EmptyList_ReturnsEmptyTables()
    {
        var snapshot = MetadataCompiler.Compile(Array.Empty<DataEntityMetadata>());

        Assert.Equal(0, snapshot.Entities.Count);
        Assert.Equal(0, snapshot.Fields.Count);
    }

    [Fact]
    public void Compile_SingleEntity_AssignsEntityIdZero()
    {
        var entity = MakeEntity("orders", MakeField("total", FormFieldType.Money), MakeField("status"));
        var snapshot = MetadataCompiler.Compile(new[] { entity });

        Assert.Equal(1, snapshot.Entities.Count);
        Assert.Equal(2, snapshot.Fields.Count);

        Assert.Equal("orders", snapshot.Entities.Slugs[0]);
        Assert.Equal(0, snapshot.Entities.FieldStart[0]);
        Assert.Equal(2, snapshot.Entities.FieldCount[0]);
    }

    [Fact]
    public void Compile_MultipleEntities_SortedBySlug_ContiguousFieldIds()
    {
        var e1 = MakeEntity("zeta", MakeField("z1"));
        var e2 = MakeEntity("alpha", MakeField("a1"), MakeField("a2"));
        var e3 = MakeEntity("mid", MakeField("m1"), MakeField("m2"), MakeField("m3"));

        var snapshot = MetadataCompiler.Compile(new[] { e1, e2, e3 });

        Assert.Equal(3, snapshot.Entities.Count);
        Assert.Equal(6, snapshot.Fields.Count);

        // Sorted by slug: alpha=0, mid=1, zeta=2
        Assert.Equal("alpha", snapshot.Entities.Slugs[0]);
        Assert.Equal("mid", snapshot.Entities.Slugs[1]);
        Assert.Equal("zeta", snapshot.Entities.Slugs[2]);

        // alpha: fields 0..1
        Assert.Equal(0, snapshot.Entities.FieldStart[0]);
        Assert.Equal(2, snapshot.Entities.FieldCount[0]);

        // mid: fields 2..4
        Assert.Equal(2, snapshot.Entities.FieldStart[1]);
        Assert.Equal(3, snapshot.Entities.FieldCount[1]);

        // zeta: fields 5..5
        Assert.Equal(5, snapshot.Entities.FieldStart[2]);
        Assert.Equal(1, snapshot.Entities.FieldCount[2]);

        // Verify field→entity back-reference
        Assert.Equal(0, snapshot.Fields.EntityIds[0]); // a1 → alpha
        Assert.Equal(0, snapshot.Fields.EntityIds[1]); // a2 → alpha
        Assert.Equal(1, snapshot.Fields.EntityIds[2]); // m1 → mid
        Assert.Equal(2, snapshot.Fields.EntityIds[5]); // z1 → zeta
    }

    [Fact]
    public void Compile_SlugLookup_ReturnsCorrectEntityId()
    {
        var entities = new[]
        {
            MakeEntity("products", MakeField("name")),
            MakeEntity("customers", MakeField("email")),
            MakeEntity("orders", MakeField("total")),
        };

        var snapshot = MetadataCompiler.Compile(entities);

        // Sorted: customers=0, orders=1, products=2
        Assert.True(snapshot.Entities.TryResolveSlug("customers", out int id0));
        Assert.Equal(0, id0);

        Assert.True(snapshot.Entities.TryResolveSlug("orders", out int id1));
        Assert.Equal(1, id1);

        Assert.True(snapshot.Entities.TryResolveSlug("products", out int id2));
        Assert.Equal(2, id2);

        Assert.False(snapshot.Entities.TryResolveSlug("nonexistent", out _));
    }

    [Fact]
    public void Compile_FieldFlags_PackedCorrectly()
    {
        var field = MakeField("name", required: true, readOnly: true);
        var entity = MakeEntity("test", field);

        var snapshot = MetadataCompiler.Compile(new[] { entity });

        var flags = snapshot.Fields.Flags[0];
        Assert.True((flags & FieldFlags.Required) != 0);
        Assert.True((flags & FieldFlags.ReadOnly) != 0);
        Assert.True((flags & FieldFlags.Lookup) == 0);
    }

    [Fact]
    public void Compile_WireTypeMapping_CorrectForKnownTypes()
    {
        var fields = new[]
        {
            MakeField("flag", FormFieldType.YesNo),
            MakeField("count", FormFieldType.Integer),
            MakeField("price", FormFieldType.Money),
            MakeField("when", FormFieldType.DateTime),
            MakeField("label", FormFieldType.String),
        };

        var snapshot = MetadataCompiler.Compile(new[] { MakeEntity("test", fields) });

        Assert.Equal(MetadataWireSerializer.WireFieldType.Bool, snapshot.Fields.WireTypes[0]);
        Assert.Equal(MetadataWireSerializer.WireFieldType.Int32, snapshot.Fields.WireTypes[1]);
        Assert.Equal(MetadataWireSerializer.WireFieldType.Decimal, snapshot.Fields.WireTypes[2]);
        Assert.Equal(MetadataWireSerializer.WireFieldType.DateTime, snapshot.Fields.WireTypes[3]);
        Assert.Equal(MetadataWireSerializer.WireFieldType.String, snapshot.Fields.WireTypes[4]);
    }

    [Fact]
    public void RouteTable_SetAndResolve_RoundTrips()
    {
        var snapshot = MetadataCompiler.Compile(new[] { MakeEntity("test", MakeField("f1")) });

        bool called = false;
        snapshot.Routes.Set(0, ApiVerb.List, ctx => { called = true; return ValueTask.CompletedTask; });

        var handler = snapshot.Routes.Resolve(0, ApiVerb.List);
        Assert.NotNull(handler);

        Assert.Null(snapshot.Routes.Resolve(0, ApiVerb.Delete));
    }

    [Fact]
    public void CompileAndSwap_AtomicallyReplacesSnapshot()
    {
        var e1 = MakeEntity("v1", MakeField("f1"));
        var first = MetadataCompiler.CompileAndSwap(new[] { e1 });

        Assert.Same(first, RuntimeSnapshot.Current);

        var e2 = MakeEntity("v2", MakeField("f2"), MakeField("f3"));
        var second = MetadataCompiler.CompileAndSwap(new[] { e2 });

        Assert.Same(second, RuntimeSnapshot.Current);
        Assert.NotSame(first, second);

        // Old snapshot is still valid (immutable)
        Assert.Equal(1, first.Entities.Count);
        Assert.Equal(1, first.Fields.Count);

        // New snapshot reflects changes
        Assert.Equal(1, second.Entities.Count);
        Assert.Equal(2, second.Fields.Count);
    }

    [Fact]
    public void Compile_IdStrategy_PreservedFromMetadata()
    {
        var entity = MakeEntity("test", MakeField("f1"));
        var snapshot = MetadataCompiler.Compile(new[] { entity });

        Assert.Equal(AutoIdStrategy.Sequential, snapshot.Entities.IdStrategies[0]);
    }

    [Fact]
    public void Compile_NavMetadata_PreservedFromMetadata()
    {
        var entity = MakeEntity("test", MakeField("f1"));
        var snapshot = MetadataCompiler.Compile(new[] { entity });

        Assert.True(snapshot.Entities.ShowOnNav[0]);
        Assert.Equal(0, snapshot.Entities.NavOrder[0]);
    }

    [Fact]
    public void Compile_ColumnSpan_PreservedFromMetadata()
    {
        var field = MakeField("wide", columnSpan: 6);
        var snapshot = MetadataCompiler.Compile(new[] { MakeEntity("test", field) });

        Assert.Equal(6, snapshot.Fields.ColumnSpans[0]);
    }
}
