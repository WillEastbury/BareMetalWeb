using System.Reflection;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for <see cref="PropertyAccessorFactory"/> covering regular, read-only, and init-only properties.
/// </summary>
public class PropertyAccessorFactoryTests
{
    // ── Test fixtures ──────────────────────────────────────────────────────

    private class RegularEntity
    {
        public string Name { get; set; } = string.Empty;
        public int Value { get; set; }
    }

    private class GetOnlyEntity
    {
        public string ReadOnlyProp { get; } = "fixed";
    }

    private class InitOnlyEntity
    {
        public string InitProp { get; init; } = string.Empty;
        public int InitInt { get; init; }
    }

    // ── BuildSetter: regular property ─────────────────────────────────────

    [Fact]
    public void BuildSetter_RegularProperty_SetsValueViaCompiledDelegate()
    {
        var prop = typeof(RegularEntity).GetProperty(nameof(RegularEntity.Name))!;
        var setter = PropertyAccessorFactory.BuildSetter(prop);

        var entity = new RegularEntity();
        setter(entity, "Alice");

        Assert.Equal("Alice", entity.Name);
    }

    [Fact]
    public void BuildSetter_RegularIntProperty_SetsValueViaCompiledDelegate()
    {
        var prop = typeof(RegularEntity).GetProperty(nameof(RegularEntity.Value))!;
        var setter = PropertyAccessorFactory.BuildSetter(prop);

        var entity = new RegularEntity();
        setter(entity, 42);

        Assert.Equal(42, entity.Value);
    }

    // ── BuildSetter: init-only property ───────────────────────────────────
    // Previously threw BadImageFormatException (Bad binary signature, 0x80131192) because the
    // expression-tree compiler cannot handle the IsExternalInit modreq on the setter return parameter.

    [Fact]
    public void BuildSetter_InitOnlyProperty_DoesNotThrow()
    {
        var prop = typeof(InitOnlyEntity).GetProperty(nameof(InitOnlyEntity.InitProp))!;

        // Must not throw BadImageFormatException
        var setter = PropertyAccessorFactory.BuildSetter(prop);
        Assert.NotNull(setter);
    }

    [Fact]
    public void BuildSetter_InitOnlyProperty_SetsValueCorrectly()
    {
        var prop = typeof(InitOnlyEntity).GetProperty(nameof(InitOnlyEntity.InitProp))!;
        var setter = PropertyAccessorFactory.BuildSetter(prop);

        var entity = new InitOnlyEntity();
        setter(entity, "Hello");

        Assert.Equal("Hello", entity.InitProp);
    }

    [Fact]
    public void BuildSetter_InitOnlyIntProperty_SetsValueCorrectly()
    {
        var prop = typeof(InitOnlyEntity).GetProperty(nameof(InitOnlyEntity.InitInt))!;
        var setter = PropertyAccessorFactory.BuildSetter(prop);

        var entity = new InitOnlyEntity();
        setter(entity, 99);

        Assert.Equal(99, entity.InitInt);
    }

    // ── BuildSetter: get-only property ────────────────────────────────────

    [Fact]
    public void BuildSetter_GetOnlyProperty_FallsBackToReflection()
    {
        var prop = typeof(GetOnlyEntity).GetProperty(nameof(GetOnlyEntity.ReadOnlyProp))!;
        var setter = PropertyAccessorFactory.BuildSetter(prop);

        // get-only property has a backing field so SetValue via reflection is a no-op
        // but the delegate must be returned without throwing
        Assert.NotNull(setter);
    }

    // ── BuildGetter: regular property ─────────────────────────────────────

    [Fact]
    public void BuildGetter_RegularProperty_ReturnsValue()
    {
        var prop = typeof(RegularEntity).GetProperty(nameof(RegularEntity.Name))!;
        var getter = PropertyAccessorFactory.BuildGetter(prop);

        var entity = new RegularEntity { Name = "Bob" };

        Assert.Equal("Bob", getter(entity));
    }

    // ── Round-trip: init-only property ────────────────────────────────────

    [Fact]
    public void GetterAndSetter_InitOnlyProperty_RoundTrip()
    {
        var prop = typeof(InitOnlyEntity).GetProperty(nameof(InitOnlyEntity.InitProp))!;
        var getter = PropertyAccessorFactory.BuildGetter(prop);
        var setter = PropertyAccessorFactory.BuildSetter(prop);

        var entity = new InitOnlyEntity();
        setter(entity, "World");

        Assert.Equal("World", getter(entity));
    }
}
