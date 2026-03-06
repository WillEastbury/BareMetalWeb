using Xunit;

namespace BareMetalWeb.Host.Tests;

public class EntityRouteTableTests
{
    [Fact]
    public void Build_EmptySlugs_CountIsZero()
    {
        var table = new EntityRouteTable();
        table.Build(Array.Empty<string>());
        Assert.Equal(0, table.Count);
    }

    [Fact]
    public void TryResolve_EmptyTable_ReturnsFalse()
    {
        var table = new EntityRouteTable();
        table.Build(Array.Empty<string>());
        Assert.False(table.TryResolve("users".AsSpan(), out _));
    }

    [Fact]
    public void Build_SingleSlug_CountIsOne()
    {
        var table = new EntityRouteTable();
        table.Build(new[] { "users" });
        Assert.Equal(1, table.Count);
    }

    [Fact]
    public void TryResolve_KnownSlug_ReturnsTrueWithInternedString()
    {
        var table = new EntityRouteTable();
        var original = "users";
        table.Build(new[] { original });

        Assert.True(table.TryResolve("users".AsSpan(), out var resolved));
        Assert.Same(original, resolved); // Same reference — zero allocation
    }

    [Fact]
    public void TryResolve_UnknownSlug_ReturnsFalse()
    {
        var table = new EntityRouteTable();
        table.Build(new[] { "users", "orders" });
        Assert.False(table.TryResolve("products".AsSpan(), out _));
    }

    [Fact]
    public void TryResolve_CaseInsensitive()
    {
        var table = new EntityRouteTable();
        table.Build(new[] { "users" });

        Assert.True(table.TryResolve("Users".AsSpan(), out var r1));
        Assert.True(table.TryResolve("USERS".AsSpan(), out var r2));
        Assert.Equal("users", r1);
        Assert.Equal("users", r2);
    }

    [Fact]
    public void TryResolve_MultipleSlugs_AllResolvable()
    {
        var slugs = new[] { "users", "orders", "products", "invoices", "categories" };
        var table = new EntityRouteTable();
        table.Build(slugs);

        Assert.Equal(5, table.Count);
        foreach (var slug in slugs)
        {
            Assert.True(table.TryResolve(slug.AsSpan(), out var resolved), $"Failed to resolve: {slug}");
            Assert.Equal(slug, resolved);
        }
    }

    [Fact]
    public void TryResolve_ManyEntities_HandlesCollisions()
    {
        // Generate enough slugs to stress collision handling
        var slugs = new List<string>();
        for (int i = 0; i < 100; i++)
            slugs.Add($"entity-{i:D3}");

        var table = new EntityRouteTable();
        table.Build(slugs);

        Assert.Equal(100, table.Count);
        foreach (var slug in slugs)
        {
            Assert.True(table.TryResolve(slug.AsSpan(), out var resolved), $"Failed: {slug}");
            Assert.Equal(slug, resolved);
        }
    }

    [Fact]
    public void TryResolve_SystemPrefix_NotInTable()
    {
        var table = new EntityRouteTable();
        table.Build(new[] { "users", "orders" });

        // System prefixes should NOT be in entity table
        Assert.False(table.TryResolve("_binary".AsSpan(), out _));
        Assert.False(table.TryResolve("_lookup".AsSpan(), out _));
        Assert.False(table.TryResolve("metadata".AsSpan(), out _));
    }

    [Fact]
    public void Build_CanRebuild()
    {
        var table = new EntityRouteTable();
        table.Build(new[] { "users" });
        Assert.True(table.TryResolve("users".AsSpan(), out _));

        table.Build(new[] { "orders" });
        Assert.False(table.TryResolve("users".AsSpan(), out _));
        Assert.True(table.TryResolve("orders".AsSpan(), out _));
    }
}
