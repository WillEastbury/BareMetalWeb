using System.Text;

namespace BareMetalWeb.Host.Tests;

public class EntityPrefixRouterTests
{
    // ── Build & Count ────────────────────────────────────────

    [Fact]
    public void Build_EmptyList_CountIsZero()
    {
        var router = new EntityPrefixRouter();
        router.Build(Array.Empty<EntityRoute>());
        Assert.Equal(0, router.Count);
    }

    [Fact]
    public void Build_FromSlugs_AssignsContiguousOrdinals()
    {
        var router = new EntityPrefixRouter();
        router.Build(new[] { "customer", "order", "invoice" });

        Assert.Equal(3, router.Count);
        Assert.True(router.TryResolve("customer"u8, out _, out int o0));
        Assert.True(router.TryResolve("order"u8, out _, out int o1));
        Assert.True(router.TryResolve("invoice"u8, out _, out int o2));
        Assert.Equal(0, o0);
        Assert.Equal(1, o1);
        Assert.Equal(2, o2);
    }

    [Fact]
    public void Build_FromEntityRoutes_PreservesOrdinals()
    {
        var router = new EntityPrefixRouter();
        router.Build(new[]
        {
            new EntityRoute("customer", 10),
            new EntityRoute("order", 20),
            new EntityRoute("invoice", 30),
        });

        Assert.True(router.TryResolve("customer"u8, out _, out int ord));
        Assert.Equal(10, ord);
    }

    // ── TryResolve (byte span) ───────────────────────────────

    [Fact]
    public void TryResolve_KnownSlug_ReturnsTrueWithName()
    {
        var router = BuildRouter("customer", "order", "invoice");

        Assert.True(router.TryResolve("customer"u8, out var name, out _));
        Assert.Equal("customer", name);
    }

    [Fact]
    public void TryResolve_UnknownSlug_ReturnsFalse()
    {
        var router = BuildRouter("customer", "order");
        Assert.False(router.TryResolve("product"u8, out _, out _));
    }

    [Fact]
    public void TryResolve_EmptySlug_ReturnsFalse()
    {
        var router = BuildRouter("customer");
        Assert.False(router.TryResolve(ReadOnlySpan<byte>.Empty, out _, out _));
    }

    [Fact]
    public void TryResolve_EmptyRouter_ReturnsFalse()
    {
        var router = new EntityPrefixRouter();
        router.Build(Array.Empty<string>());
        Assert.False(router.TryResolve("anything"u8, out _, out _));
    }

    [Fact]
    public void TryResolve_CaseInsensitive()
    {
        var router = BuildRouter("customer");

        Assert.True(router.TryResolve("Customer"u8, out _, out _));
        Assert.True(router.TryResolve("CUSTOMER"u8, out _, out _));
        Assert.True(router.TryResolve("cUsToMeR"u8, out _, out _));
    }

    [Fact]
    public void TryResolve_AllEntities_Resolvable()
    {
        var slugs = new[] { "users", "orders", "products", "invoices", "categories",
                            "tags", "roles", "permissions", "notifications", "settings" };
        var router = BuildRouter(slugs);

        foreach (var slug in slugs)
        {
            var bytes = Encoding.UTF8.GetBytes(slug);
            Assert.True(router.TryResolve(bytes, out var name, out _), $"Failed: {slug}");
            Assert.Equal(slug, name);
        }
    }

    // ── TryResolve (char span) ───────────────────────────────

    [Fact]
    public void TryResolve_CharSpan_Works()
    {
        var router = BuildRouter("customer", "order");
        Assert.True(router.TryResolve("customer".AsSpan(), out var name, out _));
        Assert.Equal("customer", name);
    }

    // ── Shared prefix handling ────────────────────────────────

    [Fact]
    public void TryResolve_SharedPrefix_LongestMatchFirst()
    {
        var router = new EntityPrefixRouter();
        router.Build(new[]
        {
            new EntityRoute("customer", 0),
            new EntityRoute("customerGroup", 1),
        });

        // "customerGroup" should match ordinal 1, not 0
        Assert.True(router.TryResolve("customerGroup"u8, out _, out int ordG));
        Assert.Equal(1, ordG);

        // "customer" should match ordinal 0
        Assert.True(router.TryResolve("customer"u8, out _, out int ordC));
        Assert.Equal(0, ordC);
    }

    [Fact]
    public void TryResolve_SharedPrefix_ThreeWay()
    {
        var router = new EntityPrefixRouter();
        router.Build(new[]
        {
            new EntityRoute("cat", 0),
            new EntityRoute("category", 1),
            new EntityRoute("categoryGroup", 2),
        });

        Assert.True(router.TryResolve("categoryGroup"u8, out _, out int o2));
        Assert.Equal(2, o2);
        Assert.True(router.TryResolve("category"u8, out _, out int o1));
        Assert.Equal(1, o1);
        Assert.True(router.TryResolve("cat"u8, out _, out int o0));
        Assert.Equal(0, o0);
    }

    // ── Match helpers ─────────────────────────────────────────

    [Fact]
    public void Match_ByteSpan_ExactMatch()
    {
        Assert.True(EntityPrefixRouter.Match("customer"u8, "customer"u8));
        Assert.False(EntityPrefixRouter.Match("customer"u8, "order"u8));
        Assert.False(EntityPrefixRouter.Match("customer"u8, "custom"u8));
    }

    [Fact]
    public void Match_StringLiteral_Works()
    {
        Assert.True(EntityPrefixRouter.Match("customer"u8, "customer"));
        Assert.False(EntityPrefixRouter.Match("customer"u8, "order"));
    }

    [Fact]
    public void Match_CaseSensitive()
    {
        // Match() is strict — no case folding
        Assert.False(EntityPrefixRouter.Match("Customer"u8, "customer"u8));
    }

    [Fact]
    public void MatchIgnoreAsciiCase_CaseInsensitive()
    {
        Assert.True(EntityPrefixRouter.MatchIgnoreAsciiCase("Customer"u8, "customer"u8));
        Assert.True(EntityPrefixRouter.MatchIgnoreAsciiCase("CUSTOMER"u8, "customer"u8));
        Assert.False(EntityPrefixRouter.MatchIgnoreAsciiCase("order"u8, "customer"u8));
    }

    [Fact]
    public void MatchIgnoreAsciiCase_DifferentLengths_ReturnsFalse()
    {
        Assert.False(EntityPrefixRouter.MatchIgnoreAsciiCase("cust"u8, "customer"u8));
    }

    // ── TryParseAndResolve (path parsing) ─────────────────────

    [Fact]
    public void TryParseAndResolve_FullPath()
    {
        var router = BuildRouter("customer", "order", "invoice");

        Assert.True(router.TryParseAndResolve(
            "/ui/customer/123"u8,
            "/ui/"u8,
            out var name, out int ordinal, out var remainder));

        Assert.Equal("customer", name);
        Assert.Equal(0, ordinal);
        Assert.True(remainder.SequenceEqual("123"u8));
    }

    [Fact]
    public void TryParseAndResolve_NoRemainder()
    {
        var router = BuildRouter("customer");

        Assert.True(router.TryParseAndResolve(
            "/ui/customer"u8, "/ui/"u8,
            out _, out int ordinal, out var remainder));

        Assert.Equal(0, ordinal);
        Assert.True(remainder.IsEmpty);
    }

    [Fact]
    public void TryParseAndResolve_WrongPrefix_ReturnsFalse()
    {
        var router = BuildRouter("customer");

        Assert.False(router.TryParseAndResolve(
            "/api/customer/123"u8, "/ui/"u8,
            out _, out _, out _));
    }

    [Fact]
    public void TryParseAndResolve_UnknownEntity_ReturnsFalse()
    {
        var router = BuildRouter("customer");

        Assert.False(router.TryParseAndResolve(
            "/ui/product/123"u8, "/ui/"u8,
            out _, out _, out _));
    }

    [Fact]
    public void TryParseAndResolve_DeepPath()
    {
        var router = BuildRouter("order");

        Assert.True(router.TryParseAndResolve(
            "/api/order/42/items/5"u8, "/api/"u8,
            out _, out int ordinal, out var remainder));

        Assert.Equal(0, ordinal);
        Assert.True(remainder.SequenceEqual("42/items/5"u8));
    }

    // ── Edge cases ────────────────────────────────────────────

    [Fact]
    public void TryResolve_SameBucket_MultipleEntities()
    {
        // All start with 'c' — same bucket
        var router = BuildRouter("customer", "category", "comment", "cart");

        Assert.True(router.TryResolve("customer"u8, out _, out _));
        Assert.True(router.TryResolve("category"u8, out _, out _));
        Assert.True(router.TryResolve("comment"u8, out _, out _));
        Assert.True(router.TryResolve("cart"u8, out _, out _));
    }

    [Fact]
    public void TryResolve_SingleCharEntity()
    {
        var router = BuildRouter("a", "b", "z");
        Assert.True(router.TryResolve("a"u8, out _, out _));
        Assert.True(router.TryResolve("z"u8, out _, out _));
    }

    [Fact]
    public void TryResolve_NumericFirstChar_ReturnsFalse()
    {
        var router = BuildRouter("customer");
        Assert.False(router.TryResolve("123entity"u8, out _, out _));
    }

    [Fact]
    public void Build_CanRebuild()
    {
        var router = new EntityPrefixRouter();
        router.Build(new[] { "customer" });
        Assert.True(router.TryResolve("customer"u8, out _, out _));

        router.Build(new[] { "order" });
        Assert.False(router.TryResolve("customer"u8, out _, out _));
        Assert.True(router.TryResolve("order"u8, out _, out _));
    }

    // ── Benchmark-style stress test ───────────────────────────

    [Fact]
    public void Benchmark_ManyEntities_AllResolvable()
    {
        var slugs = new List<string>();
        for (char c = 'a'; c <= 'z'; c++)
            slugs.Add($"{c}entity");

        var router = BuildRouter(slugs.ToArray());

        for (int iter = 0; iter < 1000; iter++)
        {
            foreach (var slug in slugs)
            {
                var bytes = Encoding.UTF8.GetBytes(slug);
                Assert.True(router.TryResolve(bytes, out _, out _));
            }
        }

        Assert.Equal(26_000, 26 * 1000); // sanity — all slugs resolved above
    }

    // ── Helper ────────────────────────────────────────────────

    private static EntityPrefixRouter BuildRouter(params string[] slugs)
    {
        var router = new EntityPrefixRouter();
        router.Build(slugs);
        return router;
    }
}
