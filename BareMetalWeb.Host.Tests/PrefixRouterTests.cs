using Xunit;

namespace BareMetalWeb.Host.Tests;

public class PrefixRouterTests
{
    // ── ClassifyRoute tests ─────────────────────────────────────────────

    [Fact]
    public void ClassifyRoute_GetEmpty_ReturnsList()
    {
        var kind = PrefixRouter.ClassifyRoute("GET", ReadOnlySpan<char>.Empty,
            out var id, out var extra, out var extraKey);
        Assert.Equal((int)ApiRouteKind.List, kind);
        Assert.True(id.IsEmpty);
        Assert.True(extra.IsEmpty);
        Assert.Null(extraKey);
    }

    [Fact]
    public void ClassifyRoute_PostEmpty_ReturnsCreate()
    {
        var kind = PrefixRouter.ClassifyRoute("POST", ReadOnlySpan<char>.Empty,
            out _, out _, out _);
        Assert.Equal((int)ApiRouteKind.Create, kind);
    }

    [Fact]
    public void ClassifyRoute_PostImport_ReturnsImport()
    {
        var kind = PrefixRouter.ClassifyRoute("POST", "import".AsSpan(),
            out _, out _, out _);
        Assert.Equal((int)ApiRouteKind.Import, kind);
    }

    [Fact]
    public void ClassifyRoute_GetImport_ReturnsNegative()
    {
        var kind = PrefixRouter.ClassifyRoute("GET", "import".AsSpan(),
            out _, out _, out _);
        Assert.Equal(-1, kind);
    }

    [Fact]
    public void ClassifyRoute_GetId_ReturnsGet()
    {
        var kind = PrefixRouter.ClassifyRoute("GET", "42".AsSpan(),
            out var id, out _, out _);
        Assert.Equal((int)ApiRouteKind.Get, kind);
        Assert.True(id.SequenceEqual("42".AsSpan()));
    }

    [Fact]
    public void ClassifyRoute_PutId_ReturnsUpdate()
    {
        var kind = PrefixRouter.ClassifyRoute("PUT", "42".AsSpan(),
            out var id, out _, out _);
        Assert.Equal((int)ApiRouteKind.Update, kind);
        Assert.True(id.SequenceEqual("42".AsSpan()));
    }

    [Fact]
    public void ClassifyRoute_PatchId_ReturnsPatch()
    {
        var kind = PrefixRouter.ClassifyRoute("PATCH", "42".AsSpan(),
            out _, out _, out _);
        Assert.Equal((int)ApiRouteKind.Patch, kind);
    }

    [Fact]
    public void ClassifyRoute_DeleteId_ReturnsDelete()
    {
        var kind = PrefixRouter.ClassifyRoute("DELETE", "42".AsSpan(),
            out _, out _, out _);
        Assert.Equal((int)ApiRouteKind.Delete, kind);
    }

    [Fact]
    public void ClassifyRoute_GetIdAttachments_ReturnsListAttachments()
    {
        var kind = PrefixRouter.ClassifyRoute("GET", "42/_attachments".AsSpan(),
            out var id, out _, out _);
        Assert.Equal((int)ApiRouteKind.ListAttachments, kind);
        Assert.True(id.SequenceEqual("42".AsSpan()));
    }

    [Fact]
    public void ClassifyRoute_PostIdAttachments_ReturnsAddAttachment()
    {
        var kind = PrefixRouter.ClassifyRoute("POST", "42/_attachments".AsSpan(),
            out _, out _, out _);
        Assert.Equal((int)ApiRouteKind.AddAttachment, kind);
    }

    [Fact]
    public void ClassifyRoute_GetIdComments_ReturnsListComments()
    {
        var kind = PrefixRouter.ClassifyRoute("GET", "42/_comments".AsSpan(),
            out _, out _, out _);
        Assert.Equal((int)ApiRouteKind.ListComments, kind);
    }

    [Fact]
    public void ClassifyRoute_PostIdComments_ReturnsAddComment()
    {
        var kind = PrefixRouter.ClassifyRoute("POST", "42/_comments".AsSpan(),
            out _, out _, out _);
        Assert.Equal((int)ApiRouteKind.AddComment, kind);
    }

    [Fact]
    public void ClassifyRoute_GetIdRelatedChain_ReturnsRelatedChain()
    {
        var kind = PrefixRouter.ClassifyRoute("GET", "42/_related-chain".AsSpan(),
            out var id, out _, out _);
        Assert.Equal((int)ApiRouteKind.RelatedChain, kind);
        Assert.True(id.SequenceEqual("42".AsSpan()));
    }

    [Fact]
    public void ClassifyRoute_GetIdFilesField_ReturnsFileGet()
    {
        var kind = PrefixRouter.ClassifyRoute("GET", "42/files/avatar".AsSpan(),
            out var id, out var extra, out var extraKey);
        Assert.Equal((int)ApiRouteKind.FileGet, kind);
        Assert.True(id.SequenceEqual("42".AsSpan()));
        Assert.True(extra.SequenceEqual("avatar".AsSpan()));
        Assert.Equal("field", extraKey);
    }

    [Fact]
    public void ClassifyRoute_PostIdCommandAction_ReturnsCommand()
    {
        var kind = PrefixRouter.ClassifyRoute("POST", "42/_command/approve".AsSpan(),
            out var id, out var extra, out var extraKey);
        Assert.Equal((int)ApiRouteKind.Command, kind);
        Assert.True(id.SequenceEqual("42".AsSpan()));
        Assert.True(extra.SequenceEqual("approve".AsSpan()));
        Assert.Equal("command", extraKey);
    }

    [Fact]
    public void ClassifyRoute_UnknownVerb_ReturnsNegative()
    {
        var kind = PrefixRouter.ClassifyRoute("OPTIONS", ReadOnlySpan<char>.Empty,
            out _, out _, out _);
        Assert.Equal(-1, kind);
    }

    [Fact]
    public void ClassifyRoute_UnknownSuffix_ReturnsNegative()
    {
        var kind = PrefixRouter.ClassifyRoute("GET", "42/unknown".AsSpan(),
            out _, out _, out _);
        Assert.Equal(-1, kind);
    }

    [Fact]
    public void ClassifyRoute_CaseInsensitiveVerb()
    {
        var kind = PrefixRouter.ClassifyRoute("get", ReadOnlySpan<char>.Empty,
            out _, out _, out _);
        Assert.Equal((int)ApiRouteKind.List, kind);
    }

    [Fact]
    public void ClassifyRoute_CaseInsensitiveSuffix()
    {
        var kind = PrefixRouter.ClassifyRoute("GET", "42/_Attachments".AsSpan(),
            out _, out _, out _);
        Assert.Equal((int)ApiRouteKind.ListAttachments, kind);
    }

    // ── ApiRouteKind coverage ───────────────────────────────────────────

    [Fact]
    public void ApiRouteKind_CountSentinel_MatchesExpected()
    {
        // Ensure the sentinel tracks the actual number of route kinds
        Assert.Equal(14, (int)ApiRouteKind._Count);
    }
}
