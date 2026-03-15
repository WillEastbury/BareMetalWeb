using BareMetalWeb.Intelligence;

namespace BareMetalWeb.Intelligence.Tests;

public class IntentClassifierTests
{
    private static readonly IntentClassifier Sut = new();

    // ── System pattern matching ───────────────────────────────────────────

    [Theory]
    [InlineData("system status",  "system.status")]
    [InlineData("system health",  "system.status")]
    [InlineData("sys health",     "system.status")]
    [InlineData("health check",   "system.status")]
    [InlineData("memory usage",   "system.memory")]
    [InlineData("memory stats",   "system.memory")]
    [InlineData("heap stats",     "system.memory")]
    [InlineData("list entities",  "system.list-entities")]
    [InlineData("show entities",  "system.list-entities")]
    [InlineData("all entities",   "system.list-entities")]
    [InlineData("rebuild index",  "system.maintenance")]
    public void Classify_SystemPattern_ReturnsExpectedIntent(string query, string expectedIntent)
    {
        var result = Sut.Classify(query.AsSpan());

        Assert.Equal(expectedIntent, result.ResolvedIntent);
        Assert.True(result.Confidence >= 0.9f, $"Confidence {result.Confidence} < 0.9 for '{query}'");
        Assert.True(result.IsConfident);
    }

    // ── Entity + action routing ───────────────────────────────────────────

    [Theory]
    [InlineData("list users",         "entity.list.users",    IntentAction.List)]
    [InlineData("show all users",     "entity.list.users",    IntentAction.List)]
    [InlineData("create user",        "entity.create.users",  IntentAction.Create)]
    [InlineData("add new user",       "entity.create.users",  IntentAction.Create)]
    [InlineData("edit user",          "entity.edit.users",    IntentAction.Edit)]
    [InlineData("update user",        "entity.edit.users",    IntentAction.Edit)]
    [InlineData("delete user",        "entity.delete.users",  IntentAction.Delete)]
    [InlineData("remove user",        "entity.delete.users",  IntentAction.Delete)]
    [InlineData("show user",          "entity.query.users",   IntentAction.Query)]
    [InlineData("describe user",      "entity.query.users",   IntentAction.Query)]
    [InlineData("list roles",         "entity.list.roles",    IntentAction.List)]
    [InlineData("create role",        "entity.create.roles",  IntentAction.Create)]
    [InlineData("list notifications", "entity.list.notifications", IntentAction.List)]
    public void Classify_EntityAction_ReturnsCorrectRouting(
        string query, string expectedIntent, IntentAction expectedAction)
    {
        var result = Sut.Classify(query.AsSpan());

        Assert.Equal(expectedIntent, result.ResolvedIntent);
        Assert.Equal(expectedAction, result.Action);
        Assert.True(result.IsConfident, $"Expected confident result for '{query}' (confidence={result.Confidence})");
    }

    // ── Unknown / low-confidence queries ─────────────────────────────────

    [Theory]
    [InlineData("hello")]
    [InlineData("xyzzy plugh")]
    [InlineData("42")]
    public void Classify_UnknownQuery_ReturnsLowConfidence(string query)
    {
        var result = Sut.Classify(query.AsSpan());

        Assert.False(result.IsConfident, $"Expected low confidence for '{query}'");
    }

    // ── Empty / null queries ──────────────────────────────────────────────

    [Fact]
    public void Classify_EmptySpan_ReturnsEmpty()
    {
        var result = Sut.Classify(ReadOnlySpan<char>.Empty);

        Assert.Equal(IntentResult.Empty.ResolvedIntent, result.ResolvedIntent);
        Assert.Equal(0f, result.Confidence);
    }

    // ── Entity ID extraction ──────────────────────────────────────────────

    [Theory]
    [InlineData("show user 42",   "42")]
    [InlineData("edit user id=5", "5")]
    [InlineData("delete user #7", "7")]
    public void Classify_QueryWithEntityId_ExtractsId(string query, string expectedId)
    {
        var result = Sut.Classify(query.AsSpan());

        Assert.Equal(expectedId, result.EntityId);
    }

    // ── Form field extraction ─────────────────────────────────────────────

    [Fact]
    public void Classify_CreateQueryWithFields_ExtractsFormFields()
    {
        var result = Sut.Classify("create user name=Alice".AsSpan());

        Assert.NotNull(result.FormFields);
        Assert.True(result.FormFields!.ContainsKey("name"));
        Assert.Equal("alice", result.FormFields["name"]);
    }

    [Fact]
    public void Classify_QueryWithoutFields_FormFieldsIsNull()
    {
        // Non-create/edit queries should not extract form fields
        var result = Sut.Classify("list users".AsSpan());

        Assert.Null(result.FormFields);
    }

    // ── Async API (no model) ──────────────────────────────────────────────

    [Fact]
    public async Task ClassifyWithFallbackAsync_NoEngine_ReturnsKeywordResult()
    {
        var result = await Sut.ClassifyWithFallbackAsync("list users", engine: null);

        Assert.True(result.ResolvedIntent.StartsWith("entity.list."), result.ResolvedIntent);
        Assert.True(result.IsConfident);
    }

    [Fact]
    public async Task ClassifyWithFallbackAsync_EmptyQuery_ReturnsEmpty()
    {
        var result = await Sut.ClassifyWithFallbackAsync("  ", engine: null);

        Assert.Equal(IntentResult.Empty.ResolvedIntent, result.ResolvedIntent);
    }

    // ── Confidence arithmetic ─────────────────────────────────────────────

    [Fact]
    public void Classify_VerbAndEntityBothMatched_ConfidenceHigherThanEitherAlone()
    {
        var verbOnly   = Sut.Classify("list xyzzy".AsSpan());      // verb only (no entity)
        var entityOnly = Sut.Classify("hello user here".AsSpan()); // entity only (no verb)
        var both       = Sut.Classify("list users".AsSpan());      // verb + entity

        // With both matched, the combined formula must exceed each alone.
        Assert.True(both.Confidence > verbOnly.Confidence,
            $"both({both.Confidence}) should be > verb-only({verbOnly.Confidence})");
        Assert.True(both.Confidence > entityOnly.Confidence,
            $"both({both.Confidence}) should be > entity-only({entityOnly.Confidence})");
    }

    // ── IntentResult helpers ──────────────────────────────────────────────

    [Fact]
    public void IntentResult_Empty_HasZeroConfidence()
    {
        Assert.Equal(0f,       IntentResult.Empty.Confidence);
        Assert.Equal("none",   IntentResult.Empty.ResolvedIntent);
        Assert.False(IntentResult.Empty.IsConfident);
    }
}
