using BareMetalWeb.Intelligence;
using BareMetalWeb.Intelligence.Interfaces;

namespace BareMetalWeb.Intelligence.Tests;

public class KeywordIntentClassifierTests
{
    private static KeywordIntentClassifier CreateClassifier()
    {
        var intents = AdminToolCatalogue.GetIntentDefinitions();
        return new KeywordIntentClassifier(intents);
    }

    [Fact]
    public void Classify_ListEntities_ReturnsCorrectIntent()
    {
        var classifier = CreateClassifier();

        var result = classifier.Classify("list all entities");

        Assert.Equal("list-entities", result.IntentName);
        Assert.True(result.IsMatch);
    }

    [Fact]
    public void Classify_ShowDataModels_ReturnsListEntities()
    {
        var classifier = CreateClassifier();

        var result = classifier.Classify("show data models");

        Assert.Equal("list-entities", result.IntentName);
        Assert.True(result.IsMatch);
    }

    [Fact]
    public void Classify_DescribeEntity_ReturnsCorrectIntent()
    {
        var classifier = CreateClassifier();

        var result = classifier.Classify("describe the fields of this entity");

        Assert.Equal("describe-entity", result.IntentName);
        Assert.True(result.IsMatch);
    }

    [Fact]
    public void Classify_QueryRecords_ReturnsQueryIntent()
    {
        var classifier = CreateClassifier();

        var result = classifier.Classify("query records from data");

        Assert.Equal("query-entity", result.IntentName);
        Assert.True(result.IsMatch);
    }

    [Fact]
    public void Classify_SystemStatus_ReturnsStatusIntent()
    {
        var classifier = CreateClassifier();

        var result = classifier.Classify("system health diagnostics");

        Assert.Equal("system-status", result.IntentName);
        Assert.True(result.IsMatch);
    }

    [Fact]
    public void Classify_Help_ReturnsHelpIntent()
    {
        var classifier = CreateClassifier();

        var result = classifier.Classify("help what can you do");

        Assert.Equal("help", result.IntentName);
        Assert.True(result.IsMatch);
    }

    [Fact]
    public void Classify_IndexStatus_ReturnsIndexIntent()
    {
        var classifier = CreateClassifier();

        var result = classifier.Classify("search index statistics");

        Assert.Equal("index-status", result.IntentName);
        Assert.True(result.IsMatch);
    }

    [Fact]
    public void Classify_EmptyQuery_ReturnsLowConfidence()
    {
        var classifier = CreateClassifier();

        var result = classifier.Classify("");

        Assert.False(result.IsMatch);
        Assert.Equal(0f, result.Confidence);
    }

    [Fact]
    public void Classify_Gibberish_ReturnsLowConfidence()
    {
        var classifier = CreateClassifier();

        var result = classifier.Classify("xyzzy plugh qwerty");

        Assert.False(result.IsHighConfidence);
    }
}
