using System;
using System.Reflection;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for the RelatedDocumentAttribute and document-chain metadata infrastructure.
/// </summary>
public class RelatedDocumentTests
{
    // ── Dummy entity types used in tests ──────────────────────────────────────

    private class SourceDoc : BaseDataObject
    {
        public string Number { get; set; } = string.Empty;
        public SourceDoc() : base("src") { }
    }

    private class DerivedDoc : BaseDataObject
    {
        [RelatedDocument(typeof(SourceDoc), DisplayField = "Number")]
        public string? SourceDocId { get; set; }
        public DerivedDoc() : base("drv") { }
    }

    private class PlainDoc : BaseDataObject
    {
        public string Title { get; set; } = string.Empty;
        public PlainDoc() : base("plain") { }
    }

    // ── Attribute construction ────────────────────────────────────────────────

    [Fact]
    public void RelatedDocumentAttribute_Ctor_SetsTargetType()
    {
        var attr = new RelatedDocumentAttribute(typeof(SourceDoc));
        Assert.Equal(typeof(SourceDoc), attr.TargetType);
    }

    [Fact]
    public void RelatedDocumentAttribute_DefaultDisplayField_IsName()
    {
        var attr = new RelatedDocumentAttribute(typeof(SourceDoc));
        Assert.Equal("Name", attr.DisplayField);
    }

    [Fact]
    public void RelatedDocumentAttribute_CustomDisplayField_IsSet()
    {
        var attr = new RelatedDocumentAttribute(typeof(SourceDoc)) { DisplayField = "Number" };
        Assert.Equal("Number", attr.DisplayField);
    }

    // ── Attribute detection on properties ────────────────────────────────────

    [Fact]
    public void RelatedDocumentAttribute_IsDetectedOnProperty()
    {
        var prop = typeof(DerivedDoc).GetProperty(nameof(DerivedDoc.SourceDocId))!;
        var attr = prop.GetCustomAttribute<RelatedDocumentAttribute>();

        Assert.NotNull(attr);
        Assert.Equal(typeof(SourceDoc), attr!.TargetType);
        Assert.Equal("Number", attr.DisplayField);
    }

    [Fact]
    public void RelatedDocumentAttribute_IsNotPresentOnUntaggedProperty()
    {
        var prop = typeof(PlainDoc).GetProperty(nameof(PlainDoc.Title))!;
        var attr = prop.GetCustomAttribute<RelatedDocumentAttribute>();

        Assert.Null(attr);
    }

    // ── ViewType enum ─────────────────────────────────────────────────────────

    [Fact]
    public void ViewType_HasSankeyOption_WithCorrectValue()
    {
        Assert.Equal(5, (int)ViewType.Sankey);
    }

    [Fact]
    public void ViewType_AllValuesIncludingSankey_AreUnique()
    {
        var values = new[]
        {
            (int)ViewType.Table,
            (int)ViewType.TreeView,
            (int)ViewType.OrgChart,
            (int)ViewType.Timeline,
            (int)ViewType.Timetable,
            (int)ViewType.Sankey
        };
        var unique = new System.Collections.Generic.HashSet<int>(values);
        Assert.Equal(values.Length, unique.Count);
    }

    // ── RelatedDocumentConfig ────────────────────────────────────────────────

    [Fact]
    public void RelatedDocumentConfig_StoresTargetTypeAndDisplayField()
    {
        var cfg = new RelatedDocumentConfig(typeof(SourceDoc), "Number");
        Assert.Equal(typeof(SourceDoc), cfg.TargetType);
        Assert.Equal("Number", cfg.DisplayField);
    }
}
