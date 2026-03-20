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
        private const int Ord_Number = BaseFieldCount + 0;
        internal new const int TotalFieldCount = BaseFieldCount + 1;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("Number", Ord_Number),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public SourceDoc() : base(TotalFieldCount) { }
        public SourceDoc(string createdBy) : base(TotalFieldCount, createdBy) { }

        public string Number
        {
            get => (string?)_values[Ord_Number] ?? string.Empty;
            set => _values[Ord_Number] = value;
        }
    }

    private class DerivedDoc : BaseDataObject
    {
        private const int Ord_SourceDocId = BaseFieldCount + 0;
        internal new const int TotalFieldCount = BaseFieldCount + 1;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("SourceDocId", Ord_SourceDocId),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public DerivedDoc() : base(TotalFieldCount) { }
        public DerivedDoc(string createdBy) : base(TotalFieldCount, createdBy) { }


        [RelatedDocument(typeof(SourceDoc), DisplayField = "Number")]
        public string? SourceDocId
        {
            get => (string?)_values[Ord_SourceDocId];
            set => _values[Ord_SourceDocId] = value;
        }
    }

    private class PlainDoc : BaseDataObject
    {
        private const int Ord_Title = BaseFieldCount + 0;
        internal new const int TotalFieldCount = BaseFieldCount + 1;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("Title", Ord_Title),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public PlainDoc() : base(TotalFieldCount) { }
        public PlainDoc(string createdBy) : base(TotalFieldCount, createdBy) { }

        public string Title
        {
            get => (string?)_values[Ord_Title] ?? string.Empty;
            set => _values[Ord_Title] = value;
        }
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
