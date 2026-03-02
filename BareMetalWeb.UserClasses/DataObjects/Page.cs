using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Data.DataObjects;

/// <summary>
/// Simple content page — renders Markdown or trusted HTML inside the platform shell.
/// No complex CMS logic; just slug-based content with publish/draft state.
/// </summary>
[DataEntity("Pages", ShowOnNav = true, NavGroup = "Content", NavOrder = 10)]
public class Page : RenderableDataObject
{
    /// <summary>URL-safe slug for this page (e.g. "about", "getting-started").</summary>
    [DataField(Label = "Slug", Order = 1, Required = true)]
    [DataIndex]
    public string Slug { get; set; } = string.Empty;

    [DataField(Label = "Title", Order = 2, Required = true)]
    public string Title { get; set; } = string.Empty;

    /// <summary>
    /// Page content — supports Markdown or trusted HTML.
    /// Content is rendered as-is inside the platform shell.
    /// </summary>
    [DataField(Label = "Content", Order = 3, FieldType = FormFieldType.TextArea)]
    public string Content { get; set; } = string.Empty;

    /// <summary>Content format: "html" or "markdown".</summary>
    [DataField(Label = "Format", Order = 4)]
    public string Format { get; set; } = "html";

    /// <summary>Publication state: "draft" or "published".</summary>
    [DataField(Label = "Status", Order = 5)]
    [DataIndex]
    public string Status { get; set; } = "draft";

    /// <summary>Optional meta description for SEO.</summary>
    [DataField(Label = "Meta Description", Order = 6)]
    public string MetaDescription { get; set; } = string.Empty;

    /// <summary>Display order in navigation (lower = earlier).</summary>
    [DataField(Label = "Nav Order", Order = 7)]
    public int NavOrder { get; set; } = 100;

    /// <summary>Whether this page appears in the site navigation.</summary>
    [DataField(Label = "Show in Nav", Order = 8)]
    public bool ShowInNav { get; set; }

    /// <summary>
    /// Required permission to view this page.
    /// Use "Public" for everyone, "Authenticated" for logged-in users only,
    /// or a comma-separated list of role names for role-based access.
    /// </summary>
    [DataField(Label = "Required Permission", Order = 9)]
    public string RequiredPermission { get; set; } = "Public";

    public override string ToString() => Title;
}
