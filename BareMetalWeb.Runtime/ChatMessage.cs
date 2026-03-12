using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted chat message within a <see cref="ChatSession"/>.
/// Each record is a single turn (user prompt or assistant response).
/// </summary>
[DataEntity("Chat Messages", ShowOnNav = false, NavGroup = "Admin", NavOrder = 1011)]
public class ChatMessage : BaseDataObject
{
    /// <summary>Foreign key to the owning ChatSession.</summary>
    [DataField(Label = "Session", Order = 1, Required = true, List = true, View = true)]
    [DataIndex]
    public uint SessionId { get; set; }

    /// <summary>Message role: user, assistant, or system.</summary>
    [DataField(Label = "Role", Order = 2, Required = true, List = true, View = true, FieldType = FormFieldType.Enum)]
    public string Role { get; set; } = "user";

    /// <summary>Message content (plain text).</summary>
    [DataField(Label = "Content", Order = 3, Required = true, View = true, FieldType = FormFieldType.TextArea)]
    public string Content { get; set; } = string.Empty;

    /// <summary>UTC timestamp when the message was created.</summary>
    [DataField(Label = "Timestamp", Order = 4, List = true, View = true, ReadOnly = true, FieldType = FormFieldType.DateTime)]
    public DateTime TimestampUtc { get; set; }

    /// <summary>Approximate token count for this message.</summary>
    [DataField(Label = "Tokens", Order = 5, View = true, ReadOnly = true, FieldType = FormFieldType.Integer)]
    public int TokenCount { get; set; }

    /// <summary>Inference latency in milliseconds (assistant messages only).</summary>
    [DataField(Label = "Latency (ms)", Order = 6, View = true, ReadOnly = true, FieldType = FormFieldType.Integer)]
    public int LatencyMs { get; set; }

    /// <summary>Resolved intent from the orchestrator (for diagnostics).</summary>
    [DataField(Label = "Intent", Order = 7, View = true, ReadOnly = true)]
    public string ResolvedIntent { get; set; } = string.Empty;

    /// <summary>Confidence score from intent classification.</summary>
    [DataField(Label = "Confidence", Order = 8, View = true, ReadOnly = true, FieldType = FormFieldType.Decimal)]
    public decimal Confidence { get; set; }

    public override string ToString() => $"[{Role}] {Content[..Math.Min(Content.Length, 50)]}";
}
