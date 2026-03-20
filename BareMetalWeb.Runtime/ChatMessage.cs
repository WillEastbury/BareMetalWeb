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
    public override string EntityTypeName => "Chat Messages";
    private const int Ord_SessionId = BaseFieldCount + 0;
    private const int Ord_Role = BaseFieldCount + 1;
    private const int Ord_Content = BaseFieldCount + 2;
    private const int Ord_TimestampUtc = BaseFieldCount + 3;
    private const int Ord_TokenCount = BaseFieldCount + 4;
    private const int Ord_LatencyMs = BaseFieldCount + 5;
    private const int Ord_ResolvedIntent = BaseFieldCount + 6;
    private const int Ord_Confidence = BaseFieldCount + 7;
    internal const int TotalFieldCount = BaseFieldCount + 8;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("Confidence", Ord_Confidence),
        new FieldSlot("Content", Ord_Content),
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("LatencyMs", Ord_LatencyMs),
        new FieldSlot("ResolvedIntent", Ord_ResolvedIntent),
        new FieldSlot("Role", Ord_Role),
        new FieldSlot("SessionId", Ord_SessionId),
        new FieldSlot("TimestampUtc", Ord_TimestampUtc),
        new FieldSlot("TokenCount", Ord_TokenCount),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public ChatMessage() : base(TotalFieldCount) { }
    public ChatMessage(string createdBy) : base(TotalFieldCount, createdBy) { }

    /// <summary>Foreign key to the owning ChatSession.</summary>
    [DataField(Label = "Session", Order = 1, Required = true, List = true, View = true)]
    [DataIndex]
    public uint SessionId
    {
        get => (uint)(_values[Ord_SessionId] ?? 0u);
        set => _values[Ord_SessionId] = value;
    }

    /// <summary>Message role: user, assistant, or system.</summary>
    [DataField(Label = "Role", Order = 2, Required = true, List = true, View = true, FieldType = FormFieldType.Enum)]
    public string Role
    {
        get => (string?)_values[Ord_Role] ?? "user";
        set => _values[Ord_Role] = value;
    }

    /// <summary>Message content (plain text).</summary>
    [DataField(Label = "Content", Order = 3, Required = true, View = true, FieldType = FormFieldType.TextArea)]
    public string Content
    {
        get => (string?)_values[Ord_Content] ?? string.Empty;
        set => _values[Ord_Content] = value;
    }

    /// <summary>UTC timestamp when the message was created.</summary>
    [DataField(Label = "Timestamp", Order = 4, List = true, View = true, ReadOnly = true, FieldType = FormFieldType.DateTime)]
    public DateTime TimestampUtc
    {
        get => _values[Ord_TimestampUtc] is DateTime dt ? dt : default;
        set => _values[Ord_TimestampUtc] = value;
    }

    /// <summary>Approximate token count for this message.</summary>
    [DataField(Label = "Tokens", Order = 5, View = true, ReadOnly = true, FieldType = FormFieldType.Integer)]
    public int TokenCount
    {
        get => (int)(_values[Ord_TokenCount] ?? 0);
        set => _values[Ord_TokenCount] = value;
    }

    /// <summary>Inference latency in milliseconds (assistant messages only).</summary>
    [DataField(Label = "Latency (ms)", Order = 6, View = true, ReadOnly = true, FieldType = FormFieldType.Integer)]
    public int LatencyMs
    {
        get => (int)(_values[Ord_LatencyMs] ?? 0);
        set => _values[Ord_LatencyMs] = value;
    }

    /// <summary>Resolved intent from the orchestrator (for diagnostics).</summary>
    [DataField(Label = "Intent", Order = 7, View = true, ReadOnly = true)]
    public string ResolvedIntent
    {
        get => (string?)_values[Ord_ResolvedIntent] ?? string.Empty;
        set => _values[Ord_ResolvedIntent] = value;
    }

    /// <summary>Confidence score from intent classification.</summary>
    [DataField(Label = "Confidence", Order = 8, View = true, ReadOnly = true, FieldType = FormFieldType.Decimal)]
    public decimal Confidence
    {
        get => (decimal)(_values[Ord_Confidence] ?? 0m);
        set => _values[Ord_Confidence] = value;
    }

    public override string ToString() => $"[{Role}] {Content[..Math.Min(Content.Length, 50)]}";
}
