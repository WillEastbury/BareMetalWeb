namespace BareMetalWeb.Data;

/// <summary>
/// Specifies how two entities are joined in a report query.
/// </summary>
public enum JoinType
{
    Inner,
    Left,
    Right,
    FullOuter
}
