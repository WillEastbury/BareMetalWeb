namespace BareMetalWeb.Core;

/// <summary>
/// Log severity levels in ascending order. The logger suppresses
/// entries below its configured minimum level with zero allocation.
/// </summary>
public enum BmwLogLevel
{
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Fatal = 5,
    Off = 6
}
