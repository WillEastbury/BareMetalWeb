namespace BareMetalWeb.Data;

public record RemoteCommandResult(
    bool Success,
    string Message,
    string? RedirectUrl = null)
{
    public static RemoteCommandResult Ok(string message) => new(true, message);
    public static RemoteCommandResult Fail(string message) => new(false, message);
}
