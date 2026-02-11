namespace BareMetalWeb.Core.Interfaces;

public interface IBufferedLogger
{
    void LogInfo(string message);
    void LogError(string message, Exception ex);
    Task RunAsync(CancellationToken cancellationToken);
    void OnApplicationStopping(CancellationTokenSource cts, Task loggerTask);
}
