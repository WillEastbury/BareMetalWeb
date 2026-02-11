namespace BareMetalWeb.Core.Interfaces;

public interface IClientRequestTracker
{
    bool ShouldThrottle(string clientIp, out string reason, out int? retryAfterSeconds);
    void RecordRequest(string clientIp);
    void GetTopClientsTable(int count, out string[] tableColumns, out string[][] tableRows);
    void GetSuspiciousClientsTable(int count, out string[] tableColumns, out string[][] tableRows);
    Task RunPruningAsync(CancellationToken token);
}
