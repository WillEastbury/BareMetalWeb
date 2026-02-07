using System;
using BareMetalWeb.WebServer;

namespace BareMetalWeb.Interfaces;

public interface IMetricsTracker
{
    void RecordRequest(int statusCode, TimeSpan elapsed);
    void RecordThrottled(TimeSpan elapsed);
    void GetMetricTable(out string[] tableColumns, out string[][] tableRows);
    MetricsSnapshot GetSnapshot();
}
