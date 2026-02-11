using System;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Host;
namespace BareMetalWeb.Core.Interfaces;

public interface IMetricsTracker
{
    void RecordRequest(int statusCode, TimeSpan elapsed);
    void RecordThrottled(TimeSpan elapsed);
    void GetMetricTable(out string[] tableColumns, out string[][] tableRows);
    MetricsSnapshot GetSnapshot();
}
