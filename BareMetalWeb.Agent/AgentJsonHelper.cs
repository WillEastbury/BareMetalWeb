using System.Text.Json;
using BareMetalWeb.ControlPlane;

namespace BareMetalWeb.Agent;

/// <summary>
/// Low-allocation JSON helper for the local agent state file (node.json).
/// Uses camelCase property names to maintain backward compatibility with the
/// existing state-file format previously produced by <c>AgentJsonContext</c>.
/// </summary>
internal static class AgentJsonHelper
{
    public static string SerializeNodeIdentity(NodeIdentity identity)
    {
        using var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
        {
            w.WriteStartObject();
            w.WriteString("nodeId", identity.NodeId);
            w.WriteString("servicePrincipal", identity.ServicePrincipal);
            w.WriteString("secret", identity.Secret);
            w.WriteString("clusterEndpoint", identity.ClusterEndpoint);
            w.WriteString("certFingerprint", identity.CertFingerprint);
            w.WriteString("ring", identity.Ring.ToString());
            w.WriteEndObject();
        }
        return System.Text.Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
    }

    public static NodeIdentity DeserializeNodeIdentity(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var identity = new NodeIdentity
        {
            NodeId          = root.TryGetProperty("nodeId", out var nid) ? nid.GetString() ?? "" : "",
            ServicePrincipal = root.TryGetProperty("servicePrincipal", out var sp) ? sp.GetString() ?? "" : "",
            Secret          = root.TryGetProperty("secret", out var sec) ? sec.GetString() ?? "" : "",
            ClusterEndpoint = root.TryGetProperty("clusterEndpoint", out var ce) ? ce.GetString() ?? "" : "",
            CertFingerprint = root.TryGetProperty("certFingerprint", out var cf) ? cf.GetString() ?? "" : "",
        };

        if (root.TryGetProperty("ring", out var ring))
        {
            var ringStr = ring.GetString();
            if (ringStr != null && Enum.TryParse<DeploymentRing>(ringStr, ignoreCase: true, out var parsed))
                identity.Ring = parsed;
        }

        return identity;
    }
}
