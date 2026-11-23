namespace TsOrch.Protocol;

public static class NodePaths
{
    public const string StateDirectory = "/var/lib/ts-orch";
    public const string NodeToken = "/var/lib/ts-orch/node.token";
    public const string RuntimeDirectory = "/run/ts-orch";
    public const string AppliedRoutesFileName = "routes.applied.json";
    public const string RoutesFile = "/run/ts-orch/routes.json";
    public const string TlsDirectory = "/run/ts-orch/tls";
    public const string EdgeMetricsFile = "/run/ts-orch/edge-metrics.json";
    public const string DataVolume = "/var/lib/ts-data";
}
