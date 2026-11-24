using System.Net;
using TsOrch.Protocol;

namespace TsOrch.Edge;

public sealed record class EdgeServerOptions
{
    public int HttpPort { get; init => field = ValidPort(value); } = 80;

    public int HttpsPort { get; init => field = ValidPort(value); } = 443;

    public int PostgresPort { get; init => field = ValidPort(value); } = 5432;

    public int InternalTerraBasePort { get; init => field = ValidOptionalPort(value); } = 18081;

    public int InternalPlatformPort { get; init => field = ValidOptionalPort(value); } = 18082;

    public bool RedirectHttpToHttps { get; init; }

    public string RoutesFile { get; init => field = ValidPath(value); } = NodePaths.RoutesFile;

    public string TlsDirectory { get; init => field = ValidPath(value); } = NodePaths.TlsDirectory;

    public string MetricsFile { get; init => field = ValidPath(value); } = NodePaths.EdgeMetricsFile;

    public TimeSpan DrainDelay { get; init => field = NonNegative(value); } = TimeSpan.FromSeconds(15);

    public TimeSpan ShutdownTimeout { get; init => field = NonNegative(value); } = TimeSpan.FromSeconds(10);

    public bool EnableHttp3 { get; init; } = true;

    public string BindAddress
    {
        get;
        init => field = IPAddress.TryParse(value, out _)
            ? value
            : throw new ArgumentException($"Edge bind address '{value}' is not an IP address.", nameof(BindAddress));
    } = "0.0.0.0";

    private static int ValidPort(int port)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(port);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, IPEndPoint.MaxPort);
        return port;
    }

    private static int ValidOptionalPort(int port)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(port);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, IPEndPoint.MaxPort);
        return port;
    }

    private static string ValidPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return Path.GetFullPath(path);
    }

    private static TimeSpan NonNegative(TimeSpan value)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(value, TimeSpan.Zero);
        return value;
    }
}
