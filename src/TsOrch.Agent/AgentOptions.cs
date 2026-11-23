namespace TsOrch.Agent;

public sealed record class AgentOptions
{
    public required Uri BackplaneUrl { get; init; }

    public string StateDirectory { get; init; } = NodePaths.StateDirectory;

    public string RuntimeDirectory { get; init; } = NodePaths.RuntimeDirectory;

    public string InstallDirectory { get; init; } = "/opt/ts-orch";

    public string DockerSocketPath { get; init; } = "/var/run/docker.sock";

    public string DataVolumePath { get; init; } = NodePaths.DataVolume;

    public string? EnrollSecret { get; init; }

    public string? EnrollSecretVault { get; init; }

    public string? EnrollSecretName { get; init; }

    public string? NodeIdOverride { get; init; }

    public string? RegionOverride { get; init; }

    public PoolKind? PoolKindOverride { get; init; }

    public string? VcnIpOverride { get; init; }

    public string LabelPrefix { get; init; } = "ts-orch";

    public TimeSpan HeartbeatInterval { get; init; } = TimeSpan.FromSeconds(10);

    public TimeSpan ReconcileInterval { get; init; } = TimeSpan.FromSeconds(30);

    public TimeSpan SecretCheckInterval { get; init; } = TimeSpan.FromHours(1);

    public TimeSpan ImageGcInterval { get; init; } = TimeSpan.FromHours(6);

    public TimeSpan ImageRetention { get; init; } = TimeSpan.FromHours(24);

    public TimeSpan KeepAliveInterval { get; init; } = TimeSpan.FromSeconds(25);

    public TimeSpan ReconnectMaxDelay { get; init; } = TimeSpan.FromSeconds(60);

    public TimeSpan RouteSwitchTimeout { get; init; } = TimeSpan.FromSeconds(30);

    public TimeSpan ContainerStopTimeout { get; init; } = TimeSpan.FromSeconds(30);

    public bool EnableCgroupParent { get; init; } = true;

    public string NodeTokenFile => Path.Combine(StateDirectory, "node.token");

    public string NodeStateFile => Path.Combine(StateDirectory, "node.json");

    public string ImageStateFile => Path.Combine(StateDirectory, "images.json");

    public string RoutesFile => Path.Combine(RuntimeDirectory, "routes.json");

    public string TlsDirectory => Path.Combine(RuntimeDirectory, "tls");

    public string TlsCertificateFile => Path.Combine(TlsDirectory, "cert.pem");

    public string TlsKeyFile => Path.Combine(TlsDirectory, "key.pem");

    public string TlsBundleFile => Path.Combine(TlsDirectory, "bundle.json");

    public string EdgeMetricsFile => Path.Combine(RuntimeDirectory, "edge-metrics.json");

    public string SecretsDirectory => Path.Combine(RuntimeDirectory, "secrets");

    public string ReleasesDirectory => Path.Combine(InstallDirectory, "releases");

    public string CurrentReleaseLink => Path.Combine(InstallDirectory, "current");

    public Result<AgentOptions, Validation> Validate()
    {
        List<string> failures = [];
        if (!BackplaneUrl.IsAbsoluteUri || (BackplaneUrl.Scheme != Uri.UriSchemeHttps && BackplaneUrl.Scheme != Uri.UriSchemeHttp))
        {
            failures.Add($"{nameof(BackplaneUrl)} must be an absolute http(s) URL.");
        }

        RequirePath(failures, nameof(StateDirectory), StateDirectory);
        RequirePath(failures, nameof(RuntimeDirectory), RuntimeDirectory);
        RequirePath(failures, nameof(InstallDirectory), InstallDirectory);
        RequirePath(failures, nameof(DockerSocketPath), DockerSocketPath);
        RequirePath(failures, nameof(DataVolumePath), DataVolumePath);
        if (string.IsNullOrWhiteSpace(EnrollSecretVault) != string.IsNullOrWhiteSpace(EnrollSecretName))
        {
            failures.Add($"{nameof(EnrollSecretVault)} and {nameof(EnrollSecretName)} must be set together.");
        }

        if (string.IsNullOrWhiteSpace(LabelPrefix) || LabelPrefix.Any(static c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_')))
        {
            failures.Add($"{nameof(LabelPrefix)} must be non-empty and contain only ASCII letters, digits, '-', '.', or '_'.");
        }

        RequirePositive(failures, nameof(HeartbeatInterval), HeartbeatInterval);
        RequirePositive(failures, nameof(ReconcileInterval), ReconcileInterval);
        RequirePositive(failures, nameof(SecretCheckInterval), SecretCheckInterval);
        RequirePositive(failures, nameof(ImageGcInterval), ImageGcInterval);
        RequirePositive(failures, nameof(ImageRetention), ImageRetention);
        RequirePositive(failures, nameof(KeepAliveInterval), KeepAliveInterval);
        RequirePositive(failures, nameof(ReconnectMaxDelay), ReconnectMaxDelay);
        RequirePositive(failures, nameof(RouteSwitchTimeout), RouteSwitchTimeout);
        RequirePositive(failures, nameof(ContainerStopTimeout), ContainerStopTimeout);
        return failures.Count == 0 ? this : new Validation(string.Join(" ", failures));
    }

    private static void RequirePath(List<string> failures, string name, string value)
    {
        if (string.IsNullOrWhiteSpace(value) || !Path.IsPathRooted(value))
        {
            failures.Add($"{name} must be an absolute path.");
        }
    }

    private static void RequirePositive(List<string> failures, string name, TimeSpan value)
    {
        if (value <= TimeSpan.Zero)
        {
            failures.Add($"{name} must be positive.");
        }
    }
}
