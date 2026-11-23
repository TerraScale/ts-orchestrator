using Microsoft.Extensions.Options;

namespace TsOrch.Agent;

public sealed class AgentOptions
{
    public Uri? BackplaneUrl { get; set; }

    public string StateDirectory { get; set; } = NodePaths.StateDirectory;

    public string RuntimeDirectory { get; set; } = NodePaths.RuntimeDirectory;

    public string InstallDirectory { get; set; } = "/opt/ts-orch";

    public string DockerSocketPath { get; set; } = "/var/run/docker.sock";

    public string DataVolumePath { get; set; } = NodePaths.DataVolume;

    public string? EnrollSecret { get; set; }

    public string? EnrollSecretVault { get; set; }

    public string? EnrollSecretName { get; set; }

    public string? NodeIdOverride { get; set; }

    public string? RegionOverride { get; set; }

    public PoolKind? PoolKindOverride { get; set; }

    public string? VcnIpOverride { get; set; }

    public string LabelPrefix { get; set; } = "ts-orch";

    public TimeSpan HeartbeatInterval { get; set; } = TimeSpan.FromSeconds(10);

    public TimeSpan ReconcileInterval { get; set; } = TimeSpan.FromSeconds(30);

    public TimeSpan SecretCheckInterval { get; set; } = TimeSpan.FromHours(1);

    public TimeSpan ImageGcInterval { get; set; } = TimeSpan.FromHours(6);

    public TimeSpan ImageRetention { get; set; } = TimeSpan.FromHours(24);

    public TimeSpan KeepAliveInterval { get; set; } = TimeSpan.FromSeconds(25);

    public TimeSpan ReconnectMaxDelay { get; set; } = TimeSpan.FromSeconds(60);

    public TimeSpan RouteSwitchTimeout { get; set; } = TimeSpan.FromSeconds(30);

    public TimeSpan ContainerStopTimeout { get; set; } = TimeSpan.FromSeconds(30);

    public bool EnableCgroupParent { get; set; } = true;

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
}

public sealed class AgentOptionsValidator : IValidateOptions<AgentOptions>
{
    public ValidateOptionsResult Validate(string? name, AgentOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        List<string> failures = [];
        if (options.BackplaneUrl is not { IsAbsoluteUri: true } url || (url.Scheme != Uri.UriSchemeHttps && url.Scheme != Uri.UriSchemeHttp))
        {
            failures.Add($"{nameof(AgentOptions.BackplaneUrl)} must be an absolute http(s) URL.");
        }

        RequirePath(failures, nameof(AgentOptions.StateDirectory), options.StateDirectory);
        RequirePath(failures, nameof(AgentOptions.RuntimeDirectory), options.RuntimeDirectory);
        RequirePath(failures, nameof(AgentOptions.InstallDirectory), options.InstallDirectory);
        RequirePath(failures, nameof(AgentOptions.DockerSocketPath), options.DockerSocketPath);
        RequirePath(failures, nameof(AgentOptions.DataVolumePath), options.DataVolumePath);
        if (string.IsNullOrWhiteSpace(options.EnrollSecret) && (string.IsNullOrWhiteSpace(options.EnrollSecretVault) || string.IsNullOrWhiteSpace(options.EnrollSecretName)))
        {
            failures.Add($"Either {nameof(AgentOptions.EnrollSecret)} or both {nameof(AgentOptions.EnrollSecretVault)} and {nameof(AgentOptions.EnrollSecretName)} are required.");
        }

        if (string.IsNullOrWhiteSpace(options.LabelPrefix) || options.LabelPrefix.Any(static c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_')))
        {
            failures.Add($"{nameof(AgentOptions.LabelPrefix)} must be non-empty and contain only ASCII letters, digits, '-', '.', or '_'.");
        }

        RequirePositive(failures, nameof(AgentOptions.HeartbeatInterval), options.HeartbeatInterval);
        RequirePositive(failures, nameof(AgentOptions.ReconcileInterval), options.ReconcileInterval);
        RequirePositive(failures, nameof(AgentOptions.SecretCheckInterval), options.SecretCheckInterval);
        RequirePositive(failures, nameof(AgentOptions.ImageGcInterval), options.ImageGcInterval);
        RequirePositive(failures, nameof(AgentOptions.ImageRetention), options.ImageRetention);
        RequirePositive(failures, nameof(AgentOptions.KeepAliveInterval), options.KeepAliveInterval);
        RequirePositive(failures, nameof(AgentOptions.ReconnectMaxDelay), options.ReconnectMaxDelay);
        RequirePositive(failures, nameof(AgentOptions.RouteSwitchTimeout), options.RouteSwitchTimeout);
        RequirePositive(failures, nameof(AgentOptions.ContainerStopTimeout), options.ContainerStopTimeout);
        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
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
