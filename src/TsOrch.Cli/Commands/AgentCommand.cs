using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using TsOrch.Agent;
using TsOrch.Oci;

namespace TsOrch.Cli;

internal sealed record class AgentSettings(
    Uri BackplaneUrl,
    string? StateDirectory,
    string? RuntimeDirectory,
    string? InstallDirectory,
    string? DockerSocketPath,
    string? DataVolumePath,
    string? EnrollSecret,
    string? EnrollSecretVault,
    string? EnrollSecretName,
    AgentIdentityOverrides Identity,
    string? LabelPrefix,
    bool? EnableCgroupParent,
    TimeSpan? HeartbeatInterval)
{
    public void ApplyTo(AgentOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.BackplaneUrl = BackplaneUrl;
        options.StateDirectory = StateDirectory ?? options.StateDirectory;
        options.RuntimeDirectory = RuntimeDirectory ?? options.RuntimeDirectory;
        options.InstallDirectory = InstallDirectory ?? options.InstallDirectory;
        options.DockerSocketPath = DockerSocketPath ?? options.DockerSocketPath;
        options.DataVolumePath = DataVolumePath ?? options.DataVolumePath;
        options.EnrollSecret = EnrollSecret;
        options.EnrollSecretVault = EnrollSecretVault;
        options.EnrollSecretName = EnrollSecretName;
        options.NodeIdOverride = Identity.NodeId;
        options.RegionOverride = Identity.Region;
        options.PoolKindOverride = Identity.PoolKind;
        options.VcnIpOverride = Identity.VcnIp;
        options.LabelPrefix = LabelPrefix ?? options.LabelPrefix;
        options.EnableCgroupParent = EnableCgroupParent ?? options.EnableCgroupParent;
        options.HeartbeatInterval = HeartbeatInterval ?? options.HeartbeatInterval;
    }
}

internal static class AgentCommand
{
    public const string RegionVariable = "TS_ORCH_REGION";
    public const string PoolKindVariable = "TS_ORCH_POOL_KIND";

    private const string OciHttpClientName = "ts-orch-oci";
    private static readonly TimeSpan OciTimeout = TimeSpan.FromSeconds(30);

    public static IReadOnlyList<CliOption> Options { get; } =
    [
        new("backplane-url", null, true),
        new("state-dir", null, true),
        new("runtime-dir", null, true),
        new("install-dir", null, true),
        new("docker-socket", null, true),
        new("data-volume", null, true),
        new("enroll-secret-vault", null, true),
        new("enroll-secret-name", null, true),
        new("node-id", null, true),
        new("region", null, true),
        new("pool-kind", null, true),
        new("vcn-ip", null, true),
        new("label-prefix", null, true),
        new("cgroup-parent", null, true),
        new("heartbeat-seconds", null, true),
        new("oci-mock-url", null, true),
    ];

    public static async Task<OrchResult<int>> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        if (!arguments.ExpectPositionals(0, "ts-orch agent [options]").TryGetValue(out _, out var usageError))
        {
            return usageError;
        }

        if (!Configure(arguments).TryGetValue(out var settings, out var settingsError))
        {
            return settingsError;
        }

        var probe = new AgentOptions();
        settings.ApplyTo(probe);
        var validation = new AgentOptionsValidator().Validate(name: null, probe);
        if (validation.Failed)
        {
            return new Validation(validation.FailureMessage);
        }

        if (!OciSetup.ResolveEnvironment(arguments.Value("oci-mock-url")).TryGetValue(out var ociEnvironment, out var ociError))
        {
            return ociError;
        }

        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { Args = [], ContentRootPath = AppContext.BaseDirectory });
        var services = builder.Services;
        services.AddSingleton(environment.TimeProvider);
        services.AddSingleton(ociEnvironment);
        services.AddHttpClient(OciHttpClientName, static client => client.Timeout = OciTimeout);
        services.AddSingleton(provider => OciSetup.Create(OciHttpClient(provider), ociEnvironment, provider.GetRequiredService<TimeProvider>()));
        services.AddSingleton<ISecretProvider>(provider => new OciSecretProvider(provider.GetRequiredService<OciClients>().Vault));
        services.AddSingleton<IHostIdentityProvider>(provider => new OciHostIdentityProvider(
            provider.GetRequiredService<OciClients>().Imds,
            new OrchHttp(OciHttpClient(provider), provider.GetRequiredService<TimeProvider>()),
            ociEnvironment,
            settings.Identity));
        services.AddTsOrchAgent(settings.ApplyTo);

        using var host = builder.Build();
        await host.RunAsync(cancellationToken);
        return Environment.ExitCode;
    }

    private static HttpClient OciHttpClient(IServiceProvider provider) =>
        provider.GetRequiredService<IHttpClientFactory>().CreateClient(OciHttpClientName);

    private static OrchResult<AgentSettings> Configure(CliArguments arguments)
    {
        var backplaneText = arguments.Setting("backplane-url", "TS_ORCH_BACKPLANE_URL") ?? OperatorSettings.DefaultUrl.AbsoluteUri;
        if (!OperatorSettings.ParseUrl(backplaneText).TryGetValue(out var backplaneUrl, out var backplaneError))
        {
            return backplaneError;
        }

        PoolKind? poolKind = null;
        if (arguments.Setting("pool-kind", PoolKindVariable) is { } poolText)
        {
            if (!ParsePoolKind(poolText).TryGetValue(out var parsedPool, out var poolError))
            {
                return poolError;
            }

            poolKind = parsedPool;
        }

        bool? cgroupParent = null;
        if (arguments.Setting("cgroup-parent", "TS_ORCH_CGROUP_PARENT") is { } cgroupText)
        {
            if (!CliArguments.ParseBool("cgroup parent", cgroupText).TryGetValue(out var parsedCgroup, out var cgroupError))
            {
                return cgroupError;
            }

            cgroupParent = parsedCgroup;
        }

        TimeSpan? heartbeat = null;
        if (arguments.Setting("heartbeat-seconds", "TS_ORCH_HEARTBEAT_SECONDS") is { } heartbeatText)
        {
            if (!CliArguments.ParseInt("heartbeat seconds", heartbeatText, 1, 3_600).TryGetValue(out var seconds, out var heartbeatError))
            {
                return heartbeatError;
            }

            heartbeat = TimeSpan.FromSeconds(seconds);
        }

        return new AgentSettings(
            backplaneUrl,
            arguments.Setting("state-dir", "TS_ORCH_STATE_DIR"),
            arguments.Setting("runtime-dir", "TS_ORCH_RUNTIME_DIR"),
            arguments.Setting("install-dir", "TS_ORCH_INSTALL_DIR"),
            arguments.Setting("docker-socket", "TS_ORCH_DOCKER_SOCKET"),
            arguments.Setting("data-volume", "TS_ORCH_DATA_VOLUME"),
            Environment.GetEnvironmentVariable("TS_ORCH_ENROLL_SECRET") is { Length: > 0 } secret ? secret : null,
            arguments.Setting("enroll-secret-vault", "TS_ORCH_ENROLL_SECRET_VAULT"),
            arguments.Setting("enroll-secret-name", "TS_ORCH_ENROLL_SECRET_NAME"),
            new AgentIdentityOverrides(
                arguments.Setting("node-id", "TS_ORCH_NODE_ID"),
                arguments.Setting("region", RegionVariable),
                poolKind,
                arguments.Setting("vcn-ip", "TS_ORCH_VCN_IP")),
            arguments.Setting("label-prefix", "TS_ORCH_LABEL_PREFIX"),
            cgroupParent,
            heartbeat);
    }

    private static OrchResult<PoolKind> ParsePoolKind(string text) => text switch
    {
        "stateful" => PoolKind.Stateful,
        "worker" => PoolKind.Worker,
        _ => new Validation($"pool kind must be 'stateful' or 'worker', got '{text}'."),
    };
}
