using Microsoft.Extensions.Hosting;
using TsOrch.Agent;
using TsOrch.Oci;

namespace TsOrch.Cli;

internal sealed record class InvalidAgentCommandOptions(string Message);

internal readonly union AgentCommandOptions(AgentOptions, InvalidAgentCommandOptions);

internal static class AgentCommand
{
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

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.ExpectPositionals(0, "ts-orch agent [options]") switch
        {
            CommandPositionalsAccepted => Configure(arguments) switch
            {
                AgentOptions options => options.Validate() switch
                {
                    AgentOptions validated => OciEnvironment.Resolve(arguments.Value("oci-mock-url")) switch
                    {
                        OciEnvironment ociEnvironment => await RunHostAsync(validated, ociEnvironment, environment, cancellationToken),
                        InvalidOciMockEndpoint invalid => environment.Usage(invalid.Message),
                    },
                    InvalidAgentConfiguration invalid => environment.Usage(invalid.Message),
                },
                InvalidAgentCommandOptions invalid => environment.Usage(invalid.Message),
            },
            CommandPositionalsInvalid invalid => environment.Usage($"usage: {invalid.Usage}"),
        };

    private static async Task<int> RunHostAsync(AgentOptions options, OciEnvironment ociEnvironment, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { Args = [], ContentRootPath = AppContext.BaseDirectory });
        builder.Services.AddTsOrchAgent(options, ociEnvironment, environment.TimeProvider);
        using var host = builder.Build();
        await host.RunAsync(cancellationToken);
        return Environment.ExitCode;
    }

    private static AgentCommandOptions Configure(CliArguments arguments) =>
        OperatorSettings.ParseUrl(arguments.Setting("backplane-url", "TS_ORCH_BACKPLANE_URL") ?? OperatorSettings.DefaultUrl.AbsoluteUri) switch
        {
            Uri backplaneUrl => Configure(arguments, backplaneUrl),
            InvalidBackplaneUrl invalid => new InvalidAgentCommandOptions(invalid.Message),
        };

    private static AgentCommandOptions Configure(CliArguments arguments, Uri backplaneUrl)
    {
        List<string> failures = [];
        var poolKind = arguments.Setting("pool-kind", "TS_ORCH_POOL_KIND") is { } poolText
            ? poolText switch
            {
                "stateful" => PoolKind.Stateful,
                "worker" => PoolKind.Worker,
                _ => Reject<PoolKind?>(failures, $"pool kind must be 'stateful' or 'worker', got '{poolText}'."),
            }
            : null;
        var cgroupParent = arguments.Setting("cgroup-parent", "TS_ORCH_CGROUP_PARENT") is { } cgroupText
            ? CliArguments.ParseBool("cgroup parent", cgroupText) switch
            {
                bool parsed => parsed,
                InvalidCliBoolean invalid => Reject<bool?>(failures, invalid.Message),
            }
            : null;
        var heartbeatSeconds = arguments.Setting("heartbeat-seconds", "TS_ORCH_HEARTBEAT_SECONDS") is { } heartbeatText
            ? CliArguments.ParseInt("heartbeat seconds", heartbeatText, 1, 3_600) switch
            {
                int parsed => parsed,
                InvalidCliInteger invalid => Reject<int?>(failures, invalid.Message),
            }
            : null;
        if (failures is [var first, ..])
        {
            return new InvalidAgentCommandOptions(first);
        }

        var defaults = new AgentOptions { BackplaneUrl = backplaneUrl };
        return defaults with
        {
            StateDirectory = arguments.Setting("state-dir", "TS_ORCH_STATE_DIR") ?? defaults.StateDirectory,
            RuntimeDirectory = arguments.Setting("runtime-dir", "TS_ORCH_RUNTIME_DIR") ?? defaults.RuntimeDirectory,
            InstallDirectory = arguments.Setting("install-dir", "TS_ORCH_INSTALL_DIR") ?? defaults.InstallDirectory,
            DockerSocketPath = arguments.Setting("docker-socket", "TS_ORCH_DOCKER_SOCKET") ?? defaults.DockerSocketPath,
            DataVolumePath = arguments.Setting("data-volume", "TS_ORCH_DATA_VOLUME") ?? defaults.DataVolumePath,
            EnrollSecret = Environment.GetEnvironmentVariable("TS_ORCH_ENROLL_SECRET") is { Length: > 0 } secret ? secret : null,
            EnrollSecretVault = arguments.Setting("enroll-secret-vault", "TS_ORCH_ENROLL_SECRET_VAULT"),
            EnrollSecretName = arguments.Setting("enroll-secret-name", "TS_ORCH_ENROLL_SECRET_NAME"),
            NodeIdOverride = arguments.Setting("node-id", "TS_ORCH_NODE_ID"),
            RegionOverride = arguments.Setting("region", "TS_ORCH_REGION"),
            PoolKindOverride = poolKind,
            VcnIpOverride = arguments.Setting("vcn-ip", "TS_ORCH_VCN_IP"),
            LabelPrefix = arguments.Setting("label-prefix", "TS_ORCH_LABEL_PREFIX") ?? defaults.LabelPrefix,
            EnableCgroupParent = cgroupParent ?? defaults.EnableCgroupParent,
            RegistryAuth = Environment.GetEnvironmentVariable("TS_ORCH_REGISTRY_AUTH") is { Length: > 0 } registryAuth ? registryAuth : null,
            HeartbeatInterval = heartbeatSeconds is { } seconds ? TimeSpan.FromSeconds(seconds) : defaults.HeartbeatInterval,
        };
    }

    private static T? Reject<T>(List<string> failures, string failure)
    {
        failures.Add(failure);
        return default;
    }
}
