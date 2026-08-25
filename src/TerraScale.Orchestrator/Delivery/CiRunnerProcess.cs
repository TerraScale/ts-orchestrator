using System.Runtime.Versioning;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.KeyValueStore;
using NATS.Client.ObjectStore;
using NATS.Net;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Delivery;

internal sealed record CiRunnerNatsConfiguration(
    string Url,
    string CredentialsFile,
    NatsTlsFiles Tls)
{
    private const UnixFileMode ForbiddenCredentialMode =
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    internal static CiRunnerNatsConfiguration Resolve(
        string? url,
        string? credentialsFile,
        string? caFile,
        string? certificateFile,
        string? keyFile)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != "tls")
            throw new ArgumentException("TS_ORCH_CI_RUNNER_NATS_URL must be an absolute tls:// URL.");
        if (string.IsNullOrWhiteSpace(credentialsFile))
            throw new ArgumentException("TS_ORCH_CI_RUNNER_NATS_CREDENTIALS_FILE is required.");
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("CI runner NATS credentials require Linux file permissions.");
        var credentials = Path.GetFullPath(credentialsFile);
        var file = new FileInfo(credentials);
        if (!file.Exists || file.LinkTarget is not null || file.Length is < 1 or > 32 * 1024 ||
            (File.GetUnixFileMode(credentials) & ForbiddenCredentialMode) != 0)
            throw new ArgumentException(
                "TS_ORCH_CI_RUNNER_NATS_CREDENTIALS_FILE must be a bounded owner-private regular file.");
        var tls = NatsTlsFiles.Resolve(
            caFile,
            certificateFile,
            keyFile,
            "TS_ORCH_CI_RUNNER_NATS_TLS") ?? throw new ArgumentException(
                "A CI runner requires its complete NATS mTLS identity.");
        return new(uri.ToString(), credentials, tls);
    }
}

internal sealed record CiRunnerProcessConfiguration(
    string Runner,
    TrustZone Zone,
    long Sequence,
    IReadOnlyList<RunnerCapability> Capabilities,
    CiRunnerNatsConfiguration Nats,
    CommandIdentityConfiguration CommandIdentity,
    string WorkspaceRoot,
    CiRunnerBuildKitRuntime BuildKit,
    int CpuMilliCores,
    long MemoryBytes,
    long EphemeralDiskBytes,
    int Pids,
    long MaximumLogBytes,
    TimeSpan IdleTimeout)
{
    private const long Mebibyte = 1024 * 1024;
    private const long Gibibyte = 1024 * Mebibyte;

    internal static CiRunnerProcessConfiguration Resolve(Func<string, string?> environment)
    {
        ArgumentNullException.ThrowIfNull(environment);
        var runner = Required(environment, "TS_ORCH_CI_RUNNER_ID");
        _ = GlobalNatsTopology.CiRunnerIdentityHash(runner);
        var zone = Required(environment, "TS_ORCH_CI_RUNNER_ZONE") switch
        {
            "untrusted-product" => TrustZone.UntrustedProduct,
            "trusted-build" => TrustZone.TrustedBuild,
            _ => throw new ArgumentException(
                "TS_ORCH_CI_RUNNER_ZONE must be 'untrusted-product' or 'trusted-build'."),
        };
        var capabilities = CapabilitiesFor(zone, environment("TS_ORCH_CI_RUNNER_CAPABILITIES"));
        var nats = CiRunnerNatsConfiguration.Resolve(
            environment("TS_ORCH_CI_RUNNER_NATS_URL"),
            environment("TS_ORCH_CI_RUNNER_NATS_CREDENTIALS_FILE"),
            environment("TS_ORCH_CI_RUNNER_NATS_TLS_CA_FILE"),
            environment("TS_ORCH_CI_RUNNER_NATS_TLS_CERT_FILE"),
            environment("TS_ORCH_CI_RUNNER_NATS_TLS_KEY_FILE"));
        var commandIdentity = CommandIdentityConfiguration.Resolve(
            null,
            environment("TS_ORCH_COMMAND_TRUST_KEY_FILES"));
        if (commandIdentity is null || commandIdentity.TrustKeyFiles.Count == 0)
            throw new ArgumentException("A CI runner requires at least one command trust key.");

        var workspace = Path.GetFullPath(Required(environment, "TS_ORCH_CI_RUNNER_WORKSPACE_ROOT"));
        var runtime = CiRunnerBuildKitRuntime.Create(
            Required(environment, "XDG_RUNTIME_DIR"),
            Required(environment, "HOME"),
            Required(environment, "TS_ORCH_CI_RUNNER_OUTPUT_ROOT"),
            Required(environment, "DOCKER_CONFIG"));
        var roots = new[]
        {
            workspace,
            runtime.RuntimeDirectory,
            runtime.HomeDirectory,
            runtime.OutputRoot,
            runtime.DockerConfigDirectory,
        };
        for (var left = 0; left < roots.Length; left++)
        for (var right = left + 1; right < roots.Length; right++)
            if (Within(roots[left], roots[right]) || Within(roots[right], roots[left]))
                throw new ArgumentException("CI runner runtime roots must be disjoint.");

        return new(
            runner,
            zone,
            PositiveLong(environment, "TS_ORCH_CI_RUNNER_SEQUENCE", 1, long.MaxValue, required: true),
            capabilities,
            nats,
            commandIdentity,
            workspace,
            runtime,
            checked((int)PositiveLong(environment, "TS_ORCH_CI_RUNNER_CPU_MILLICORES", 100, 8_000,
                CiRunnerResourceProfile.CpuMilliCores)),
            PositiveLong(environment, "TS_ORCH_CI_RUNNER_MEMORY_BYTES", 256 * Mebibyte, 8 * Gibibyte,
                CiRunnerResourceProfile.MemoryBytes),
            PositiveLong(environment, "TS_ORCH_CI_RUNNER_EPHEMERAL_DISK_BYTES", Gibibyte, 200 * Gibibyte,
                CiRunnerResourceProfile.EphemeralDiskBytes),
            checked((int)PositiveLong(environment, "TS_ORCH_CI_RUNNER_PIDS", 64, 4_096,
                CiRunnerResourceProfile.Pids)),
            PositiveLong(environment, "TS_ORCH_CI_RUNNER_MAXIMUM_LOG_BYTES", Mebibyte, 512 * Mebibyte,
                CiRunnerResourceProfile.MaximumLogBytes),
            TimeSpan.FromSeconds(PositiveLong(
                environment,
                "TS_ORCH_CI_RUNNER_IDLE_SECONDS",
                30,
                900,
                60)));
    }

    internal RunnerEvidence RunnerEvidence(RepositoryCiAcceptedJob accepted)
        => CreateRunnerEvidence(accepted, Runner, Zone, Sequence, Capabilities);

    internal static RunnerEvidence CreateRunnerEvidence(
        RepositoryCiAcceptedJob accepted,
        string runner,
        TrustZone zone,
        long sequence,
        IReadOnlyList<RunnerCapability> capabilities)
    {
        ArgumentNullException.ThrowIfNull(accepted);
        ArgumentNullException.ThrowIfNull(capabilities);
        var command = accepted.Command;
        if (command.Runner != runner || command.RunnerSequence != sequence ||
            command.AllowedZones is not [var commandZone] || commandZone != zone)
            throw new InvalidDataException("The CI command does not target this runner profile.");
        return new(new(runner), zone, sequence, true, capabilities);
    }

    internal CiRunnerIsolationEvidence IsolationEvidence(
        RepositoryCiAcceptedJob accepted,
        CiRunnerLinuxIsolationObservation observation)
        => CreateIsolationEvidence(
            accepted,
            Runner,
            Zone,
            Sequence,
            Capabilities,
            observation,
            CpuMilliCores,
            MemoryBytes,
            EphemeralDiskBytes,
            Pids,
            MaximumLogBytes);

    internal static CiRunnerIsolationEvidence CreateIsolationEvidence(
        RepositoryCiAcceptedJob accepted,
        string runnerId,
        TrustZone zone,
        long sequence,
        IReadOnlyList<RunnerCapability> capabilities,
        CiRunnerLinuxIsolationObservation observation,
        int cpuMilliCores,
        long memoryBytes,
        long ephemeralDiskBytes,
        int pids,
        long maximumLogBytes)
    {
        CiRunnerLinuxIsolationProbe.Require(
            observation,
            cpuMilliCores,
            memoryBytes,
            ephemeralDiskBytes,
            pids);
        var runner = CreateRunnerEvidence(accepted, runnerId, zone, sequence, capabilities);
        var command = accepted.Command;
        var signing = command.RequiredCapabilities.Contains(RunnerCapability.Sign);
        var evidence = new CiRunnerIsolationEvidence(
            new(command.Job),
            runner.Runner,
            runner.Sequence,
            zone,
            zone == TrustZone.UntrustedProduct
                ? CiRunnerNodeClass.UntrustedProduct
                : CiRunnerNodeClass.TrustedBuild,
            zone == TrustZone.UntrustedProduct
                ? CiRunnerNetworkScope.PublicDependenciesOnly
                : CiRunnerNetworkScope.ArtifactServicesOnly,
            zone == TrustZone.TrustedBuild && signing
                ? CiRunnerCredentialProfile.CandidatePublishAndSign
                : CiRunnerCredentialProfile.None,
            zone == TrustZone.UntrustedProduct
                ? CiRunnerCacheScope.UntrustedIsolated
                : CiRunnerCacheScope.TrustedVerified,
            Ephemeral: true,
            Disposable: true,
            observation.ReadOnlyRootFilesystem,
            observation.RootlessBuildKit,
            observation.HostDockerSocketMounted,
            observation.NoNewPrivileges,
            observation.UserNamespace,
            observation.Seccomp,
            observation.CgroupV2,
            MetadataServiceReachable: false,
            ProductionNetworkReachable: false,
            ControlNatsReachable: false,
            DatabaseReachable: false,
            WorkloadIdentityBound: true,
            CredentialsShortLived: true,
            CredentialsPhaseScoped: true,
            LogsRedacted: true,
            LogSecretScanPassed: true,
            cpuMilliCores,
            memoryBytes,
            ephemeralDiskBytes,
            pids,
            maximumLogBytes);
        if (RepositoryCiJobJournal.IsolationDigest(evidence) != command.IsolationDigest)
            throw new InvalidDataException("The CI command isolation digest does not match this runner profile.");
        return evidence;
    }

    private static IReadOnlyList<RunnerCapability> CapabilitiesFor(TrustZone zone, string? value)
    {
        var supplied = string.IsNullOrWhiteSpace(value)
            ? zone == TrustZone.UntrustedProduct ? "compile,test" : "compile,test,sign"
            : value;
        var capabilities = supplied.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(static capability => capability switch
            {
                "compile" => RunnerCapability.Compile,
                "test" => RunnerCapability.Test,
                "sign" => RunnerCapability.Sign,
                _ => throw new ArgumentException("A CI runner capability is invalid."),
            })
            .Distinct()
            .Order()
            .ToArray();
        if (capabilities.Length is < 1 or > 3 ||
            zone == TrustZone.UntrustedProduct && capabilities.Contains(RunnerCapability.Sign))
            throw new ArgumentException("The CI runner capability set is invalid for its trust zone.");
        return Array.AsReadOnly(capabilities);
    }

    private static string Required(Func<string, string?> environment, string key)
    {
        var value = environment(key);
        return string.IsNullOrWhiteSpace(value)
            ? throw new ArgumentException($"{key} is required.")
            : value.Trim();
    }

    private static long PositiveLong(
        Func<string, string?> environment,
        string key,
        long minimum,
        long maximum,
        long? fallback = null,
        bool required = false)
    {
        var value = environment(key);
        if (string.IsNullOrWhiteSpace(value) && !required && fallback is not null) return fallback.Value;
        if (!long.TryParse(value, System.Globalization.CultureInfo.InvariantCulture, out var parsed) ||
            parsed < minimum || parsed > maximum)
            throw new ArgumentException($"{key} must be an integer from {minimum} through {maximum}.");
        return parsed;
    }

    private static bool Within(string value, string parent)
    {
        var path = Path.GetFullPath(value);
        var root = Path.GetFullPath(parent);
        return path == root || path.StartsWith(
            root.EndsWith(Path.DirectorySeparatorChar) ? root : root + Path.DirectorySeparatorChar,
            StringComparison.Ordinal);
    }
}

/// <summary>Runs one ephemeral CI worker and exits after a bounded idle period.</summary>
[SupportedOSPlatform("linux")]
internal static class CiRunnerProcess
{
    private static readonly TimeSpan AllowedClockSkew = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan PullWait = TimeSpan.FromSeconds(10);
    private static readonly UnixFileMode PrivateDirectoryMode = UnixFileMode.UserRead |
        UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    internal static async Task<int> ExecuteAsync(
        Func<string, string?> environment,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("CI runners require Linux isolation.");
        var configuration = CiRunnerProcessConfiguration.Resolve(environment);
        RequirePrivateDirectory(configuration.WorkspaceRoot);
        RequirePrivateDirectory(configuration.BuildKit.RuntimeDirectory);
        RequirePrivateDirectory(configuration.BuildKit.HomeDirectory);
        RequirePrivateDirectory(configuration.BuildKit.OutputRoot);
        RequirePrivateDirectory(configuration.BuildKit.DockerConfigDirectory);

        using var commandIdentity = configuration.CommandIdentity.Open();
        var verifier = commandIdentity.Verifier ??
            throw new InvalidOperationException("The CI runner command verifier is unavailable.");
        await using var daemon = await CiRunnerBuildKitDaemon.StartAsync(
            CiRunnerBuildKitDaemonInvocationCompiler.Create(configuration.BuildKit),
            cancellationToken);
        var isolation = CiRunnerLinuxIsolationProbe.Observe(configuration, daemon);
        await using var nats = await CiRunnerNatsRuntime.ConnectAsync(configuration, cancellationToken);
        using var stopping = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var runner = RunAsync(configuration, isolation, nats, verifier, stopping.Token);
        var completed = await Task.WhenAny(runner, daemon.Completion);
        if (completed == daemon.Completion)
        {
            stopping.Cancel();
            try
            {
                await runner;
            }
            catch (OperationCanceledException) when (stopping.IsCancellationRequested)
            {
            }
            await daemon.Completion;
        }
        return await runner;
    }

    private static async Task<int> RunAsync(
        CiRunnerProcessConfiguration configuration,
        CiRunnerLinuxIsolationObservation isolation,
        CiRunnerNatsRuntime runtime,
        ICommandSignatureVerifier verifier,
        CancellationToken cancellationToken)
    {
        var ledger = new NatsForgejoDeliveryLedger(runtime.Jobs);
        var objects = new NatsDeliveryObjectStore(runtime.Objects);
        var executions = new RepositoryCiJobExecutionJournal(ledger);
        var inbox = new RepositoryCiJobInbox(
            new RepositoryCiJobAcceptanceJournal(ledger, objects),
            executions);
        var consumer = new RepositoryCiJobNatsConsumer(
            runtime.Consumer,
            inbox,
            runtime.Topology,
            Zone(configuration.Zone),
            configuration.Runner);
        var coordinator = new CiRunnerExecutionCoordinator(
            executions,
            new CiRunnerSourceMaterializer(objects),
            new CiRunnerBuildKitExecutor(new ProcessCiRunnerBuildKitProcess()),
            new CiRunnerDurableResultSink(objects));
        var idleSince = DateTimeOffset.UtcNow;
        while (DateTimeOffset.UtcNow - idleSince < configuration.IdleTimeout)
        {
            var receipt = await consumer.NextAndExecuteAsync(
                DateTimeOffset.UtcNow,
                AllowedClockSkew,
                PullWait,
                verifier,
                (accepted, token) => coordinator.ExecuteAsync(
                    accepted,
                    configuration.RunnerEvidence(accepted),
                    configuration.IsolationEvidence(accepted, isolation),
                    configuration.BuildKit,
                    configuration.WorkspaceRoot,
                    ExecutionLeaseId(accepted),
                    token),
                cancellationToken);
            if (receipt is not null) idleSince = DateTimeOffset.UtcNow;
        }
        return 0;
    }

    internal static string ExecutionLeaseId(RepositoryCiAcceptedJob accepted) =>
        (accepted ?? throw new ArgumentNullException(nameof(accepted))).Command.Operation;

    private static string Zone(TrustZone zone) => zone switch
    {
        TrustZone.UntrustedProduct => "untrusted-product",
        TrustZone.TrustedBuild => "trusted-build",
        _ => throw new ArgumentOutOfRangeException(nameof(zone)),
    };

    private static void RequirePrivateDirectory(string path)
    {
        var directory = new DirectoryInfo(path);
        if (!directory.Exists || directory.LinkTarget is not null ||
            File.GetUnixFileMode(path) != PrivateDirectoryMode)
            throw new InvalidDataException("A CI runner runtime directory is missing, linked, or not owner-private.");
    }
}

internal sealed class CiRunnerNatsRuntime : IAsyncDisposable
{
    private readonly NatsClient client;

    private CiRunnerNatsRuntime(
        NatsClient client,
        INatsJSConsumer consumer,
        INatsKVStore jobs,
        INatsObjStore objects,
        GlobalNatsTopology topology)
    {
        this.client = client;
        Consumer = consumer;
        Jobs = jobs;
        Objects = objects;
        Topology = topology;
    }

    internal INatsJSConsumer Consumer { get; }
    internal INatsKVStore Jobs { get; }
    internal INatsObjStore Objects { get; }
    internal GlobalNatsTopology Topology { get; }

    internal static async Task<CiRunnerNatsRuntime> ConnectAsync(
        CiRunnerProcessConfiguration configuration,
        CancellationToken cancellationToken)
    {
        var options = Options(configuration.Nats);
        var client = new NatsClient(options);
        try
        {
            await client.ConnectAsync();
            await NatsRuntime.VerifyAnonymousDeniedAsync(
                configuration.Nats.Url,
                configuration.Nats.Tls,
                cancellationToken);
            var topology = new GlobalNatsTopology(3);
            var expected = topology.CiJobConsumer(
                configuration.Zone == TrustZone.UntrustedProduct ? "untrusted-product" : "trusted-build",
                configuration.Runner);
            if (expected.Name is not { } consumerName)
                throw new InvalidOperationException("The CI runner consumer profile has no durable name.");
            var jetStream = client.CreateJetStreamContext();
            var consumer = await jetStream.GetConsumerAsync(
                GlobalNatsTopology.CiStream,
                consumerName,
                cancellationToken);
            await consumer.RefreshAsync(cancellationToken);
            if (!CiRunnerConsumerReconciler.Matches(consumer.Info, expected))
                throw new InvalidOperationException("The CI runner consumer does not match its closed profile.");
            var jobs = await jetStream.CreateKeyValueStoreContext().GetStoreAsync(
                GlobalNatsTopology.RunnerJobsBucket,
                cancellationToken);
            var objects = await jetStream.CreateObjectStoreContext().GetObjectStoreAsync(
                GlobalNatsTopology.RunnerBundlesBucket,
                cancellationToken);
            return new(client, consumer, jobs, objects, topology);
        }
        catch
        {
            await client.DisposeAsync();
            throw;
        }
    }

    internal static NatsOpts Options(CiRunnerNatsConfiguration configuration) => new()
    {
        Url = configuration.Url,
        RetryOnInitialConnect = true,
        RequestTimeout = TimeSpan.FromSeconds(15),
        AuthOpts = new NatsAuthOpts { CredsFile = configuration.CredentialsFile },
        TlsOpts = new NatsTlsOpts
        {
            Mode = TlsMode.Require,
            CaFile = configuration.Tls.CaFile,
            CertFile = configuration.Tls.CertificateFile,
            KeyFile = configuration.Tls.KeyFile,
        },
    };

    public ValueTask DisposeAsync() => client.DisposeAsync();
}
