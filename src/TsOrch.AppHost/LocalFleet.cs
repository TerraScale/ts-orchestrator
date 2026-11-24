using System.Globalization;
using System.Runtime.InteropServices;

namespace TsOrch.AppHost;

internal sealed record class LocalNode(int Index, string PoolKind, int HttpPort, int HttpsPort, int PostgresPort);

internal static class LocalFleet
{
    public const string EnrollSecret = "ts-orch-local-enroll";
    public const string EnrollSecretName = "ts-orch-node-enroll";
    public const string VaultId = "ocid1.vault.oc1.sa-saopaulo-1.localdev";
    public const string Region = "gru";

    private const string CliProject = "../TsOrch.Cli/TsOrch.Cli.csproj";
    private const string AppHostAssemblyFile = "TsOrch.AppHost.dll";

    public static DistributedApplication Build(string[] args)
    {
        var builder = DistributedApplication.CreateBuilder(args);
        var instance = DevInstance();
        int Port(int basePort) => basePort + (100 * instance);
        static string Text(int value) => value.ToString(CultureInfo.InvariantCulture);

        var suffix = instance == 0 ? string.Empty : $"-{Text(instance)}";
        var repoRoot = Path.GetFullPath(Path.Combine(builder.AppHostDirectory, "..", ".."));
        var localRoot = Path.Combine(Path.GetTempPath(), $"ts-orch-local{suffix}");
        ResetDirectory(Path.Combine(localRoot, "wrangler"));

        var workerUrl = $"http://127.0.0.1:{Text(Port(8787))}";
        var ociMockUrl = $"http://127.0.0.1:{Text(Port(19100))}";
        LocalNode[] nodes =
        [
            new(1, "stateful", Port(18080), Port(18443), Port(15432)),
            new(2, "worker", Port(18081), Port(18444), Port(15433)),
        ];

        var keys = LocalCryptoKeys.Generate(LocalCryptoKeys.DefaultSshPublicKeyPath());
        var envFile = keys.WriteWorkerEnvFile(
            localRoot,
            [
                new("LOCAL_DEV", "true"),
                new("DEV_ORIGINS", "1"),
                new("OCI_BASE_URL", ociMockUrl),
                new("NODE_ENROLL_SECRET", EnrollSecret),
            ]);

        var appHostAssembly = Path.Combine(AppContext.BaseDirectory, AppHostAssemblyFile);
        var dotnetRoot = Path.GetFullPath(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "..", "..", ".."));
        var ociMock = builder.AddExecutable("oci-mock", "dotnet", localRoot, appHostAssembly)
            .WithArgs(
                OciMockOptions.Flag,
                "--port",
                Text(Port(19100)),
                "--seed-secret",
                $"{EnrollSecretName}={EnrollSecret}",
                "--seed-services",
                Path.Combine(repoRoot, "deploy", "services"))
            .WithHttpEndpoint(port: Port(19100), targetPort: Port(19100), name: "http", isProxied: false)
            .WithHttpHealthCheck("/healthz", endpointName: "http");

        var worker = builder.AddExecutable(
                "worker",
                "npx",
                Path.Combine(repoRoot, "worker"),
                "wrangler",
                "dev",
                "--local",
                "--infer-origin-from-routes=false",
                "--port",
                Text(Port(8787)),
                "--ip",
                "127.0.0.1",
                "--inspector-port",
                Text(Port(9229)),
                "--persist-to",
                Path.Combine(localRoot, "wrangler"),
                "--env-file",
                envFile,
                "--show-interactive-dev-session=false")
            .WithEnvironment("WRANGLER_SEND_METRICS", "false")
            .WithHttpEndpoint(port: Port(8787), targetPort: Port(8787), name: "http", isProxied: false)
            .WithHttpHealthCheck("/api/me", endpointName: "http")
            .WaitFor(ociMock)
            .WithLocalChaosCommands(new LocalChaosTargets(
                new Uri(workerUrl),
                new Uri(ociMockUrl),
                "local-1",
                "local-2",
                "ts-dashboard",
                "gru-1-stripe-secret-key",
                Region));

        var seeder = builder.AddExecutable("seeder", "dotnet", localRoot, appHostAssembly)
            .WithArgs(
                LocalSeederOptions.Flag,
                "--worker-url",
                workerUrl,
                "--repo-root",
                repoRoot,
                "--local-region",
                Region,
                "--edge-url",
                $"http://127.0.0.1:{Text(nodes[0].HttpPort)}")
            .WaitFor(worker);

        foreach (var node in nodes)
        {
            var nodeRoot = Path.Combine(localRoot, $"node-{Text(node.Index)}");
            var runtimeDirectory = ResetDirectory(Path.Combine(nodeRoot, "run"));
            var stateDirectory = ResetDirectory(Path.Combine(nodeRoot, "state"));
            var installDirectory = ResetDirectory(Path.Combine(nodeRoot, "install"));
            var dataDirectory = Directory.CreateDirectory(Path.Combine(nodeRoot, "data")).FullName;

            builder.AddDotnetProject($"edge-{Text(node.Index)}", CliProject)
                .WithArgs("edge")
                .WithEnvironment("DOTNET_ROOT", dotnetRoot)
                .WithEnvironment("TS_ORCH_RUNTIME_DIR", runtimeDirectory)
                .WithEnvironment("TS_ORCH_EDGE_BIND", "127.0.0.1")
                .WithEnvironment("TS_ORCH_EDGE_HTTP_PORT", Text(node.HttpPort))
                .WithEnvironment("TS_ORCH_EDGE_HTTPS_PORT", Text(node.HttpsPort))
                .WithEnvironment("TS_ORCH_EDGE_POSTGRES_PORT", Text(node.PostgresPort))
                .WithEnvironment("TS_ORCH_EDGE_INTERNAL_TERRABASE_PORT", "0")
                .WithEnvironment("TS_ORCH_EDGE_INTERNAL_PLATFORM_PORT", "0")
                .WithEnvironment("TS_ORCH_EDGE_DRAIN_SECONDS", "2")
                .WithEnvironment("TS_ORCH_EDGE_SHUTDOWN_SECONDS", "5")
                .WithEnvironment("TS_ORCH_EDGE_HTTP3", "false")
                .WithHttpEndpoint(port: node.HttpPort, targetPort: node.HttpPort, name: "http", isProxied: false)
                .WithHttpsEndpoint(port: node.HttpsPort, targetPort: node.HttpsPort, name: "https", isProxied: false)
                .WithEndpoint(port: node.PostgresPort, targetPort: node.PostgresPort, scheme: "tcp", name: "postgres", isProxied: false)
                .WithHttpHealthCheck("/readyz", endpointName: "http");

            builder.AddDotnetProject($"agent-{Text(node.Index)}", CliProject)
                .WithArgs("agent")
                .WithEnvironment("DOTNET_ROOT", dotnetRoot)
                .WithEnvironment("TS_ORCH_BACKPLANE_URL", workerUrl)
                .WithEnvironment("TS_ORCH_STATE_DIR", stateDirectory)
                .WithEnvironment("TS_ORCH_RUNTIME_DIR", runtimeDirectory)
                .WithEnvironment("TS_ORCH_INSTALL_DIR", installDirectory)
                .WithEnvironment("TS_ORCH_DOCKER_SOCKET", "/var/run/docker.sock")
                .WithEnvironment("TS_ORCH_DATA_VOLUME", dataDirectory)
                .WithEnvironment("TS_ORCH_ENROLL_SECRET_VAULT", VaultId)
                .WithEnvironment("TS_ORCH_ENROLL_SECRET_NAME", EnrollSecretName)
                .WithEnvironment("TS_ORCH_NODE_ID", $"local-{Text(node.Index)}")
                .WithEnvironment("TS_ORCH_REGION", Region)
                .WithEnvironment("TS_ORCH_POOL_KIND", node.PoolKind)
                .WithEnvironment("TS_ORCH_VCN_IP", "127.0.0.1")
                .WithEnvironment("TS_ORCH_LABEL_PREFIX", $"ts-orch-local{suffix}-{Text(node.Index)}")
                .WithEnvironment("TS_ORCH_CGROUP_PARENT", "false")
                .WithEnvironment("TS_ORCH_HEARTBEAT_SECONDS", "10")
                .WithEnvironment("TS_ORCH_OCI_MOCK_URL", ociMockUrl)
                .WaitFor(ociMock)
                .WaitForCompletion(seeder);
        }

        return builder.Build();
    }

    private static int DevInstance()
    {
        var raw = Environment.GetEnvironmentVariable("TS_DEV_INSTANCE");
        if (raw is null)
        {
            return 0;
        }

        return int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var instance) && instance is >= 0 and <= 99
            ? instance
            : throw new ArgumentException($"TS_DEV_INSTANCE must be an integer between 0 and 99, got '{raw}'.", nameof(raw));
    }

    private static string ResetDirectory(string path)
    {
        if (Directory.Exists(path))
        {
            Directory.Delete(path, recursive: true);
        }

        return Directory.CreateDirectory(path).FullName;
    }
}
