using System.Text.Json;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.Runtime;

internal static class HostRuntimeCli
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public static int Execute(IReadOnlyList<string> arguments)
    {
        if (arguments.FirstOrDefault() is not "plan")
        {
            throw new ArgumentException("Unknown runtime command. Use 'runtime plan'.");
        }
        var values = ParseValues(arguments.Skip(1).ToArray());
        var role = ParseRole(Required(values, "--role"));
        var descriptor = AdmittedRoleCatalog.Get(role);
        var driver = values.TryGetValue("--driver", out var driverValue)
            ? ParseDriver(driverValue)
            : descriptor.DefaultDriver;
        var architecture = values.TryGetValue("--architecture", out var architectureValue)
            ? ParseArchitecture(architectureValue)
            : HostArchitecture.Arm64;
        var plan = HostRuntimePlan.Create(
            role,
            driver,
            new RuntimeAllocationId(Required(values, "--allocation")),
            new ArtifactDigest(Required(values, "--digest")),
            architecture);
        Console.WriteLine(JsonSerializer.Serialize(plan, SerializerOptions));
        return 0;
    }

    internal static AdmittedRole ParseRole(string value) => value switch
    {
        "api" => AdmittedRole.Api,
        "authentication" => AdmittedRole.Authentication,
        "customer-dashboard" => AdmittedRole.CustomerDashboard,
        "terrabase-member" => AdmittedRole.TerraBaseMember,
        "orchestrator" => AdmittedRole.Orchestrator,
        "control-nats-server" => AdmittedRole.ControlNatsServer,
        "product-nats-server" => AdmittedRole.ProductNatsServer,
        "grafana" => AdmittedRole.Grafana,
        "metrics-store" => AdmittedRole.MetricsStore,
        "loki" => AdmittedRole.Loki,
        "tempo" => AdmittedRole.Tempo,
        "alertmanager" => AdmittedRole.Alertmanager,
        "otlp-ingest" => AdmittedRole.OtlpIngest,
        "synthetic-check" => AdmittedRole.SyntheticCheck,
        "regional-telemetry-agent" => AdmittedRole.RegionalTelemetryAgent,
        "vpn-coordination-relay" => AdmittedRole.VpnCoordinationRelay,
        "route-policy-controller" => AdmittedRole.RoutePolicyController,
        "ci-runner" => AdmittedRole.CiRunner,
        _ => throw new ArgumentException($"Unknown or unadmitted role '{value}'.")
    };

    private static RuntimeDriver ParseDriver(string value) => value switch
    {
        "systemd" => RuntimeDriver.NativeSystemd,
        "oci" => RuntimeDriver.OciContainer,
        _ => throw new ArgumentException("Runtime driver must be 'systemd' or 'oci'.")
    };

    private static HostArchitecture ParseArchitecture(string value) => value switch
    {
        "arm64" => HostArchitecture.Arm64,
        "x64" => HostArchitecture.X64,
        _ => throw new ArgumentException("Architecture must be 'arm64' or 'x64'.")
    };

    private static Dictionary<string, string> ParseValues(IReadOnlyList<string> arguments)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < arguments.Count; index += 2)
        {
            if (index + 1 >= arguments.Count || !arguments[index].StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException("Runtime plan options must be '--name value' pairs.");
            }
            if (!values.TryAdd(arguments[index], arguments[index + 1]))
            {
                throw new ArgumentException($"Duplicate runtime option '{arguments[index]}'.");
            }
        }
        var unknown = values.Keys.Except(
            ["--role", "--driver", "--allocation", "--digest", "--architecture"],
            StringComparer.Ordinal).FirstOrDefault();
        if (unknown is not null)
        {
            throw new ArgumentException($"Unknown runtime option '{unknown}'.");
        }
        return values;
    }

    private static string Required(IReadOnlyDictionary<string, string> values, string key) =>
        values.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new ArgumentException($"Runtime plan requires {key}.");
}
