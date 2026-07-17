using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.ControlPlane.Providers;

public sealed class OciCiRunnerPoolConfiguration
{
    private const int MaximumConfigurationBytes = 256 * 1024;
    private const int MaximumBootstrapBytes = 32 * 1024;
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private OciCiRunnerPoolConfiguration(
        Uri endpoint,
        OciCiRunnerLaunchTemplate template,
        TimeSpan idleTimeout,
        TimeSpan pollInterval,
        OciCiRunnerPoolSlot[] slots)
    {
        Endpoint = endpoint;
        Template = template;
        IdleTimeout = idleTimeout;
        PollInterval = pollInterval;
        Slots = Array.AsReadOnly(slots);
    }

    public Uri Endpoint { get; }
    internal OciCiRunnerLaunchTemplate Template { get; }
    internal TimeSpan IdleTimeout { get; }
    internal TimeSpan PollInterval { get; }
    internal IReadOnlyList<OciCiRunnerPoolSlot> Slots { get; }

    public static OciCiRunnerPoolConfiguration? Load(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var fullPath = Path.GetFullPath(path);
        var file = new FileInfo(fullPath);
        if (!file.Exists || file.LinkTarget is not null || file.Length is < 1 or > MaximumConfigurationBytes)
            throw new ArgumentException("The OCI CI runner pool configuration must be a bounded regular file.", nameof(path));
        using var stream = File.OpenRead(fullPath);
        var document = JsonSerializer.Deserialize<PoolDocument>(stream, SerializerOptions)
            ?? throw new InvalidDataException("The OCI CI runner pool configuration is empty.");
        if (document.SchemaVersion != 1 || document.Runners is not { Length: >= 1 and <= 32 })
            throw new InvalidDataException("The OCI CI runner pool configuration has an unsupported shape.");
        if (!Uri.TryCreate(document.Endpoint, UriKind.Absolute, out var endpoint) ||
            endpoint.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(endpoint.UserInfo) ||
            endpoint.AbsolutePath != "/" || !string.IsNullOrEmpty(endpoint.Query) ||
            !endpoint.Host.StartsWith("iaas.", StringComparison.Ordinal) ||
            !endpoint.Host.EndsWith(".oraclecloud.com", StringComparison.Ordinal))
            throw new InvalidDataException("The OCI CI runner pool endpoint is invalid.");
        if (document.IdleSeconds is < 30 or > 900 || document.PollSeconds is < 1 or > 30)
            throw new InvalidDataException("The OCI CI runner pool timing is outside its bound.");

        var template = new OciCiRunnerLaunchTemplate(
            document.CompartmentId,
            document.AvailabilityDomain,
            document.FaultDomain,
            document.SubnetId,
            document.NetworkSecurityGroupIds ?? [],
            document.ImageId,
            document.Generation);
        var baseDirectory = file.DirectoryName ?? Directory.GetCurrentDirectory();
        var slots = document.Runners.Select(value => Slot(value, baseDirectory)).ToArray();
        if (slots.Select(static slot => slot.Demand.Runner).Distinct(StringComparer.Ordinal).Count() != slots.Length)
            throw new InvalidDataException("OCI CI runner identities must be unique.");
        return new(
            endpoint,
            template,
            TimeSpan.FromSeconds(document.IdleSeconds),
            TimeSpan.FromSeconds(document.PollSeconds),
            slots);
    }

    private static OciCiRunnerPoolSlot Slot(RunnerDocument value, string baseDirectory)
    {
        if (value is null) throw new InvalidDataException("An OCI CI runner slot is empty.");
        var zone = value.Zone switch
        {
            "untrusted-product" => TrustZone.UntrustedProduct,
            "trusted-build" => TrustZone.TrustedBuild,
            _ => throw new InvalidDataException("An OCI CI runner slot has an unsupported trust zone."),
        };
        if (string.IsNullOrWhiteSpace(value.BootstrapFile))
            throw new InvalidDataException("An OCI CI runner slot has no bootstrap file.");
        var path = Path.GetFullPath(value.BootstrapFile, baseDirectory);
        var file = new FileInfo(path);
        if (!file.Exists || file.LinkTarget is not null || file.Length is < 1 or > MaximumBootstrapBytes)
            throw new InvalidDataException("An OCI CI runner bootstrap must be a bounded regular file.");
        var content = File.ReadAllBytes(path);
        var text = new UTF8Encoding(false, true).GetString(content);
        if (!text.StartsWith("#cloud-config", StringComparison.Ordinal) &&
            !text.StartsWith("#!", StringComparison.Ordinal))
            throw new InvalidDataException("An OCI CI runner bootstrap must be cloud-init or an executable script.");
        if (ContainsCredential(text))
            throw new InvalidDataException("OCI user_data must not contain a plaintext credential.");
        var demand = new OciCiRunnerDemand(
            value.Runner,
            zone,
            value.Sequence,
            Convert.ToBase64String(content),
            Convert.ToHexStringLower(SHA256.HashData(content)));
        return new(demand);
    }

    private static bool ContainsCredential(string value) =>
        value.Contains("BEGIN NATS USER JWT", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("BEGIN USER NKEY SEED", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("PRIVATE KEY-----", StringComparison.OrdinalIgnoreCase);

    private sealed record PoolDocument(
        int SchemaVersion,
        string Endpoint,
        string CompartmentId,
        string AvailabilityDomain,
        string? FaultDomain,
        string SubnetId,
        string[]? NetworkSecurityGroupIds,
        string ImageId,
        long Generation,
        int IdleSeconds,
        int PollSeconds,
        RunnerDocument[]? Runners);

    private sealed record RunnerDocument(
        string Runner,
        string Zone,
        long Sequence,
        string BootstrapFile);
}

internal sealed class OciCiRunnerPoolSlot(OciCiRunnerDemand demand)
{
    internal OciCiRunnerDemand Demand { get; } = demand;

    internal RunnerEvidence Evidence(bool available) => new(
        new(Demand.Runner),
        Demand.Zone,
        Demand.Sequence,
        available,
        Demand.Zone == TrustZone.UntrustedProduct
            ? [RunnerCapability.Compile, RunnerCapability.Test]
            : [RunnerCapability.Compile, RunnerCapability.Test, RunnerCapability.Sign]);

    internal CiRunnerIsolationEvidence Isolation(RepositoryCiPipelineJob job) =>
        CiRunnerResourceProfile.Isolation(job.Request, Evidence(true));
}
