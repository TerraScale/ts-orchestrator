using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.ControlPlane.Providers;
using TerraScale.Orchestrator.ControlPlane.TerraBase;

namespace TerraScale.Orchestrator.Nodes;

/// <summary>
/// The operator-loaded member-host fleet deployment (<c>TS_ORCH_MEMBER_FLEET_FILE</c>): the
/// OCI Compute endpoint the fleet mutates through, the pinned launch template of every
/// TerraBase region it serves, and the shared member bootstrap. A closed shape with no
/// inline credentials; the endpoint serves exactly one OCI region, so a cell's fleet file
/// carries only the region templates that endpoint can act on — a placement for a region
/// without a template is refused by the fleet, never misrouted into another region's
/// compartment. Global topology is one fleet file per regional cell.
/// </summary>
public sealed class OciMemberHostFleetConfigurationFile
{
    private const int MaximumConfigurationBytes = 64 * 1024;
    private const int MaximumBootstrapBytes = 32 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        AllowDuplicateProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private OciMemberHostFleetConfigurationFile(
        Uri endpoint,
        string environment,
        IReadOnlyDictionary<string, OciCiRunnerLaunchTemplate> templates,
        OciMemberHostBootstrap bootstrap)
    {
        Endpoint = endpoint;
        Environment = environment;
        Templates = templates;
        Bootstrap = bootstrap;
    }

    public Uri Endpoint { get; }
    public string Environment { get; }

    internal IReadOnlyDictionary<string, OciCiRunnerLaunchTemplate> Templates { get; }

    internal OciMemberHostBootstrap Bootstrap { get; }

    /// <summary>Builds the fleet configuration for one cell: drain commands are addressed
    /// inside the controller's own NATS cell, so the cell is never file configuration.</summary>
    internal OciMemberHostFleetConfiguration ForCell(string cell) => new(cell, Templates, Bootstrap);

    public static OciMemberHostFleetConfigurationFile? Load(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var fullPath = Path.GetFullPath(path);
        var file = new FileInfo(fullPath);
        if (!file.Exists || file.LinkTarget is not null || file.Length is < 1 or > MaximumConfigurationBytes)
            throw new ArgumentException("The member host fleet configuration must be a bounded regular file.", nameof(path));
        using var stream = File.OpenRead(fullPath);
        var document = JsonSerializer.Deserialize<FleetDocument>(stream, SerializerOptions)
            ?? throw new InvalidDataException("The member host fleet configuration is empty.");
        if (document.SchemaVersion != 2 || document.Regions is not { Length: >= 1 and <= 8 } ||
            document.Environment is not { Length: >= 1 and <= 64 } ||
            document.Environment.Any(c => c is not (>= 'a' and <= 'z' or >= '0' and <= '9' or '-')))
            throw new InvalidDataException("The member host fleet configuration has an unsupported shape.");
        if (!Uri.TryCreate(document.Endpoint, UriKind.Absolute, out var endpoint) ||
            endpoint.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(endpoint.UserInfo) ||
            endpoint.AbsolutePath != "/" || !string.IsNullOrEmpty(endpoint.Query) ||
            !endpoint.Host.StartsWith("iaas.", StringComparison.Ordinal) ||
            !endpoint.Host.EndsWith(".oraclecloud.com", StringComparison.Ordinal))
            throw new InvalidDataException("The member host fleet endpoint is invalid.");
        if (string.IsNullOrWhiteSpace(document.BootstrapFile))
            throw new InvalidDataException("The member host fleet has no bootstrap file.");

        var baseDirectory = file.DirectoryName ?? Directory.GetCurrentDirectory();
        var templates = new Dictionary<string, OciCiRunnerLaunchTemplate>(StringComparer.Ordinal);
        foreach (var region in document.Regions)
        {
            if (region is null || region.Generation is not > 0 ||
                string.IsNullOrWhiteSpace(region.CompartmentId) ||
                string.IsNullOrWhiteSpace(region.AvailabilityDomain) ||
                string.IsNullOrWhiteSpace(region.SubnetId) ||
                string.IsNullOrWhiteSpace(region.ImageId) ||
                !TerraBaseRegionCode.TryCreate(region.Region, out var code))
                throw new InvalidDataException("A member host fleet region template has an unsupported shape.");
            if (templates.ContainsKey(code.Value))
                throw new InvalidDataException("Member host fleet region templates must be unique.");
            templates.Add(
                code.Value,
                new OciCiRunnerLaunchTemplate(
                    region.CompartmentId,
                    region.AvailabilityDomain,
                    region.FaultDomain,
                    region.SubnetId,
                    region.NetworkSecurityGroupIds ?? [],
                    region.ImageId,
                    region.Generation.Value));
        }
        return new(endpoint, document.Environment, templates, ReadBootstrap(baseDirectory, document.BootstrapFile!));
    }

    private static OciMemberHostBootstrap ReadBootstrap(string baseDirectory, string bootstrapFile)
    {
        var path = Path.GetFullPath(bootstrapFile, baseDirectory);
        var file = new FileInfo(path);
        if (!file.Exists || file.LinkTarget is not null || file.Length is < 1 or > MaximumBootstrapBytes)
            throw new InvalidDataException("The member host bootstrap must be a bounded regular file.");
        var content = File.ReadAllBytes(path);
        var text = StrictUtf8.GetString(content);
        if (!text.StartsWith("#cloud-config", StringComparison.Ordinal) &&
            !text.StartsWith("#!", StringComparison.Ordinal))
            throw new InvalidDataException("The member host bootstrap must be cloud-init or an executable script.");
        return new(
            Convert.ToBase64String(content),
            Convert.ToHexStringLower(SHA256.HashData(content)));
    }

    private sealed record FleetDocument(
        int? SchemaVersion,
        string? Endpoint,
        string? Environment,
        string? BootstrapFile,
        RegionDocument[]? Regions);

    private sealed record RegionDocument(
        string? Region,
        string? CompartmentId,
        string? AvailabilityDomain,
        string? FaultDomain,
        string? SubnetId,
        string[]? NetworkSecurityGroupIds,
        string? ImageId,
        long? Generation);
}
