using System.Text.Json;
using TerraScale.Orchestrator.Nodes;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// The member-host fleet configuration file: bounded closed shape, exact region codes,
/// one template per TerraBase region, and the same operator-boundary bootstrap checks
/// the CI pool configuration applies.
/// </summary>
public sealed class OciMemberHostFleetConfigurationFileTests
{
    [Test]
    public async Task LoadsTheEndpointRegionTemplatesAndBootstrap()
    {
        var root = Directory.CreateDirectory(Path.Combine(
            Path.GetTempPath(),
            $"ts-orch-member-fleet-{Guid.NewGuid():N}"));
        try
        {
            const string bootstrap = "#cloud-config\nruncmd:\n  - [systemctl, start, terrabase-member]\n";
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "member.cloud-init"), bootstrap);
            var path = Path.Combine(root.FullName, "fleet.json");
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new
            {
                schemaVersion = 2,
                environment = "production",
                endpoint = "https://iaas.sa-saopaulo-1.oraclecloud.com/",
                bootstrapFile = "member.cloud-init",
                regions = new object[]
                {
                    Region("GRU", "ocid1.compartment.oc1..gru"),
                    Region("SFO", "ocid1.compartment.oc1..sfo"),
                }
            }));

            var fleet = OciMemberHostFleetConfigurationFile.Load(path)!;
            var configuration = fleet.ForCell("gru");

            await Assert.That(fleet.Endpoint.Host).IsEqualTo("iaas.sa-saopaulo-1.oraclecloud.com");
            await Assert.That(fleet.Environment).IsEqualTo("production");
            await Assert.That(configuration.Cell).IsEqualTo("gru");
            await Assert.That(configuration.Templates.Keys).IsEquivalentTo(["GRU", "SFO"]);
            await Assert.That(configuration.Templates["GRU"].CompartmentId)
                .IsEqualTo("ocid1.compartment.oc1..gru");
            // The bootstrap is pinned digest-addressed, exactly as the launch plan emits it.
            await Assert.That(configuration.Bootstrap.CloudInitBase64)
                .IsEqualTo(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(bootstrap)));
            // The loaded fleet serves placement requests for its configured regions only.
            var plan = configuration.Plan(new(
                "prod-db", "permanent-gru-a", "GRU", "gru-p0", Permanent: true, "create-prod-db-permanent-gru-a"));
            await Assert.That(plan.Template.CompartmentId).IsEqualTo("ocid1.compartment.oc1..gru");
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Test]
    public async Task RejectsUnknownDuplicateAndLowercaseRegions()
    {
        var root = Root();
        try
        {
            await File.WriteAllTextAsync(
                Path.Combine(root.FullName, "member.cloud-init"), "#cloud-config\nruncmd: []\n");
            await Assert.That(async () => await LoadAsync(root, Region("gru", "ocid1.compartment.oc1..gru")))
                .Throws<InvalidDataException>();
            await Assert.That(async () => await LoadAsync(root, Region("XXL", "ocid1.compartment.oc1..xxl")))
                .Throws<InvalidDataException>();
            await Assert.That(async () => await LoadAsync(
                    root, Region("GRU", "ocid1.compartment.oc1..a"), Region("GRU", "ocid1.compartment.oc1..b")))
                .Throws<InvalidDataException>();
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Test]
    public async Task RejectsBootstrapCarryingAPlaintextCredential()
    {
        var root = Root();
        try
        {
            await File.WriteAllTextAsync(
                Path.Combine(root.FullName, "member.cloud-init"),
                "#cloud-config\nwrite_files:\n  - path: /run/nats.jwt\n    content: |\n      -----BEGIN NATS USER JWT-----\n");
            await Assert.That(async () => await LoadAsync(root, Region("GRU", "ocid1.compartment.oc1..gru")))
                .Throws<ArgumentException>();
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Test]
    public async Task AbsentConfigurationLoadsAsNull()
    {
        await Assert.That(OciMemberHostFleetConfigurationFile.Load(null)).IsNull();
        await Assert.That(OciMemberHostFleetConfigurationFile.Load("  ")).IsNull();
    }

    [Test]
    [Arguments(1, "production")]
    [Arguments(2, null)]
    [Arguments(2, "")]
    [Arguments(2, "prod.*")]
    public async Task Requires_the_explicit_schema2_delivery_environment(int schema, string? environment)
    {
        var root = Root();
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root.FullName, "member.cloud-init"), "#cloud-config\nruncmd: []\n");
            var path = Path.Combine(root.FullName, "fleet.json");
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new
            {
                schemaVersion = schema,
                environment,
                endpoint = "https://iaas.sa-saopaulo-1.oraclecloud.com/",
                bootstrapFile = "member.cloud-init",
                regions = new[] { Region("GRU", "ocid1.compartment.oc1..gru") }
            }));
            await Assert.That(() => OciMemberHostFleetConfigurationFile.Load(path)).Throws<InvalidDataException>();
        }
        finally { root.Delete(recursive: true); }
    }

    private static async Task<OciMemberHostFleetConfigurationFile> LoadAsync(
        DirectoryInfo root, params object[] regions)
    {
        var path = Path.Combine(root.FullName, "fleet.json");
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new
        {
            schemaVersion = 2,
            environment = "production",
            endpoint = "https://iaas.sa-saopaulo-1.oraclecloud.com/",
            bootstrapFile = "member.cloud-init",
            regions
        }));
        return OciMemberHostFleetConfigurationFile.Load(path) ??
            throw new InvalidOperationException("The member host fleet configuration did not load.");
    }

    private static object Region(string region, string compartment) => new
    {
        region,
        compartmentId = compartment,
        availabilityDomain = "sa-saopaulo-1-ad-1",
        faultDomain = "FAULT-DOMAIN-2",
        subnetId = "ocid1.subnet.oc1.sa-saopaulo-1.member",
        networkSecurityGroupIds = new[] { "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.member" },
        imageId = "ocid1.image.oc1.sa-saopaulo-1.terrabase",
        generation = 5,
    };

    private static DirectoryInfo Root() =>
        Directory.CreateDirectory(Path.Combine(
            Path.GetTempPath(),
            $"ts-orch-member-fleet-{Guid.NewGuid():N}"));
}
