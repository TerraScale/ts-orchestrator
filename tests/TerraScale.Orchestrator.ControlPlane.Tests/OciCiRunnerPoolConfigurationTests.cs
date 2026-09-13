using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class OciCiRunnerPoolConfigurationTests
{
    [Test]
    public async Task LoadsBoundedFixedSlotsWhoseMetadataContainsNoCredential()
    {
        var root = Directory.CreateDirectory(Path.Combine(
            Path.GetTempPath(),
            $"ts-orch-oci-ci-{Guid.NewGuid():N}"));
        try
        {
            await File.WriteAllTextAsync(
                Path.Combine(root.FullName, "untrusted.cloud-init"),
                "#cloud-config\nruncmd:\n  - [oci, secrets, secret-bundle, get, --secret-id, ocid1.vaultsecret.oc1..runner]\n");
            await File.WriteAllTextAsync(
                Path.Combine(root.FullName, "trusted.cloud-init"),
                "#cloud-config\nruncmd:\n  - [oci, secrets, secret-bundle, get, --secret-id, ocid1.vaultsecret.oc1..trusted]\n");
            var path = Path.Combine(root.FullName, "pool.json");
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                endpoint = "https://iaas.sa-saopaulo-1.oraclecloud.com/",
                compartmentId = "ocid1.compartment.oc1..ci",
                availabilityDomain = "sa-saopaulo-1-ad-1",
                faultDomain = "FAULT-DOMAIN-1",
                subnetId = "ocid1.subnet.oc1.sa-saopaulo-1.ci",
                networkSecurityGroupIds = new[] { "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.ci" },
                imageId = "ocid1.image.oc1.sa-saopaulo-1.runner",
                generation = 7,
                idleSeconds = 60,
                pollSeconds = 5,
                runners = new[]
                {
                    new { runner = "ci-untrusted-1", zone = "untrusted-product", sequence = 10, bootstrapFile = "untrusted.cloud-init" },
                    new { runner = "ci-trusted-1", zone = "trusted-build", sequence = 10, bootstrapFile = "trusted.cloud-init" },
                }
            }));

            var pool = OciCiRunnerPoolConfiguration.Load(path)!;
            var launch = OciCiRunnerRequestCompiler.Launch(new(
                pool.Slots[0].Demand,
                pool.Template));

            await Assert.That(pool.Endpoint.Host).IsEqualTo("iaas.sa-saopaulo-1.oraclecloud.com");
            await Assert.That(pool.Slots).Count().IsEqualTo(2);
            await Assert.That(pool.Slots[0].Evidence(true).Capabilities)
                .IsEquivalentTo([RunnerCapability.Compile, RunnerCapability.Test]);
            await Assert.That(launch.LaunchInstanceDetails.Metadata["user_data"])
                .IsEqualTo(pool.Slots[0].Demand.BootstrapCloudInitBase64);
            await Assert.That(launch.LaunchInstanceDetails.PreemptibleInstanceConfig).IsNotNull();
            await Assert.That(launch.LaunchInstanceDetails.CreateVnicDetails.AssignPublicIp).IsFalse();
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }

    [Test]
    [Arguments("-----BEGIN NATS USER JWT-----")]
    [Arguments("-----BEGIN USER NKEY SEED-----")]
    [Arguments("-----BEGIN RSA PRIVATE KEY-----")]
    [Arguments("-----BEGIN OPENSSH PRIVATE KEY-----")]
    public async Task RejectsPlaintextCredentialsInOciMetadata(string credential)
    {
        var root = Directory.CreateDirectory(Path.Combine(
            Path.GetTempPath(),
            $"ts-orch-oci-ci-secret-{Guid.NewGuid():N}"));
        try
        {
            await File.WriteAllTextAsync(
                Path.Combine(root.FullName, "runner.cloud-init"),
                $"#cloud-config\n# {credential}\n");
            var path = Path.Combine(root.FullName, "pool.json");
            await File.WriteAllTextAsync(path, """
                {
                  "schemaVersion":1,
                  "endpoint":"https://iaas.sa-saopaulo-1.oraclecloud.com/",
                  "compartmentId":"ocid1.compartment.oc1..ci",
                  "availabilityDomain":"sa-saopaulo-1-ad-1",
                  "subnetId":"ocid1.subnet.oc1.sa-saopaulo-1.ci",
                  "networkSecurityGroupIds":["ocid1.networksecuritygroup.oc1.sa-saopaulo-1.ci"],
                  "imageId":"ocid1.image.oc1.sa-saopaulo-1.runner",
                  "generation":7,
                  "idleSeconds":60,
                  "pollSeconds":5,
                  "runners":[{"runner":"ci-untrusted-1","zone":"untrusted-product","sequence":10,"bootstrapFile":"runner.cloud-init"}]
                }
                """);

            await Assert.That(() => OciCiRunnerPoolConfiguration.Load(path))
                .Throws<InvalidDataException>();
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }
}

