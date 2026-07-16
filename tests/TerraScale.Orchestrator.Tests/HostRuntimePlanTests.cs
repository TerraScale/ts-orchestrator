using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class HostRuntimePlanTests
{
    private const string Digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Test]
    public async Task NativePlanUsesOnlyCatalogDerivedPathsAndHardenedSystemdProperties()
    {
        var plan = HostRuntimePlan.Create(
            AdmittedRole.TerraBaseMember,
            RuntimeDriver.NativeSystemd,
            new RuntimeAllocationId("gru-terrabase-1"),
            new ArtifactDigest(Digest),
            HostArchitecture.Arm64);

        await Assert.That(plan.Systemd).IsNotNull();
        await Assert.That(plan.Oci).IsNull();
        await Assert.That(plan.Systemd!.UnitName).IsEqualTo("terrascale-gru-terrabase-1.service");
        await Assert.That(plan.Systemd.Executable)
            .IsEqualTo($"/opt/terrascale/artifacts/terrabase-server/sha256-{Digest}/terrabase-server");
        await Assert.That(plan.Systemd.Properties).Contains("NoNewPrivileges=yes");
        await Assert.That(plan.Systemd.Properties).Contains("ProtectSystem=strict");
        await Assert.That(plan.Systemd.Properties).Contains("ProtectControlGroups=yes");
        await Assert.That(plan.Systemd.Properties)
            .Contains("EnvironmentFile=-/var/lib/terrascale-gru-terrabase-1/environment");
        await Assert.That(plan.Systemd.Properties)
            .Contains("LoadCredentialEncrypted=workload:/var/lib/terrascale-gru-terrabase-1/credentials/workload.cred");
    }

    [Test]
    public async Task OciPlanIsDigestPinnedRootlessAndCapabilityFree()
    {
        var plan = HostRuntimePlan.Create(
            AdmittedRole.Api,
            RuntimeDriver.OciContainer,
            new RuntimeAllocationId("sfo-api-1"),
            new ArtifactDigest(Digest),
            HostArchitecture.Arm64);

        await Assert.That(plan.Oci).IsNotNull();
        await Assert.That(plan.Systemd).IsNull();
        await Assert.That(plan.Oci!.ImageReference)
            .IsEqualTo($"registry.terrascale.internal/terrascale/terrascale-api@sha256:{Digest}");
        await Assert.That(plan.Oci.Platform).IsEqualTo("linux/arm64");
        await Assert.That(plan.Oci.Security.RunAsUser).IsEqualTo(65532U);
        await Assert.That(plan.Oci.Security.NoNewPrivileges).IsTrue();
        await Assert.That(plan.Oci.Security.ReadOnlyRootFileSystem).IsTrue();
        await Assert.That(plan.Oci.Security.DroppedCapabilities).IsEquivalentTo(["ALL"]);
    }

    [Test]
    public async Task RuntimeInputsCannotInjectPathsImagesOrUnknownRoles()
    {
        await Assert.That(() => new RuntimeAllocationId("../../root")).Throws<ArgumentException>();
        await Assert.That(() => new ArtifactDigest("latest")).Throws<ArgumentException>();
        await Assert.That(() => HostRuntimeCli.ParseRole("arbitrary-container")).Throws<ArgumentException>();
    }
}
