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
        await Assert.That(plan.Systemd.Properties).Contains($"MemoryMax={plan.Resources.MemoryMaxBytes}");
        await Assert.That(plan.Systemd.Properties).Contains($"MemoryHigh={plan.Resources.MemoryHighBytes}");
        await Assert.That(plan.Systemd.Properties).Contains("MemorySwapMax=0");
        await Assert.That(plan.Systemd.Properties).Contains($"CPUWeight={plan.Resources.CpuWeight}");
        await Assert.That(plan.Systemd.Properties).Contains($"IOWeight={plan.Resources.IoWeight}");
        await Assert.That(plan.Systemd.Properties).Contains($"Nice={plan.Resources.Nice}");
    }

    [Test]
    public async Task OciPlanIsDigestPinnedRootlessAndCapabilityFree()
    {
        var plan = HostRuntimePlan.Create(
            AdmittedRole.CustomerDashboard,
            RuntimeDriver.OciContainer,
            new RuntimeAllocationId("sfo-dashboard-1"),
            new ArtifactDigest(Digest),
            HostArchitecture.Arm64);

        await Assert.That(plan.Oci).IsNotNull();
        await Assert.That(plan.Systemd).IsNull();
        await Assert.That(plan.Oci!.ImageReference)
            .IsEqualTo($"registry.terrascale.internal/terrascale/terrascale-dashboard@sha256:{Digest}");
        await Assert.That(plan.Oci.Platform).IsEqualTo("linux/arm64");
        await Assert.That(plan.Oci.Security.RunAsUser).IsEqualTo(65532U);
        await Assert.That(plan.Oci.Security.NoNewPrivileges).IsTrue();
        await Assert.That(plan.Oci.Security.ReadOnlyRootFileSystem).IsTrue();
        await Assert.That(plan.Oci.Security.DroppedCapabilities).IsEquivalentTo(["ALL"]);
        await Assert.That(plan.Oci.Security.CgroupParent).IsEqualTo("terrascale/sfo-dashboard-1");
        await Assert.That(plan.Resources.MemorySwapMaxBytes).IsEqualTo(0);
    }

    [Test]
    public async Task RuntimeLimitsCanBeReducedWithinTheClosedRolePolicy()
    {
        var requested = new RuntimeResourceLimits(512L * 1024 * 1024, 128, 100, 100, 100, 5);

        var plan = HostRuntimePlan.Create(
            AdmittedRole.CustomerDashboard,
            RuntimeDriver.OciContainer,
            new RuntimeAllocationId("gru-dashboard-limited"),
            new ArtifactDigest(Digest),
            HostArchitecture.Arm64,
            requested);

        await Assert.That(plan.SchemaVersion).IsEqualTo(2);
        await Assert.That(plan.Resources).IsEqualTo(requested);
        await Assert.That(plan.Resources.MemoryHighBytes).IsEqualTo(483_183_820);
    }

    [Test]
    public async Task RuntimeLimitsCannotEscapeTheClosedRolePolicy()
    {
        var excessive = new RuntimeResourceLimits(2L * 1024 * 1024 * 1024, 128, 100, 100, 100, 5);

        await Assert.That(() => HostRuntimePlan.Create(
                AdmittedRole.CustomerDashboard,
                RuntimeDriver.OciContainer,
                new RuntimeAllocationId("gru-dashboard-excessive"),
                new ArtifactDigest(Digest),
                HostArchitecture.Arm64,
                excessive))
            .Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task RuntimeCliAcceptsExplicitContainerLimits()
    {
        var plan = HostRuntimeCli.ParsePlan([
            "plan", "--role", "customer-dashboard", "--allocation", "gru-dashboard-cli", "--digest", Digest,
            "--memory-max-bytes", "536870912", "--tasks-max", "128",
            "--cpu-quota-percent", "100", "--cpu-weight", "100", "--io-weight", "100", "--nice", "5"
        ]);

        await Assert.That(plan.Resources)
            .IsEqualTo(new RuntimeResourceLimits(536870912, 128, 100, 100, 100, 5));
    }

    [Test]
    public async Task RuntimeInputsCannotInjectPathsImagesOrUnknownRoles()
    {
        await Assert.That(() => new RuntimeAllocationId("../../root")).Throws<ArgumentException>();
        await Assert.That(() => new ArtifactDigest("latest")).Throws<ArgumentException>();
        await Assert.That(() => HostRuntimeCli.ParseRole("arbitrary-container")).Throws<ArgumentException>();
    }
}
