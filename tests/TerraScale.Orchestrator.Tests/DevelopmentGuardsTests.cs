using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentGuardsTests
{
    [Test]
    public async Task HealthPathRejectsKindsWithoutAnHttpHealthContract()
    {
        await Assert.That(() => DevelopmentHealthProbe.HealthPath(DevelopmentResourceKind.ControlNats))
            .Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task SecondaryPortGuardRejectsIncompleteTopology()
    {
        var resource = new DevelopmentResourcePlan(
            "gru-terrabase-1",
            "gru",
            DevelopmentResourceKind.TerraBase,
            1,
            18650);

        await Assert.That(() => DevelopmentGuards.RequireSecondaryPort(resource))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task PathAndEndpointGuardsRejectIncompleteArtifacts()
    {
        await Assert.That(() => DevelopmentGuards.RequireDirectory("state.json", "State file"))
            .Throws<InvalidOperationException>();

        var observation = new DevelopmentResourceObservation(
            "gru-platform",
            "gru",
            DevelopmentResourceKind.Platform,
            1,
            DevelopmentResourceState.Ready,
            true,
            null,
            null,
            null,
            "ready",
            DateTimeOffset.UtcNow);

        await Assert.That(() => DevelopmentGuards.RequireEndpoint(observation))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task LabOptionGuardRejectsMissingConfiguration()
    {
        await Assert.That(() => DevelopmentGuards.RequireLabOption(null, "--state-file"))
            .Throws<InvalidOperationException>();
    }
}
