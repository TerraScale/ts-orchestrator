using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class CiRunnerProcessTests
{
    [Test]
    public async Task RuntimeProfileReconstructsOnlyTheSignedRunnerIsolation()
    {
        var accepted = await RepositoryCiJobInboxTests.AcceptedAsync();
        var command = accepted.Command;
        var expected = CiRunnerExecutionPlannerTests.Isolation(command);

        var evidence = CiRunnerProcessConfiguration.CreateIsolationEvidence(
            accepted,
            command.Runner,
            command.AllowedZones.Single(),
            command.RunnerSequence,
            command.RequiredCapabilities,
            expected.CpuMilliCores,
            expected.MemoryBytes,
            expected.EphemeralDiskBytes,
            expected.Pids,
            expected.MaximumLogBytes);

        await Assert.That(evidence).IsEqualTo(expected);
        await Assert.That(() => CiRunnerProcessConfiguration.CreateIsolationEvidence(
                accepted,
                command.Runner,
                command.AllowedZones.Single(),
                command.RunnerSequence,
                command.RequiredCapabilities,
                expected.CpuMilliCores,
                expected.MemoryBytes + 1,
                expected.EphemeralDiskBytes,
                expected.Pids,
                expected.MaximumLogBytes))
            .Throws<InvalidDataException>();
        await Assert.That(() => CiRunnerProcessConfiguration.CreateRunnerEvidence(
                accepted,
                "runner-other",
                TrustZone.UntrustedProduct,
                command.RunnerSequence,
                command.RequiredCapabilities))
            .Throws<InvalidDataException>();
    }
}
