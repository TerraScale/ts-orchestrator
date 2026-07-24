using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class PreDeploymentEvidenceTests
{
    [Test]
    public async Task BoundedCompleteEvidenceIsAccepted()
    {
        var evidence = CreateEvidence();

        await Assert.That(evidence.HasBoundedValidationEvidence()).IsTrue();
    }

    [Test]
    public async Task ObservationAboveExecutionLimitIsRejected()
    {
        var evidence = CreateEvidence();
        var observations = evidence.ProcessObservations!.ToArray();
        observations[0] = observations[0] with { PeakMemoryBytes = 20L * 1024 * 1024 * 1024 + 1 };

        await Assert.That((evidence with { ProcessObservations = observations }).HasBoundedValidationEvidence())
            .IsFalse();
    }

    private static PreDeploymentEvidence CreateEvidence()
    {
        var modules = Enumerable.Range(1, 5)
            .Select(index => new PreDeploymentTestModule($"module-{index}", index, 4))
            .ToArray();
        var observations = modules
            .Select((module, index) => new PreDeploymentProcessObservation(
                module.Module,
                1_000 + index,
                64L * 1024 * 1024,
                4,
                100))
            .Concat([
                new("solution-build", 2_000, 128L * 1024 * 1024, 8, 200),
                new("orchestrator-policy-tooling-tests", 2_001, 64L * 1024 * 1024, 2, 100)
            ])
            .ToArray();
        return new(
            2,
            "pass",
            "commit",
            "digest",
            "regional",
            DateTimeOffset.UtcNow.AddHours(1),
            new(24L * 1024 * 1024 * 1024, 20L * 1024 * 1024 * 1024, 4L * 1024 * 1024 * 1024, 1, 4, 512),
            modules,
            observations);
    }
}
