using TerraScale.Orchestrator.Operations;

namespace TerraScale.Orchestrator.Tests;

public sealed class OperatorCliBoundaryTests
{
    [Test]
    public async Task OperatorParserRejectsOddAndTrailingArguments()
    {
        foreach (var arguments in new[]
                 {
                     new[] { "--cell" },
                     new[] { "--cell", "gru", "--nats-url" },
                     new[] { "--cell", "gru", "dangling" }
                 })
        {
            await Assert.That(() => OperatorCli.ParseValues(arguments))
                .Throws<ArgumentException>();
        }
    }

    [Test]
    public async Task RegionalStatusRejectsMissingCapabilitiesAndInvalidTimeWindow()
    {
        var observedAt = DateTimeOffset.UtcNow;
        var status = new RegionalControllerStatus(
            2,
            "gru",
            "1",
            3,
            true,
            observedAt.AddMinutes(1),
            observedAt,
            "test",
            ["reconciliation"],
            "leader",
            true,
            4,
            9,
            observedAt.AddMinutes(2));

        await Assert.That(() => status.Validate("gru"))
            .Throws<InvalidOperationException>();
        await Assert.That(() => (status with { StartedAt = observedAt.AddMinutes(-1), Capabilities = [] }).Validate("gru"))
            .Throws<InvalidOperationException>();
        await Assert.That(() => (status with { StartedAt = observedAt.AddMinutes(-1), AuthorityLeaseExpiresAt = observedAt }).Validate("gru"))
            .Throws<InvalidOperationException>();
    }
}
