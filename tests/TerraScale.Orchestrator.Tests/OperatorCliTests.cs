using TerraScale.Orchestrator.Operations;

namespace TerraScale.Orchestrator.Tests;

public sealed class OperatorCliTests
{
    [Test]
    public async Task OperatorOptionsAreClosedAndRejectDuplicates()
    {
        var parsed = OperatorCli.ParseValues([
            "--cell", "gru",
            "--nats-url", "nats://127.0.0.1:4222"
        ]);

        await Assert.That(parsed["--cell"]).IsEqualTo("gru");
        await Assert.That(() => OperatorCli.ParseValues(["--cell", "gru", "--cell", "sfo"]))
            .Throws<ArgumentException>();
        await Assert.That(() => OperatorCli.ParseValues(["--token", "secret"]))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task RegionalStatusRejectsWrongCellAndUnqualifiedCapabilities()
    {
        var status = new RegionalControllerStatus(
            2,
            "gru",
            "1",
            3,
            true,
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow,
            "test",
            ["reconciliation", "runtime"],
            "leader",
            true,
            4,
            9,
            DateTimeOffset.UtcNow.AddSeconds(10));

        status.Validate("gru");
        await Assert.That(() => status.Validate("sfo")).Throws<InvalidOperationException>();
        await Assert.That(() => (status with { Capabilities = ["runtime", "runtime"] }).Validate("gru"))
            .Throws<InvalidOperationException>();
        await Assert.That(() => (status with { AuthorityEpoch = 0 }).Validate("gru"))
            .Throws<InvalidOperationException>();
        await Assert.That(() => (status with { AuthorityState = "follower" }).Validate("gru"))
            .Throws<InvalidOperationException>();
    }
}
