using TerraScale.Orchestrator;

namespace TerraScale.Orchestrator.Tests;

public sealed class BuildVersionTests
{
    [Test]
    public async Task DisplayNameIncludesContractAndProtocolVersions()
    {
        var version = new BuildVersion("stable", 3);

        await Assert.That(version.DisplayName)
            .IsEqualTo("TerraScale Orchestrator stable (protocol v3)");
    }
}
