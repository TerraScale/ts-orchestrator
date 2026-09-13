using TerraScale.Orchestrator.Contracts;

namespace TerraScale.Orchestrator.ModelTests;

public sealed class ModelTestAssemblyTests
{
    [Test]
    public async Task ContractVersionRemainsExplicitlyDraftUntilOwnerGatesClose()
    {
        await Assert.That(ContractVersion.Draft).IsNotNullOrWhiteSpace();
        await Assert.That(ContractVersion.Draft).Contains("draft");
    }
}

