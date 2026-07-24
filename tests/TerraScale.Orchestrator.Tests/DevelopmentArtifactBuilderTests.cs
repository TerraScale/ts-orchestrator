using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentArtifactBuilderTests
{
    [Test]
    public async Task FailureDiagnosticPrefersTheCompilerError()
    {
        var diagnostic = DevelopmentArtifactBuilder.Diagnostic(
            "",
            """
            Determining projects to restore...
            Program.cs(78,13): error CS8321: The local function is never used
            Build FAILED.
            """);

        await Assert.That(diagnostic)
            .IsEqualTo("Program.cs(78,13): error CS8321: The local function is never used");
    }
}
