using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentStateStoreTests
{
    [Test]
    public async Task StartingStateDoesNotPublishCutoverEndpoints()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-state-{Guid.NewGuid():N}");
        var stateFile = Path.Combine(directory, "state.json");
        var endpointsFile = Path.Combine(directory, "endpoints.json");
        var now = DateTimeOffset.UtcNow;
        var state = new DevelopmentRuntimeState(
            2,
            "devhost-three-cell-r3",
            7,
            now,
            now,
            [],
            new DevelopmentReconciliationState(47, 0, 0, 0, 47, 0, [], []));

        try
        {
            await DevelopmentStateStore.WriteAsync(
                stateFile,
                endpointsFile,
                state,
                endpoints: null,
                CancellationToken.None);

            await Assert.That(File.Exists(stateFile)).IsTrue();
            await Assert.That(File.Exists(endpointsFile)).IsFalse();

            await DevelopmentStateStore.WriteAsync(
                stateFile,
                endpointsFile,
                state,
                new DevelopmentEndpointMap(
                    1,
                    7,
                    new Dictionary<string, string> { ["api"] = "http://127.0.0.1:1" }),
                CancellationToken.None);
            await Assert.That(File.Exists(endpointsFile)).IsTrue();
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }
}
