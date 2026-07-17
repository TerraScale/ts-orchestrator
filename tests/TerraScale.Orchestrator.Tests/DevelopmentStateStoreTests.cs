using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentStateStoreTests
{
    [Test]
    public async Task ObsoleteResourceKindIsIgnoredAsDisposableState()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-state-{Guid.NewGuid():N}");
        var stateFile = Path.Combine(directory, "state.json");
        Directory.CreateDirectory(directory);
        try
        {
            await File.WriteAllTextAsync(
                stateFile,
                """
                {
                  "schemaVersion": 2,
                  "profile": "dev-containers-three-cell-lean",
                  "generation": 7,
                  "startedAt": "2026-07-17T00:00:00Z",
                  "observedAt": "2026-07-17T00:00:00Z",
                  "resources": [{
                    "name": "gru-api",
                    "cell": "gru",
                    "kind": "api",
                    "replica": 1,
                    "state": "ready",
                    "healthy": true,
                    "detail": "obsolete",
                    "observedAt": "2026-07-17T00:00:00Z"
                  }],
                  "reconciliation": {
                    "desiredResources": 1,
                    "observedResources": 1,
                    "readyResources": 1,
                    "startingResources": 0,
                    "degradedResources": 0,
                    "failedResources": 0,
                    "missingResources": [],
                    "unexpectedResources": []
                  }
                }
                """);

            await Assert.That(await DevelopmentStateStore.ReadAsync(stateFile, CancellationToken.None)).IsNull();
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Test]
    public async Task StartingStateDoesNotPublishCutoverEndpoints()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-state-{Guid.NewGuid():N}");
        var stateFile = Path.Combine(directory, "state.json");
        var endpointsFile = Path.Combine(directory, "endpoints.json");
        var now = DateTimeOffset.UtcNow;
        var state = new DevelopmentRuntimeState(
            2,
            "dev-containers-three-cell-lean",
            7,
            now,
            now,
            [],
            new DevelopmentReconciliationState(23, 0, 0, 0, 23, 0, [], []));

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
                    new Dictionary<string, string> { ["platform"] = "http://127.0.0.1:1" }),
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
