using System.Net;
using System.Text.Json;
using TUnit.Assertions;
using TUnit.Core;
using TerraScale.Orchestrator.ControlPlane.DatabasePlacement;
using TerraScale.Orchestrator.ControlPlane.EdgeRouting;
using static TerraScale.Orchestrator.ControlPlane.Tests.EdgeRouting.EdgeRoutingTestData;
using static TerraScale.Orchestrator.ControlPlane.Tests.EdgeRouting.FakeCloudflareKvTransport;

namespace TerraScale.Orchestrator.ControlPlane.Tests.EdgeRouting;

public sealed class EdgeRoutingPublisherTests
{
    private static MutableEdgePlacementSource Source(params EdgeDatabasePlacement[] databases) =>
        new(Snapshot(databases: databases.ToDictionary(
            database => database.DatabaseName,
            database => database)));

    [Test]
    public async Task HealthWriteIsObservedBeforeAnyPlacementWriteInEveryPass()
    {
        using var transport = new FakeCloudflareKvTransport();
        var source = Source(Database(), Database(name: "zeta"));
        var publisher = Publisher(transport, source);

        await publisher.PublishAsync();
        var firstPassEnd = transport.Calls.Count;
        source.Set(Snapshot(databases: new Dictionary<string, EdgeDatabasePlacement>
        {
            ["zeta"] = Database(name: "zeta", revision: 2),
        }));
        await publisher.PublishAsync();
        var secondPassEnd = transport.Calls.Count;
        await publisher.PublishAsync();
        var thirdPassEnd = transport.Calls.Count;

        foreach (var (from, to) in new[] { (0, firstPassEnd), (firstPassEnd, secondPassEnd), (secondPassEnd, thirdPassEnd) })
        {
            var passCalls = transport.Calls.Take(to).Skip(from).ToList();
            var healthAt = passCalls.FindIndex(call => call == $"PUT {RegionsNamespaceId} values regions");
            await Assert.That(healthAt).IsGreaterThanOrEqualTo(0);
            await Assert.That(passCalls.Count(call => call == $"PUT {RegionsNamespaceId} values regions")).IsEqualTo(1);
            foreach (var call in passCalls.Where(call => call.Contains(PlacementNamespaceId, StringComparison.Ordinal)))
                await Assert.That(passCalls.IndexOf(call)).IsGreaterThan(healthAt);
        }
    }

    [Test]
    public async Task UnchangedSecondPassWritesOnlyTheHealthDocument()
    {
        using var transport = new FakeCloudflareKvTransport();
        var publisher = Publisher(transport, Source(Database(), Database(name: "zeta")));

        var first = await publisher.PublishAsync();
        var callsAfterFirst = transport.Calls.Count;
        var second = await publisher.PublishAsync();

        await Assert.That(first.PlacementWrites).IsEqualTo(2);
        await Assert.That(second.PlacementWrites).IsEqualTo(0);
        await Assert.That(second.PlacementSkips).IsEqualTo(2);
        await Assert.That(second.DeletedKeys).IsEqualTo(0);
        await Assert.That(transport.Calls.Skip(callsAfterFirst).ToList())
            .IsEquivalentTo([$"PUT {RegionsNamespaceId} values regions"]);
    }

    [Test]
    public async Task ChangedEligibilityProducesExactlyOneWriteWithBumpedRevision()
    {
        using var transport = new FakeCloudflareKvTransport();
        var source = Source(Database(branches: MainBranch((RegionCode.Gru, true, true), (RegionCode.Sfo, true, true))));
        var publisher = Publisher(transport, source);

        await publisher.PublishAsync();
        var callsAfterFirst = transport.Calls.Count;
        source.Set(Snapshot(databases: new Dictionary<string, EdgeDatabasePlacement>
        {
            ["orders"] = Database(revision: 2, branches: MainBranch((RegionCode.Gru, true, true), (RegionCode.Sfo, true, false))),
        }));
        var second = await publisher.PublishAsync();

        await Assert.That(second.PlacementWrites).IsEqualTo(1);
        await Assert.That(second.PlacementSkips).IsEqualTo(0);
        var bulkWrites = transport.Calls.Skip(callsAfterFirst).Where(call => call.Contains("bulk", StringComparison.Ordinal)).ToList();
        await Assert.That(bulkWrites).IsEquivalentTo([$"PUT {PlacementNamespaceId} bulk 1"]);

        using var document = JsonDocument.Parse(transport.StoredValue(PlacementNamespaceId, "db:orders")!);
        var root = document.RootElement;
        await Assert.That(root.GetProperty("v").GetInt32()).IsEqualTo(2);
        await Assert.That(root.GetProperty("rev").GetInt32()).IsEqualTo(2);
        var main = root.GetProperty("br").GetProperty("main");
        await Assert.That(main.GetArrayLength()).IsEqualTo(2);
        await Assert.That(main[0].GetProperty("region").GetString()).IsEqualTo("GRU");
        await Assert.That(main[0].GetProperty("write").GetBoolean()).IsTrue();
        await Assert.That(main[1].GetProperty("region").GetString()).IsEqualTo("SFO");
        await Assert.That(main[1].GetProperty("write").GetBoolean()).IsFalse();
    }

    [Test]
    public async Task FingerprintIgnoresDictionaryKeyOrderPermutations()
    {
        using var transport = new FakeCloudflareKvTransport();
        var alpha = Database(name: "alpha");
        var zeta = Database(name: "zeta");
        var source = new MutableEdgePlacementSource(Snapshot(databases: new Dictionary<string, EdgeDatabasePlacement>
        {
            ["zeta"] = zeta,
            ["alpha"] = alpha,
        }));
        var publisher = Publisher(transport, source);

        await publisher.PublishAsync();
        source.Set(Snapshot(databases: new Dictionary<string, EdgeDatabasePlacement>
        {
            ["alpha"] = alpha,
            ["zeta"] = zeta,
        }));
        var second = await publisher.PublishAsync();

        await Assert.That(second.PlacementWrites).IsEqualTo(0);
        await Assert.That(second.PlacementSkips).IsEqualTo(2);
    }

    [Test]
    public async Task StaleKeyIsDeletedOnlyAfterEveryWriteSucceededAndFailedWritesRetryNextPass()
    {
        using var transport = new FakeCloudflareKvTransport();
        var source = Source(Database(name: "alpha"), Database(name: "beta"));
        var publisher = Publisher(transport, source);

        await publisher.PublishAsync();
        source.Set(Snapshot(databases: new Dictionary<string, EdgeDatabasePlacement>
        {
            ["alpha"] = Database(name: "alpha", revision: 2),
        }));
        transport.Fail("PUT", "/bulk", HttpStatusCode.InternalServerError, times: 4);

        var failure = (await Assert.ThrowsAsync<EdgePublishOperationException>(() => publisher.PublishAsync()))!;
        await Assert.That(failure.Step).IsEqualTo(EdgePublishStepCode.PlacementWrite);
        await Assert.That(transport.Calls.Any(call => call.StartsWith("DELETE", StringComparison.Ordinal))).IsFalse();
        await Assert.That(transport.HasKey(PlacementNamespaceId, "db:beta")).IsTrue();

        var third = await publisher.PublishAsync();
        await Assert.That(third.PlacementWrites).IsEqualTo(1);
        await Assert.That(third.DeletedKeys).IsEqualTo(1);
        using var document = JsonDocument.Parse(transport.StoredValue(PlacementNamespaceId, "db:alpha")!);
        await Assert.That(document.RootElement.GetProperty("rev").GetInt32()).IsEqualTo(2);
        await Assert.That(transport.HasKey(PlacementNamespaceId, "db:beta")).IsFalse();
    }

    [Test]
    public async Task FailedStaleDeleteIsRetriedOnTheNextPass()
    {
        using var transport = new FakeCloudflareKvTransport();
        var source = Source(Database(name: "alpha"), Database(name: "beta"));
        var publisher = Publisher(transport, source);

        await publisher.PublishAsync();
        source.Set(Snapshot(databases: new Dictionary<string, EdgeDatabasePlacement>
        {
            ["alpha"] = Database(name: "alpha"),
        }));
        transport.Fail("DELETE", "/bulk", HttpStatusCode.InternalServerError, times: 4);
        await Assert.ThrowsAsync<EdgePublishOperationException>(() => publisher.PublishAsync());
        await Assert.That(transport.HasKey(PlacementNamespaceId, "db:beta")).IsTrue();

        var callsAfterFailure = transport.Calls.Count;
        var third = await publisher.PublishAsync();
        await Assert.That(third.PlacementWrites).IsEqualTo(0);
        await Assert.That(third.DeletedKeys).IsEqualTo(1);
        await Assert.That(transport.HasKey(PlacementNamespaceId, "db:beta")).IsFalse();
        await Assert.That(transport.Calls.Skip(callsAfterFailure).Where(call => call.Contains("bulk", StringComparison.Ordinal)).ToList())
            .IsEquivalentTo([$"DELETE {PlacementNamespaceId} bulk 1"]);
    }

    [Test]
    public async Task TransientPlacementFailureRetriesWithObservableBackoffAndSucceeds()
    {
        using var transport = new FakeCloudflareKvTransport();
        var clock = new FakeEdgeTimeProvider();
        transport.Fail("PUT", "/bulk", HttpStatusCode.InternalServerError, times: 1);
        var publisher = Publisher(transport, Source(Database(), Database(name: "zeta")), clock: clock);

        var result = await publisher.PublishAsync();

        await Assert.That(result.PlacementWrites).IsEqualTo(2);
        await Assert.That(transport.Calls.Count(call => call == $"PUT {PlacementNamespaceId} bulk 2")).IsEqualTo(2);
        await Assert.That(clock.Delays.Count).IsEqualTo(1);
        await Assert.That(clock.Delays[0] >= TimeSpan.FromMilliseconds(250)).IsTrue();
        await Assert.That(clock.Delays[0] < TimeSpan.FromMilliseconds(500)).IsTrue();
    }

    [Test]
    public async Task HealthWriteFailureSkipsEveryPlacementWriteOfThePass()
    {
        using var transport = new FakeCloudflareKvTransport();
        var clock = new FakeEdgeTimeProvider();
        transport.Fail("PUT", "/values/regions", HttpStatusCode.InternalServerError, times: 4);
        var publisher = Publisher(transport, Source(Database()), clock: clock);

        var failure = (await Assert.ThrowsAsync<EdgePublishOperationException>(() => publisher.PublishAsync()))!;
        await Assert.That(failure.Step).IsEqualTo(EdgePublishStepCode.HealthWrite);
        await Assert.That(transport.Calls.Any(call => call.Contains(PlacementNamespaceId, StringComparison.Ordinal))).IsFalse();
        await Assert.That(clock.Delays.Count).IsEqualTo(3);
        await Assert.That(clock.Delays[0] >= TimeSpan.FromMilliseconds(250)).IsTrue();
        await Assert.That(clock.Delays[1] >= TimeSpan.FromMilliseconds(500)).IsTrue();
        await Assert.That(clock.Delays[2] >= TimeSpan.FromMilliseconds(1000)).IsTrue();
    }

    [Test]
    public async Task ValidationFailsClosedWithoutAnyWrite()
    {
        using var transport = new FakeCloudflareKvTransport();
        var publisher = Publisher(transport, new FuncEdgePlacementSource(() => Task.FromResult<EdgePlacementSnapshot?>(null)));

        var rows = new (EdgePlacementSnapshot Snapshot, EdgePlacementErrorCode Expected)[]
        {
            new(Snapshot(databases: new Dictionary<string, EdgeDatabasePlacement>
                {
                    ["Orders"] = Database(name: "Orders"),
                }),
                EdgePlacementErrorCode.DatabaseNameInvalid),
            new(Snapshot(databases: new Dictionary<string, EdgeDatabasePlacement>
                {
                    ["orders"] = Database(name: "orders", branches: new Dictionary<string, IReadOnlyList<EdgeBranchPlacement>>
                    {
                        ["Main"] = MainBranch((RegionCode.Gru, true, true))["main"],
                    }),
                }),
                EdgePlacementErrorCode.BranchNameInvalid),
            new(Snapshot(databases: new Dictionary<string, EdgeDatabasePlacement>
                {
                    ["orders"] = Database(name: "orders", branches: MainBranch((RegionCode.FromValue("XYZ"), true, true))),
                }),
                EdgePlacementErrorCode.BranchRegionNotInCatalog),
            new(Snapshot(databases: new Dictionary<string, EdgeDatabasePlacement>
                {
                    ["orders"] = Database(name: "orders", branches: new Dictionary<string, IReadOnlyList<EdgeBranchPlacement>>
                    {
                        ["main"] = Array.Empty<EdgeBranchPlacement>(),
                    }),
                }),
                EdgePlacementErrorCode.BranchRegionListEmpty),
            new(Snapshot(databases: new Dictionary<string, EdgeDatabasePlacement>
                {
                    ["orders"] = Database(name: "orders", branches: MainBranch((RegionCode.Gru, true, true), (RegionCode.Gru, true, false))),
                }),
                EdgePlacementErrorCode.BranchRegionDuplicate),
            new(Snapshot(databases: new Dictionary<string, EdgeDatabasePlacement>
                {
                    ["orders"] = Database(name: "orders", residency: EdgeResidency.FromLabel("EU Only")),
                }),
                EdgePlacementErrorCode.ResidencyLabelInvalid),
            new(Snapshot(databases: new Dictionary<string, EdgeDatabasePlacement>
                {
                    ["orders"] = Database(name: "orders", residency: EdgeResidency.FromRegions([])),
                }),
                EdgePlacementErrorCode.ResidencyRegionsEmpty),
            new(Snapshot(databases: new Dictionary<string, EdgeDatabasePlacement>
                {
                    ["orders"] = Database(name: "orders", revision: -1),
                }),
                EdgePlacementErrorCode.RevisionNegative),
            new(Snapshot(databases: new Dictionary<string, EdgeDatabasePlacement>
                {
                    ["orders"] = Database(name: "orders", branches: new Dictionary<string, IReadOnlyList<EdgeBranchPlacement>>()),
                }),
                EdgePlacementErrorCode.BranchRegionListEmpty),
        };

        foreach (var row in rows)
        {
            var source = new MutableEdgePlacementSource(row.Snapshot);
            var exception = (await Assert.ThrowsAsync<EdgePlacementValidationException>(() => Publisher(transport, source).PublishAsync()))!;
            await Assert.That(exception.Errors.Any(error => error.Code == row.Expected)).IsTrue();
        }

        var missing = (await Assert.ThrowsAsync<EdgePlacementValidationException>(() => publisher.PublishAsync()))!;
        await Assert.That(missing.Errors.Single().Code).IsEqualTo(EdgePlacementErrorCode.SnapshotMissing);
        await Assert.That(transport.Calls).IsEmpty();
    }

    [Test]
    public async Task RevisionRegressionAgainstThePublishedDocumentRejectsThePass()
    {
        using var transport = new FakeCloudflareKvTransport();
        transport.Seed(PlacementNamespaceId, "db:orders", """{"v":2,"rev":10,"u":1,"res":null,"br":{}}""");
        var publisher = Publisher(transport, Source(Database(revision: 5)));

        var failure = (await Assert.ThrowsAsync<EdgeRevisionRegressionException>(() => publisher.PublishAsync()))!;
        await Assert.That(failure.Database).IsEqualTo("orders");
        await Assert.That(failure.SourceRevision).IsEqualTo(5);
        await Assert.That(failure.PublishedRevision).IsEqualTo(10);
        await Assert.That(transport.Calls.Any(call => call.Contains("bulk", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    public async Task BulkWritesChunkAtTheCloudflareLimit()
    {
        using var transport = new FakeCloudflareKvTransport();
        var databases = Enumerable.Range(0, 10_001).ToDictionary(
            index => $"db-{index:d5}",
            index => Database(name: $"db-{index:d5}"));
        var publisher = Publisher(transport, new StaticEdgePlacementSource(Snapshot(databases: databases)));

        var result = await publisher.PublishAsync();

        await Assert.That(result.PlacementWrites).IsEqualTo(10_001);
        await Assert.That(transport.Calls.Where(call => call.StartsWith($"PUT {PlacementNamespaceId} bulk", StringComparison.Ordinal)).ToList())
            .IsEquivalentTo([$"PUT {PlacementNamespaceId} bulk 10000", $"PUT {PlacementNamespaceId} bulk 1"]);
    }

    [Test]
    public async Task ExceedingTheWriteBudgetFailsThePassBeforeAnyWrite()
    {
        using var transport = new FakeCloudflareKvTransport();
        var publisher = Publisher(
            transport,
            Source(Database(name: "alpha"), Database(name: "beta"), Database(name: "gamma")),
            new EdgeRoutingPublisherOptions { MaximumWritesPerPass = 2 });

        var failure = (await Assert.ThrowsAsync<EdgePublishBudgetException>(() => publisher.PublishAsync()))!;
        await Assert.That(failure.PlannedWrites).IsEqualTo(3);
        await Assert.That(failure.MaximumWrites).IsEqualTo(2);
        await Assert.That(transport.Calls).IsEmpty();
    }

    [Test]
    public async Task PlacementDocumentMatchesTheAdrSchemaV2WireShape()
    {
        using var transport = new FakeCloudflareKvTransport();
        var databases = new Dictionary<string, EdgeDatabasePlacement>
        {
            ["labelled"] = Database(name: "labelled", residency: EdgeResidency.FromLabel("eu-only")),
            ["listed"] = Database(name: "listed", residency: EdgeResidency.FromRegions([RegionCode.Gru, RegionCode.Fra])),
            ["free"] = Database(name: "free"),
        };
        var publisher = Publisher(transport, new StaticEdgePlacementSource(Snapshot(databases: databases)), clock: new FakeEdgeTimeProvider());

        await publisher.PublishAsync();

        foreach (var name in databases.Keys)
        {
            using var document = JsonDocument.Parse(transport.StoredValue(PlacementNamespaceId, $"db:{name}")!);
            var root = document.RootElement;
            await Assert.That(root.GetProperty("v").GetInt32()).IsEqualTo(2);
            await Assert.That(root.GetProperty("rev").GetInt32()).IsEqualTo(1);
            await Assert.That(root.GetProperty("u").GetInt64()).IsEqualTo(FakeEdgeTimeProvider.Timestamp.ToUnixTimeSeconds());
            var main = root.GetProperty("br").GetProperty("main");
            await Assert.That(main[0].GetProperty("region").GetString()).IsEqualTo("GRU");
            await Assert.That(main[0].GetProperty("read").GetBoolean()).IsTrue();
            await Assert.That(main[1].GetProperty("region").GetString()).IsEqualTo("SFO");
            await Assert.That(main[1].GetProperty("read").GetBoolean()).IsTrue();
        }

        using var labelled = JsonDocument.Parse(transport.StoredValue(PlacementNamespaceId, "db:labelled")!);
        await Assert.That(labelled.RootElement.GetProperty("res").GetString()).IsEqualTo("eu-only");
        using var listed = JsonDocument.Parse(transport.StoredValue(PlacementNamespaceId, "db:listed")!);
        var residency = listed.RootElement.GetProperty("res");
        await Assert.That(residency.ValueKind).IsEqualTo(JsonValueKind.Array);
        await Assert.That(residency.EnumerateArray().Select(entry => entry.GetString()!).ToList())
            .IsEquivalentTo(["FRA", "GRU"]);
        using var free = JsonDocument.Parse(transport.StoredValue(PlacementNamespaceId, "db:free")!);
        await Assert.That(free.RootElement.GetProperty("res").ValueKind).IsEqualTo(JsonValueKind.Null);
    }

    [Test]
    public async Task HealthDocumentMatchesTheTsProxyHealthDocShape()
    {
        using var transport = new FakeCloudflareKvTransport();
        var publisher = Publisher(transport, Source(Database()));

        await publisher.PublishAsync();

        using var document = JsonDocument.Parse(transport.StoredValue(RegionsNamespaceId, "regions")!);
        var root = document.RootElement;
        await Assert.That(root.GetProperty("v").GetInt32()).IsEqualTo(1);
        await Assert.That(root.GetProperty("updated").GetInt64()).IsEqualTo(HealthUpdated);
        var regions = root.GetProperty("regions");
        await Assert.That(regions.EnumerateObject().Select(property => property.Name).ToList())
            .IsEquivalentTo(["FRA", "GRU", "SFO"]);
        var gru = regions.GetProperty("GRU");
        await Assert.That(gru.GetProperty("ok").GetBoolean()).IsTrue();
        await Assert.That(gru.GetProperty("lag_ms").GetInt32()).IsEqualTo(0);
        await Assert.That(gru.GetProperty("lat").GetDouble()).IsEqualTo(-23.43);
        await Assert.That(gru.GetProperty("lon").GetDouble()).IsEqualTo(-46.47);
        await Assert.That(regions.GetProperty("FRA").TryGetProperty("lag_ms", out _)).IsFalse();
        await Assert.That(regions.GetProperty("FRA").GetProperty("ok").GetBoolean()).IsFalse();
        var catalog = root.GetProperty("catalog");
        await Assert.That(catalog.GetArrayLength()).IsEqualTo(3);
        var frankfurt = catalog.EnumerateArray().Single(entry => entry.GetProperty("code").GetString() == "FRA");
        await Assert.That(frankfurt.GetProperty("name").GetString()).IsEqualTo("Frankfurt");
        await Assert.That(frankfurt.GetProperty("country").GetString()).IsEqualTo("DE");
        await Assert.That(frankfurt.GetProperty("lat").GetDouble()).IsEqualTo(50.03);
        await Assert.That(frankfurt.GetProperty("lon").GetDouble()).IsEqualTo(8.57);
    }

    [Test]
    public async Task NamespaceIdsAreResolvedOnceAndCachedAcrossPasses()
    {
        using var transport = new FakeCloudflareKvTransport();
        var publisher = Publisher(transport, Source(Database()));

        await publisher.PublishAsync();
        await publisher.PublishAsync();
        await publisher.PublishAsync();

        await Assert.That(transport.Calls.Count(call => call == "GET namespaces")).IsEqualTo(2);
    }
}
