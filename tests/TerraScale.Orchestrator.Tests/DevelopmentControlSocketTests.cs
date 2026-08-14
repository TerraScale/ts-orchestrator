using System.Net.Sockets;
using System.Text.Json;
using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentControlSocketTests
{
    [Test]
    public async Task ImpactMappingSelectsOnlyDashboardAndRequiredDependents()
    {
        var dashboard = DevelopmentReconcilePlanner.Plan(
            DevelopmentTopology.CreateRegional(),
            Request("TerraScale.Internals", ["src/Dashboard/TerraScale.Dashboard.Next/app/page.tsx"]));
        var terraBase = DevelopmentReconcilePlanner.Plan(
            DevelopmentTopology.CreateRegional(),
            Request("TerraBase", ["src/TerraBase.Server/Program.cs"]));

        await Assert.That(dashboard.Resources.Select(resource => resource.Kind).Distinct())
            .IsEquivalentTo([DevelopmentResourceKind.Dashboard]);
        await Assert.That(dashboard.Resources.Count).IsEqualTo(3);
        await Assert.That(terraBase.Resources.Select(resource => resource.Kind).Distinct())
            .IsEquivalentTo([
                DevelopmentResourceKind.TerraBase,
                DevelopmentResourceKind.Authentication,
                DevelopmentResourceKind.Platform,
                DevelopmentResourceKind.Dashboard
            ]);
        await Assert.That(terraBase.Resources.Count).IsEqualTo(12);
    }

    [Test]
    public async Task UnsafeOrUnmappedRequestsFailClosed()
    {
        var topology = DevelopmentTopology.CreateQuick();

        await Assert.That(() => DevelopmentReconcilePlanner.Plan(
                topology,
                Request("TerraScale.Internals", ["../secret"])))
            .Throws<InvalidDataException>();
        await Assert.That(() => DevelopmentReconcilePlanner.Plan(
                topology,
                Request("Terrascale.Documentation", ["src/content/index.md"])))
            .Throws<InvalidDataException>();
        await Assert.That(() => DevelopmentReconcilePlanner.Plan(
                topology,
                Request("TerraScale.Internals", ["src/Core/Something.cs"])))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task DocumentationOnlyInternalsUpdatesAreNoOp()
    {
        var topology = DevelopmentTopology.CreateQuick();
        var plan = DevelopmentReconcilePlanner.Plan(
            topology,
            Request("TerraScale.Internals", ["PLAN.md", "docs/implementation/sync/PLAN.md"]));

        await Assert.That(plan.Resources).IsEmpty();
        await Assert.That(plan.ReconciliationId).IsNotNull().And.IsNotEmpty();
        await Assert.That(plan.ReconciliationId.StartsWith("dev-", StringComparison.Ordinal)).IsTrue();

        // Single docs path (formerly fail-closed) is now an accepted no-op.
        var docsOnly = DevelopmentReconcilePlanner.Plan(
            topology,
            Request("TerraScale.Internals", ["docs/readme.md"]));
        await Assert.That(docsOnly.Resources).IsEmpty();
    }

    [Test]
    public async Task TerraBaseLargeSafePathListsPlanBeyondLegacyCap()
    {
        // Regression for 732315f: TerraBase ZString/n-gram refactors routinely
        // ship 130+ safe relative paths. Impact ignores the path list for kind
        // selection, but the planner must still accept counts above the former
        // 128-entry cap (and reject empty vs oversized with distinct errors).
        var topology = DevelopmentTopology.CreateRegional();
        var aboveLegacyCap = Enumerable.Range(0, 129)
            .Select(index => $"src/TerraBase.Core/Module{index:D3}.cs")
            .ToArray();
        var plan = DevelopmentReconcilePlanner.Plan(
            topology,
            Request("TerraBase", aboveLegacyCap));

        await Assert.That(plan.Resources.Select(resource => resource.Kind).Distinct())
            .IsEquivalentTo([
                DevelopmentResourceKind.TerraBase,
                DevelopmentResourceKind.Authentication,
                DevelopmentResourceKind.Platform,
                DevelopmentResourceKind.Dashboard
            ]);
        await Assert.That(plan.Resources.Count).IsEqualTo(12);

        var empty = await Assert.That(() => DevelopmentReconcilePlanner.Plan(
                topology,
                Request("TerraBase", [])))
            .Throws<InvalidDataException>();
        var oversized = await Assert.That(() => DevelopmentReconcilePlanner.Plan(
                topology,
                Request(
                    "TerraBase",
                    Enumerable.Range(0, DevelopmentReconcilePlanner.MaximumChangedPaths + 1)
                        .Select(index => $"src/TerraBase.Core/Oversize{index:D4}.cs")
                        .ToArray())))
            .Throws<InvalidDataException>();
        var unsafePath = await Assert.That(() => DevelopmentReconcilePlanner.Plan(
                topology,
                Request("TerraBase", ["../secret"])))
            .Throws<InvalidDataException>();

        await Assert.That(empty!.Message)
            .IsEqualTo("Changed paths must be a non-empty list of relative repository paths.");
        await Assert.That(oversized!.Message)
            .IsEqualTo(
                $"Changed paths exceed the maximum of {DevelopmentReconcilePlanner.MaximumChangedPaths} entries.");
        await Assert.That(unsafePath!.Message)
            .IsEqualTo("Changed paths must be bounded relative repository paths.");
        await Assert.That(empty.Message).IsNotEqualTo(oversized.Message);
        await Assert.That(oversized.Message).IsNotEqualTo(unsafePath.Message);
    }

    [Test]
    public async Task OwnerSocketDeduplicatesExactRequestsAndRejectsConflicts()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }
        var root = Path.Combine(Path.GetTempPath(), $"ts-orch-control-{Guid.NewGuid():N}");
        var path = Path.Combine(root, "orchestrator.sock");
        var calls = 0;
        try
        {
            await using var server = DevelopmentControlSocket.Start(path, request =>
            {
                calls++;
                var plan = DevelopmentReconcilePlanner.Plan(DevelopmentTopology.CreateQuick(), request);
                return new(
                    DevelopmentReconcilePlanner.SchemaVersion,
                    request.RequestId,
                    true,
                    plan.ReconciliationId,
                    null);
            });
            var request = Request(
                "TerraScale.Internals",
                ["src/Dashboard/TerraScale.Dashboard.Next/app/page.tsx"]);
            var first = await SendAsync(path, request);
            var duplicate = await SendAsync(path, request);
            var conflict = await SendAsync(path, request with
            {
                CurrentCommit = "cccccccccccccccccccccccccccccccccccccccc"
            });
            using var stalled = new Socket(
                AddressFamily.Unix,
                SocketType.Stream,
                ProtocolType.Unspecified);
            await stalled.ConnectAsync(new UnixDomainSocketEndPoint(path));
            var recovered = await SendAsync(path, request with { RequestId = "request-2" })
                .WaitAsync(TimeSpan.FromSeconds(5));

            await Assert.That(first.Accepted).IsTrue();
            await Assert.That(duplicate).IsEqualTo(first);
            await Assert.That(conflict.Accepted).IsFalse();
            await Assert.That(recovered.Accepted).IsTrue();
            await Assert.That(calls).IsEqualTo(2);
            await Assert.That(File.GetUnixFileMode(path))
                .IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private static DevelopmentReconcileRequest Request(
        string repository,
        IReadOnlyList<string> paths) =>
        new(
            DevelopmentReconcilePlanner.SchemaVersion,
            "request-1",
            repository,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            paths);

    private static async Task<DevelopmentReconcileResponse> SendAsync(
        string path,
        DevelopmentReconcileRequest request)
    {
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await socket.ConnectAsync(new UnixDomainSocketEndPoint(path));
        await using var stream = new NetworkStream(socket, ownsSocket: false);
        var options = JsonSerializerOptions.Web;
        await JsonSerializer.SerializeAsync(stream, request, options);
        await stream.WriteAsync("\n"u8.ToArray());
        await stream.FlushAsync();
        socket.Shutdown(SocketShutdown.Send);
        return await JsonSerializer.DeserializeAsync<DevelopmentReconcileResponse>(
            stream,
            options)
            ?? throw new InvalidDataException("Missing socket response.");
    }
}
