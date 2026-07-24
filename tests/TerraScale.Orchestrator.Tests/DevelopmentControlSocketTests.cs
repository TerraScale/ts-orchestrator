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
                Request("TerraScale.Internals", ["docs/readme.md"])))
            .Throws<InvalidDataException>();
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

            await Assert.That(first.Accepted).IsTrue();
            await Assert.That(duplicate).IsEqualTo(first);
            await Assert.That(conflict.Accepted).IsFalse();
            await Assert.That(calls).IsEqualTo(1);
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
        await JsonSerializer.SerializeAsync(stream, request);
        await stream.WriteAsync("\n"u8.ToArray());
        await stream.FlushAsync();
        socket.Shutdown(SocketShutdown.Send);
        return await JsonSerializer.DeserializeAsync<DevelopmentReconcileResponse>(
            stream,
            new JsonSerializerOptions(JsonSerializerDefaults.Web))
            ?? throw new InvalidDataException("Missing socket response.");
    }
}
