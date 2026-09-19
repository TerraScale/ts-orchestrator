using System.Text.Json;
using NATS.Client.Core;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.ControlPlane.TerraBase;
using TerraScale.Orchestrator.Nodes;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// The NATS-backed member-host seams against a real containerized NATS: readiness is the
/// presence of the host observation, health is the schema-2 projection, a schema-1 or
/// unreadable observation reads as not reporting, and drain commands publish on the
/// controller connection at the taxonomy's fenced subject.
/// </summary>
[NotInParallel("TerrabasePlacement")]
public sealed class NatsMemberHostSeamsTests
{
    private const string Instance = "ocid1.instance.oc1.sa-saopaulo-1.member-a";

    [Test]
    public async Task ReadinessAndHealthProjectFromTheSchema2Observation()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var server = await PlacementNatsServer.StartAsync();
        var seams = new NatsMemberHostSeams(server.Runtime, server.Connection);
        await server.Runtime.PutAsync(
            Key(),
            JsonSerializer.Serialize(
                Observation(memberUp: true, lag: 5, role: "Leader", peer: 2, min: 3),
                HostConvergenceJsonContext.Default.HostConvergenceObservation),
            cancellationToken: CancellationToken.None);

        await Assert.That(
            await seams.HasHostReportedAsync(Instance, CancellationToken.None)).IsTrue();
        var health = await seams.ObserveMemberHealthAsync(Instance, CancellationToken.None);
        await Assert.That(health).IsNotNull();
        await Assert.That(health!.Up).IsTrue();
        await Assert.That(health.ReplicationLagSequences).IsEqualTo(5);
        await Assert.That(health.Role).IsEqualTo("Leader");
        await Assert.That(health.PeerAckCount).IsEqualTo(2);
        await Assert.That(health.MinReplicas).IsEqualTo(3);
    }

    [Test]
    public async Task Schema1UnreadableAndAbsentObservationsReadAsNotReporting()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var server = await PlacementNatsServer.StartAsync();
        var seams = new NatsMemberHostSeams(server.Runtime, server.Connection);

        // A schema-1 observation proves the host reported but carries no member health.
        await server.Runtime.PutAsync(
            Key(),
            JsonSerializer.Serialize(
                Observation(memberUp: null, lag: null, role: null, peer: null, min: null),
                HostConvergenceJsonContext.Default.HostConvergenceObservation),
            cancellationToken: CancellationToken.None);
        await Assert.That(
            await seams.HasHostReportedAsync(Instance, CancellationToken.None)).IsTrue();
        await Assert.That(
            await seams.ObserveMemberHealthAsync(Instance, CancellationToken.None)).IsNull();

        // An unreadable record is the member's own evidence gap, never a fleet failure.
        await server.Runtime.PutAsync(Key(), "{not-json", cancellationToken: CancellationToken.None);
        await Assert.That(
            await seams.ObserveMemberHealthAsync(Instance, CancellationToken.None)).IsNull();

        // An instance that never reported reads as absent everywhere.
        await Assert.That(
            await seams.HasHostReportedAsync("ocid1.instance.oc1..never-started", CancellationToken.None)).IsFalse();
        await Assert.That(
            await seams.ObserveMemberHealthAsync("ocid1.instance.oc1..never-started", CancellationToken.None)).IsNull();
    }

    [Test]
    public async Task DrainCommandPublishesOnTheConnectionAtTheFencedSubject()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var server = await PlacementNatsServer.StartAsync();
        var seams = new NatsMemberHostSeams(server.Runtime, server.Connection);
        var subject = NatsSubjectTaxonomy.HostAgentCommandSubject("gru", Instance, "drain");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await using var subscription = await server.Connection.SubscribeCoreAsync<string>(
            subject,
            opts: new NatsSubOpts { MaxMsgs = 1, Timeout = TimeSpan.FromSeconds(5) },
            cancellationToken: timeout.Token);
        await server.Connection.PingAsync(timeout.Token);

        await seams.PublishAsync(subject, timeout.Token);

        var message = await subscription.Msgs.ReadAsync(timeout.Token);
        await Assert.That(message.Subject).IsEqualTo(subject);
        await Assert.That(message.Data is null or { Length: 0 }).IsTrue();
    }

    private static string Key(string instance = Instance) =>
        $"host.{instance}.{TerraBasePlacementReconciler.MemberArtifactKey}";

    private static HostConvergenceObservation Observation(
        bool? memberUp, long? lag, string? role, int? peer, int? min) =>
        new(
            memberUp is null ? 1 : HostConvergenceObservation.CurrentSchemaVersion,
            "gru",
            Instance,
            TerraBasePlacementReconciler.MemberArtifactKey,
            $"sha256:{new string('a', 64)}",
            "running",
            "terrabase-server.service",
            DateTimeOffset.UtcNow,
            MemberUp: memberUp,
            MemberReplicationLagSequences: lag,
            MemberRole: role,
            MemberPeerAckCount: peer,
            MemberMinReplicas: min);
}
