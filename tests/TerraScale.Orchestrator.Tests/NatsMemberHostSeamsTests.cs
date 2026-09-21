using System.Text.Json;
using NATS.Client.Core;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.ControlPlane.TerraBase;
using TerraScale.Orchestrator.Nodes;
using TerraScale.Orchestrator.Protocol.Messaging;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Consumer policy tests use real NATS with an assumed authorized-report source. The real
/// signature/session boundary is covered separately by SessionAuthorizedHostReportReaderTests.
/// </summary>
[NotInParallel("TerrabasePlacement")]
public sealed class NatsMemberHostSeamsTests
{
    private const string Instance = "ocid1.instance.oc1.sa-saopaulo-1.member-a";
    private static readonly string Digest = $"sha256:{new string('a', 64)}";
    private static readonly DateTimeOffset Now = new(2026, 9, 20, 0, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task ReadinessAndHealthProjectFromTheSchema2Observation()
    {
        if (!OperatingSystem.IsLinux()) return;

        await using var server = await PlacementNatsServer.StartAsync();
        var seams = await CreateAsync(server);
        await server.Runtime.PutAsync(
            Key(),
            JsonSerializer.Serialize(
                Observation(memberUp: true, lag: 5, role: "leader", peer: 2, min: 3),
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
        var seams = await CreateAsync(server);

        // Admission permits volume recovery, but schema-1 proves no member health.
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
        var seams = await CreateAsync(server);
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
            Digest,
            "converged",
            "terrabase-server.service",
            Now,
            MemberUp: memberUp,
            MemberReplicationLagSequences: lag,
            MemberRole: role,
            MemberPeerAckCount: peer,
            MemberMinReplicas: min);

    [Test]
    public async Task Admitted_host_can_recover_storage_before_a_member_has_started()
    {
        if (!OperatingSystem.IsLinux()) return;
        await using var server = await PlacementNatsServer.StartAsync();
        var seams = await CreateAsync(server);
        await Assert.That(await seams.HasHostReportedAsync(Instance, CancellationToken.None)).IsTrue();
        await Assert.That(await seams.ObserveMemberHealthAsync(Instance, CancellationToken.None)).IsNull();
        await PutObservationAsync(server, Observation(false, 0, "Unknown", 0, 3));
        await Assert.That(await seams.HasHostReportedAsync(Instance, CancellationToken.None)).IsTrue();
        await Assert.That((await seams.ObserveMemberHealthAsync(Instance, CancellationToken.None))!.Up).IsFalse();
        await PutObservationAsync(server, Observation(true, 0, "Follower", 2, 3));
        await Assert.That((await seams.ObserveMemberHealthAsync(Instance, CancellationToken.None))!.Up).IsTrue();
        await PutAdmissionAsync(server, Admission() with { Ready = false });
        await Assert.That(await seams.HasHostReportedAsync(Instance, CancellationToken.None)).IsFalse();
        await Assert.That(await seams.ObserveMemberHealthAsync(Instance, CancellationToken.None)).IsNull();
    }

    [Test]
    [Arguments("node")]
    [Arguments("cell")]
    [Arguments("environment")]
    [Arguments("artifact")]
    [Arguments("digest")]
    [Arguments("stale")]
    [Arguments("future")]
    [Arguments("schema")]
    public async Task Admission_must_match_the_exact_node_target_and_current_time(string mismatch)
    {
        if (!OperatingSystem.IsLinux()) return;
        await using var server = await PlacementNatsServer.StartAsync();
        var seams = await CreateAsync(server);
        var record = Admission();
        record = mismatch switch
        {
            "node" => record with { Instance = "other-node" },
            "cell" => record with { Cell = "fra" },
            "environment" => record with { Environment = "staging" },
            "artifact" => record with { ArtifactKey = "ts-auth" },
            "digest" => record with { Digest = "sha256:" + new string('b', 64) },
            "stale" => record with { ObservedAt = Now.AddMinutes(-11) },
            "future" => record with { ObservedAt = Now.AddSeconds(1) },
            _ => record with { SchemaVersion = 99 }
        };
        await PutAdmissionAsync(server, record);
        await PutObservationAsync(server, Observation(true, 0, "Follower", 2, 3));
        await Assert.That(await seams.HasHostReportedAsync(Instance, CancellationToken.None)).IsFalse();
        await Assert.That(await seams.ObserveMemberHealthAsync(Instance, CancellationToken.None)).IsNull();
    }

    [Test]
    [Arguments("node")]
    [Arguments("cell")]
    [Arguments("artifact")]
    [Arguments("digest")]
    [Arguments("stale")]
    [Arguments("future")]
    [Arguments("failed")]
    [Arguments("error")]
    [Arguments("negative-lag")]
    [Arguments("missing-acks")]
    [Arguments("unknown-role")]
    public async Task Unbound_or_incomplete_service_evidence_never_reports_a_healthy_member(string mismatch)
    {
        if (!OperatingSystem.IsLinux()) return;
        await using var server = await PlacementNatsServer.StartAsync();
        var seams = await CreateAsync(server);
        var record = Observation(true, 0, "Follower", 2, 3);
        record = mismatch switch
        {
            "node" => record with { Instance = "other-node" },
            "cell" => record with { Cell = "fra" },
            "artifact" => record with { ArtifactKey = "ts-auth" },
            "digest" => record with { Digest = "sha256:" + new string('b', 64) },
            "stale" => record with { ObservedAt = Now.AddMinutes(-11) },
            "future" => record with { ObservedAt = Now.AddSeconds(1) },
            "failed" => record with { State = "failed" },
            "error" => record with { Error = "not-serving" },
            "negative-lag" => record with { MemberReplicationLagSequences = -1 },
            "missing-acks" => record with { MemberPeerAckCount = null },
            _ => record with { MemberRole = "Unknown" }
        };
        await PutObservationAsync(server, record);
        await Assert.That(await seams.HasHostReportedAsync(Instance, CancellationToken.None)).IsTrue();
        await Assert.That(await seams.ObserveMemberHealthAsync(Instance, CancellationToken.None)).IsNull();
    }

    [Test]
    public async Task Promotion_or_removal_of_the_admitted_target_invalidates_previous_readiness()
    {
        if (!OperatingSystem.IsLinux()) return;
        await using var server = await PlacementNatsServer.StartAsync();
        var seams = await CreateAsync(server);
        await PutObservationAsync(server, Observation(true, 0, "Follower", 2, 3));
        await server.Delivery.PutAsync(TargetKey(), JsonSerializer.Serialize(new { artifactDigest = "sha256:" + new string('b', 64) }));
        await Assert.That(await seams.HasHostReportedAsync(Instance, CancellationToken.None)).IsFalse();
        await Assert.That(await seams.ObserveMemberHealthAsync(Instance, CancellationToken.None)).IsNull();
        await server.Delivery.DeleteAsync(TargetKey());
        await Assert.That(await seams.HasHostReportedAsync(Instance, CancellationToken.None)).IsFalse();
        await server.Delivery.PutAsync(TargetKey(), "{bad-json");
        await Assert.That(await seams.HasHostReportedAsync(Instance, CancellationToken.None)).IsFalse();
    }

    [Test]
    public async Task Member_health_requires_one_unexpired_enrollment_generation_and_process_session()
    {
        await using var server = await PlacementNatsServer.StartAsync();
        await server.Delivery.PutAsync(TargetKey(), JsonSerializer.Serialize(new { artifactDigest = Digest }));
        var session = new HostReportSession("enrollment", 1, "process", 1);
        var admission = new AuthorizedHostReport(Admission(), null, session, Now.AddSeconds(1));
        var runtime = new AuthorizedHostReport(null, Observation(true, 0, "Follower", 2, 3), session, Now.AddSeconds(1));
        var reports = new ReportPair { Admission = admission, Runtime = runtime };
        var seams = new NatsMemberHostSeams(reports, server.Delivery, server.Connection, "gru", "production", new Clock());
        await Assert.That((await seams.ObserveMemberHealthAsync(Instance, CancellationToken.None))!.Up).IsTrue();
        foreach (var changed in new[]
                 {
                     runtime with { Session = session with { EnrollmentDigest = "other" } },
                     runtime with { Session = session with { Generation = 2 } },
                     runtime with { Session = session with { SessionId = "other" } },
                     runtime with { Session = session with { Epoch = 2 } },
                     runtime with { ExpiresAt = Now }
                 })
        {
            reports.Runtime = changed;
            await Assert.That(await seams.ObserveMemberHealthAsync(Instance, CancellationToken.None)).IsNull();
        }
        reports.Runtime = runtime;
        reports.Admission = admission with { ExpiresAt = Now };
        await Assert.That(await seams.HasHostReportedAsync(Instance, CancellationToken.None)).IsFalse();
        await Assert.That(await seams.ObserveMemberHealthAsync(Instance, CancellationToken.None)).IsNull();
    }

    private sealed class ReportPair : IAuthorizedHostReportReader
    {
        internal required AuthorizedHostReport Admission { get; set; }
        internal required AuthorizedHostReport Runtime { get; set; }
        public Task<AuthorizedHostReport?> ReadAsync(string key, CancellationToken cancellationToken) =>
            Task.FromResult<AuthorizedHostReport?>(key.StartsWith("host.admission.", StringComparison.Ordinal) ? Admission : Runtime);
    }

    private static async Task<NatsMemberHostSeams> CreateAsync(PlacementNatsServer server)
    {
        await server.Delivery.PutAsync(TargetKey(), JsonSerializer.Serialize(new { artifactDigest = Digest }));
        await PutAdmissionAsync(server, Admission());
        return new(new AssumedAuthorizedHostReportReader(server.Runtime), server.Delivery, server.Connection, "gru", "production", new Clock());
    }

    private static string TargetKey() => DirectDeliveryTargetKey.For("terrabase-server", "production", "gru");
    private static HostAdmissionObservation Admission() => new(1, "gru", Instance, "production", "terrabase-server", Digest, true, Now);
    private static async Task PutAdmissionAsync(PlacementNatsServer server, HostAdmissionObservation record) =>
        _ = await server.Runtime.PutAsync(HostAdmissionObservation.Key(Instance, "terrabase-server"),
            JsonSerializer.Serialize(record, HostAdmissionObservationJsonContext.Default.HostAdmissionObservation));
    private static async Task PutObservationAsync(PlacementNatsServer server, HostConvergenceObservation record) =>
        _ = await server.Runtime.PutAsync(Key(), JsonSerializer.Serialize(record, HostConvergenceJsonContext.Default.HostConvergenceObservation));
    private sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }
}
