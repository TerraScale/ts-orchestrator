using System.Reflection;
using System.Text.Json;
using NATS.Client.KeyValueStore;
using NATS.Net;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Nodes;

namespace TerraScale.Orchestrator.Tests;

[NotInParallel(LocalNatsServerLease.SchedulingConstraint)]
public sealed class SessionAuthorizedHostReportReaderTests
{
    private static readonly string Digest = "sha256:" + new string('a', 64);

    [Test]
    public async Task Withheld_store_read_is_bounded_and_explicit_caller_cancellation_is_preserved()
    {
        var proxy = DispatchProxy.Create<INatsKVStore, WithheldRead>();
        using var material = new SessionMaterial();
        var reader = new SessionAuthorizedHostReportReader(proxy, new(proxy, material.Policy()));
        try
        {
            var attempt = reader.ReadAsync("host.example.ts-auth", CancellationToken.None);
            await Assert.That(await attempt.WaitAsync(TimeSpan.FromSeconds(8))).IsNull();
            using var cancelled = new CancellationTokenSource();
            cancelled.Cancel();
            await Assert.That(() => reader.ReadAsync("host.example.ts-auth", cancelled.Token)).Throws<OperationCanceledException>();
        }
        finally { ((WithheldRead)proxy).Read.TrySetResult(new("test", "host.example.ts-auth") { Value = "{}", Revision = 1 }); }
    }

    [Test]
    public async Task Real_R3_member_recovery_health_and_operator_status_require_the_current_session()
    {
        await using var cluster = await NatsControlR3L0cFixture.StartAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await cluster.ProvisionAsync(deadline.Token);
        await using var client = await cluster.ConnectAsync(cluster.Controller, cancellationToken: deadline.Token);
        var js = client.CreateJetStreamContext();
        var runtime = await js.CreateKeyValueStoreContext().GetStoreAsync("ORCH_RUNTIME", deadline.Token);
        var delivery = await js.CreateKeyValueStoreContext().GetStoreAsync("ORCH_DELIVERY", deadline.Token);
        var bundles = await js.CreateObjectStoreContext().GetObjectStoreAsync(cluster.Topology.Bundles.Bucket, deadline.Token);
        using var reports = await AdmittedHostReportFixture.CreateAsync(client, runtime, deadline.Token, realTime: true);
        var admission = Admission(reports);
        var observation = new HostConvergenceObservation(2, "gru", reports.Node, "terrabase-server", Digest,
            "converged", "member.service", reports.Material.Clock.GetUtcNow(), MemberUp: true,
            MemberReplicationLagSequences: 0, MemberRole: "Leader", MemberPeerAckCount: 2, MemberMinReplicas: 3);
        await reports.PutAsync(reports.Sign(admission), deadline.Token);
        await reports.PutAsync(reports.Sign(observation), deadline.Token);
        await delivery.PutAsync(DirectDeliveryTargetKey.For("terrabase-server", "production", "gru"),
            JsonSerializer.Serialize(new { artifactDigest = Digest }), cancellationToken: deadline.Token);
        await delivery.PutAsync("gitops.cell.test", """{"cell":"gru","payloadObject":"admitted"}""", cancellationToken: deadline.Token);
        await bundles.PutAsync("admitted", JsonSerializer.SerializeToUtf8Bytes(new
        {
            generation = 1,
            desiredWorkloads = new[] { new { role = "TerraBaseMember", cells = new[] { "gru" }, replicas = 3, artifactDigest = Digest } }
        }), cancellationToken: deadline.Token);
        var seams = new NatsMemberHostSeams(reports.Reader, delivery, client.Connection, "gru", "production", reports.Material.Clock);
        await Assert.That(await seams.HasHostReportedAsync(reports.Node, deadline.Token)).IsTrue();
        await Assert.That((await seams.ObserveMemberHealthAsync(reports.Node, deadline.Token))?.Up).IsTrue();
        var options = new OrchestratorOptions(OrchestratorCommand.Check, "gru", "nats://127.0.0.1:4222", 3);
        var status = await NatsRuntime.BuildOperatorStatusAsync(delivery, bundles, runtime, options,
            new("gru", 3, "local"), DateTimeOffset.UtcNow, deadline.Token, authorizedHostReports: reports.Reader);
        await Assert.That(status.Workloads.Single(value => value.Workload == "terrabase-server").ReadyReplicas).IsEqualTo(1);
        await reports.PutAsync(reports.Sign(admission with { Ready = false, ObservedAt = DateTimeOffset.UtcNow }), deadline.Token);
        status = await NatsRuntime.BuildOperatorStatusAsync(delivery, bundles, runtime, options,
            new("gru", 3, "local"), DateTimeOffset.UtcNow, deadline.Token, authorizedHostReports: reports.Reader);
        await Assert.That(status.Workloads.Single(value => value.Workload == "terrabase-server").ReadyReplicas).IsEqualTo(0);
        await Assert.That(status.Needs.Contains("host-admission-not-ready")).IsTrue();
        await Assert.That(await seams.ObserveMemberHealthAsync(reports.Node, deadline.Token)).IsNull();
        await reports.PutAsync(reports.Sign(admission with { ObservedAt = DateTimeOffset.UtcNow }), deadline.Token);
        // A controller without configured authorization cannot reuse the same valid signed record.
        status = await NatsRuntime.BuildOperatorStatusAsync(delivery, bundles, runtime, options,
            new("gru", 3, "local"), DateTimeOffset.UtcNow, deadline.Token);
        await Assert.That(status.Workloads.Single(value => value.Workload == "terrabase-server").ReadyReplicas).IsEqualTo(0);
        await Assert.That(await reports.Authority.RevokeAsync(reports.Node, 1, reports.Epoch, deadline.Token)).IsTrue();
        await Assert.That(await seams.HasHostReportedAsync(reports.Node, deadline.Token)).IsFalse();
        await Assert.That(await seams.ObserveMemberHealthAsync(reports.Node, deadline.Token)).IsNull();
        status = await NatsRuntime.BuildOperatorStatusAsync(delivery, bundles, runtime, options,
            new("gru", 3, "local"), DateTimeOffset.UtcNow, deadline.Token, authorizedHostReports: reports.Reader);
        await Assert.That(status.Workloads.Single(value => value.Workload == "terrabase-server").ReadyReplicas).IsEqualTo(0);
    }

    [Test]
    public async Task Stale_report_replica_cannot_restore_readiness_after_a_newer_withdrawal()
    {
        await using var cluster = await NatsControlR3L0cFixture.StartAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await cluster.ProvisionAsync(deadline.Token);
        await using var client = await cluster.ConnectAsync(cluster.Controller, cancellationToken: deadline.Token);
        var runtime = await client.CreateJetStreamContext().CreateKeyValueStoreContext().GetStoreAsync("ORCH_RUNTIME", deadline.Token);
        using var reports = await AdmittedHostReportFixture.CreateAsync(client, runtime, deadline.Token);
        var record = reports.Sign(Admission(reports));
        await reports.PutAsync(record, deadline.Token);
        var stale = await runtime.GetEntryAsync<string>(record.Key, cancellationToken: deadline.Token);
        var accepted = await reports.Reader.ReadAsync(record.Key, deadline.Token);
        await Assert.That(accepted?.Admission?.Ready).IsTrue();
        var current = await runtime.GetEntryAsync<string>(record.Key, cancellationToken: deadline.Token);
        await Assert.That(current.Revision).IsGreaterThan(stale.Revision);
        await Assert.That(current.Value).IsEqualTo(stale.Value);
        reports.Material.Clock.Advance(TimeSpan.FromSeconds(1));
        await reports.PutAsync(reports.Sign(Admission(reports) with { Ready = false }), deadline.Token);
        var proxy = DispatchProxy.Create<INatsKVStore, RegionalHostReportAuthorizationTests.StaleReplica>();
        var intercepted = (RegionalHostReportAuthorizationTests.StaleReplica)proxy;
        intercepted.Inner = runtime;
        intercepted.Entry = stale;
        intercepted.RemainingStaleReads = 2;
        var reader = new SessionAuthorizedHostReportReader(proxy, reports.Authority, reports.Material.Clock);
        await Assert.That((await reader.ReadAsync(record.Key, deadline.Token))?.Admission?.Ready).IsFalse();
        intercepted.RemainingStaleReads = 8;
        await Assert.That(await reader.ReadAsync(record.Key, deadline.Token)).IsNull();
        reports.Material.Clock.Advance(TimeSpan.FromSeconds(10));
        await Assert.That(await reports.Reader.ReadAsync(record.Key, deadline.Token)).IsNull();
        // A fresh proof still cannot turn an expired process lease into readiness.
        reports.Material.Clock.Advance(TimeSpan.FromSeconds(20));
        await reports.PutAsync(reports.Sign(Admission(reports)), deadline.Token);
        await Assert.That(await reports.Reader.ReadAsync(record.Key, deadline.Token)).IsNull();
    }

    [Test]
    public async Task Missing_plain_relocated_tampered_and_malformed_records_fail_closed()
    {
        await using var cluster = await NatsControlR3L0cFixture.StartAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await cluster.ProvisionAsync(deadline.Token);
        await using var client = await cluster.ConnectAsync(cluster.Controller, cancellationToken: deadline.Token);
        var runtime = await client.CreateJetStreamContext().CreateKeyValueStoreContext().GetStoreAsync("ORCH_RUNTIME", deadline.Token);
        using var reports = await AdmittedHostReportFixture.CreateAsync(client, runtime, deadline.Token);
        var admission = Admission(reports);
        var record = reports.Sign(admission);
        var json = JsonSerializer.Serialize(record, RegionalHostSessionAuthority.JsonOptions);
        await Assert.That(await reports.Reader.ReadAsync(record.Key, deadline.Token)).IsNull();
        foreach (var malformed in new[]
                 {
                     "null", "{}", "{bad-json", new string('x', StoredHostReport.MaximumBytes + 1),
                     JsonSerializer.Serialize(admission), json.Replace("\"Ready\":true", "\"Ready\":false", StringComparison.Ordinal),
                     "{\"Unexpected\":true," + json[1..], "{\"SchemaVersion\":1," + json[1..],
                     JsonSerializer.Serialize(record with { SchemaVersion = 99 }),
                     JsonSerializer.Serialize(record with { Proof = null! }),
                     JsonSerializer.Serialize(record with { Admission = null })
                 })
        {
            await runtime.PutAsync(record.Key, malformed, cancellationToken: deadline.Token);
            await Assert.That(await reports.Reader.ReadAsync(record.Key, deadline.Token)).IsNull();
        }
        var wrongKey = HostAdmissionObservation.Key("another-node", "terrabase-server");
        await reports.PutAsync(record, deadline.Token, wrongKey);
        await Assert.That(await reports.Reader.ReadAsync(wrongKey, deadline.Token)).IsNull();
        await reports.PutAsync(record, deadline.Token);
        await Assert.That((await reports.Reader.ReadAsync(record.Key, deadline.Token))?.Admission?.Ready).IsTrue();
        await runtime.DeleteAsync(record.Key, cancellationToken: deadline.Token);
        await Assert.That(await reports.Reader.ReadAsync(record.Key, deadline.Token)).IsNull();
    }

    private static HostAdmissionObservation Admission(AdmittedHostReportFixture reports) =>
        new(1, "gru", reports.Node, "production", "terrabase-server", Digest, true, reports.Material.Clock.GetUtcNow());

    public class WithheldRead : DispatchProxy
    {
        internal TaskCompletionSource<NatsKVEntry<string>> Read { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override object? Invoke(MethodInfo? method, object?[]? args) => method!.Name == nameof(INatsKVStore.GetEntryAsync)
            ? new ValueTask<NatsKVEntry<string>>(Read.Task)
            : throw new NotSupportedException(method.Name);
    }
}
