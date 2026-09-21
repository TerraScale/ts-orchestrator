using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using NATS.Client.Core;
using NATS.Client.KeyValueStore;
using NATS.Net;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

[NotInParallel(LocalNatsServerLease.SchedulingConstraint)]
public sealed class RegionalHostDesiredTests
{
    private static readonly string Digest = "sha256:" + new string('a', 64);

    [Test]
    [Arguments("epoch")]
    [Arguments("session")]
    [Arguments("nonce")]
    [Arguments("role")]
    [Arguments("time")]
    [Arguments("signature")]
    [Arguments("environment")]
    [Arguments("node")]
    [Arguments("generation")]
    public async Task Desired_proof_binds_each_identity_scope_and_freshness_field(string mutation)
    {
        using var material = new SessionMaterial();
        var now = material.Clock.GetUtcNow();
        var request = RegionalHostDesiredRequest.Sign(material.Enroll(1), material.Authentication, new string('a', 32), 1,
            AdmittedRole.TerraBaseMember, now);
        await Assert.That(request.HasValidProof("gru", now)).IsTrue();
        var document = JsonNode.Parse(request.Serialize())!;
        switch (mutation)
        {
            case "epoch": document["Epoch"] = 2; break;
            case "session": document["SessionId"] = new string('b', 32); break;
            case "nonce": document["RequestId"] = new string('c', 32); break;
            case "role": document["Role"] = (int)AdmittedRole.Authentication; break;
            case "time": document["IssuedAt"] = now.AddTicks(-1); break;
            case "signature": document["Signature"] = Convert.ToBase64String(new byte[64]); break;
            case "environment": document["Enrollment"]!["Scope"]!["Environment"] = "development"; break;
            case "node": document["Enrollment"]!["NodeId"] = "host-2"; break;
            case "generation": document["Enrollment"]!["BootstrapGeneration"] = 2; break;
        }
        var changed = JsonSerializer.Deserialize<RegionalHostDesiredRequest>(document.ToJsonString(), RegionalHostSessionAuthority.JsonOptions)!;
        await Assert.That(changed.HasValidProof("gru", now)).IsFalse();
    }

    [Test]
    public async Task Desired_wire_rejects_unknown_missing_duplicate_fields_wrong_subjects_and_other_operation_signatures()
    {
        using var material = new SessionMaterial();
        var enrollment = material.Enroll(1);
        var now = material.Clock.GetUtcNow();
        var request = RegionalHostDesiredRequest.Sign(enrollment, material.Authentication, new string('a', 32), 1,
            AdmittedRole.TerraBaseMember, now);
        var subject = RegionalHostDesiredRequest.Subject("gru", enrollment.NodeId);
        var reply = RegionalHostDesiredRequest.ReplySubject("gru", enrollment.NodeId, request.RequestId);
        bool Reads(string json, string requestSubject, string responseSubject, DateTimeOffset time) =>
            RegionalHostDesiredRequest.TryRead(json, requestSubject, responseSubject, "gru", time, out _);
        await Assert.That(Reads(request.Serialize(), subject, reply, now)).IsTrue();
        foreach (var json in new[] { "{\"Unknown\":true," + request.Serialize()[1..], "{\"Epoch\":1," + request.Serialize()[1..],
                     request.Serialize().Replace("\"Epoch\":1,", "", StringComparison.Ordinal), new string(' ', 16_385),
                     material.Request(enrollment).Serialize() })
            await Assert.That(Reads(json, subject, reply, now)).IsFalse();
        foreach (var invalidReply in new[] { "_INBOX.1", RegionalHostDesiredRequest.ReplySubject("gru", "host-2", request.RequestId),
                     RegionalHostDesiredRequest.ReplySubject("fra", enrollment.NodeId, request.RequestId) })
            await Assert.That(Reads(request.Serialize(), subject, invalidReply, now)).IsFalse();
        await Assert.That(Reads(request.Serialize(), RegionalHostDesiredRequest.Subject("gru", "host-2"), reply, now)).IsFalse();
        await Assert.That(Reads(request.Serialize(), subject, reply, now.AddTicks(-1))).IsFalse();
        await Assert.That(Reads(request.Serialize(), subject, reply, now.AddSeconds(10))).IsFalse();
        var wrongDomain = new RegionalHostDesiredRequest(1, enrollment, request.SessionId, 1, request.Role,
            request.RequestId, now, material.Request(enrollment).Signature);
        await Assert.That(wrongDomain.HasValidProof("gru", now)).IsFalse();
        await Assert.That(() => RegionalHostDesiredRequest.Sign(enrollment, material.Authentication, request.SessionId, 1,
            AdmittedRole.Authentication, now)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Responses_bind_exact_request_epoch_generation_digest_presence_and_expiry()
    {
        using var material = new SessionMaterial();
        var now = material.Clock.GetUtcNow();
        var request = RegionalHostDesiredRequest.Sign(material.Enroll(1), material.Authentication, new string('a', 32), 1,
            AdmittedRole.TerraBaseMember, now);
        var valid = new RegionalHostDesiredResponse(1, request.RequestId, request.RequestDigest,
            RegionalHostSessionDecision.Accepted, 1, 1, now.AddSeconds(10), Digest, 1);
        valid.RequireBinding(request, now);
        (valid with { ArtifactDigest = null, Revision = 0 }).RequireBinding(request, now);
        foreach (var changed in new[] { valid with { RequestId = new string('b', 32) }, valid with { RequestDigest = new string('c', 64) },
                     valid with { Generation = 2 }, valid with { Epoch = 2 }, valid with { ExpiresAt = now },
                     valid with { ExpiresAt = now.AddSeconds(11) }, valid with { ArtifactDigest = null },
                     valid with { Revision = 0 }, valid with { ArtifactDigest = Digest.ToUpperInvariant() },
                     valid with { Decision = RegionalHostSessionDecision.Revoked }, valid with { Decision = (RegionalHostSessionDecision)999 } })
            await Assert.That(() => changed.RequireBinding(request, now)).Throws<InvalidDataException>();
    }

    [Test]
    public async Task Restricted_R3_hosts_select_separate_roles_and_environments_without_private_store_access()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var store = await Store(harness, deadline.Token);
        await using var service = await RegionalHostDesiredService.StartAsync(harness.Controller.Connection,
            new(store, harness.Authority), deadline.Token);
        await Put(store, harness.First.Artifact, "production", Digest, deadline.Token);
        await Put(store, harness.First.Artifact, "development", "sha256:" + new string('b', 64), deadline.Token);
        var first = Source(harness, harness.First);
        var second = Source(harness, harness.Second);
        await Assert.That(await first.ReadAsync(harness.First.Role, "production", "gru", deadline.Token)).IsEqualTo(Digest);
        await Assert.That(await second.ReadAsync(harness.Second.Role, "production", "gru", deadline.Token)).IsNull();
        await Put(store, harness.Second.Artifact, "production", "sha256:" + new string('c', 64), deadline.Token);
        await Assert.That(await second.ReadAsync(harness.Second.Role, "production", "gru", deadline.Token)).IsEqualTo("sha256:" + new string('c', 64));
        await Assert.That(() => first.ReadAsync(harness.First.Role, "development", "gru", deadline.Token)).Throws<InvalidOperationException>();
        await Assert.That(() => first.ReadAsync(harness.First.Role, "production", "fra", deadline.Token)).Throws<InvalidOperationException>();
        await Assert.That(() => first.ReadAsync(harness.Second.Role, "production", "gru", deadline.Token)).Throws<InvalidOperationException>();
        await Assert.That(async () => _ = await first.SendAsync(harness.Second.Signer.SignDesired(harness.Second.Role), deadline.Token)).Throws<InvalidOperationException>();
        foreach (var bucket in new[] { "ORCH_DELIVERY", "ORCH_RUNTIME", "ORCH_NODE_ENROLLMENTS" })
        {
            await using var probe = await harness.Cluster.ConnectAsync(harness.Cluster.HostAgent, cancellationToken: deadline.Token);
            await Assert.That(async () => _ = await probe.CreateJetStreamContext().CreateKeyValueStoreContext()
                .GetStoreAsync(bucket, deadline.Token)).Throws<NatsException>();
        }
        await using (var probe = await harness.Cluster.ConnectAsync(harness.Cluster.HostAgent, cancellationToken: deadline.Token))
            await Assert.That(async () => _ = await probe.CreateJetStreamContext().CreateObjectStoreContext()
                .GetObjectStoreAsync("ORCH_ARTIFACTS", cancellationToken: deadline.Token)).Throws<NatsException>();
        await store.DeleteAsync(DirectDeliveryTargetKey.For(harness.First.Artifact, "production", "gru"), cancellationToken: deadline.Token);
        await Assert.That(await first.ReadAsync(harness.First.Role, "production", "gru", deadline.Token)).IsNull();
        await Assert.That(await harness.Authority.RevokeAsync(harness.First.Node, 1, harness.First.Lease.Epoch, deadline.Token)).IsTrue();
        var denied = await first.SendAsync(harness.First.Signer.SignDesired(harness.First.Role), deadline.Token);
        await Assert.That(denied.Decision).IsEqualTo(RegionalHostSessionDecision.Revoked);
        await Assert.That(service.Snapshot.Absent).IsEqualTo(2);
    }

    [Test]
    public async Task Convergence_consumes_the_restricted_source_and_keeps_execution_behind_admission()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token, realTime: true);
        var store = await Store(harness, deadline.Token);
        await using var service = await RegionalHostDesiredService.StartAsync(harness.Controller.Connection, new(store, harness.Authority), deadline.Token);
        var host = harness.First;
        await Put(store, host.Artifact, "production", Digest, deadline.Token);
        // Every unused execution/storage seam is absent: this pass must reach only signed selection and reports.
        await using var runtime = HostConvergenceRuntime.Create(new TestHostCycleCoordinator(), Source(harness, host), null!, host.Publisher, null!, null!,
            new([host.Role], "production", Path.Combine(harness.Cluster.DirectoryPath, "artifacts"), HostArchitecture.X64),
            "gru", host.Node, admission: new BlockedAdmission());
        await runtime.ReconcileOnceAsync(host.Role, AdmittedRoleCatalog.Get(host.Role), deadline.Token);
        var observed = await harness.Reader.ReadAsync($"host.{host.Node}.{host.Artifact}", deadline.Token);
        await Assert.That(observed?.Runtime?.Digest).IsEqualTo(Digest);
        await Assert.That(observed?.Runtime?.State).IsEqualTo("blocked-admission");
        await harness.Authority.RevokeAsync(host.Node, 1, host.Lease.Epoch, deadline.Token);
        await Assert.That(() => runtime.ReconcileOnceAsync(host.Role, AdmittedRoleCatalog.Get(host.Role), deadline.Token)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Malformed_desired_and_unavailable_store_are_failures_and_one_host_cannot_clear_another_failure()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var store = await Store(harness, deadline.Token);
        var proxy = DispatchProxy.Create<INatsKVStore, DesiredStore>();
        var fault = (DesiredStore)proxy;
        fault.Inner = store;
        await using var service = await RegionalHostDesiredService.StartAsync(harness.Controller.Connection, new(proxy, harness.Authority), deadline.Token);
        var first = Source(harness, harness.First);
        var key = DirectDeliveryTargetKey.For(harness.First.Artifact, "production", "gru");
        foreach (var json in new[] { "{}", "null", "{\"artifactDigest\":\"invalid\",\"manifestDigest\":\"invalid\",\"kind\":\"service\"}",
                     JsonSerializer.Serialize(new { artifactDigest = Digest, kind = "service" }),
                     JsonSerializer.Serialize(new { artifactDigest = Digest, manifestDigest = Digest, kind = "unknown" }),
                     "{\"extra\":true," + Target(Digest)[1..], "{\"kind\":\"service\"," + Target(Digest)[1..] })
        {
            await store.PutAsync(key, json, cancellationToken: deadline.Token);
            await Assert.That((await first.SendAsync(harness.First.Signer.SignDesired(harness.First.Role), deadline.Token)).Decision)
                .IsEqualTo(RegionalHostSessionDecision.InvalidStore);
        }
        await Assert.That(await Source(harness, harness.Second).ReadAsync(harness.Second.Role, "production", "gru", deadline.Token)).IsNull();
        await Assert.That(service.Snapshot.RetryPending).IsTrue();
        fault.Fail = true;
        await Assert.That((await first.SendAsync(harness.First.Signer.SignDesired(harness.First.Role), deadline.Token)).Decision)
            .IsEqualTo(RegionalHostSessionDecision.StoreUnavailable);
        fault.Fail = false;
        await store.PutAsync(key, Target(Digest), cancellationToken: deadline.Token);
        await Assert.That(await first.ReadAsync(harness.First.Role, "production", "gru", deadline.Token)).IsEqualTo(Digest);
        await WaitUntil(() => !service.Snapshot.RetryPending, deadline.Token);
    }

    [Test]
    public async Task Stale_positive_desired_reads_cannot_resurrect_deleted_or_replaced_targets_and_sessions()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var store = await Store(harness, deadline.Token);
        var key = DirectDeliveryTargetKey.For(harness.First.Artifact, "production", "gru");
        await Put(store, harness.First.Artifact, "production", Digest, deadline.Token);
        var stale = await store.GetEntryAsync<string>(key, cancellationToken: deadline.Token);
        var proxy = DispatchProxy.Create<INatsKVStore, RegionalHostReportAuthorizationTests.StaleReplica>();
        var intercepted = (RegionalHostReportAuthorizationTests.StaleReplica)proxy;
        intercepted.Inner = store;
        intercepted.Entry = stale;
        intercepted.RemainingStaleReads = 2;
        var authority = new RegionalHostDesiredAuthority(proxy, harness.Authority);
        await store.DeleteAsync(key, cancellationToken: deadline.Token);
        await Assert.That((await authority.ReadAsync(harness.First.Signer.SignDesired(harness.First.Role), deadline.Token)).ArtifactDigest).IsNull();
        await Assert.That(intercepted.Confirmations).IsEqualTo(2);
        var replacement = "sha256:" + new string('d', 64);
        await Put(store, harness.First.Artifact, "production", replacement, deadline.Token);
        intercepted.RemainingStaleReads = 2;
        await Assert.That((await authority.ReadAsync(harness.First.Signer.SignDesired(harness.First.Role), deadline.Token)).ArtifactDigest).IsEqualTo(replacement);
        intercepted.RemainingStaleReads = 8;
        await Assert.That((await authority.ReadAsync(harness.First.Signer.SignDesired(harness.First.Role), deadline.Token)).Decision)
            .IsEqualTo(RegionalHostSessionDecision.Contention);

        var sessionProxy = DispatchProxy.Create<INatsKVStore, RegionalHostReportAuthorizationTests.StaleReplica>();
        var sessionStale = (RegionalHostReportAuthorizationTests.StaleReplica)sessionProxy;
        sessionStale.Inner = harness.Sessions;
        sessionStale.Entry = await harness.Sessions.GetEntryAsync<string>(RegionalHostSessionAuthority.Key(harness.First.Node), cancellationToken: deadline.Token);
        sessionStale.RemainingStaleReads = 2;
        await harness.Authority.RevokeAsync(harness.First.Node, 1, harness.First.Lease.Epoch, deadline.Token);
        var sessions = new RegionalHostSessionAuthority(sessionProxy, harness.Material.Policy(), harness.Material.Clock);
        await Assert.That((await new RegionalHostDesiredAuthority(store, sessions).ReadAsync(harness.First.Signer.SignDesired(harness.First.Role), deadline.Token)).Decision)
            .IsEqualTo(RegionalHostSessionDecision.Revoked);
        await Assert.That(sessionStale.Confirmations).IsEqualTo(2);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Stalled_store_is_bounded_preserves_renewals_and_does_not_accumulate_abandoned_operations(bool synchronous)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var store = await Store(harness, deadline.Token);
        await Put(store, harness.First.Artifact, "production", Digest, deadline.Token);
        var proxy = DispatchProxy.Create<INatsKVStore, DesiredStore>();
        var fault = (DesiredStore)proxy;
        fault.Inner = store;
        fault.Hold = true;
        fault.Synchronous = synchronous;
        var service = await RegionalHostDesiredService.StartAsync(harness.Controller.Connection, new(proxy, harness.Authority), deadline.Token);
        try
        {
            var source = Source(harness, harness.First);
            for (var index = 0; index < 3; index++)
                await Assert.That((await source.SendAsync(harness.First.Signer.SignDesired(harness.First.Role), deadline.Token)).Decision)
                    .IsEqualTo(RegionalHostSessionDecision.StoreUnavailable);
            await Assert.That(fault.Reads).IsEqualTo(1);
            await Assert.That(service.Snapshot.InFlight).IsTrue();
            harness.Material.Clock.Advance(TimeSpan.FromSeconds(1));
            var renewal = harness.Material.Request(harness.First.Request.Enrollment, harness.First.Request.SessionId, harness.First.Lease.Epoch);
            await Assert.That((await new NatsRegionalHostSessionClient(harness.First.Client.Connection, "gru", harness.First.Node)
                .SendAsync(renewal, deadline.Token)).Accepted).IsTrue();
            await Assert.That(service.Snapshot.RetryPending).IsTrue();
        }
        finally
        {
            try { await service.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(2)); }
            finally
            {
                fault.Release.TrySetResult(await store.GetEntryAsync<string>(DirectDeliveryTargetKey.For(harness.First.Artifact, "production", "gru"), cancellationToken: deadline.Token));
            }
        }
    }

    [Test]
    public async Task Host_transport_rejects_wrong_expired_malformed_and_cancelled_replies()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var host = harness.First;
        await using var requests = await harness.Controller.Connection.SubscribeCoreAsync<string>(
            RegionalHostDesiredRequest.Subject("gru", host.Node), cancellationToken: deadline.Token);
        await harness.Controller.Connection.PingAsync(deadline.Token);
        foreach (var mutation in new[] { "nonce", "expiry", "unknown", "cancel" })
        {
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
            var request = host.Signer.SignDesired(host.Role);
            var pending = Source(harness, host).SendAsync(request, cancellation.Token);
            var incoming = await requests.Msgs.ReadAsync(deadline.Token);
            var response = new RegionalHostDesiredResponse(1, request.RequestId, request.RequestDigest, RegionalHostSessionDecision.Accepted,
                1, host.Lease.Epoch, harness.Material.Clock.GetUtcNow().AddSeconds(10), Digest, 1);
            if (mutation == "nonce") response = response with { RequestId = new string('b', 32) };
            if (mutation == "expiry") response = response with { ExpiresAt = harness.Material.Clock.GetUtcNow() };
            if (mutation == "cancel") cancellation.Cancel();
            var json = JsonSerializer.Serialize(response, RegionalHostSessionAuthority.JsonOptions);
            if (mutation == "unknown") json = "{\"unknown\":true," + json[1..];
            await harness.Controller.Connection.PublishAsync(incoming.ReplyTo!, json, cancellationToken: deadline.Token);
            if (mutation == "cancel") await Assert.That(async () => _ = await pending).Throws<OperationCanceledException>();
            else if (mutation == "unknown") await Assert.That(async () => _ = await pending).Throws<JsonException>();
            else await Assert.That(async () => _ = await pending).Throws<InvalidDataException>();
        }
    }

    [Test]
    public async Task Revocation_during_desired_read_prevents_release_of_data()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var store = await Store(harness, deadline.Token);
        await Put(store, harness.First.Artifact, "production", Digest, deadline.Token);
        var proxy = DispatchProxy.Create<INatsKVStore, DesiredStore>();
        var fault = (DesiredStore)proxy;
        fault.Inner = store;
        fault.Hold = true;
        var read = new RegionalHostDesiredAuthority(proxy, harness.Authority).ReadAsync(harness.First.Signer.SignDesired(harness.First.Role), deadline.Token);
        await fault.Entered.Task.WaitAsync(deadline.Token);
        await harness.Authority.RevokeAsync(harness.First.Node, 1, harness.First.Lease.Epoch, deadline.Token);
        fault.Release.TrySetResult(await store.GetEntryAsync<string>(DirectDeliveryTargetKey.For(harness.First.Artifact, "production", "gru"), cancellationToken: deadline.Token));
        var response = await read;
        await Assert.That(response.Decision).IsEqualTo(RegionalHostSessionDecision.Revoked);
        await Assert.That(response.ArtifactDigest).IsNull();
    }

    private static NatsHostDesiredArtifactSource Source(SignedHostReportHarness harness, SignedHostReportHarness.ReportHost host) =>
        new(host.Client.Connection, "gru", host.Node, () => host.Signer, harness.Material.Clock);
    private static ValueTask<INatsKVStore> Store(SignedHostReportHarness harness, CancellationToken token) =>
        harness.Controller.CreateJetStreamContext().CreateKeyValueStoreContext().GetStoreAsync("ORCH_DELIVERY", token);
    private static string Target(string digest) => JsonSerializer.Serialize(new { artifactDigest = digest, manifestDigest = digest, kind = "service" });
    private static async Task Put(INatsKVStore store, string artifact, string environment, string digest, CancellationToken token) =>
        _ = await store.PutAsync(DirectDeliveryTargetKey.For(artifact, environment, "gru"), Target(digest), cancellationToken: token);
    private static async Task WaitUntil(Func<bool> check, CancellationToken token)
    {
        while (!check()) await Task.Delay(10, token);
    }

    private sealed class BlockedAdmission : IHostAdmissionGate
    {
        public ValueTask<HostAdmissionSnapshot> ObserveAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(new HostAdmissionSnapshot(false, false, "awaiting-material"));
    }

    public class DesiredStore : DispatchProxy
    {
        internal INatsKVStore Inner { get; set; } = null!;
        internal bool Fail { get; set; }
        internal bool Hold { get; set; }
        internal bool Synchronous { get; set; }
        internal int Reads;
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource<NatsKVEntry<string>> Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override object? Invoke(MethodInfo? method, object?[]? args)
        {
            if (method!.Name == nameof(INatsKVStore.GetEntryAsync))
            {
                Interlocked.Increment(ref Reads);
                Entered.TrySetResult();
                if (Fail) throw new IOException("Injected unavailable desired storage.");
                if (Hold) return Synchronous ? ValueTask.FromResult(Release.Task.GetAwaiter().GetResult()) : new ValueTask<NatsKVEntry<string>>(Release.Task);
            }
            try { return method.Invoke(Inner, args); }
            catch (TargetInvocationException exception) when (exception.InnerException is { } inner)
            { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(inner).Throw(); throw; }
        }
    }
}
