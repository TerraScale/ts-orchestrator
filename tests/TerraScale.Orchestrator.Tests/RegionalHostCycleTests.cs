using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using NATS.Client.Core;
using NATS.Client.JetStream.Models;
using NATS.Client.KeyValueStore;
using NATS.Net;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

[NotInParallel("NatsR3")]
public sealed class RegionalHostCycleTests
{
    private static readonly string Digest = "sha256:" + new string('a', 64);
    private static readonly string OtherDigest = "sha256:" + new string('b', 64);

    [Test]
    [Arguments("Role")]
    [Arguments("ArtifactDigest")]
    [Arguments("Operation")]
    [Arguments("AttemptId")]
    [Arguments("CycleId")]
    [Arguments("Fence")]
    [Arguments("Epoch")]
    [Arguments("SessionId")]
    [Arguments("RequestId")]
    [Arguments("IssuedAt")]
    [Arguments("Signature")]
    [Arguments("Enrollment")]
    public async Task Cycle_proof_binds_every_operation_identity_scope_and_time_field(string changed)
    {
        using var material = new SessionMaterial();
        var request = RegionalHostCycleRequest.Sign(material.Enroll(1), material.Authentication, new string('a', 32), 1,
            AdmittedRole.TerraBaseMember, Digest, RegionalHostCycleOperation.Fail, new string('b', 32), new string('c', 32), 1,
            material.Clock.GetUtcNow());
        await Assert.That(request.HasValidProof("gru", material.Clock.GetUtcNow())).IsTrue();
        var json = JsonNode.Parse(request.Serialize())!;
        switch (changed)
        {
            case "Role": json[changed] = (int)AdmittedRole.Authentication; break;
            case "ArtifactDigest": json[changed] = OtherDigest; break;
            case "Operation": json[changed] = (int)RegionalHostCycleOperation.Complete; break;
            case "Fence": case "Epoch": json[changed] = 2; break;
            case "IssuedAt": json[changed] = request.IssuedAt.AddTicks(-1); break;
            case "Signature": json[changed] = Convert.ToBase64String(new byte[64]); break;
            case "Enrollment": json[changed]!["Scope"]!["Environment"] = "development"; break;
            default: json[changed] = new string('f', 32); break;
        }
        await Assert.That(RegionalHostCycleRequest.TryRead(json.ToJsonString(), RegionalHostCycleRequest.Subject("gru", request.Enrollment.NodeId),
            RegionalHostCycleRequest.ReplySubject("gru", request.Enrollment.NodeId, request.RequestId), "gru", material.Clock.GetUtcNow(), out _)).IsFalse();
    }

    [Test]
    public async Task Cycle_storage_requires_bounded_non_expiring_R3_and_backoff_saturates_without_overflow()
    {
        var canonical = NatsOperationJournalStore.CanonicalKeyValueStream(new NatsTopology("gru", 3).Delivery);
        RegionalHostCycleAuthority.ValidateStoreConfiguration(canonical);
        foreach (var invalid in new[] { canonical with { Name = "KV_ORCH_RUNTIME" }, canonical with { MaxAge = TimeSpan.FromMinutes(5) },
                     canonical with { NumReplicas = 1 }, canonical with { MaxMsgs = 1 }, canonical with { MaxMsgsPerSubject = 1 },
                     canonical with { Discard = StreamConfigDiscard.Old }, canonical with { AllowMsgTTL = true },
                     canonical with { MaxBytes = -1 }, canonical with { NoAck = true }, canonical with { MaxMsgSize = -1 },
                     canonical with { Storage = StreamConfigStorage.Memory }, canonical with { Retention = StreamConfigRetention.Workqueue },
                     canonical with { SubjectDeleteMarkerTTL = TimeSpan.FromSeconds(1) } })
            await Assert.That(() => RegionalHostCycleAuthority.ValidateStoreConfiguration(invalid)).Throws<InvalidDataException>();
        await Assert.That(Enumerable.Range(1, 8).Select(value => RegionalHostCycleAuthority.Backoff(value).TotalSeconds).ToArray())
            .IsEquivalentTo(new double[] { 30, 60, 120, 240, 480, 900, 900, 900 });
        await Assert.That(RegionalHostCycleAuthority.Backoff(int.MinValue)).IsEqualTo(TimeSpan.FromSeconds(30));
        await Assert.That(RegionalHostCycleAuthority.Backoff(int.MaxValue)).IsEqualTo(TimeSpan.FromSeconds(900));
    }

    [Test]
    public async Task Responses_reject_misbound_expired_and_inconsistent_cycle_receipts()
    {
        using var material = new SessionMaterial();
        var now = material.Clock.GetUtcNow();
        var begin = RegionalHostCycleRequest.Sign(material.Enroll(1), material.Authentication, new string('a', 32), 1,
            AdmittedRole.TerraBaseMember, Digest, RegionalHostCycleOperation.Begin, new string('b', 32), null, 0, now);
        var active = new RegionalHostCycleResponse(1, begin.RequestId, begin.RequestDigest, RegionalHostSessionDecision.Accepted,
            1, 1, now.AddSeconds(10), RegionalHostCycleDisposition.Active, new string('c', 32), 1, 0, null, null);
        active.RequireBinding(begin, now);
        var failed = active with { Disposition = RegionalHostCycleDisposition.Settled, Succeeded = false, Failures = 1, NotBefore = now.AddSeconds(30) };
        failed.RequireBinding(begin, now);
        (failed with { Disposition = RegionalHostCycleDisposition.Backoff, Succeeded = null }).RequireBinding(begin, now);
        (active with { Disposition = RegionalHostCycleDisposition.Busy }).RequireBinding(begin, now);
        (active with { Disposition = RegionalHostCycleDisposition.Settled, Succeeded = true }).RequireBinding(begin, now);
        foreach (var malformed in new[] {
            active with { RequestId = new string('f', 32) }, active with { RequestDigest = new string('f', 64) },
            active with { Generation = 2 }, active with { Epoch = 2 }, active with { SchemaVersion = 2 },
            active with { Decision = (RegionalHostSessionDecision)999 }, active with { Disposition = (RegionalHostCycleDisposition)999 },
            active with { ExpiresAt = now }, active with { ExpiresAt = now.AddMinutes(1) },
            active with { ExpiresAt = now.AddSeconds(10).ToOffset(TimeSpan.FromHours(1)) },
            active with { Fence = 0 }, active with { CycleId = new string('G', 32) }, active with { Failures = 7 },
            active with { Succeeded = true }, active with { NotBefore = now },
            active with { Disposition = RegionalHostCycleDisposition.Busy, Succeeded = false },
            active with { Disposition = RegionalHostCycleDisposition.Backoff, Failures = 1 },
            failed with { Disposition = RegionalHostCycleDisposition.Backoff }, failed with { Failures = 0 },
            failed with { NotBefore = null }, failed with { Succeeded = true }, failed with { Succeeded = null },
            failed with { NotBefore = now.AddHours(1) }, failed with { NotBefore = now.ToOffset(TimeSpan.FromHours(1)) },
            active with { Decision = RegionalHostSessionDecision.EnrollmentDenied } })
            await Assert.That(() => malformed.RequireBinding(begin, now)).Throws<InvalidDataException>();

        var outcome = RegionalHostCycleRequest.Sign(begin.Enrollment, material.Authentication, begin.SessionId, begin.Epoch,
            begin.Role, Digest, RegionalHostCycleOperation.Fail, begin.AttemptId, active.CycleId, active.Fence, now);
        var settled = failed with { RequestId = outcome.RequestId, RequestDigest = outcome.RequestDigest };
        settled.RequireBinding(outcome, now);
        foreach (var malformed in new[] { settled with { CycleId = new string('d', 32) }, settled with { Fence = 2 },
            settled with { Disposition = RegionalHostCycleDisposition.Backoff, Succeeded = null },
            settled with { Succeeded = true, Failures = 0, NotBefore = null } })
            await Assert.That(() => malformed.RequireBinding(outcome, now)).Throws<InvalidDataException>();
    }

    [Test]
    public async Task Restricted_client_rejects_malformed_and_misbound_controller_wire_responses()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        await using var subscription = await harness.Controller.Connection.SubscribeCoreAsync<string>(
            RegionalHostCycleRequest.Subject("gru", harness.First.Node), cancellationToken: deadline.Token);
        await harness.Controller.Connection.PingAsync(deadline.Token);
        var source = Source(harness, harness.First);
        foreach (var failure in new[] { "oversized", "malformed", "unknown-field", "misbound", "expired", "denied-receipt" })
        {
            var request = Begin(harness.First);
            var pending = source.SendAsync(request, deadline.Token);
            var message = await subscription.Msgs.ReadAsync(deadline.Token);
            var response = RegionalHostCycleResponse.Deny(request, RegionalHostSessionDecision.StoreUnavailable);
            var json = failure switch
            {
                "oversized" => new string('x', 4097),
                "malformed" => "not-json",
                "unknown-field" => request.Serialize(),
                "misbound" => JsonSerializer.Serialize(response with { RequestId = new string('f', 32) }, RegionalHostSessionAuthority.JsonOptions),
                "expired" => JsonSerializer.Serialize(response with { Decision = RegionalHostSessionDecision.Accepted,
                    Disposition = RegionalHostCycleDisposition.Active, CycleId = new string('c', 32), Fence = 1,
                    ExpiresAt = harness.Material.Clock.GetUtcNow() }, RegionalHostSessionAuthority.JsonOptions),
                _ => JsonSerializer.Serialize(response with { Fence = 1 }, RegionalHostSessionAuthority.JsonOptions)
            };
            await harness.Controller.Connection.PublishAsync(message.ReplyTo!, json, cancellationToken: deadline.Token);
            if (failure is "malformed" or "unknown-field")
                await Assert.That(async () => _ = await pending).Throws<JsonException>();
            else await Assert.That(async () => _ = await pending).Throws<InvalidDataException>();
        }
    }

    [Test]
    public async Task R3_controller_races_outcome_replays_and_new_targets_preserve_one_cycle_and_fence_old_results()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var store = await Store(harness, deadline.Token);
        await Put(store, harness.First, Digest, deadline.Token);
        var authority = new RegionalHostCycleAuthority(store, harness.Authority);
        await using var peer = await harness.Cluster.ConnectAsync(harness.Cluster.ControllerTwo, member: 1, cancellationToken: deadline.Token);
        var second = new RegionalHostCycleAuthority(await peer.CreateJetStreamContext().CreateKeyValueStoreContext()
            .GetStoreAsync("ORCH_DELIVERY", deadline.Token), harness.Authority);
        var begin = Begin(harness.First);
        var results = await Task.WhenAll(authority.ProcessAsync(begin, deadline.Token), second.ProcessAsync(begin, deadline.Token));
        foreach (var result in results) { result.RequireBinding(begin, harness.Material.Clock.GetUtcNow()); await Assert.That(result.Accepted).IsTrue(); }
        await Assert.That(results[0].CycleId).IsEqualTo(results[1].CycleId);
        await Assert.That(results[0].Fence).IsEqualTo(1UL);
        var busyRequest = Begin(harness.First);
        var busy = await second.ProcessAsync(busyRequest, deadline.Token);
        busy.RequireBinding(busyRequest, harness.Material.Clock.GetUtcNow());
        await Assert.That(busy.Disposition).IsEqualTo(RegionalHostCycleDisposition.Busy);
        var fail = Outcome(harness.First, begin, results[0], false);
        var failed = await authority.ProcessAsync(fail, deadline.Token);
        failed.RequireBinding(fail, harness.Material.Clock.GetUtcNow());
        await Assert.That(failed.Failures).IsEqualTo(1);
        harness.Material.Clock.Advance(TimeSpan.FromSeconds(1));
        var retry = await second.ProcessAsync(Outcome(harness.First, begin, results[0], false), deadline.Token);
        await Assert.That(retry.NotBefore).IsEqualTo(failed.NotBefore);
        await Assert.That(retry.Failures).IsEqualTo(1);
        await Assert.That((await authority.ProcessAsync(Outcome(harness.First, begin, results[0], true), deadline.Token)).Accepted).IsFalse();
        await Assert.That((await authority.ProcessAsync(Begin(harness.First), deadline.Token)).Disposition).IsEqualTo(RegionalHostCycleDisposition.Backoff);
        await Put(store, harness.First, OtherDigest, deadline.Token);
        var newer = Begin(harness.First, OtherDigest);
        var next = await second.ProcessAsync(newer, deadline.Token);
        await Assert.That(next.Disposition).IsEqualTo(RegionalHostCycleDisposition.Active);
        await Assert.That(next.Fence).IsEqualTo(2UL);
        await Assert.That(next.Failures).IsEqualTo(0);
        await Assert.That((await authority.ProcessAsync(Outcome(harness.First, begin, results[0], false), deadline.Token)).Accepted).IsFalse();
        var success = await second.ProcessAsync(Outcome(harness.First, newer, next, true), deadline.Token);
        await Assert.That(success.Succeeded).IsTrue();
        await Assert.That((await authority.ProcessAsync(newer, deadline.Token)).Disposition).IsEqualTo(RegionalHostCycleDisposition.Settled);
        await Assert.That((await Read(store, harness.First, deadline.Token)).Fence).IsEqualTo(2UL);
    }

    [Test]
    public async Task Restricted_hosts_keep_auth_and_terrabase_cycles_independent_across_service_restart()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var store = await Store(harness, deadline.Token);
        foreach (var host in new[] { harness.First, harness.Second }) await Put(store, host, Digest, deadline.Token);
        var one = Source(harness, harness.First);
        var two = Source(harness, harness.Second);
        HostConvergenceCycle? cycle;
        await using (var service = await RegionalHostCycleService.StartAsync(harness.Controller.Connection, new(store, harness.Authority), deadline.Token))
        {
            cycle = await one.BeginAsync(harness.First.Role, "production", "gru", Digest, deadline.Token);
            await Assert.That(cycle).IsNotNull();
            await Assert.That(await one.BeginAsync(harness.First.Role, "production", "gru", Digest, deadline.Token)).IsNull();
            await one.FinishAsync(cycle!, false, deadline.Token);
            await Assert.That(await one.BeginAsync(harness.First.Role, "production", "gru", Digest, deadline.Token)).IsNull();
            var independent = await two.BeginAsync(harness.Second.Role, "production", "gru", Digest, deadline.Token);
            await Assert.That(independent).IsNotNull();
            await two.FinishAsync(independent!, true, deadline.Token);
            await Assert.That(async () => _ = await one.BeginAsync(harness.Second.Role, "production", "gru", Digest, deadline.Token))
                .Throws<InvalidOperationException>();
            await Assert.That(async () => _ = await one.BeginAsync(harness.First.Role, "development", "gru", Digest, deadline.Token))
                .Throws<InvalidOperationException>();
            await Assert.That(async () => _ = await one.SendAsync(Begin(harness.Second), deadline.Token)).Throws<InvalidOperationException>();
            while (service.Snapshot.Settled != 2) await Task.Delay(5, deadline.Token);
            await Assert.That(service.Snapshot.Backoff).IsEqualTo(1L);
        }
        await using var restarted = await RegionalHostCycleService.StartAsync(harness.Controller.Connection, new(store, harness.Authority), deadline.Token);
        await Assert.That(await Source(harness, harness.First).BeginAsync(harness.First.Role, "production", "gru", Digest, deadline.Token)).IsNull();
        await Assert.That((await Read(store, harness.First, deadline.Token)).Failures).IsEqualTo(1);
        await using var probe = await harness.Cluster.ConnectAsync(harness.Cluster.HostAgent, cancellationToken: deadline.Token);
        await Assert.That(async () => _ = await probe.CreateJetStreamContext().CreateKeyValueStoreContext()
            .GetStoreAsync("ORCH_DELIVERY", deadline.Token)).Throws<NatsException>();
    }

    [Test]
    public async Task Success_for_another_role_on_the_same_host_cannot_hide_pending_storage_failure()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var store = await Store(harness, deadline.Token);
        foreach (var host in new[] { harness.First, harness.Second }) await Put(store, host, Digest, deadline.Token);
        harness.Material.Clock.Advance(TimeSpan.FromSeconds(31));
        var enrollment = harness.Material.Enroll(2, authentication: harness.First.Authentication,
            scope: new("production", [AdmittedRole.TerraBaseMember, AdmittedRole.Authentication]), node: harness.First.Node);
        var acquire = harness.Material.Request(enrollment, authentication: harness.First.Authentication);
        var lease = await new NatsRegionalHostSessionClient(harness.First.Client.Connection, "gru", harness.First.Node).SendAsync(acquire, deadline.Token);
        await Assert.That(lease.Accepted).IsTrue();
        var signer = new RegionalHostSessionSigner(acquire, lease, harness.First.Authentication, harness.Material.Clock);
        var client = new NatsHostCycleCoordinator(harness.First.Client.Connection, "gru", harness.First.Node, () => signer, harness.Material.Clock);
        var proxy = DispatchProxy.Create<INatsKVStore, CycleStore>();
        var intercepted = (CycleStore)proxy;
        intercepted.Inner = store;
        intercepted.UnavailableKey = Key(harness.First);
        await using var service = await RegionalHostCycleService.StartAsync(harness.Controller.Connection, new(proxy, harness.Authority), deadline.Token);
        await Assert.That((await client.SendAsync(signer.SignCycle(AdmittedRole.TerraBaseMember, Digest,
            RegionalHostCycleOperation.Begin, Guid.NewGuid().ToString("N")), deadline.Token)).Decision).IsEqualTo(RegionalHostSessionDecision.StoreUnavailable);
        await Assert.That(await client.BeginAsync(AdmittedRole.Authentication, "production", "gru", Digest, deadline.Token)).IsNotNull();
        while (service.Snapshot.Active != 1) await Task.Delay(5, deadline.Token);
        await Assert.That(service.Snapshot.RetryPending).IsTrue();
        intercepted.UnavailableKey = null;
        await Assert.That(await client.BeginAsync(AdmittedRole.TerraBaseMember, "production", "gru", Digest, deadline.Token)).IsNotNull();
        while (service.Snapshot.Active != 2) await Task.Delay(5, deadline.Token);
        await Assert.That(service.Snapshot.RetryPending).IsFalse();
    }

    [Test]
    public async Task Abandoned_active_cycle_is_counted_once_and_failures_persist_beyond_runtime_TTL_until_success()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var store = await Store(harness, deadline.Token);
        await Put(store, harness.First, Digest, deadline.Token);
        var authority = new RegionalHostCycleAuthority(store, harness.Authority);
        await authority.ProcessAsync(Begin(harness.First), deadline.Token);
        var signer = harness.First.Signer;
        for (var expected = 1; expected <= 7; expected++)
        {
            if (expected == 1)
            {
                harness.Material.Clock.Advance(TimeSpan.FromSeconds(31));
                signer = await RestartSigner(harness, deadline.Token);
                var abandoned = await authority.ProcessAsync(signer.SignCycle(harness.First.Role, Digest,
                    RegionalHostCycleOperation.Begin, Guid.NewGuid().ToString("N")), deadline.Token);
                await Assert.That(abandoned.Disposition).IsEqualTo(RegionalHostCycleDisposition.Backoff);
            }
            else
            {
                var previous = await Read(store, harness.First, deadline.Token);
                harness.Material.Clock.Advance(previous.NotBefore!.Value - harness.Material.Clock.GetUtcNow() + TimeSpan.FromSeconds(1));
                signer = await RestartSigner(harness, deadline.Token);
                var begin = signer.SignCycle(harness.First.Role, Digest, RegionalHostCycleOperation.Begin, Guid.NewGuid().ToString("N"));
                var started = await authority.ProcessAsync(begin, deadline.Token);
                await Assert.That(started.Disposition).IsEqualTo(RegionalHostCycleDisposition.Active);
                var outcome = signer.SignCycle(harness.First.Role, Digest, RegionalHostCycleOperation.Fail, begin.AttemptId, started.CycleId, started.Fence);
                await Assert.That((await authority.ProcessAsync(outcome, deadline.Token)).Accepted).IsTrue();
            }
            var record = await Read(store, harness.First, deadline.Token);
            await Assert.That(record.Failures).IsEqualTo(Math.Min(6, expected));
            await Assert.That(record.NotBefore - record.UpdatedAt).IsEqualTo(RegionalHostCycleAuthority.Backoff(expected));
            var replay = await authority.ProcessAsync(signer.SignCycle(harness.First.Role, Digest, RegionalHostCycleOperation.Begin,
                Guid.NewGuid().ToString("N")), deadline.Token);
            await Assert.That(replay.Disposition).IsEqualTo(RegionalHostCycleDisposition.Backoff);
            await Assert.That(replay.NotBefore).IsEqualTo(record.NotBefore);
        }
        var lastFailure = await Read(store, harness.First, deadline.Token);
        harness.Material.Clock.Advance(lastFailure.NotBefore!.Value - harness.Material.Clock.GetUtcNow() + TimeSpan.FromSeconds(1));
        signer = await RestartSigner(harness, deadline.Token);
        var fixedBegin = signer.SignCycle(harness.First.Role, Digest, RegionalHostCycleOperation.Begin, Guid.NewGuid().ToString("N"));
        var repaired = await authority.ProcessAsync(fixedBegin, deadline.Token);
        await Assert.That(repaired.Failures).IsEqualTo(6);
        await Assert.That((await authority.ProcessAsync(signer.SignCycle(harness.First.Role, Digest, RegionalHostCycleOperation.Complete,
            fixedBegin.AttemptId, repaired.CycleId, repaired.Fence), deadline.Token)).Succeeded).IsTrue();
        await Assert.That((await Read(store, harness.First, deadline.Token)).Failures).IsEqualTo(0);
    }

    [Test]
    public async Task Stale_positive_reads_cannot_resurrect_old_cycles_and_tombstones_fail_closed()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var store = await Store(harness, deadline.Token);
        await Put(store, harness.First, Digest, deadline.Token);
        var authority = new RegionalHostCycleAuthority(store, harness.Authority);
        var begin = Begin(harness.First);
        var active = await authority.ProcessAsync(begin, deadline.Token);
        var key = Key(harness.First);
        var stale = await store.GetEntryAsync<string>(key, cancellationToken: deadline.Token);
        await authority.ProcessAsync(Outcome(harness.First, begin, active, false), deadline.Token);
        var proxy = DispatchProxy.Create<INatsKVStore, CycleStore>();
        var intercepted = (CycleStore)proxy;
        intercepted.Inner = store;
        intercepted.Stale = stale;
        intercepted.StaleReads = 2;
        var guarded = new RegionalHostCycleAuthority(proxy, harness.Authority);
        await Assert.That((await guarded.ProcessAsync(begin, deadline.Token)).Disposition).IsEqualTo(RegionalHostCycleDisposition.Settled);
        await Assert.That((await Read(store, harness.First, deadline.Token)).Failures).IsEqualTo(1);
        await store.DeleteAsync(key, cancellationToken: deadline.Token);
        intercepted.AbsentReads = 1;
        await Assert.That((await guarded.ProcessAsync(Begin(harness.First), deadline.Token)).Decision).IsEqualTo(RegionalHostSessionDecision.InvalidStore);
    }

    [Test]
    [Arguments("target")]
    [Arguments("revoke")]
    [Arguments("expire")]
    public async Task A_state_write_cannot_return_an_active_receipt_after_target_or_session_authority_changes(string change)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var store = await Store(harness, deadline.Token);
        await Put(store, harness.First, Digest, deadline.Token);
        var proxy = DispatchProxy.Create<INatsKVStore, CycleStore>();
        var intercepted = (CycleStore)proxy;
        intercepted.Inner = store;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        intercepted.AfterWrite = async () => { entered.TrySetResult(); await release.Task; };
        var processing = new RegionalHostCycleAuthority(proxy, harness.Authority).ProcessAsync(Begin(harness.First), deadline.Token);
        await entered.Task.WaitAsync(deadline.Token);
        try
        {
            if (change == "target") await Put(store, harness.First, OtherDigest, deadline.Token);
            if (change == "revoke") await harness.Authority.RevokeAsync(harness.First.Node, 1, harness.First.Lease.Epoch, deadline.Token);
            if (change == "expire") harness.Material.Clock.Advance(TimeSpan.FromSeconds(30));
        }
        finally { release.TrySetResult(); }
        var response = await processing;
        await Assert.That(response.Accepted).IsFalse();
        await Assert.That(response.CycleId).IsNull();
        // Bookkeeping may have committed before revocation. It is not an execution grant.
        await Assert.That((await Read(store, harness.First, deadline.Token)).Phase).IsEqualTo(RegionalHostCyclePhase.Active);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Stalled_cycle_storage_is_bounded_and_cannot_starve_session_renewal(bool synchronous)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var store = await Store(harness, deadline.Token);
        await Put(store, harness.First, Digest, deadline.Token);
        var proxy = DispatchProxy.Create<INatsKVStore, CycleStore>();
        var intercepted = (CycleStore)proxy;
        intercepted.Inner = store;
        intercepted.HoldReads = true;
        intercepted.Synchronous = synchronous;
        var service = await RegionalHostCycleService.StartAsync(harness.Controller.Connection, new(proxy, harness.Authority), deadline.Token);
        try
        {
            for (var attempt = 0; attempt < 3; attempt++)
                await Assert.That((await Source(harness, harness.First).SendAsync(Begin(harness.First), deadline.Token)).Decision)
                    .IsEqualTo(RegionalHostSessionDecision.StoreUnavailable);
            await Assert.That(intercepted.Reads).IsEqualTo(1);
            await Assert.That(service.Snapshot.InFlight).IsTrue();
            await Assert.That(service.Snapshot.RetryPending).IsTrue();
            harness.Material.Clock.Advance(TimeSpan.FromSeconds(1));
            var renewal = harness.Material.Request(harness.First.Request.Enrollment, harness.First.Request.SessionId, harness.First.Lease.Epoch,
                harness.First.Authentication);
            await Assert.That((await new NatsRegionalHostSessionClient(harness.First.Client.Connection, "gru", harness.First.Node)
                .SendAsync(renewal, deadline.Token)).Accepted).IsTrue();
        }
        finally
        {
            try { await service.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(2)); }
            finally { intercepted.Release.TrySetException(new NatsKVKeyNotFoundException()); }
        }
        while (service.Snapshot.InFlight) await Task.Delay(5, deadline.Token);
        await Assert.That(intercepted.Writes).IsEqualTo(0);
    }

    [Test]
    public async Task Malformed_or_cross_scope_durable_records_are_not_overwritten()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var store = await Store(harness, deadline.Token);
        await Put(store, harness.First, Digest, deadline.Token);
        var authority = new RegionalHostCycleAuthority(store, harness.Authority);
        await authority.ProcessAsync(Begin(harness.First), deadline.Token);
        var original = await Read(store, harness.First, deadline.Token);
        var records = new[] { original with { NodeId = harness.Second.Node }, original with { Environment = "development" },
            original with { Failures = int.MaxValue }, original with { Fence = 0 }, original with { Phase = (RegionalHostCyclePhase)99 },
            original with { Phase = RegionalHostCyclePhase.Failed, Failures = 1, NotBefore = original.UpdatedAt },
            original with { Phase = RegionalHostCyclePhase.Succeeded, Failures = 1 }, original with { CycleId = new string('G', 32) } };
        foreach (var record in records)
        {
            var revision = await store.PutAsync(Key(harness.First), JsonSerializer.Serialize(record, RegionalHostSessionAuthority.JsonOptions), cancellationToken: deadline.Token);
            await Assert.That((await authority.ProcessAsync(Begin(harness.First), deadline.Token)).Decision).IsEqualTo(RegionalHostSessionDecision.InvalidStore);
            await Assert.That((await store.GetEntryAsync<string>(Key(harness.First), cancellationToken: deadline.Token)).Revision).IsEqualTo(revision);
        }
    }

    [Test]
    public async Task Lost_begin_and_outcome_replies_keep_stable_operation_identity_and_never_double_count()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var store = await Store(harness, deadline.Token);
        await Put(store, harness.First, Digest, deadline.Token);
        var authority = new RegionalHostCycleAuthority(store, harness.Authority);
        await using var subscription = await harness.Controller.Connection.SubscribeCoreAsync<string>(
            RegionalHostCycleRequest.Subject("gru", harness.First.Node), cancellationToken: deadline.Token);
        await harness.Controller.Connection.PingAsync(deadline.Token);
        var droppedBegin = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var droppedOutcome = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var serving = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
        var loop = Task.Run(async () =>
        {
            try
            {
                await foreach (var message in subscription.Msgs.ReadAllAsync(serving.Token))
                {
                    if (!RegionalHostCycleRequest.TryRead(message.Data, message.Subject, message.ReplyTo, "gru", harness.Material.Clock.GetUtcNow(), out var request)) continue;
                    var response = await authority.ProcessAsync(request!, serving.Token);
                    if (request!.Operation == RegionalHostCycleOperation.Begin && droppedBegin.TrySetResult()) continue;
                    if (request.Operation == RegionalHostCycleOperation.Fail && droppedOutcome.TrySetResult()) continue;
                    await harness.Controller.Connection.PublishAsync(message.ReplyTo!, JsonSerializer.Serialize(response, RegionalHostSessionAuthority.JsonOptions),
                        cancellationToken: serving.Token);
                }
            }
            catch (OperationCanceledException) when (serving.IsCancellationRequested) { }
        });
        try
        {
            var caller = Source(harness, harness.First);
            using var beginCancellation = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
            var unknown = caller.BeginAsync(harness.First.Role, "production", "gru", Digest, beginCancellation.Token);
            await droppedBegin.Task.WaitAsync(deadline.Token);
            beginCancellation.Cancel();
            await Assert.That(async () => _ = await unknown).Throws<OperationCanceledException>();
            var original = await Read(store, harness.First, deadline.Token);
            var accepted = await caller.BeginAsync(harness.First.Role, "production", "gru", Digest, deadline.Token);
            await Assert.That(accepted!.CycleId).IsEqualTo(original.CycleId);
            using var outcomeCancellation = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
            var failed = caller.FinishAsync(accepted, false, outcomeCancellation.Token);
            await droppedOutcome.Task.WaitAsync(deadline.Token);
            outcomeCancellation.Cancel();
            await Assert.That(() => failed).Throws<OperationCanceledException>();
            var before = await Read(store, harness.First, deadline.Token);
            harness.Material.Clock.Advance(TimeSpan.FromSeconds(1));
            await caller.FlushAsync(harness.First.Role, deadline.Token);
            var after = await Read(store, harness.First, deadline.Token);
            await Assert.That(after.Failures).IsEqualTo(1);
            await Assert.That(after.NotBefore).IsEqualTo(before.NotBefore);
            await Assert.That(after.Fence).IsEqualTo(original.Fence);
        }
        finally { serving.Cancel(); await loop; }
    }

    private static string Key(SignedHostReportHarness.ReportHost host) => RegionalHostCycleAuthority.Key("gru", host.Node, "production", host.Role);
    private static RegionalHostCycleRequest Begin(SignedHostReportHarness.ReportHost host, string? digest = null) =>
        host.Signer.SignCycle(host.Role, digest ?? Digest, RegionalHostCycleOperation.Begin, Guid.NewGuid().ToString("N"));
    private static RegionalHostCycleRequest Outcome(SignedHostReportHarness.ReportHost host, RegionalHostCycleRequest begin,
        RegionalHostCycleResponse receipt, bool succeeded) => host.Signer.SignCycle(host.Role, begin.ArtifactDigest,
        succeeded ? RegionalHostCycleOperation.Complete : RegionalHostCycleOperation.Fail, begin.AttemptId, receipt.CycleId, receipt.Fence);
    private static ValueTask<INatsKVStore> Store(SignedHostReportHarness harness, CancellationToken token) =>
        harness.Controller.CreateJetStreamContext().CreateKeyValueStoreContext().GetStoreAsync("ORCH_DELIVERY", token);
    private static async Task Put(INatsKVStore store, SignedHostReportHarness.ReportHost host, string digest, CancellationToken token) =>
        _ = await store.PutAsync(DirectDeliveryTargetKey.For(host.Artifact, "production", "gru"),
            JsonSerializer.Serialize(new { artifactDigest = digest, manifestDigest = digest, kind = "service" }), cancellationToken: token);
    private static async Task<RegionalHostCycleRecord> Read(INatsKVStore store, SignedHostReportHarness.ReportHost host, CancellationToken token)
    {
        var entry = await store.GetEntryAsync<string>(Key(host), cancellationToken: token);
        entry.EnsureSuccess();
        return JsonSerializer.Deserialize<RegionalHostCycleRecord>(entry.Value!, RegionalHostSessionAuthority.JsonOptions)!;
    }
    private static NatsHostCycleCoordinator Source(SignedHostReportHarness harness, SignedHostReportHarness.ReportHost host) =>
        new(host.Client.Connection, "gru", host.Node, () => host.Signer, harness.Material.Clock);
    private static async Task<RegionalHostSessionSigner> RestartSigner(SignedHostReportHarness harness, CancellationToken token)
    {
        var request = harness.Material.Request(harness.First.Request.Enrollment, authentication: harness.First.Authentication);
        var lease = await harness.Authority.ProcessAsync(request, token);
        if (!lease.Accepted) throw new InvalidOperationException($"Test session restart denied: {lease.Decision}.");
        return new(request, lease, harness.First.Authentication, harness.Material.Clock);
    }

    public class CycleStore : DispatchProxy
    {
        internal INatsKVStore Inner { get; set; } = null!;
        internal NatsKVEntry<string>? Stale { get; set; }
        internal int StaleReads { get; set; }
        internal int AbsentReads { get; set; }
        internal bool HoldReads { get; set; }
        internal bool Synchronous { get; set; }
        internal string? UnavailableKey { get; set; }
        internal int Reads;
        internal int Writes;
        internal Func<Task>? AfterWrite { get; set; }
        internal TaskCompletionSource<NatsKVEntry<string>> Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override object? Invoke(MethodInfo? method, object?[]? args)
        {
            var cycle = args is { Length: > 0 } && args[0] is string key && key.StartsWith("host.cycle.", StringComparison.Ordinal);
            if (method!.Name == nameof(INatsKVStore.GetEntryAsync) && cycle)
            {
                Interlocked.Increment(ref Reads);
                if (args![0] as string == UnavailableKey) return ValueTask.FromException<NatsKVEntry<string>>(new IOException("Injected cycle storage failure."));
                if (HoldReads) return Synchronous ? ValueTask.FromResult(Release.Task.GetAwaiter().GetResult()) : new ValueTask<NatsKVEntry<string>>(Release.Task);
                if (AbsentReads-- > 0) return ValueTask.FromException<NatsKVEntry<string>>(new NatsKVKeyNotFoundException());
                if (Stale is { } stale && StaleReads-- > 0) return ValueTask.FromResult(stale);
            }
            try
            {
                var result = method.Invoke(Inner, args);
                if (method.Name == nameof(INatsKVStore.UpdateAsync) && cycle)
                {
                    Interlocked.Increment(ref Writes);
                    if (AfterWrite is { } after) return new ValueTask<ulong>(AfterAsync((ValueTask<ulong>)result!, after));
                }
                return result;
            }
            catch (TargetInvocationException exception) when (exception.InnerException is { } inner)
            { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(inner).Throw(); throw; }
        }
        private static async Task<ulong> AfterAsync(ValueTask<ulong> write, Func<Task> after)
        {
            var revision = await write;
            await after();
            return revision;
        }
    }
}
