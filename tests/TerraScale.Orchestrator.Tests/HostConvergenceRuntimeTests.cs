using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NATS.Client.KeyValueStore;
using NATS.Client.Core;
using NATS.Net;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Nodes;
using TerraScale.Orchestrator.Runtime;
using TerraScale.Orchestrator.Protocol.Subjects;
using TUnit.Core;
using HostRole = TerraScale.Orchestrator.Runtime.AdmittedRole;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Leaderless host convergence against a real NATS server: desired digest in, verified
/// artifact installed, systemd plan converged, observation reported — with rollback on a
/// failed post-converge observation and replace-lease serialization for stateful roles.
/// </summary>
public sealed class HostConvergenceRuntimeTests
{
    [Test]
    public async Task Production_host_report_publisher_uses_only_its_manifest_agent_permissions()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var (delivery, runtimeStore, _) = server.Stores();
        await using var host = server.RestrictedHost();
        await host.ConnectAsync();
        var artifact = Encoding.UTF8.GetBytes("scoped-report-binary");
        var hex = Convert.ToHexStringLower(SHA256.HashData(artifact));
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{hex}");
        await using var convergence = StartConvergence(delivery, runtimeStore, host.Connection,
            Path.Combine(server.Directory, "artifacts"), new MemoryArtifactSource(("sha256-" + hex, artifact)),
            new FakeConverger(), new FakeAdmissionGate(true, true, "admitted"));
        await convergence.ReconcileOnceAsync(HostRole.TerraBaseMember,
            AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), deadline.Token);
        await Assert.That((await ReadObservationAsync(runtimeStore, "terrabase-server"))!.State).IsEqualTo("converged");
        await Assert.That(await new NatsMemberHostSeams(new AssumedAuthorizedHostReportReader(runtimeStore), delivery, host.Connection,
            "gru", "production", TimeProvider.System).HasHostReportedAsync("test-1", deadline.Token)).IsTrue();

        // The host's report connection cannot write private KV or publish for another host.
        await server.RequireHostPublishDeniedAsync("$KV.ORCH_RUNTIME.host.test-2.terrabase-server", deadline.Token);
        await server.RequireHostPublishDeniedAsync(HostObservationRelay.ReportSubject("gru", "test-2"), deadline.Token);
        await Assert.That(async () => await runtimeStore.GetEntryAsync<string>("host.test-2.terrabase-server", cancellationToken: deadline.Token))
            .Throws<NatsKVKeyNotFoundException>();
        // Positive control after denial: this identity is still connected and can report itself.
        await convergence.ReconcileOnceAsync(HostRole.TerraBaseMember,
            AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), deadline.Token);
        await Assert.That((await ReadObservationAsync(runtimeStore, "terrabase-server"))!.State).IsEqualTo("converged");
    }

    [Test]
    public async Task Report_transport_uses_manifest_scopes_for_controller_and_multiple_hosts()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (_, runtimeStore, _) = server.Stores();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        foreach (var instance in new[] { "test-1", "test-2" })
        {
            await using var host = server.RestrictedHost(instance);
            await host.ConnectAsync();
            await new NatsHostObservationPublisher(host.Connection, "gru", instance).PublishAsync(
                new HostAdmissionObservation(1, "gru", instance, "production", "terrabase-server",
                    "sha256:" + new string('a', 64), true, DateTimeOffset.UtcNow), deadline.Token);
            await Assert.That((await runtimeStore.GetEntryAsync<string>(
                HostAdmissionObservation.Key(instance, "terrabase-server"))).Revision).IsGreaterThan(0UL);
        }
        // A regional controller cannot impersonate a host report or cross the region boundary.
        await server.RequirePublishDeniedAsync("relay", HostObservationRelay.ReportSubject("gru", "test-1"), deadline.Token);
        await server.RequirePublishDeniedAsync("relay", HostObservationRelay.ReplySubject("fra", "test-1", new string('a', 32)), deadline.Token);
    }

    [Test]
    public async Task Relay_refuses_store_retention_that_allows_accepted_reports_to_outlive_ordering()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (_, _, connection) = server.Stores();
        var keyValue = new NatsKVContext(new NATS.Client.JetStream.NatsJSContext(connection));
        var shortStore = await keyValue.CreateStoreAsync(new NatsKVConfig("SHORT_REPORTS")
        {
            MaxAge = HostObservationRelay.MaximumReportAge
        });
        await Assert.That(async () =>
        {
            await using var unexpected = await HostObservationRelay.StartAsync(connection, shortStore, "gru", CancellationToken.None);
        }).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Relay_rejects_forged_subject_identity_reply_schema_time_and_duplicate_fields()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (_, runtimeStore, _) = server.Stores();
        await using var host = server.RestrictedHost();
        await host.ConnectAsync();
        var now = DateTimeOffset.UtcNow.AddSeconds(-1);
        var admission = new HostAdmissionObservation(1, "gru", "test-1", "production", "terrabase-server",
            "sha256:" + new string('a', 64), true, now);
        foreach (var mutation in new[] { "identity", "cell", "reply", "schema", "future", "old", "duplicate" })
        {
            var candidate = admission with
            {
                Instance = mutation == "identity" ? "test-2" : admission.Instance,
                Cell = mutation == "cell" ? "fra" : admission.Cell,
                SchemaVersion = mutation == "schema" ? 99 : 1,
                ObservedAt = mutation == "future" ? now.AddHours(1) : mutation == "old" ? now.AddSeconds(-31) : now
            };
            var envelope = new HostReportEnvelope(1, Guid.NewGuid().ToString("N"), candidate, null);
            var json = JsonSerializer.Serialize(envelope, HostObservationRelay.JsonOptions);
            if (mutation == "duplicate") json = json[..^1] + ",\"SchemaVersion\":1}";
            await host.Connection.PublishAsync(HostObservationRelay.ReportSubject("gru", "test-1"), json,
                replyTo: HostObservationRelay.ReplySubject("gru", mutation == "reply" ? "test-2" : "test-1", envelope.RequestId));
        }
        var publisher = new NatsHostObservationPublisher(host.Connection, "gru", "test-1");
        await publisher.PublishAsync(admission with { Ready = false }, CancellationToken.None);
        var stored = await runtimeStore.GetEntryAsync<string>(HostAdmissionObservation.Key("test-1", "terrabase-server"));
        await Assert.That(JsonSerializer.Deserialize<HostAdmissionObservation>(stored.Value!)!.Ready).IsFalse();
        await Assert.That(server.ReportSnapshot.Rejected).IsEqualTo(7);
        await Assert.That(async () => await runtimeStore.GetEntryAsync<string>(HostAdmissionObservation.Key("test-2", "terrabase-server")))
            .Throws<NatsKVKeyNotFoundException>();
    }

    [Test]
    public async Task Relay_does_not_allow_host_runtime_keys_to_alias_admission_backoff_or_replace_state()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (_, runtimeStore, connection) = server.Stores();
        foreach (var instance in new[] { "admission.test-1", "backoff.test-1", "replace" })
        {
            var observation = new HostConvergenceObservation(2, "gru", instance, "terrabase-server",
                "sha256:" + new string('a', 64), "converged", null, DateTimeOffset.UtcNow);
            var envelope = new HostReportEnvelope(1, Guid.NewGuid().ToString("N"), null, observation);
            await connection.PublishAsync(HostObservationRelay.ReportSubject("gru", instance),
                JsonSerializer.Serialize(envelope, HostObservationRelay.JsonOptions),
                replyTo: HostObservationRelay.ReplySubject("gru", instance, envelope.RequestId));
        }
        // An acknowledged valid report fences processing of the three queued invalid reports.
        await new NatsHostObservationPublisher(connection, "gru", "test-1").PublishAsync(
            new HostAdmissionObservation(1, "gru", "test-1", "production", "terrabase-server",
                "sha256:" + new string('b', 64), false, DateTimeOffset.UtcNow), CancellationToken.None);
        await Assert.That(server.ReportSnapshot.Rejected).IsEqualTo(3);
        await Assert.That(async () => await runtimeStore.GetEntryAsync<string>("host.replace.terrabase-server"))
            .Throws<NatsKVKeyNotFoundException>();
    }

    [Test]
    public async Task Another_hosts_success_does_not_hide_a_failed_report_until_the_failed_host_retries()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (_, runtimeStore, connection) = server.Stores();
        var failing = DispatchProxy.Create<INatsKVStore, FailingReportRuntimeStore>();
        var store = (FailingReportRuntimeStore)(object)failing;
        store.Inner = runtimeStore;
        store.FailNextWrite = true;
        await server.UseReportStoreAsync(failing);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var admission = new HostAdmissionObservation(1, "gru", "test-1", "production", "terrabase-server",
            "sha256:" + new string('a', 64), true, DateTimeOffset.UtcNow);
        var envelope = new HostReportEnvelope(1, Guid.NewGuid().ToString("N"), admission, null);
        await connection.PublishAsync(HostObservationRelay.ReportSubject("gru", "test-1"),
            JsonSerializer.Serialize(envelope, HostObservationRelay.JsonOptions),
            replyTo: HostObservationRelay.ReplySubject("gru", "test-1", envelope.RequestId), cancellationToken: deadline.Token);
        while (server.ReportSnapshot.Failed == 0) await Task.Delay(10, deadline.Token);
        await new NatsHostObservationPublisher(connection, "gru", "test-2").PublishAsync(
            admission with { Instance = "test-2" }, deadline.Token);
        await Assert.That(server.ReportSnapshot.RetryPending).IsTrue();
        await new NatsHostObservationPublisher(connection, "gru", "test-1").PublishAsync(admission, deadline.Token);
        await Assert.That(server.ReportSnapshot.RetryPending).IsFalse();
        await Assert.That(server.ReportSnapshot.Failed).IsEqualTo(1);
    }

    [Test]
    public async Task Old_report_cannot_restore_admission_after_withdrawal_and_exact_retry_is_idempotent()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (_, runtimeStore, _) = server.Stores();
        await using var host = server.RestrictedHost();
        await host.ConnectAsync();
        var publisher = new NatsHostObservationPublisher(host.Connection, "gru", "test-1");
        var admission = new HostAdmissionObservation(1, "gru", "test-1", "production", "terrabase-server",
            "sha256:" + new string('a', 64), true, DateTimeOffset.UtcNow.AddSeconds(-2));
        await publisher.PublishAsync(admission, CancellationToken.None);
        var withdrawn = admission with { Ready = false, ObservedAt = admission.ObservedAt.AddSeconds(1) };
        await publisher.PublishAsync(withdrawn, CancellationToken.None);
        var key = HostAdmissionObservation.Key("test-1", "terrabase-server");
        var revision = (await runtimeStore.GetEntryAsync<string>(key)).Revision;
        await Assert.That(() => publisher.PublishAsync(admission, CancellationToken.None)).Throws<InvalidOperationException>();
        await publisher.PublishAsync(withdrawn, CancellationToken.None);
        var current = await runtimeStore.GetEntryAsync<string>(key);
        await Assert.That(current.Revision).IsEqualTo(revision);
        await Assert.That(JsonSerializer.Deserialize<HostAdmissionObservation>(current.Value!)!.Ready).IsFalse();
    }

    [Test]
    public async Task Fresh_node_does_not_start_or_pick_up_work_before_regional_admission()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var installRoot = Path.Combine(server.Directory, "artifacts");
        var artifact = Encoding.UTF8.GetBytes("admission-gated-binary");
        var hex = Convert.ToHexStringLower(SHA256.HashData(artifact));
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{hex}");
        var admission = new FakeAdmissionGate(false, false, "enrollment-pending");
        var converger = new FakeConverger();
        await using var convergence = StartConvergence(
            delivery,
            runtimeStore,
            client,
            installRoot,
            new MemoryArtifactSource(("sha256-" + hex, artifact)),
            converger,
            admission);

        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember,
            AdmittedRoleCatalog.Get(HostRole.TerraBaseMember),
            CancellationToken.None);

        var blocked = await ReadObservationAsync(runtimeStore, "terrabase-server");
        await Assert.That(converger.ConvergedPlans).IsEmpty();
        await Assert.That(blocked!.State).IsEqualTo("blocked-admission");
        await Assert.That(blocked.Error).IsEqualTo("enrollment-pending");
        var seams = new NatsMemberHostSeams(new AssumedAuthorizedHostReportReader(runtimeStore), delivery, client, "gru", "production", TimeProvider.System);
        await Assert.That(await seams.HasHostReportedAsync("test-1", CancellationToken.None)).IsFalse();

        admission.Authorized = true;
        admission.CredentialsReady = true;
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember,
            AdmittedRoleCatalog.Get(HostRole.TerraBaseMember),
            CancellationToken.None);

        await Assert.That(converger.ConvergedPlans).Count().IsEqualTo(1);
        await Assert.That((await ReadObservationAsync(runtimeStore, "terrabase-server"))!.State)
            .IsEqualTo("converged");
        await Assert.That(await seams.HasHostReportedAsync("test-1", CancellationToken.None)).IsTrue();
        admission.Authorized = false;
        await convergence.ReconcileOnceAsync(HostRole.TerraBaseMember,
            AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);
        await Assert.That(await seams.HasHostReportedAsync("test-1", CancellationToken.None)).IsFalse();
        await Assert.That(converger.ConvergedPlans).Count().IsEqualTo(1);
    }

    [Test]
    public async Task Enrollment_readiness_is_published_before_service_start_to_allow_volume_recovery()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var artifact = Encoding.UTF8.GetBytes("member-awaiting-volume");
        var hex = Convert.ToHexStringLower(SHA256.HashData(artifact));
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{hex}");
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var converger = new FakeConverger { ConvergeBarrier = release.Task };
        await using var convergence = StartConvergence(delivery, runtimeStore, client,
            Path.Combine(server.Directory, "artifacts"), new MemoryArtifactSource(("sha256-" + hex, artifact)),
            converger, new FakeAdmissionGate(true, true, "admitted"));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var reconcile = convergence.ReconcileOnceAsync(HostRole.TerraBaseMember,
            AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), timeout.Token);
        try
        {
            await converger.FirstConvergeStarted.WaitAsync(timeout.Token);
            var seams = new NatsMemberHostSeams(new AssumedAuthorizedHostReportReader(runtimeStore), delivery, client, "gru", "production", TimeProvider.System);
            await Assert.That(converger.ConvergedPlans).IsEmpty();
            await Assert.That(await seams.HasHostReportedAsync("test-1", timeout.Token)).IsTrue();
            await Assert.That(await seams.ObserveMemberHealthAsync("test-1", timeout.Token)).IsNull();
        }
        finally
        {
            release.TrySetResult();
            await reconcile;
        }
    }

    [Test]
    public async Task Oci_node_identity_survives_convergence_and_keeps_one_allocation_across_upgrades()
    {
        const string node = "ocid1.instance.oc1.sa-saopaulo-1.aaaaaaaaabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmn";
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var installRoot = Path.Combine(server.Directory, "oci-artifacts");
        var first = Encoding.UTF8.GetBytes("oci-member-v1");
        var second = Encoding.UTF8.GetBytes("oci-member-v2");
        var firstHex = Convert.ToHexStringLower(SHA256.HashData(first));
        var secondHex = Convert.ToHexStringLower(SHA256.HashData(second));
        var converger = new FakeConverger();
        // This exercises allocation/report identity with controller-owned stores.
        // The dedicated restricted host entry point has its own remaining gate.
        await using var convergence = HostConvergenceRuntime.Create(delivery, runtimeStore, client,
            new MemoryArtifactSource(("sha256-" + firstHex, first), ("sha256-" + secondHex, second)),
            converger, new HostConvergenceConfiguration([HostRole.TerraBaseMember], "production", installRoot,
                HostArchitecture.Arm64), "gru", node);
        foreach (var hex in new[] { firstHex, secondHex })
        {
            await server.PutDesiredDigest("terrabase-server", "production", "gru", "sha256:" + hex);
            await convergence.ReconcileOnceAsync(HostRole.TerraBaseMember,
                AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);
            var entry = await runtimeStore.GetEntryAsync<string>($"host.{node}.terrabase-server");
            entry.EnsureSuccess();
            var report = JsonSerializer.Deserialize<HostConvergenceObservation>(entry.Value!);
            await Assert.That(report!.Instance).IsEqualTo(node);
            await Assert.That(report.Digest).IsEqualTo("sha256:" + hex);
            await Assert.That(report.State).IsEqualTo("converged");
        }
        await Assert.That(converger.ConvergedPlans.Count).IsEqualTo(2);
        await Assert.That(converger.ConvergedPlans[0].AllocationId).IsEqualTo(converger.ConvergedPlans[1].AllocationId);
        var allocation = converger.ConvergedPlans[0].AllocationId;
        await Assert.That(allocation.Value.Length).IsLessThanOrEqualTo(63);
        await Assert.That(allocation).IsNotEqualTo(HostConvergenceRuntime.AllocationIdFor("sfo", node, "terrabase-server"));
        await Assert.That(allocation).IsNotEqualTo(HostConvergenceRuntime.AllocationIdFor("gru", node + "2", "terrabase-server"));
        await Assert.That(allocation).IsNotEqualTo(HostConvergenceRuntime.AllocationIdFor("gru", node, "ts-auth"));
        await Assert.That(HostConvergenceRuntime.AllocationIdFor("ab", "c", "d"))
            .IsNotEqualTo(HostConvergenceRuntime.AllocationIdFor("a", "bc", "d"));
    }

    [Test]
    public async Task ConvergesDesiredDigestInstallsVerifiedArtifactAndReportsObservation()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var installRoot = Path.Combine(server.Directory, "artifacts");
        var artifact = Encoding.UTF8.GetBytes("terrabase-binary-v2");
        var hex = Convert.ToHexStringLower(SHA256.HashData(artifact));
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{hex}");

        var converger = new FakeConverger();
        await using var convergence = StartConvergence(
            delivery, runtimeStore, client, installRoot,
            source: new MemoryArtifactSource(("sha256-" + hex, artifact)), converger: converger);

        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);

        var installed = Path.Combine(installRoot, "terrabase-server", $"sha256-{hex}", "terrabase-server");
        await Assert.That(await File.ReadAllBytesAsync(installed)).IsEquivalentTo(artifact);
        await Assert.That(converger.ConvergedPlans.Count).IsEqualTo(1);
        await Assert.That(converger.ConvergedPlans[0].Systemd!.Executable).IsEqualTo(installed);
        await Assert.That(converger.ConvergedPlans[0].ArtifactDigest!.Value).IsEqualTo(hex);

        var observation = await ReadObservationAsync(runtimeStore, "terrabase-server");
        await Assert.That(observation!.State).IsEqualTo("converged");
        await Assert.That(observation.Digest).IsEqualTo($"sha256:{hex}");
        var marker = JsonSerializer.Deserialize<JsonElement>(
            await File.ReadAllTextAsync(Path.Combine(installRoot, "terrabase-server", "current.json")));
        await Assert.That(marker.GetProperty("digest").GetString()).IsEqualTo($"sha256:{hex}");
    }

    [Test]
    public async Task SameDigestWhileServingReconcilesToNoOp()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var installRoot = Path.Combine(server.Directory, "artifacts");
        var artifact = Encoding.UTF8.GetBytes("same-binary");
        var hex = Convert.ToHexStringLower(SHA256.HashData(artifact));
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{hex}");

        var converger = new FakeConverger();
        await using var convergence = StartConvergence(
            delivery, runtimeStore, client, installRoot,
            source: new MemoryArtifactSource(("sha256-" + hex, artifact)), converger: converger);
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);
        var converged = converger.ConvergedPlans.Count;
        await Assert.That(converged).IsGreaterThan(0);

        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);

        await Assert.That(converger.ConvergedPlans.Count).IsEqualTo(converged);
    }

    [Test]
    public async Task FailedObservationAfterReplacementRollsBackToTheExactPreviousDigest()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var installRoot = Path.Combine(server.Directory, "artifacts");
        var good = Encoding.UTF8.GetBytes("known-good-binary");
        var broken = Encoding.UTF8.GetBytes("crash-looping-binary");
        var goodHex = Convert.ToHexStringLower(SHA256.HashData(good));
        var brokenHex = Convert.ToHexStringLower(SHA256.HashData(broken));
        var source = new MemoryArtifactSource(
            ("sha256-" + goodHex, good),
            ("sha256-" + brokenHex, broken));

        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{goodHex}");
        var converger = new FakeConverger();
        await using var convergence = StartConvergence(
            delivery, runtimeStore, client, installRoot, source, converger);
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);
        await Assert.That(converger.ConvergedPlans.Single().ArtifactDigest!.Value).IsEqualTo(goodHex);

        converger.FailWhenRunning(brokenHex);
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{brokenHex}");
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);

        var observation = await ReadObservationAsync(runtimeStore, "terrabase-server");
        await Assert.That(observation!.State).IsEqualTo("rolled-back");
        await Assert.That(observation.Digest).IsEqualTo($"sha256:{goodHex}");
        // The final converged plan is the restored previous version, never the broken one.
        await Assert.That(converger.ConvergedPlans.Last().ArtifactDigest!.Value).IsEqualTo(goodHex);
    }

    [Test]
    public async Task CorruptedArtifactFailsClosedWithoutTouchingTheRunningVersion()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var installRoot = Path.Combine(server.Directory, "artifacts");
        var good = Encoding.UTF8.GetBytes("still-running");
        var tampered = Encoding.UTF8.GetBytes("tampered-bytes");
        var goodHex = Convert.ToHexStringLower(SHA256.HashData(good));
        var tamperedHex = Convert.ToHexStringLower(SHA256.HashData(tampered));
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{goodHex}");
        var converger = new FakeConverger();
        await using var first = StartConvergence(
            delivery, runtimeStore, client, installRoot,
            source: new MemoryArtifactSource(("sha256-" + goodHex, good)), converger: converger);
        await first.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);

        // The store object named for the desired digest returns different bytes.
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{tamperedHex}");
        await using var second = StartConvergence(
            delivery, runtimeStore, client, installRoot,
            source: new MemoryArtifactSource(("sha256-" + tamperedHex, good), ("sha256-" + goodHex, good)),
            converger: converger);
        await second.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);

        // The host stays on the exact previous digest and never executes unverified bytes.
        var observation = await ReadObservationAsync(runtimeStore, "terrabase-server");
        await Assert.That(observation!.Digest).IsEqualTo($"sha256:{goodHex}");
        await Assert.That(
            File.Exists(Path.Combine(installRoot, "terrabase-server", $"sha256-{tamperedHex}", "terrabase-server")))
            .IsFalse();
        await Assert.That(converger.ConvergedPlans.All(plan =>
            plan.ArtifactDigest!.Value != tamperedHex)).IsTrue();
    }

    [Test]
    public async Task UpgradeStopsTheOldUnitBeforeConvergingTheNewOneAndDistributesItsEnvironment()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var installRoot = Path.Combine(server.Directory, "artifacts");
        var environmentDirectory = Path.Combine(server.Directory, "host-env");
        var stateDirectoryRoot = Path.Combine(server.Directory, "state");
        Directory.CreateDirectory(environmentDirectory);
        var v1 = Encoding.UTF8.GetBytes("member-v1");
        var v2 = Encoding.UTF8.GetBytes("member-v2");
        var v1Hex = Convert.ToHexStringLower(SHA256.HashData(v1));
        var v2Hex = Convert.ToHexStringLower(SHA256.HashData(v2));
        await File.WriteAllTextAsync(
            Path.Combine(environmentDirectory, "terrabase-server.env"),
            "TERRABASE_REGION=GRU\nTERRABASE_NODE_ID=gru-member-1\n");
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{v1Hex}");

        var converger = new FakeConverger();
        var configuration = new HostConvergenceConfiguration(
            [HostRole.TerraBaseMember],
            "production",
            installRoot,
            HostArchitecture.Arm64,
            EnvironmentDirectory: environmentDirectory,
            StateDirectoryRoot: stateDirectoryRoot);
        await using var convergence = HostConvergenceRuntime.Create(
            delivery, runtimeStore, client, new MemoryArtifactSource(
                ("sha256-" + v1Hex, v1), ("sha256-" + v2Hex, v2)), converger, configuration,
            "gru", "test-1", observationTimeout: TimeSpan.FromSeconds(3));
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);
        var firstAttempt = converger.Actions.Count;
        await Assert.That(firstAttempt).IsGreaterThan(0);

        // The unit's EnvironmentFile landed where the plan's property names it.
        var unit = converger.ConvergedPlans[0].Systemd!;
        var environmentProperty = unit.Properties.Single(static value =>
            value.StartsWith("EnvironmentFile=-", StringComparison.Ordinal));
        var environmentFile = environmentProperty["EnvironmentFile=-".Length..];
        await Assert.That(environmentFile).IsEqualTo(
            Path.Combine(stateDirectoryRoot, "terrascale-" + HostConvergenceRuntime.AllocationIdFor("gru", "test-1", "terrabase-server").Value, "environment"));
        await Assert.That(File.Exists(environmentFile)).IsTrue();
        await Assert.That(await File.ReadAllTextAsync(environmentFile)).Contains("TERRABASE_REGION=GRU");

        // A second version replaces the first: the old transient unit is stopped BEFORE the
        // new one converges, so the old binary can never keep serving a stale digest.
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{v2Hex}");
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);
        var upgraded = converger.ConvergedPlans.Last();
        await Assert.That(upgraded.ArtifactDigest!.Value).IsEqualTo(v2Hex);
        var actionList = converger.Actions.ToList();
        var lastConverge = actionList.LastIndexOf("converge");
        await Assert.That(lastConverge).IsGreaterThan(0);
        await Assert.That(converger.Actions[lastConverge - 1]).IsEqualTo("stop");
    }

    [Test]
    public async Task StatefulReplaceLeaseSerializesAndExpires()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (_, runtimeStore, _) = server.Stores();
        var descriptor = AdmittedRoleCatalog.Get(HostRole.TerraBaseMember);
        var convergenceA = StartConvergence(server);
        var convergenceB = StartConvergence(server);

        var leaseA = await convergenceA.AcquireReplaceLeaseAsync(descriptor, CancellationToken.None);
        await Assert.That(leaseA).IsNotNull();
        var leaseB = await convergenceB.AcquireReplaceLeaseAsync(descriptor, CancellationToken.None);
        await Assert.That(leaseB).IsNull();

        await leaseA!.DisposeAsync();
        var leaseB2 = await convergenceB.AcquireReplaceLeaseAsync(descriptor, CancellationToken.None);
        await Assert.That(leaseB2).IsNotNull();
        await leaseB2!.DisposeAsync();
        await Assert.That(async () =>
        {
            var released = await runtimeStore.GetEntryAsync<string>("host.replace.terrabase-server");
            released.EnsureSuccess();
        }).Throws<Exception>();
    }

    [Test]
    public async Task Stale_handle_cannot_release_a_new_claim_from_the_same_host()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (_, runtimeStore, _) = server.Stores();
        var descriptor = AdmittedRoleCatalog.Get(HostRole.TerraBaseMember);
        await using var oldProcess = StartConvergence(server);
        await using var restartedProcess = StartConvergence(server);
        var oldHandle = await oldProcess.AcquireReplaceLeaseAsync(descriptor, CancellationToken.None);
        await Assert.That(oldHandle).IsNotNull();
        var key = "host.replace.terrabase-server";
        var oldClaim = JsonSerializer.Deserialize<HostConvergenceReplaceLease>((await runtimeStore.GetEntryAsync<string>(key)).Value!)!;
        await runtimeStore.PutAsync(key, JsonSerializer.Serialize(oldClaim with { ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1) },
            HostConvergenceJsonContext.Default.HostConvergenceReplaceLease));
        await using var newHandle = await restartedProcess.AcquireReplaceLeaseAsync(descriptor, CancellationToken.None);
        await Assert.That(newHandle).IsNotNull();
        var newEntry = await runtimeStore.GetEntryAsync<string>(key);
        await oldHandle!.DisposeAsync();
        var afterCleanup = await runtimeStore.GetEntryAsync<string>(key);
        await Assert.That(afterCleanup.Revision).IsEqualTo(newEntry.Revision);
        await Assert.That(JsonSerializer.Deserialize<HostConvergenceReplaceLease>(afterCleanup.Value!)!.Holder)
            .IsNotEqualTo(oldClaim.Holder);
    }

    [Test]
    public async Task Lease_release_cannot_delete_a_takeover_between_its_read_and_delete()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, connection) = server.Stores();
        var proxy = DispatchProxy.Create<INatsKVStore, TakeoverBeforeLeaseDeleteStore>();
        var takeover = (TakeoverBeforeLeaseDeleteStore)(object)proxy;
        takeover.Inner = runtimeStore;
        await using var convergence = StartConvergence(delivery, proxy, connection,
            Path.Combine(server.Directory, "artifacts"), new MemoryArtifactSource(), new FakeConverger());
        var handle = await convergence.AcquireReplaceLeaseAsync(AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);
        await Assert.That(handle).IsNotNull();
        takeover.TakeOverOnDelete = true;
        await handle!.DisposeAsync();
        var current = await runtimeStore.GetEntryAsync<string>("host.replace.terrabase-server");
        await Assert.That(JsonSerializer.Deserialize<HostConvergenceReplaceLease>(current.Value!)!.Holder).IsEqualTo("peer-new-claim");
    }

    private class TakeoverBeforeLeaseDeleteStore : DispatchProxy
    {
        public INatsKVStore? Inner { get; set; }
        public bool TakeOverOnDelete { get; set; }

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            if (targetMethod!.Name == "DeleteAsync" && TakeOverOnDelete)
            {
                TakeOverOnDelete = false;
                return DeleteAfterTakeoverAsync((string)args![0]!, (NatsKVDeleteOpts?)args[1], (CancellationToken)args[2]!);
            }
            return targetMethod.Invoke(Inner, args);
        }

        private async ValueTask DeleteAfterTakeoverAsync(string key, NatsKVDeleteOpts? options, CancellationToken cancellationToken)
        {
            await Inner!.PutAsync(key, JsonSerializer.Serialize(
                new HostConvergenceReplaceLease("peer-new-claim", DateTimeOffset.UtcNow.AddMinutes(1)),
                HostConvergenceJsonContext.Default.HostConvergenceReplaceLease), cancellationToken: cancellationToken);
            await Inner.DeleteAsync(key, options, cancellationToken);
        }
    }

    [Test]
    public async Task TheReplaceLeaseIsRenewedWhileItsHolderWorksSoAPeerCannotStealItMidAttempt()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var installRoot = Path.Combine(server.Directory, "artifacts");
        var artifact = Encoding.UTF8.GetBytes("slow-replacement");
        var hex = Convert.ToHexStringLower(SHA256.HashData(artifact));
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{hex}");

        // The pass outlives the lease duration several times over. The renewal budget is
        // deliberately generous (two thirds of the duration): a loaded CI runner's scheduler
        // stalls must not manufacture an expired lease out of holder jitter.
        var converger = new FakeConverger { ConvergeDelay = TimeSpan.FromSeconds(4) };
        var configuration = new HostConvergenceConfiguration(
            [HostRole.TerraBaseMember], "production", installRoot, HostArchitecture.Arm64);
        await using var convergence = HostConvergenceRuntime.Create(
            delivery, runtimeStore, client, new MemoryArtifactSource(("sha256-" + hex, artifact)),
            converger, configuration, "gru", "test-1",
            observationTimeout: TimeSpan.FromSeconds(3),
            replaceLeaseDuration: TimeSpan.FromSeconds(3));
        var descriptor = AdmittedRoleCatalog.Get(HostRole.TerraBaseMember);
        var pass = convergence.ReconcileOnceAsync(HostRole.TerraBaseMember, descriptor, CancellationToken.None);

        // A peer host must never acquire the lease while the holder is alive and renewing;
        // probing starts only once the holder demonstrably holds it (first converge underway).
        await converger.FirstConvergeStarted;
        await using var peer = HostConvergenceRuntime.Create(
            delivery, runtimeStore, client, new MemoryArtifactSource(), new FakeConverger(),
            configuration, "gru", "test-2", observationTimeout: TimeSpan.FromSeconds(3));
        while (!pass.IsCompleted)
        {
            await using var stolen = await peer.AcquireReplaceLeaseAsync(descriptor, CancellationToken.None);
            await Assert.That(stolen).IsNull();
            // The probe itself is KV traffic against the same fixture as the renewals, so
            // it stays slow enough not to starve the holder's renewal loop.
            await Task.Delay(500);
        }
        await pass;

        var observation = await ReadObservationAsync(runtimeStore, "terrabase-server");
        await Assert.That(observation!.State).IsEqualTo("converged");
    }

    [Test]
    public async Task LosingTheReplaceLeaseMidAttemptAbortsTheAttemptWithoutClaimingConvergence()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var installRoot = Path.Combine(server.Directory, "artifacts");
        var artifact = Encoding.UTF8.GetBytes("steal-me");
        var hex = Convert.ToHexStringLower(SHA256.HashData(artifact));
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{hex}");

        var converger = new FakeConverger { ConvergeDelay = TimeSpan.FromSeconds(5) };
        await using var convergence = HostConvergenceRuntime.Create(
            delivery, runtimeStore, client, new MemoryArtifactSource(("sha256-" + hex, artifact)),
            converger, new HostConvergenceConfiguration(
                [HostRole.TerraBaseMember], "production", installRoot, HostArchitecture.Arm64),
            "gru", "test-1",
            observationTimeout: TimeSpan.FromSeconds(3),
            replaceLeaseDuration: TimeSpan.FromSeconds(1));
        var pass = convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);

        // Another host force-owns the lease while this holder is still working: the holder's
        // renewal must notice, abort the attempt, and never claim convergence.
        await Task.Delay(300);
        await runtimeStore.PutAsync("host.replace.terrabase-server", JsonSerializer.Serialize(
            new HostConvergenceReplaceLease("gru.peer-host", DateTimeOffset.UtcNow + TimeSpan.FromMinutes(5)),
            HostConvergenceJsonContext.Default.HostConvergenceReplaceLease));

        await Assert.That(async () => await pass).Throws<OperationCanceledException>();
        var observation = await ReadObservationAsync(runtimeStore, "terrabase-server");
        await Assert.That(observation).IsNull();
    }

    [Test]
    public async Task AnExpiredSelfOwnedReplaceLeaseIsReacquirableByTheSameRestartedHolder()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (_, runtimeStore, _) = server.Stores();
        var descriptor = AdmittedRoleCatalog.Get(HostRole.TerraBaseMember);
        var convergence = StartConvergence(server);
        var key = "host.replace.terrabase-server";

        string Lease(string holder, DateTimeOffset expiresAt) => JsonSerializer.Serialize(
            new HostConvergenceReplaceLease(holder, expiresAt),
            HostConvergenceJsonContext.Default.HostConvergenceReplaceLease);

        // A live lease — even one still held under our own name — is never acquirable.
        await runtimeStore.PutAsync(key, Lease("gru.test-1", DateTimeOffset.UtcNow + TimeSpan.FromMinutes(1)));
        await Assert.That(await convergence.AcquireReplaceLeaseAsync(descriptor, CancellationToken.None)).IsNull();

        // A crashed peer's expired lease is taken over.
        await runtimeStore.PutAsync(key, Lease("gru.other-host", DateTimeOffset.UtcNow - TimeSpan.FromSeconds(1)));
        await using var taken = await convergence.AcquireReplaceLeaseAsync(descriptor, CancellationToken.None);
        await Assert.That(taken).IsNotNull();

        // This instance crashed mid-replacement and left its OWN lease behind: once expired it
        // re-acquires it, so its member does not stay down until the next digest admission.
        await runtimeStore.PutAsync(key, Lease("gru.test-1", DateTimeOffset.UtcNow - TimeSpan.FromSeconds(1)));
        await using var reacquired = await convergence.AcquireReplaceLeaseAsync(descriptor, CancellationToken.None);
        await Assert.That(reacquired).IsNotNull();
    }

    [Test]
    public async Task AFailedRollbackReportsRollbackFailedAndKeepsThePreviousMarker()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var installRoot = Path.Combine(server.Directory, "artifacts");
        var good = Encoding.UTF8.GetBytes("known-good-binary");
        var broken = Encoding.UTF8.GetBytes("crash-looping-binary");
        var goodHex = Convert.ToHexStringLower(SHA256.HashData(good));
        var brokenHex = Convert.ToHexStringLower(SHA256.HashData(broken));
        var source = new MemoryArtifactSource(
            ("sha256-" + goodHex, good),
            ("sha256-" + brokenHex, broken));

        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{goodHex}");
        var converger = new FakeConverger();
        await using var convergence = StartConvergence(
            delivery, runtimeStore, client, installRoot, source, converger);
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);

        // Both the replacement AND the restore attempt fail their observations.
        converger.FailWhenRunning(brokenHex);
        converger.FailWhenRunning(goodHex);
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{brokenHex}");
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);

        var observation = await ReadObservationAsync(runtimeStore, "terrabase-server");
        await Assert.That(observation!.State).IsEqualTo("rollback-failed");
        await Assert.That(observation.Digest).IsEqualTo($"sha256:{brokenHex}");
        await Assert.That(observation.Error).IsNotNull();
        // The marker still names the last digest that actually converged, so the next pass
        // retries the un-rolled-back replacement from it.
        var marker = JsonSerializer.Deserialize<JsonElement>(
            await File.ReadAllTextAsync(Path.Combine(installRoot, "terrabase-server", "current.json")));
        await Assert.That(marker.GetProperty("digest").GetString()).IsEqualTo($"sha256:{goodHex}");
        await Assert.That(converger.ConvergedPlans.Last().ArtifactDigest!.Value).IsEqualTo(goodHex);
    }

    [Test]
    public async Task AnAutoRestartingReplacementNeverCountsAsConvergedAndRollsBack()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var installRoot = Path.Combine(server.Directory, "artifacts");
        var good = Encoding.UTF8.GetBytes("known-good-binary");
        var crashLooping = Encoding.UTF8.GetBytes("auto-restart-looping-binary");
        var goodHex = Convert.ToHexStringLower(SHA256.HashData(good));
        var crashHex = Convert.ToHexStringLower(SHA256.HashData(crashLooping));
        var source = new MemoryArtifactSource(
            ("sha256-" + goodHex, good),
            ("sha256-" + crashHex, crashLooping));

        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{goodHex}");
        var converger = new FakeConverger();
        await using var convergence = FastConvergence(delivery, runtimeStore, client, installRoot, source, converger);
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);

        // The replacement binary execs then dies; Restart=always holds the unit in
        // activating/auto-restart (Starting, no live main PID) indefinitely.
        converger.HoldInAutoRestart(crashHex);
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{crashHex}");
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);

        // A merely-starting unit never releases the cycle as converged and serving: the
        // pass must report the restored previous digest, never the crash-looping one.
        var observation = await ReadObservationAsync(runtimeStore, "terrabase-server");
        await Assert.That(observation!.State).IsEqualTo("rolled-back");
        await Assert.That(observation.Digest).IsEqualTo($"sha256:{goodHex}");
        await Assert.That(converger.ConvergedPlans.Last().ArtifactDigest!.Value).IsEqualTo(goodHex);
    }

    [Test]
    public async Task AnAutoRestartingUnitIsNotServingSoThePassDoesNotEarlyReturn()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var installRoot = Path.Combine(server.Directory, "artifacts");
        var good = Encoding.UTF8.GetBytes("serving-then-crash-looping");
        var goodHex = Convert.ToHexStringLower(SHA256.HashData(good));

        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{goodHex}");
        var converger = new FakeConverger();
        await using var convergence = FastConvergence(
            delivery, runtimeStore, client, installRoot,
            new MemoryArtifactSource(("sha256-" + goodHex, good)), converger);
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);
        var converged = converger.ConvergedPlans.Count;

        // The serving unit crashes and systemd holds it in auto-restart while the desired
        // digest is unchanged: a starting unit must not count as serving, so the pass
        // replaces it instead of passively early-returning.
        converger.HoldInAutoRestart(goodHex);
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);
        await Assert.That(converger.ConvergedPlans.Count).IsGreaterThan(converged);
        // It never reaches a running observation again: the cycle (and its own restore)
        // fails rather than claiming convergence over a crash-looping unit.
        var observation = await ReadObservationAsync(runtimeStore, "terrabase-server");
        await Assert.That(observation!.State).IsEqualTo("rollback-failed");
    }

    [Test]
    public async Task AFailedConvergeAndRollbackCycleBacksOffTheNextAttemptDurably()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var installRoot = Path.Combine(server.Directory, "artifacts");
        var good = Encoding.UTF8.GetBytes("known-good-binary");
        var broken = Encoding.UTF8.GetBytes("crash-looping-binary");
        var goodHex = Convert.ToHexStringLower(SHA256.HashData(good));
        var brokenHex = Convert.ToHexStringLower(SHA256.HashData(broken));
        var source = new MemoryArtifactSource(
            ("sha256-" + goodHex, good),
            ("sha256-" + brokenHex, broken));

        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{goodHex}");
        var converger = new FakeConverger();
        await using var convergence = FastConvergence(delivery, runtimeStore, client, installRoot, source, converger);
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);

        // The poisoned digest fails its cycle and the healthy previous unit is restored.
        converger.FailWhenRunning(brokenHex);
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{brokenHex}");
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);
        var actionsAfterFailedCycle = converger.Actions.Count;

        // The very next pass must NOT re-stop the restored unit for the same poisoned
        // digest: the failed cycle left a durable backoff.
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);
        await Assert.That(converger.Actions.Count).IsEqualTo(actionsAfterFailedCycle);

        var entry = await runtimeStore.GetEntryAsync<string>("host.backoff.test-1.terrabase-server");
        entry.EnsureSuccess();
        var backoff = JsonSerializer.Deserialize<HostConvergenceBackoff>(
            entry.Value!, HostConvergenceJsonContext.Default.HostConvergenceBackoff);
        await Assert.That(backoff!.Failures).IsEqualTo(1);
        await Assert.That(backoff.Digest).IsEqualTo($"sha256:{brokenHex}");
        await Assert.That(backoff.NotBefore).IsGreaterThan(DateTimeOffset.UtcNow);
    }

    [Test]
    public async Task BackoffEscalatesAcrossFailedCyclesAndAConvergingCycleResets()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var installRoot = Path.Combine(server.Directory, "artifacts");
        var good = Encoding.UTF8.GetBytes("known-good-binary");
        var broken = Encoding.UTF8.GetBytes("crash-looping-binary");
        var repaired = Encoding.UTF8.GetBytes("repaired-binary");
        var goodHex = Convert.ToHexStringLower(SHA256.HashData(good));
        var brokenHex = Convert.ToHexStringLower(SHA256.HashData(broken));
        var repairedHex = Convert.ToHexStringLower(SHA256.HashData(repaired));
        var source = new MemoryArtifactSource(
            ("sha256-" + goodHex, good),
            ("sha256-" + brokenHex, broken),
            ("sha256-" + repairedHex, repaired));

        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{goodHex}");
        var converger = new FakeConverger();
        await using var convergence = FastConvergence(delivery, runtimeStore, client, installRoot, source, converger);
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);

        // A backoff ladder persisted by a previous process: three failures against the
        // broken digest, already expired, so the next pass goes through and escalates it.
        await runtimeStore.PutAsync("host.backoff.test-1.terrabase-server", JsonSerializer.Serialize(
            new HostConvergenceBackoff(
                $"sha256:{brokenHex}", 3, DateTimeOffset.UtcNow - TimeSpan.FromSeconds(1)),
            HostConvergenceJsonContext.Default.HostConvergenceBackoff));
        converger.FailWhenRunning(brokenHex);
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{brokenHex}");
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);

        var entry = await runtimeStore.GetEntryAsync<string>("host.backoff.test-1.terrabase-server");
        entry.EnsureSuccess();
        var backoff = JsonSerializer.Deserialize<HostConvergenceBackoff>(
            entry.Value!, HostConvergenceJsonContext.Default.HostConvergenceBackoff);
        await Assert.That(backoff!.Failures).IsEqualTo(4);
        // 30s doubled three times = 4 minutes, well under the 15-minute cap.
        await Assert.That(backoff.NotBefore - DateTimeOffset.UtcNow).IsGreaterThan(TimeSpan.FromMinutes(3));
        await Assert.That(backoff.NotBefore - DateTimeOffset.UtcNow).IsLessThan(TimeSpan.FromMinutes(5));
        var actionsAfterCycle = converger.Actions.Count;

        // The escalated window actually gates the next pass.
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);
        await Assert.That(converger.Actions.Count).IsEqualTo(actionsAfterCycle);

        // A different admitted digest (the operator's remedy) is not the broken digest's
        // backoff, and a cycle that converges clears the ladder entirely.
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{repairedHex}");
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);
        var observation = await ReadObservationAsync(runtimeStore, "terrabase-server");
        await Assert.That(observation!.State).IsEqualTo("converged");
        await Assert.That(observation.Digest).IsEqualTo($"sha256:{repairedHex}");
        await Assert.That(async () =>
        {
            var cleared = await runtimeStore.GetEntryAsync<string>("host.backoff.test-1.terrabase-server");
            cleared.EnsureSuccess();
        }).Throws<Exception>();
    }

    [Test]
    public async Task APersistentlyFailingReconcilePassIsLoggedWhileTheLoopRetries()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        // Undecodable desired state makes every pass throw before any durable side effect.
        await delivery.PutAsync(
            DirectDeliveryTargetKey.For("terrabase-server", "production", "gru"), "not-json");

        // TUnit captures Console.Error per test, including the background loop's writes.
        await using var convergence = HostConvergenceRuntime.Start(
            delivery, runtimeStore, client, new MemoryArtifactSource(), new FakeConverger(),
            new HostConvergenceConfiguration(
                [HostRole.TerraBaseMember], "production",
                Path.Combine(server.Directory, "artifacts"), HostArchitecture.Arm64),
            "gru", "test-1", observationTimeout: TimeSpan.FromSeconds(3));
        var output = TestContext.Current!.Output;
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
        while (DateTime.UtcNow < deadline && !output.GetErrorOutput().Contains("Host convergence pass"))
            await Task.Delay(100);
        await Assert.That(output.GetErrorOutput())
            .Contains("Host convergence pass for TerraBaseMember failed (JsonException)");
    }

    [Test]
    public async Task AFailedObservationReportDoesNotSuppressTheNextPublish()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var installRoot = Path.Combine(server.Directory, "artifacts");
        var artifact = Encoding.UTF8.GetBytes("reported-on-the-second-pass");
        var hex = Convert.ToHexStringLower(SHA256.HashData(artifact));
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{hex}");

        var failing = DispatchProxy.Create<INatsKVStore, FailingReportRuntimeStore>();
        var store = (FailingReportRuntimeStore)(object)failing;
        store.Inner = runtimeStore;
        store.FailNextWrite = true;
        await server.UseReportStoreAsync(failing);

        var converger = new FakeConverger();
        await using var convergence = HostConvergenceRuntime.Create(
            delivery, runtimeStore, client, new MemoryArtifactSource(("sha256-" + hex, artifact)),
            converger, new HostConvergenceConfiguration(
                [HostRole.TerraBaseMember], "production", installRoot, HostArchitecture.Arm64),
            "gru", "test-1", observationTimeout: TimeSpan.FromSeconds(3));

        // The durable observation put fails: the pass must fail with the marker still absent,
        // so the next pass cannot early-return on an unreported convergence.
        await Assert.That(async () =>
        {
            await convergence.ReconcileOnceAsync(
                HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);
        }).Throws<Exception>();
        await Assert.That(File.Exists(Path.Combine(installRoot, "terrabase-server", "current.json"))).IsFalse();

        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);

        var observation = await ReadObservationAsync(runtimeStore, "terrabase-server");
        await Assert.That(observation!.State).IsEqualTo("converged");
        await Assert.That(File.Exists(Path.Combine(installRoot, "terrabase-server", "current.json"))).IsTrue();
    }

    /// <summary>KV store proxy failing the next report write once, proving report-before-marker ordering.</summary>
    private class FailingReportRuntimeStore : DispatchProxy
    {
        public INatsKVStore? Inner { get; set; }

        public bool FailNextWrite { get; set; }

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            if (targetMethod!.Name is "CreateAsync" or "UpdateAsync" && FailNextWrite)
            {
                FailNextWrite = false;
                throw new NatsKVException("The runtime observation store is unavailable.");
            }
            return targetMethod.Invoke(Inner, args);
        }
    }

    private static HostConvergenceRuntime StartConvergence(ConvergenceNatsServer server) =>
        StartConvergence(server.Stores().Item1, server.Stores().Item2, server.Stores().Item3,
            Path.Combine(server.Directory, "artifacts"), new MemoryArtifactSource(), new FakeConverger());

    /// <summary>A convergence runtime with a millisecond observation cadence for failure-path tests.</summary>
    private static HostConvergenceRuntime FastConvergence(
        INatsKVStore delivery,
        INatsKVStore runtimeStore,
        NATS.Client.Core.INatsConnection connection,
        string installRoot,
        IHostArtifactSource source,
        IHostRuntimeConverger converger)
    {
        var convergence = HostConvergenceRuntime.Create(
            delivery,
            runtimeStore,
            connection,
            source,
            converger,
            new HostConvergenceConfiguration(
                [HostRole.TerraBaseMember],
                "production",
                installRoot,
                HostArchitecture.Arm64),
            "gru",
            "test-1",
            observationTimeout: TimeSpan.FromMilliseconds(200));
        convergence.ObservationPollInterval = TimeSpan.FromMilliseconds(20);
        return convergence;
    }

    private static HostConvergenceRuntime StartConvergence(
        INatsKVStore delivery,
        INatsKVStore runtimeStore,
        NATS.Client.Core.INatsConnection connection,
        string installRoot,
        IHostArtifactSource source,
        IHostRuntimeConverger converger,
        IHostAdmissionGate? admission = null) =>
        HostConvergenceRuntime.Create(
            delivery,
            runtimeStore,
            connection,
            source,
            converger,
            new HostConvergenceConfiguration(
                [HostRole.TerraBaseMember],
                "production",
                installRoot,
                HostArchitecture.Arm64),
            "gru",
            "test-1",
            observationTimeout: TimeSpan.FromSeconds(3),
            admission: admission);

    internal static async Task<HostConvergenceObservation?> ReadObservationAsync(
        INatsKVStore runtimeStore,
        string artifactKey)
    {
        try
        {
            var entry = await runtimeStore.GetEntryAsync<string>($"host.test-1.{artifactKey}");
            entry.EnsureSuccess();
            return JsonSerializer.Deserialize<HostConvergenceObservation>(
                entry.Value!, HostConvergenceJsonContext.Default.HostConvergenceObservation);
        }
        catch (NatsKVException)
        {
            return null;
        }
    }

    private sealed class FakeConverger : IHostRuntimeConverger
    {
        public Task? ConvergeBarrier { get; init; }
        private readonly List<HostRuntimePlan> plans = [];
        private readonly List<string> actions = [];
        private readonly HashSet<string> failingHexes = [];
        private readonly HashSet<string> autoRestartHexes = [];

        public IReadOnlyList<HostRuntimePlan> ConvergedPlans => plans;

        /// <summary>Ordered action log ("stop"/"converge") proving replacement ordering.</summary>
        public IReadOnlyList<string> Actions => actions;

        /// <summary>Simulates an attempt that outlives the replace lease duration.</summary>
        public TimeSpan? ConvergeDelay { get; set; }

        private readonly TaskCompletionSource firstConverge =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <summary>Completes when the first converge attempt begins (the lease is held by then).</summary>
        public Task FirstConvergeStarted => firstConverge.Task;

        public void FailWhenRunning(string hex) => failingHexes.Add(hex);

        /// <summary>Simulates a crash-looping unit systemd holds in activating/auto-restart.</summary>
        public void HoldInAutoRestart(string hex) => autoRestartHexes.Add(hex);

        public Task StopAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
        {
            actions.Add("stop");
            return Task.CompletedTask;
        }

        public async Task ConvergeAsync(HostRuntimePlan plan, CancellationToken cancellationToken)
        {
            firstConverge.TrySetResult();
            if (ConvergeBarrier is { } barrier) await barrier.WaitAsync(cancellationToken);
            if (ConvergeDelay is { } delay)
                await Task.Delay(delay, cancellationToken);
            plans.Add(plan);
            actions.Add("converge");
        }

        public Task<SystemdAllocationObservation> ObserveAsync(
            HostRuntimePlan plan,
            CancellationToken cancellationToken)
        {
            var hex = plan.ArtifactDigest!.Value;
            var failed = failingHexes.Contains(hex);
            var autoRestart = autoRestartHexes.Contains(hex);
            return Task.FromResult(new SystemdAllocationObservation(
                plan.Systemd!.UnitName,
                failed ? SystemdAllocationState.Failed :
                    autoRestart ? SystemdAllocationState.Starting : SystemdAllocationState.Running,
                failed || autoRestart ? null : 4242,
                failed ? "exit-code" : autoRestart ? "auto-restart" : "success"));
        }
    }

    private sealed class FakeAdmissionGate(
        bool authorized,
        bool credentialsReady,
        string reason) : IHostAdmissionGate
    {
        public bool Authorized { get; set; } = authorized;
        public bool CredentialsReady { get; set; } = credentialsReady;
        public string Reason { get; set; } = reason;

        public ValueTask<HostAdmissionSnapshot> ObserveAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(new HostAdmissionSnapshot(Authorized, CredentialsReady, Reason));
    }

    [Test]
    public async Task MemberHealthGaugesRideTheObservationAndSchemaOneStaysValid()
    {
        await using var server = await ConvergenceNatsServer.StartAsync();
        var (delivery, runtimeStore, client) = server.Stores();
        var installRoot = Path.Combine(server.Directory, "artifacts");
        var artifact = Encoding.UTF8.GetBytes("member-health-binary");
        var hex = Convert.ToHexStringLower(SHA256.HashData(artifact));
        await server.PutDesiredDigest("terrabase-server", "production", "gru", $"sha256:{hex}");
        await using var member = await MemberHealthListener.StartAsync();

        var convergence = HostConvergenceRuntime.Create(
            delivery,
            runtimeStore,
            client,
            new MemoryArtifactSource(("sha256-" + hex, artifact)),
            new FakeConverger(),
            new HostConvergenceConfiguration(
                [HostRole.TerraBaseMember],
                "production",
                installRoot,
                HostArchitecture.Arm64,
                MemberObservabilityUrl: member.Url),
            "gru",
            "test-1",
            observationTimeout: TimeSpan.FromSeconds(3));
        await convergence.ReconcileOnceAsync(
            HostRole.TerraBaseMember, AdmittedRoleCatalog.Get(HostRole.TerraBaseMember), CancellationToken.None);

        var observation = await ReadObservationAsync(runtimeStore, "terrabase-server");
        await Assert.That(observation!.SchemaVersion)
            .IsEqualTo(HostConvergenceObservation.CurrentSchemaVersion);
        await Assert.That(observation.MemberUp).IsTrue();
        await Assert.That(observation.MemberReplicationLagSequences).IsEqualTo(7);
        await Assert.That(observation.MemberRole).IsEqualTo("leader");
        await Assert.That(observation.MemberPeerAckCount).IsEqualTo(2);
        await Assert.That(observation.MemberMinReplicas).IsEqualTo(1);

        // Schema 1 (pre-member-health) documents stay valid; the gauges are schema 2's alone.
        var schemaOne = observation with { SchemaVersion = 1, MemberUp = null, MemberReplicationLagSequences = null, MemberRole = null, MemberPeerAckCount = null, MemberMinReplicas = null };
        schemaOne.Validate();
        await Assert.That(() => (schemaOne with { MemberUp = true }).Validate())
            .Throws<InvalidOperationException>();
    }

    /// <summary>A loopback listener that answers exactly like a TerraBase member's observability endpoint.</summary>
    private sealed class MemberHealthListener : IAsyncDisposable
    {
        private readonly HttpListener listener;
        private readonly Task accept;

        private MemberHealthListener(HttpListener listener, Task accept)
        {
            this.listener = listener;
            this.accept = accept;
            Url = listener.Prefixes.Single();
        }

        public string Url { get; }

        public static async Task<MemberHealthListener> StartAsync()
        {
            var port = GetFreeLoopbackPort();
            var listener = new HttpListener();
            listener.Prefixes.Add($"http://127.0.0.1:{port}/");
            listener.Start();
            var member = new MemberHealthListener(listener, Task.Run(() => AcceptLoopAsync(listener)));
            // The listener must answer before the converge pass scrapes it.
            using var probe = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
            for (var attempt = 0; attempt < 50; attempt++)
            {
                try
                {
                    using var response = await probe.GetAsync($"{member.Url}api/v1/health");
                    if (response.IsSuccessStatusCode)
                        return member;
                }
                catch (HttpRequestException)
                {
                }
                await Task.Delay(100);
            }
            await member.DisposeAsync();
            throw new TimeoutException("The member health listener never became ready.");
        }

        private static async Task AcceptLoopAsync(HttpListener listener)
        {
            while (listener.IsListening)
            {
                HttpListenerContext context;
                try
                {
                    context = await listener.GetContextAsync();
                }
                catch (HttpListenerException)
                {
                    return;
                }
                catch (ObjectDisposedException)
                {
                    return;
                }
                var path = context.Request.Url!.AbsolutePath;
                switch (path)
                {
                    case "/api/v1/health":
                        var health = Encoding.UTF8.GetBytes(
                            """{"role":"leader","peerAckCount":2,"minReplicas":1}""");
                        context.Response.ContentType = "application/json";
                        context.Response.OutputStream.Write(health);
                        break;
                    case "/health/ready":
                        break;
                    default:
                        var metrics = Encoding.UTF8.GetBytes(
                            "terrabase_replication_lag_sequences{member=\"a\"} 7\n");
                        context.Response.OutputStream.Write(metrics);
                        break;
                }
                context.Response.Close();
            }
        }

        private static int GetFreeLoopbackPort()
        {
            var probe = new TcpListener(IPAddress.Loopback, 0);
            probe.Start();
            var port = ((IPEndPoint)probe.LocalEndpoint).Port;
            probe.Stop();
            return port;
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                listener.Stop();
            }
            catch (ObjectDisposedException)
            {
            }
            try
            {
                await accept.WaitAsync(TimeSpan.FromSeconds(2));
            }
            catch (TimeoutException)
            {
            }
            listener.Close();
        }
    }

    private sealed class MemoryArtifactSource(params (string Name, byte[] Bytes)[] objects) : IHostArtifactSource
    {
        private readonly Dictionary<string, byte[]> stored =
            objects.ToDictionary(static value => value.Name, static value => value.Bytes, StringComparer.Ordinal);

        public Task CopyIntoAsync(string objectName, Stream destination, CancellationToken cancellationToken)
        {
            if (!stored.TryGetValue(objectName, out var bytes))
                throw new NATS.Client.ObjectStore.NatsObjNotFoundException("object");
            destination.Write(bytes, 0, bytes.Length);
            return Task.CompletedTask;
        }
    }

    private sealed class ConvergenceNatsServer : IAsyncDisposable
    {
        private readonly LocalNatsServerLease.Handle lease;
        private Process? nats;
        private NatsClient? client;
        private NatsClient? relayClient;
        private NATS.Client.KeyValueStore.INatsKVStore? delivery;
        private NATS.Client.KeyValueStore.INatsKVStore? runtimeStore;
        private HostObservationRelay? reports;
        private string url = string.Empty;

        private ConvergenceNatsServer(string directory, LocalNatsServerLease.Handle lease)
        {
            this.lease = lease;
            Directory = directory;
        }

        public string Directory { get; }

        public static async Task<ConvergenceNatsServer> StartAsync()
        {
            var lease = await LocalNatsServerLease.AcquireAsync();
            var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-host-convergence-{Guid.NewGuid():N}");
            ConvergenceNatsServer? server = null;
            try
            {
                System.IO.Directory.CreateDirectory(directory);
                var listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                var port = ((IPEndPoint)listener.LocalEndpoint).Port;
                listener.Stop();
                var configuration = Path.Combine(directory, "nats.conf");
                static string Permissions(NatsControlAccountScope scope) => JsonSerializer.Serialize(new
                {
                    publish = new { allow = scope.Publish }, subscribe = new { allow = scope.Subscribe }
                }, new JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
                var hostPermissions = Permissions(NatsControlAccountScope.Create(NatsControlAccountKind.HostAgent, "gru", "test-1"));
                var secondHostPermissions = Permissions(NatsControlAccountScope.Create(NatsControlAccountKind.HostAgent, "gru", "test-2"));
                var controllerPermissions = Permissions(NatsControlAccountScope.Create(NatsControlAccountKind.RegionalController, "gru"));
                await File.WriteAllTextAsync(configuration,
                    $"port: {port}\njetstream {{ store_dir: \"{Path.Combine(directory, "store")}\" }}\n" +
                    "authorization { users: [" +
                    "{user: \"controller\", password: \"synthetic-controller\"}," +
                    "{user: \"relay\", password: \"synthetic-relay\", permissions: " + controllerPermissions + "}," +
                    "{user: \"host-2\", password: \"synthetic-host-2\", permissions: " + secondHostPermissions + "}," +
                    "{user: \"host\", password: \"synthetic-host\", permissions: " + hostPermissions + "}] }\n");
                var containers = await ContainerizedNatsCluster.CreateAsync(directory, [port]);
                server = new ConvergenceNatsServer(directory, lease) { Containers = containers };
                server.nats = containers.Start(configuration);
                server.url = $"nats://127.0.0.1:{port}";
                server.client = new NatsClient(new NatsOpts
                {
                    Url = server.url,
                    AuthOpts = new NatsAuthOpts { Username = "controller", Password = "synthetic-controller" },
                    ConnectTimeout = TimeSpan.FromSeconds(5),
                    RequestTimeout = TimeSpan.FromSeconds(5)
                });
                for (var attempt = 1; ; attempt++)
                {
                    try
                    {
                        await server.client.ConnectAsync();
                        break;
                    }
                    catch (NatsException) when (attempt < 150)
                    {
                        if (server.nats.HasExited)
                            throw new InvalidOperationException("Fixture NATS exited: " + await server.nats.StandardError.ReadToEndAsync());
                        await Task.Delay(200);
                    }
                }
                await NatsOperationJournalProvisioner.ProvisionControllerTopologyAsync(
                    server.client, new NatsTopology("gru", 1, "test-1"), CancellationToken.None);
                var keyValue = server.client.CreateJetStreamContext().CreateKeyValueStoreContext();
                server.delivery = await keyValue.GetStoreAsync("ORCH_DELIVERY");
                server.runtimeStore = await keyValue.GetStoreAsync("ORCH_RUNTIME");
                // Control traffic uses the real controller manifest; the private store is
                // a separate injected controller handle. This is not full host-startup qualification.
                server.relayClient = server.RestrictedClient("relay");
                await server.relayClient.ConnectAsync();
                server.reports = await HostObservationRelay.StartAsync(server.relayClient.Connection, server.runtimeStore, "gru", CancellationToken.None);
                return server;
            }
            catch
            {
                if (server is not null)
                    await server.DisposeAsync();
                else
                    await new LocalNatsServerLease.DirectoryCleanupOwner(directory, lease).DisposeAsync();
                throw;
            }
        }

        private ContainerizedNatsCluster? Containers { get; set; }

        internal NatsClient RestrictedHost(string instance = "test-1") => RestrictedClient(instance == "test-1" ? "host" : "host-2");

        private NatsClient RestrictedClient(string user) => new(new NatsOpts
        {
            Url = url,
            AuthOpts = new NatsAuthOpts { Username = user, Password = "synthetic-" + user },
            ConnectTimeout = TimeSpan.FromSeconds(5),
            RequestTimeout = TimeSpan.FromSeconds(2)
        });

        internal Task RequireHostPublishDeniedAsync(string subject, CancellationToken cancellationToken) =>
            RequirePublishDeniedAsync("host", subject, cancellationToken);

        internal async Task RequirePublishDeniedAsync(string user, string subject, CancellationToken cancellationToken)
        {
            using var socket = new TcpClient();
            await socket.ConnectAsync("127.0.0.1", new Uri(url).Port, cancellationToken);
            await using var stream = socket.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
            await Assert.That(await reader.ReadLineAsync(cancellationToken)).StartsWith("INFO ");
            await stream.WriteAsync(Encoding.ASCII.GetBytes(
                $"CONNECT {{\"user\":\"{user}\",\"pass\":\"synthetic-{user}\"}}\r\n" +
                $"PUB {subject} 6\r\nforged\r\nPING\r\n"), cancellationToken);
            for (var line = 0; line < 8; line++)
            {
                var response = await reader.ReadLineAsync(cancellationToken);
                if (response?.StartsWith("-ERR", StringComparison.Ordinal) == true)
                {
                    await Assert.That(response).Contains("Permissions Violation");
                    await Assert.That(response).Contains(subject);
                    return;
                }
                if (response is null or "PONG") break;
            }
            throw new InvalidOperationException("NATS did not explicitly deny the host's forbidden publish.");
        }

        internal async Task UseReportStoreAsync(INatsKVStore store)
        {
            if (reports is not null) await reports.DisposeAsync();
            reports = await HostObservationRelay.StartAsync(relayClient!.Connection, store, "gru", CancellationToken.None);
        }

        internal HostReportRelaySnapshot ReportSnapshot => reports!.Snapshot;

        public (INatsKVStore, INatsKVStore, NATS.Client.Core.INatsConnection) Stores()
        {
            if (delivery is null || runtimeStore is null || client is null)
                throw new InvalidOperationException("The convergence NATS server is not started.");
            return (delivery, runtimeStore, client.Connection);
        }

        public async Task PutDesiredDigest(string service, string environment, string region, string digest) =>
            await delivery!.PutAsync(
                DirectDeliveryTargetKey.For(service, environment, region),
                JsonSerializer.Serialize(new
                {
                    artifactDigest = digest,
                    manifestDigest = "sha256:" + new string('a', 64),
                    kind = "service"
                }));

        public async ValueTask DisposeAsync()
        {
            if (reports is not null) await reports.DisposeAsync();
            if (relayClient is not null) await relayClient.DisposeAsync();
            if (client is not null) await client.DisposeAsync();
            if (nats is not null && Containers is not null) await Containers.StopAsync(nats);
            if (Containers is not null) await Containers.DisposeAsync();
            await new LocalNatsServerLease.DirectoryCleanupOwner(Directory, lease).DisposeAsync();
        }
    }
}
