using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using NATS.Client.Core;
using NATS.Client.KeyValueStore;
using NATS.Client.ObjectStore;
using NATS.Net;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

[NotInParallel("NatsR3")]
public sealed class RegionalHostArtifactTests
{
    private static readonly string Digest = "sha256:" + new string('a', 64);

    [Test]
    [Arguments("digest")]
    [Arguments("offset")]
    [Arguments("length")]
    [Arguments("epoch")]
    [Arguments("session")]
    [Arguments("nonce")]
    [Arguments("role")]
    [Arguments("time")]
    [Arguments("signature")]
    [Arguments("environment")]
    [Arguments("node")]
    [Arguments("generation")]
    public async Task Artifact_proof_binds_each_identity_scope_and_freshness_field(string mutation)
    {
        using var material = new SessionMaterial();
        var now = material.Clock.GetUtcNow();
        var request = RegionalHostArtifactRequest.Sign(material.Enroll(1), material.Authentication, new string('a', 32), 1,
            AdmittedRole.TerraBaseMember, Digest, 0, 1024, now);
        await Assert.That(request.HasValidProof("gru", now)).IsTrue();
        var document = JsonNode.Parse(request.Serialize())!;
        switch (mutation)
        {
            case "digest": document["ArtifactDigest"] = "sha256:" + new string('b', 64); break;
            case "offset": document["Offset"] = 512; break;
            case "length": document["Length"] = 512; break;
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
        var changed = JsonSerializer.Deserialize<RegionalHostArtifactRequest>(document.ToJsonString(), RegionalHostSessionAuthority.JsonOptions)!;
        await Assert.That(changed.HasValidProof("gru", now)).IsFalse();
    }

    [Test]
    public async Task Artifact_wire_rejects_unknown_missing_duplicate_fields_wrong_subjects_and_other_operation_signatures()
    {
        using var material = new SessionMaterial();
        var enrollment = material.Enroll(1);
        var now = material.Clock.GetUtcNow();
        var request = RegionalHostArtifactRequest.Sign(enrollment, material.Authentication, new string('a', 32), 1,
            AdmittedRole.TerraBaseMember, Digest, 0, 1024, now);
        var subject = RegionalHostArtifactRequest.Subject("gru", enrollment.NodeId);
        var reply = RegionalHostArtifactRequest.ReplySubject("gru", enrollment.NodeId, request.RequestId);
        bool Reads(string json, string requestSubject, string responseSubject, DateTimeOffset time) =>
            RegionalHostArtifactRequest.TryRead(json, requestSubject, responseSubject, "gru", time, out _);
        await Assert.That(Reads(request.Serialize(), subject, reply, now)).IsTrue();
        foreach (var json in new[] { "{\"Unknown\":true," + request.Serialize()[1..], "{\"Epoch\":1," + request.Serialize()[1..],
                     request.Serialize().Replace("\"Epoch\":1,", "", StringComparison.Ordinal), new string(' ', 16_385),
                     material.Request(enrollment).Serialize() })
            await Assert.That(Reads(json, subject, reply, now)).IsFalse();
        foreach (var invalidReply in new[] { "_INBOX.1", RegionalHostArtifactRequest.ReplySubject("gru", "host-2", request.RequestId),
                     RegionalHostArtifactRequest.ReplySubject("fra", enrollment.NodeId, request.RequestId) })
            await Assert.That(Reads(request.Serialize(), subject, invalidReply, now)).IsFalse();
        await Assert.That(Reads(request.Serialize(), RegionalHostArtifactRequest.Subject("gru", "host-2"), reply, now)).IsFalse();
        await Assert.That(Reads(request.Serialize(), subject, reply, now.AddTicks(-1))).IsFalse();
        await Assert.That(Reads(request.Serialize(), subject, reply, now.AddSeconds(10))).IsFalse();
        var wrongDomain = new RegionalHostArtifactRequest(1, enrollment, request.SessionId, 1, request.Role,
            Digest, 0, 1024, request.RequestId, now, material.Request(enrollment).Signature);
        await Assert.That(wrongDomain.HasValidProof("gru", now)).IsFalse();
        await Assert.That(() => RegionalHostArtifactRequest.Sign(enrollment, material.Authentication, request.SessionId, 1,
            AdmittedRole.Authentication, Digest, 0, 1024, now)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Response_binding_rejects_wrong_ranges_lengths_identity_and_expiry()
    {
        using var material = new SessionMaterial();
        var now = material.Clock.GetUtcNow();
        var request = RegionalHostArtifactRequest.Sign(material.Enroll(1), material.Authentication, new string('a', 32), 1,
            AdmittedRole.TerraBaseMember, Digest, 4, 2, now);
        var valid = new RegionalHostArtifactResponse(1, request.RequestId, request.RequestDigest, RegionalHostSessionDecision.Accepted,
            1, 1, now.AddSeconds(10), Digest, 4, 6, [1, 2], true);
        valid.RequireBinding(request, now);
        foreach (var changed in new[] { valid with { RequestId = new string('b', 32) }, valid with { RequestDigest = new string('c', 64) },
                     valid with { Epoch = 2 }, valid with { Generation = 2 }, valid with { ArtifactDigest = "sha256:" + new string('b', 64) },
                     valid with { Offset = 0 }, valid with { TotalBytes = 0 }, valid with { TotalBytes = RegionalArtifactCache.MaximumArtifactBytes + 1 },
                     valid with { Bytes = [] }, valid with { Bytes = [1, 2, 3] }, valid with { Bytes = null }, valid with { End = false },
                     valid with { ExpiresAt = now }, valid with { ExpiresAt = now.AddSeconds(11) },
                     valid with { Decision = RegionalHostSessionDecision.Revoked }, valid with { Decision = (RegionalHostSessionDecision)999 } })
            await Assert.That(() => changed.RequireBinding(request, now)).Throws<InvalidDataException>();
    }

    [Test]
    public async Task Restricted_R3_hosts_download_role_specific_chunks_without_private_store_grants_and_survive_cache_restart()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var store = await Store(harness, deadline.Token);
        var objects = await Objects(harness, deadline.Token);
        var bytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(2 * RegionalArtifactCache.MaximumChunkBytes + 17);
        var digest = RegionalArtifactCacheTests.Digest(bytes);
        await objects.PutAsync("sha256-" + digest[7..], bytes, deadline.Token);
        await Put(store, harness.First, digest, deadline.Token);
        for (var restart = 0; restart < 2; restart++)
        {
            using var cache = new RegionalArtifactCache(new NatsRegionalArtifactDownloader(objects));
            await using var service = await RegionalHostArtifactService.StartAsync(harness.Controller.Connection,
                new(store, harness.Authority, cache), deadline.Token);
            using var output = new MemoryStream();
            var source = Source(harness, harness.First);
            await source.CopyIntoAsync(harness.First.Role, "production", "gru", digest, output, deadline.Token);
            await Assert.That(output.ToArray().SequenceEqual(bytes)).IsTrue();
            await Assert.That((await Source(harness, harness.Second).SendAsync(
                harness.Second.Signer.SignArtifact(harness.Second.Role, digest, 0, 1), deadline.Token)).Decision)
                .IsEqualTo(RegionalHostSessionDecision.EnrollmentDenied);
            await Assert.That(() => source.CopyIntoAsync(harness.Second.Role, "production", "gru", digest, output, deadline.Token)).Throws<InvalidOperationException>();
            await Assert.That(() => source.CopyIntoAsync(harness.First.Role, "development", "gru", digest, output, deadline.Token)).Throws<InvalidOperationException>();
            await Assert.That(() => source.CopyIntoAsync(harness.First.Role, "production", "fra", digest, output, deadline.Token)).Throws<InvalidOperationException>();
            await Assert.That(async () => _ = await source.SendAsync(harness.Second.Signer.SignArtifact(harness.Second.Role, digest, 0, 1), deadline.Token))
                .Throws<InvalidOperationException>();
            while (service.Snapshot.Chunks != 3) await Task.Delay(5, deadline.Token);
            await Assert.That(service.Snapshot.Bytes).IsEqualTo(bytes.LongLength);
            await Assert.That(service.Snapshot.CacheEntries).IsEqualTo(1);
        }
        await using var probe = await harness.Cluster.ConnectAsync(harness.Cluster.HostAgent, cancellationToken: deadline.Token);
        await Assert.That(async () => _ = await probe.CreateJetStreamContext().CreateObjectStoreContext()
            .GetObjectStoreAsync("ORCH_ARTIFACTS", deadline.Token)).Throws<NatsException>();
        await objects.AddLinkAsync("sha256-" + Digest[7..], "sha256-" + digest[7..], deadline.Token);
        await Put(store, harness.First, Digest, deadline.Token);
        using var linkCache = new RegionalArtifactCache(new NatsRegionalArtifactDownloader(objects));
        await using var linkService = await RegionalHostArtifactService.StartAsync(harness.Controller.Connection,
            new(store, harness.Authority, linkCache), deadline.Token);
        var linked = await Source(harness, harness.First).SendAsync(harness.First.Signer.SignArtifact(harness.First.Role, Digest, 0, 1), deadline.Token);
        await Assert.That(linked.Decision).IsEqualTo(RegionalHostSessionDecision.InvalidStore);
        await Assert.That(linked.Bytes).IsNull();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Core_convergence_installs_only_verified_bytes_and_never_dispatches_corrupt_partial_artifacts(bool corruptTransport)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token, realTime: true);
        var store = await Store(harness, deadline.Token);
        var objects = await Objects(harness, deadline.Token);
        await using var desired = await RegionalHostDesiredService.StartAsync(harness.Controller.Connection, new(store, harness.Authority), deadline.Token);
        using var cache = new RegionalArtifactCache(new NatsRegionalArtifactDownloader(objects));
        var transport = new CorruptingReader(cache) { Corrupt = corruptTransport };
        await using var artifacts = await RegionalHostArtifactService.StartAsync(harness.Controller.Connection, new(store, harness.Authority, transport), deadline.Token);
        var host = harness.First;
        byte[] bytes = [1, 2, 3, 4, 5];
        var digest = RegionalArtifactCacheTests.Digest(bytes);
        var descriptor = AdmittedRoleCatalog.Get(host.Role);
        await Put(store, host, digest, deadline.Token);
        var root = Path.Combine(harness.Cluster.DirectoryPath, "artifact-convergence");
        var native = new Native();
        await using var cycleService = await RegionalHostCycleService.StartAsync(harness.Controller.Connection, new(store, harness.Authority), deadline.Token);
        var cycles = new NatsHostCycleCoordinator(host.Client.Connection, "gru", host.Node, () => host.Signer, harness.Material.Clock);
        // Runtime KV is still controller-supplied for the remaining restricted replacement-lease gate.
        await using var runtime = HostConvergenceRuntime.Create(cycles,
            new NatsHostDesiredArtifactSource(host.Client.Connection, "gru", host.Node, () => host.Signer, harness.Material.Clock),
            harness.Runtime, host.Publisher, Source(harness, host), native, new([host.Role], "production", root, HostArchitecture.X64),
            "gru", host.Node, admission: new Admission());
        await objects.PutAsync("sha256-" + digest[7..], corruptTransport ? bytes : new byte[] { 9, 8 }, deadline.Token);
        await runtime.ReconcileOnceAsync(host.Role, descriptor, deadline.Token);
        await Assert.That(native.Started).IsNull();
        await Assert.That(Directory.GetFiles(root, "*", SearchOption.AllDirectories)).IsEmpty();
        // A corrected immutable artifact gets a new digest and desired target; it does not overwrite a digest-addressed object.
        transport.Corrupt = false;
        bytes = [6, 7, 8, 9, 10];
        digest = RegionalArtifactCacheTests.Digest(bytes);
        await objects.PutAsync("sha256-" + digest[7..], bytes, deadline.Token);
        await Put(store, host, digest, deadline.Token);
        await runtime.ReconcileOnceAsync(host.Role, descriptor, deadline.Token);
        await Assert.That(native.Started).IsNotNull();
        await Assert.That((await File.ReadAllBytesAsync(native.Started!.Systemd!.Executable, deadline.Token)).SequenceEqual(bytes)).IsTrue();
    }

    [Test]
    [Arguments("target")]
    [Arguments("revoke")]
    [Arguments("expire")]
    public async Task Authority_rechecks_target_and_session_after_reading_bytes(string change)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var store = await Store(harness, deadline.Token);
        var host = harness.First;
        await Put(store, host, Digest, deadline.Token);
        var reader = new Reader();
        var authority = new RegionalHostArtifactAuthority(store, harness.Authority, reader);
        var read = authority.ReadAsync(host.Signer.SignArtifact(host.Role, Digest, 0, 1), deadline.Token);
        await reader.Started.Task.WaitAsync(deadline.Token);
        try
        {
            if (change == "target") await Put(store, host, "sha256:" + new string('b', 64), deadline.Token);
            if (change == "revoke") await harness.Authority.RevokeAsync(host.Node, 1, host.Lease.Epoch, deadline.Token);
            if (change == "expire") harness.Material.Clock.Advance(TimeSpan.FromSeconds(30));
        }
        finally { reader.Release.TrySetResult(new(1, [1])); }
        var response = await read;
        await Assert.That(response.Accepted).IsFalse();
        await Assert.That(response.Bytes).IsNull();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Stalled_reader_is_bounded_and_does_not_block_session_renewal(bool synchronous)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var store = await Store(harness, deadline.Token);
        await Put(store, harness.First, Digest, deadline.Token);
        var reader = new Reader { Synchronous = synchronous };
        var service = await RegionalHostArtifactService.StartAsync(harness.Controller.Connection, new(store, harness.Authority, reader), deadline.Token);
        try
        {
            for (var i = 0; i < 3; i++)
                await Assert.That((await Source(harness, harness.First).SendAsync(harness.First.Signer.SignArtifact(harness.First.Role, Digest, 0, 1), deadline.Token)).Decision)
                    .IsEqualTo(RegionalHostSessionDecision.StoreUnavailable);
            await Assert.That(reader.Calls).IsEqualTo(1);
            await Assert.That(service.Snapshot.InFlight).IsTrue();
            await Assert.That(service.Snapshot.RetryPending).IsTrue();
            harness.Material.Clock.Advance(TimeSpan.FromSeconds(1));
            var renewal = harness.Material.Request(harness.First.Request.Enrollment, harness.First.Request.SessionId, harness.First.Lease.Epoch);
            await Assert.That((await new NatsRegionalHostSessionClient(harness.First.Client.Connection, "gru", harness.First.Node)
                .SendAsync(renewal, deadline.Token)).Accepted).IsTrue();
        }
        finally
        {
            try { await service.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(2)); }
            finally { reader.Release.TrySetResult(new(1, [1])); }
        }
    }

    [Test]
    public async Task Host_transport_rejects_misbound_malformed_noncanonical_and_cancelled_replies()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var host = harness.First;
        await using var requests = await harness.Controller.Connection.SubscribeCoreAsync<string>(
            RegionalHostArtifactRequest.Subject("gru", host.Node), cancellationToken: deadline.Token);
        await harness.Controller.Connection.PingAsync(deadline.Token);
        foreach (var mutation in new[] { "nonce", "expiry", "offset", "length", "end", "unknown", "duplicate", "base64", "oversize", "cancel" })
        {
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
            var request = host.Signer.SignArtifact(host.Role, Digest, 0, 2);
            var pending = Source(harness, host).SendAsync(request, cancellation.Token);
            var incoming = await requests.Msgs.ReadAsync(deadline.Token);
            var response = new RegionalHostArtifactResponse(1, request.RequestId, request.RequestDigest, RegionalHostSessionDecision.Accepted,
                1, host.Lease.Epoch, harness.Material.Clock.GetUtcNow().AddSeconds(10), Digest, 0, 2, [1, 2], true);
            response = mutation switch
            {
                "nonce" => response with { RequestId = new string('b', 32) }, "expiry" => response with { ExpiresAt = harness.Material.Clock.GetUtcNow() },
                "offset" => response with { Offset = 1 }, "length" => response with { Bytes = [1] }, "end" => response with { End = false }, _ => response
            };
            var json = JsonSerializer.Serialize(response, RegionalHostSessionAuthority.JsonOptions);
            if (mutation == "unknown") json = "{\"unknown\":true," + json[1..];
            if (mutation == "duplicate") json = "{\"Offset\":0," + json[1..];
            if (mutation == "base64") json = json.Replace("AQI=", "AQI= ", StringComparison.Ordinal);
            if (mutation == "oversize") json = new string(' ', RegionalHostArtifactResponse.MaximumWireBytes + 1);
            if (mutation == "cancel") cancellation.Cancel();
            await harness.Controller.Connection.PublishAsync(incoming.ReplyTo!, json, cancellationToken: deadline.Token);
            if (mutation == "cancel") await Assert.That(async () => _ = await pending).Throws<OperationCanceledException>();
            else if (mutation is "unknown" or "duplicate") await Assert.That(async () => _ = await pending).Throws<JsonException>();
            else await Assert.That(async () => _ = await pending).Throws<InvalidDataException>();
        }
    }

    private static NatsHostArtifactSource Source(SignedHostReportHarness harness, SignedHostReportHarness.ReportHost host) =>
        new(host.Client.Connection, "gru", host.Node, () => host.Signer, harness.Material.Clock);
    private static ValueTask<INatsKVStore> Store(SignedHostReportHarness harness, CancellationToken token) =>
        harness.Controller.CreateJetStreamContext().CreateKeyValueStoreContext().GetStoreAsync("ORCH_DELIVERY", token);
    private static ValueTask<INatsObjStore> Objects(SignedHostReportHarness harness, CancellationToken token) =>
        harness.Controller.CreateJetStreamContext().CreateObjectStoreContext().GetObjectStoreAsync("ORCH_ARTIFACTS", token);
    private static async Task Put(INatsKVStore store, SignedHostReportHarness.ReportHost host, string digest, CancellationToken token) =>
        _ = await store.PutAsync(DirectDeliveryTargetKey.For(host.Artifact, "production", "gru"),
            JsonSerializer.Serialize(new { artifactDigest = digest, manifestDigest = digest, kind = "service" }), cancellationToken: token);

    [Test]
    public async Task Stale_targets_and_sessions_cannot_authorize_artifact_reads()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var store = await Store(harness, deadline.Token);
        var host = harness.First;
        await Put(store, host, Digest, deadline.Token);
        var key = DirectDeliveryTargetKey.For(host.Artifact, "production", "gru");
        var stale = await store.GetEntryAsync<string>(key, cancellationToken: deadline.Token);
        var proxy = DispatchProxy.Create<INatsKVStore, RegionalHostReportAuthorizationTests.StaleReplica>();
        var intercepted = (RegionalHostReportAuthorizationTests.StaleReplica)proxy;
        intercepted.Inner = store;
        intercepted.Entry = stale;
        intercepted.RemainingStaleReads = 2;
        await store.DeleteAsync(key, cancellationToken: deadline.Token);
        var reader = new Reader();
        reader.Release.TrySetResult(new(1, [1]));
        var authority = new RegionalHostArtifactAuthority(proxy, harness.Authority, reader);
        await Assert.That((await authority.ReadAsync(host.Signer.SignArtifact(host.Role, Digest, 0, 1), deadline.Token)).Decision)
            .IsEqualTo(RegionalHostSessionDecision.EnrollmentDenied);
        await Assert.That(reader.Calls).IsEqualTo(0);
        await Assert.That(intercepted.Confirmations).IsEqualTo(2);

        await Put(store, host, Digest, deadline.Token);
        var sessionProxy = DispatchProxy.Create<INatsKVStore, RegionalHostReportAuthorizationTests.StaleReplica>();
        var sessions = (RegionalHostReportAuthorizationTests.StaleReplica)sessionProxy;
        sessions.Inner = harness.Sessions;
        sessions.Entry = await harness.Sessions.GetEntryAsync<string>(RegionalHostSessionAuthority.Key(host.Node), cancellationToken: deadline.Token);
        sessions.RemainingStaleReads = 2;
        await harness.Authority.RevokeAsync(host.Node, 1, host.Lease.Epoch, deadline.Token);
        var revoked = new RegionalHostSessionAuthority(sessionProxy, harness.Material.Policy(), harness.Material.Clock);
        await Assert.That((await new RegionalHostArtifactAuthority(store, revoked, reader)
            .ReadAsync(host.Signer.SignArtifact(host.Role, Digest, 0, 1), deadline.Token)).Decision).IsEqualTo(RegionalHostSessionDecision.Revoked);
        await Assert.That(reader.Calls).IsEqualTo(0);
    }

    private sealed class Reader : IRegionalArtifactReader
    {
        internal bool Synchronous;
        internal int Calls;
        internal TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource<RegionalArtifactChunk> Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<RegionalArtifactChunk> ReadAsync(string digest, long offset, int length, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Calls);
            Started.TrySetResult();
            return Synchronous ? Task.FromResult(Release.Task.GetAwaiter().GetResult()) : Release.Task;
        }
    }

    private sealed class CorruptingReader(IRegionalArtifactReader inner) : IRegionalArtifactReader
    {
        internal bool Corrupt;
        public async Task<RegionalArtifactChunk> ReadAsync(string digest, long offset, int length, CancellationToken cancellationToken)
        {
            var chunk = await inner.ReadAsync(digest, offset, length, cancellationToken);
            if (Corrupt) chunk.Bytes[0] ^= 0xff;
            return chunk;
        }
    }

    private sealed class Admission : IHostAdmissionGate
    {
        public ValueTask<HostAdmissionSnapshot> ObserveAsync(CancellationToken cancellationToken) => ValueTask.FromResult(new HostAdmissionSnapshot(true, true, "test"));
    }

    private sealed class Native : IHostRuntimeConverger
    {
        internal HostRuntimePlan? Started;
        public Task ConvergeAsync(HostRuntimePlan plan, CancellationToken cancellationToken) { Started = plan; return Task.CompletedTask; }
        public Task StopAsync(HostRuntimePlan plan, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<SystemdAllocationObservation> ObserveAsync(HostRuntimePlan plan, CancellationToken cancellationToken) =>
            Task.FromResult(new SystemdAllocationObservation(plan.Systemd!.UnitName, SystemdAllocationState.Running, 123, "test"));
    }
}
