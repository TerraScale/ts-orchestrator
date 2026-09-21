using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using NATS.Client.Core;
using NATS.Client.KeyValueStore;
using NATS.Client.JetStream.Models;
using NATS.Net;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

[NotInParallel("NatsR3")]
public sealed class SignedHostReportTransportTests
{
    private static readonly string Digest = "sha256:" + new string('a', 64);

    [Test]
    public async Task Two_restricted_JWT_hosts_report_their_own_admitted_roles_and_cannot_publish_outside_their_scope()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        foreach (var host in new[] { harness.First, harness.Second })
        {
            await host.Publisher.PublishAsync(Admission(harness, host), deadline.Token);
            await host.Publisher.PublishAsync(Runtime(harness, host), deadline.Token);
            await Assert.That((await harness.Reader.ReadAsync(HostAdmissionObservation.Key(host.Node, host.Artifact), deadline.Token))?.Admission?.Ready).IsTrue();
            await Assert.That((await harness.Reader.ReadAsync($"host.{host.Node}.{host.Artifact}", deadline.Token))?.Runtime?.State).IsEqualTo("converged");
            // Forbidden generic request/reply can poison the SDK inbox/PING path. Keep
            // deliberate permission probes off the production report connection.
            foreach (var bucket in new[] { "ORCH_RUNTIME", "ORCH_DELIVERY", "ORCH_NODE_ENROLLMENTS" })
            {
                var identity = host == harness.First ? harness.Cluster.HostAgent : harness.Cluster.HostAgentTwo;
                await using var probe = await harness.Cluster.ConnectAsync(identity, cancellationToken: deadline.Token);
                await Assert.That(async () => _ = await probe.CreateJetStreamContext().CreateKeyValueStoreContext()
                    .GetStoreAsync(bucket, deadline.Token)).Throws<NatsException>();
            }
        }
        foreach (var subject in new[]
                 {
                     "$KV.ORCH_RUNTIME.host.host-2.ts-auth",
                     HostObservationRelay.ReportSubject("gru", "host-2"),
                     HostObservationRelay.ReportSubject("fra", "host-1")
                 })
            await RequirePublishDeniedAsync(harness.Cluster, harness.Cluster.HostAgent, subject, deadline.Token);
        await RequirePublishDeniedAsync(harness.Cluster, harness.Cluster.Controller,
            HostObservationRelay.ReportSubject("gru", "host-1"), deadline.Token);
        await RequirePublishDeniedAsync(harness.Cluster, harness.Cluster.Controller,
            HostObservationRelay.ReplySubject("fra", "host-1", new string('a', 32)), deadline.Token);
        // Positive controls after the denials still use the enrolled host identities.
        harness.Material.Clock.Advance(TimeSpan.FromSeconds(1));
        await harness.First.Publisher.PublishAsync(Runtime(harness, harness.First), deadline.Token);
        await harness.Second.Publisher.PublishAsync(Runtime(harness, harness.Second), deadline.Token);
    }

    [Test]
    public async Task Lost_ack_retries_bind_exact_bytes_while_stale_replicas_cannot_ack_a_withdrawn_report()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var host = harness.First;
        var report = host.Signer.Sign(Admission(harness, host));
        // Store without listening for the acknowledgement, simulating a lost reply.
        await SendRawAsync(host, report.Serialize(), report.RequestId, deadline.Token);
        await WaitUntilAsync(() => harness.Relay.Snapshot.Accepted == 1, deadline.Token);
        var stale = await harness.Runtime.GetEntryAsync<string>(report.Stored.Key, cancellationToken: deadline.Token);
        await host.Publisher.PublishAsync(report, deadline.Token);
        await harness.Reader.ReadAsync(report.Stored.Key, deadline.Token);
        await host.Publisher.PublishAsync(report, deadline.Token);
        var latest = await harness.Runtime.GetEntryAsync<string>(report.Stored.Key, cancellationToken: deadline.Token);
        await Assert.That(latest.Revision).IsGreaterThan(stale.Revision);
        await Assert.That(latest.Value).IsEqualTo(stale.Value);

        harness.Material.Clock.Advance(TimeSpan.FromSeconds(1));
        var withdrawal = host.Signer.Sign(Admission(harness, host) with { Ready = false });
        await host.Publisher.PublishAsync(withdrawal, deadline.Token);
        var proxy = DispatchProxy.Create<INatsKVStore, RegionalHostReportAuthorizationTests.StaleReplica>();
        var intercepted = (RegionalHostReportAuthorizationTests.StaleReplica)proxy;
        intercepted.Inner = harness.Runtime;
        intercepted.Entry = stale;
        intercepted.RemainingStaleReads = 2;
        await harness.UseReportStoreAsync(proxy, deadline.Token);
        await Assert.That(() => host.Publisher.PublishAsync(report, deadline.Token)).Throws<InvalidOperationException>();
        await Assert.That(intercepted.Confirmations).IsEqualTo(2);
        intercepted.RemainingStaleReads = 8;
        await Assert.That(() => host.Publisher.PublishAsync(report, deadline.Token)).Throws<InvalidOperationException>();
        await WaitUntilAsync(() => harness.Relay.Snapshot.Failed == 1, deadline.Token);
        await Assert.That(harness.Relay.Snapshot.RetryPending).IsTrue();
        await host.Publisher.PublishAsync(withdrawal, deadline.Token);
        await WaitUntilAsync(() => !harness.Relay.Snapshot.RetryPending, deadline.Token);
        await Assert.That((await harness.Reader.ReadAsync(report.Stored.Key, deadline.Token))?.Admission?.Ready).IsFalse();
    }

    [Test]
    public async Task Malformed_unsigned_tampered_and_misrouted_reports_never_replace_an_admitted_report()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var host = harness.First;
        var admission = Admission(harness, host);
        var report = host.Signer.Sign(admission);
        var json = report.Serialize();
        var mutations = new List<string>
        {
            "null", "{}", "{bad-json", new string('x', StoredHostReport.MaximumBytes + 1),
            JsonSerializer.Serialize(admission),
            "{\"Unexpected\":true," + json[1..], "{\"SchemaVersion\":2," + json[1..],
            (report with { SchemaVersion = 1 }).Serialize(), (report with { Proof = null! }).Serialize(),
            (report with { Admission = null }).Serialize(),
            (report with { Runtime = Runtime(harness, host) }).Serialize(),
            (report with { Admission = admission with { Ready = false } }).Serialize(),
            (report with { Admission = admission with { Instance = "host-2" } }).Serialize(),
            (report with { Admission = admission with { Cell = "fra" } }).Serialize(),
            (report with { Admission = admission with { Instance = null! } }).Serialize(),
            host.Signer.Sign(admission with { SchemaVersion = 99 }).Serialize(),
            host.Signer.Sign(admission with { ObservedAt = admission.ObservedAt.AddSeconds(1) }).Serialize(),
            host.Signer.Sign(admission with { ObservedAt = admission.ObservedAt.AddSeconds(-31) }).Serialize()
        };
        foreach (var (field, value) in new (string, System.Text.Json.Nodes.JsonNode)[]
                 {
                     ("Signature", System.Text.Json.Nodes.JsonValue.Create(Convert.ToBase64String(new byte[64]))!),
                     ("Epoch", System.Text.Json.Nodes.JsonValue.Create(999)!),
                     ("Kind", System.Text.Json.Nodes.JsonValue.Create((int)RegionalHostReportKind.Runtime)!),
                     ("Role", System.Text.Json.Nodes.JsonValue.Create((int)AdmittedRole.Authentication)!)
                 })
        {
            var mutated = JsonSerializer.SerializeToNode(report, HostObservationRelay.JsonOptions)!;
            mutated["Proof"]![field] = value;
            mutations.Add(mutated.ToJsonString());
        }
        foreach (var candidate in mutations)
        {
            var nonce = report.RequestId;
            try
            {
                using var parsed = JsonDocument.Parse(candidate);
                if (parsed.RootElement.ValueKind == JsonValueKind.Object && parsed.RootElement.TryGetProperty("Proof", out var proof) &&
                    proof.ValueKind == JsonValueKind.Object && proof.TryGetProperty("RequestId", out var requestId))
                    nonce = requestId.GetString()!;
            }
            catch (JsonException) { }
            await SendRawAsync(host, candidate, nonce, deadline.Token);
        }
        var invalidCount = mutations.Count;
        await SendRawAsync(host, json, new string('b', 32), deadline.Token);
        // A valid proof for host-2 sent on host-1's allowed route is rejected before storage.
        var other = harness.Second.Signer.Sign(Admission(harness, harness.Second));
        await SendRawAsync(host, other.Serialize(), other.RequestId, deadline.Token);
        await WaitUntilAsync(() => harness.Relay.Snapshot.Rejected == invalidCount + 2, deadline.Token);
        await host.Publisher.PublishAsync(host.Signer.Sign(admission), deadline.Token);
        await WaitUntilAsync(() => harness.Relay.Snapshot.Accepted == 1, deadline.Token);
        await Assert.That(harness.Relay.Snapshot.Accepted).IsEqualTo(1);
        await Assert.That((await harness.Reader.ReadAsync(report.Stored.Key, deadline.Token))?.Admission?.Ready).IsTrue();
        await Assert.That(await harness.Reader.ReadAsync(other.Stored.Key, deadline.Token)).IsNull();
        await Assert.That(harness.Relay.Completion.IsCompleted).IsFalse();
    }

    [Test]
    public async Task Revocation_expiry_replacement_generation_and_wrong_role_prevent_report_acceptance()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var host = harness.First;
        var original = host.Signer.Sign(Admission(harness, host));
        await host.Publisher.PublishAsync(original, deadline.Token);
        await Assert.That(() => host.Signer.Sign(Admission(harness, host) with { ArtifactKey = harness.Second.Artifact })).Throws<InvalidOperationException>();
        await Assert.That(await harness.Authority.RevokeAsync(host.Node, 1, host.Lease.Epoch, deadline.Token)).IsTrue();
        await Assert.That(() => host.Publisher.PublishAsync(original, deadline.Token)).Throws<InvalidOperationException>();
        harness.Material.Clock.Advance(RegionalHostSessionAuthority.LeaseLifetime);
        var request = harness.Material.Request(harness.Material.Enroll(2, node: host.Node));
        var lease = await new NatsRegionalHostSessionClient(host.Client.Connection, "gru", host.Node).SendAsync(request, deadline.Token);
        await Assert.That(lease.Accepted).IsTrue();
        await Assert.That(lease.Epoch).IsGreaterThan(host.Lease.Epoch);
        var signer = new RegionalHostReportSigner(request, lease, host.Authentication, harness.Material.Clock);
        var replacement = signer.Sign(Admission(harness, host));
        await host.Publisher.PublishAsync(replacement, deadline.Token);
        await Assert.That(() => host.Publisher.PublishAsync(original, deadline.Token)).Throws<InvalidOperationException>();
        harness.Material.Clock.Advance(RegionalHostSessionAuthority.LeaseLifetime);
        await Assert.That(() => signer.Sign(Admission(harness, host))).Throws<InvalidOperationException>();
        await Assert.That(() => host.Publisher.PublishAsync(replacement, deadline.Token)).Throws<InvalidOperationException>();
        await Assert.That(await harness.Reader.ReadAsync(original.Stored.Key, deadline.Token)).IsNull();
    }

    [Test]
    public async Task Another_hosts_success_cannot_hide_failed_persistence_and_deleted_ordering_state_cannot_be_resurrected()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var host = harness.First;
        var report = host.Signer.Sign(Admission(harness, host));
        var proxy = DispatchProxy.Create<INatsKVStore, FailOneWrite>();
        var failing = (FailOneWrite)proxy;
        failing.Inner = harness.Runtime;
        failing.FailKey = report.Stored.Key;
        await harness.UseReportStoreAsync(proxy, deadline.Token);
        await SendRawAsync(host, report.Serialize(), report.RequestId, deadline.Token);
        await WaitUntilAsync(() => harness.Relay.Snapshot.Failed == 1, deadline.Token);
        await harness.Second.Publisher.PublishAsync(Admission(harness, harness.Second), deadline.Token);
        await WaitUntilAsync(() => harness.Relay.Snapshot.Accepted == 1, deadline.Token);
        await Assert.That(harness.Relay.Snapshot.RetryPending).IsTrue();
        await host.Publisher.PublishAsync(report, deadline.Token);
        await WaitUntilAsync(() => !harness.Relay.Snapshot.RetryPending, deadline.Token);
        await harness.Runtime.DeleteAsync(report.Stored.Key, cancellationToken: deadline.Token);
        await Assert.That(() => host.Publisher.PublishAsync(report, deadline.Token)).Throws<InvalidOperationException>();
        await Assert.That(await harness.Reader.ReadAsync(report.Stored.Key, deadline.Token)).IsNull();
    }

    [Test]
    public async Task Relay_startup_has_its_own_deadline_and_preserves_caller_cancellation()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var withheld = DispatchProxy.Create<INatsKVStore, RegionalHostSessionConfigurationTests.WithheldStoreStatus>();
        await Assert.That(async () => _ = await HostObservationRelay.StartAsync(harness.Controller.Connection, withheld,
            harness.Authority, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(8))).Throws<TimeoutException>();
        using var caller = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
        await Assert.That(async () => _ = await HostObservationRelay.StartAsync(harness.Controller.Connection, withheld,
            harness.Authority, caller.Token).WaitAsync(TimeSpan.FromSeconds(2))).Throws<OperationCanceledException>();
    }

    [Test]
    public async Task Report_retention_requires_durable_acknowledged_R3_ordering_and_startup_checks_the_actual_store()
    {
        var canonical = NatsOperationJournalStore.CanonicalKeyValueStream(new NatsTopology("gru", 3, "controller-1").Runtime);
        HostObservationRelay.ValidateStoreConfiguration(canonical);
        foreach (var invalid in new[]
                 {
                     canonical with { MaxAge = HostObservationRelay.MaximumReportAge },
                     canonical with { NumReplicas = 1 }, canonical with { NoAck = true },
                     canonical with { Storage = StreamConfigStorage.Memory }, canonical with { Retention = StreamConfigRetention.Interest },
                     canonical with { Discard = StreamConfigDiscard.Old }, canonical with { MaxMsgs = 1 },
                     canonical with { AllowMsgTTL = true }, canonical with { SubjectDeleteMarkerTTL = TimeSpan.FromSeconds(1) }
                 })
            await Assert.That(() => HostObservationRelay.ValidateStoreConfiguration(invalid)).Throws<InvalidOperationException>();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        await harness.StopRelayAsync();
        await using var infrastructure = await harness.Cluster.ConnectAsync(harness.Cluster.Infrastructure, cancellationToken: deadline.Token);
        var configuration = (await harness.Runtime.GetStatusAsync(deadline.Token)).Info.Config;
        await infrastructure.CreateJetStreamContext().UpdateStreamAsync(configuration with { MaxAge = HostObservationRelay.MaximumReportAge, DuplicateWindow = TimeSpan.FromSeconds(1) }, deadline.Token);
        await Assert.That(async () => _ = await HostObservationRelay.StartAsync(harness.Controller.Connection,
            harness.Runtime, harness.Authority, deadline.Token)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Publisher_rejects_acknowledgements_not_bound_to_the_exact_envelope()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await using var harness = await SignedHostReportHarness.StartAsync(deadline.Token);
        var report = harness.First.Signer.Sign(Admission(harness, harness.First));
        await harness.StopRelayAsync();
        await using var requests = await harness.Controller.Connection.SubscribeCoreAsync<string>(
            HostObservationRelay.ReportSubject("gru", harness.First.Node), cancellationToken: deadline.Token);
        await harness.Controller.Connection.PingAsync(deadline.Token);
        var valid = new HostReportAcknowledgement(2, report.RequestId, report.Digest, true, null);
        var json = JsonSerializer.Serialize(valid, HostObservationRelay.JsonOptions);
        foreach (var response in new[]
                 {
                     "null", "{}", new string('x', 4097),
                     JsonSerializer.Serialize(valid with { SchemaVersion = 1 }),
                     JsonSerializer.Serialize(valid with { RequestId = new string('b', 32) }),
                     JsonSerializer.Serialize(valid with { ReportDigest = new string('b', 64) }),
                     JsonSerializer.Serialize(valid with { Accepted = false }),
                     JsonSerializer.Serialize(valid with { Error = "rejected" }),
                     "{\"SchemaVersion\":2," + json[1..], "{\"Unexpected\":1," + json[1..]
                 })
        {
            var publishing = harness.First.Publisher.PublishAsync(report, deadline.Token);
            var request = await requests.Msgs.ReadAsync(deadline.Token);
            await harness.Controller.Connection.PublishAsync(request.ReplyTo!, response, cancellationToken: deadline.Token);
            var error = await Assert.That(() => publishing).Throws<Exception>();
            await Assert.That(error is InvalidDataException or InvalidOperationException or JsonException).IsTrue();
        }
        var accepted = harness.First.Publisher.PublishAsync(report, deadline.Token);
        var last = await requests.Msgs.ReadAsync(deadline.Token);
        await harness.Controller.Connection.PublishAsync(last.ReplyTo!, json, cancellationToken: deadline.Token);
        await accepted;
    }

    [Test]
    public async Task Publisher_deadline_bounds_a_withheld_PONG_and_preserves_caller_cancellation()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var stopping = new CancellationTokenSource();
        var serving = RegionalHostSessionAuthorityTests.ServeHandshakeOnlyAsync(listener, stopping.Token);
        try
        {
            await using var connection = new NatsConnection(NatsOpts.Default with
            {
                Url = $"nats://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}", PingInterval = TimeSpan.FromHours(1)
            });
            await connection.ConnectAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(3));
            using var material = new SessionMaterial();
            var request = material.Request(material.Enroll(1));
            var lease = new RegionalHostSessionResponse(2, request.RequestId, request.RequestDigest, RegionalHostSessionDecision.Accepted,
                1, 1, request.IssuedAt + RegionalHostSessionAuthority.LeaseLifetime);
            var signer = new RegionalHostReportSigner(request, lease, material.Authentication, material.Clock);
            var publisher = new NatsHostObservationPublisher(connection, "gru", request.Enrollment.NodeId, () => signer);
            var report = new HostAdmissionObservation(1, "gru", request.Enrollment.NodeId, "production", "terrabase-server", Digest, true, material.Clock.GetUtcNow());
            await Assert.That(() => publisher.PublishAsync(report, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(8)))
                .Throws<OperationCanceledException>();
            using var caller = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
            await Assert.That(() => publisher.PublishAsync(report, caller.Token).WaitAsync(TimeSpan.FromSeconds(2)))
                .Throws<OperationCanceledException>();
        }
        finally { stopping.Cancel(); await serving; }
    }

    private static HostAdmissionObservation Admission(SignedHostReportHarness harness, SignedHostReportHarness.ReportHost host) =>
        new(1, "gru", host.Node, "production", host.Artifact, Digest, true, harness.Material.Clock.GetUtcNow());

    private static HostConvergenceObservation Runtime(SignedHostReportHarness harness, SignedHostReportHarness.ReportHost host) =>
        new(2, "gru", host.Node, host.Artifact, Digest, "converged", "workload.service", harness.Material.Clock.GetUtcNow(),
            MemberUp: host.Role == AdmittedRole.TerraBaseMember ? true : null);

    private static async Task SendRawAsync(SignedHostReportHarness.ReportHost host, string json, string requestId, CancellationToken token) =>
        await host.Client.Connection.PublishAsync(HostObservationRelay.ReportSubject("gru", host.Node), json,
            replyTo: HostObservationRelay.ReplySubject("gru", host.Node, requestId), cancellationToken: token);

    private static async Task WaitUntilAsync(Func<bool> complete, CancellationToken token)
    {
        while (!complete()) await Task.Delay(10, token);
    }

    private static async Task RequirePublishDeniedAsync(NatsControlR3L0cFixture cluster,
        NatsControlR3L0cFixture.NatsControlR3L0cIdentity identity, string subject, CancellationToken token)
    {
        using var logs = new PermissionLog();
        await using var client = new NatsClient(cluster.ClientOptions(identity) with { LoggerFactory = logs });
        await client.ConnectAsync().AsTask().WaitAsync(token);
        await client.Connection.PublishAsync(subject, "forbidden", cancellationToken: token);
        await WaitUntilAsync(() => logs.Messages.Any(message => message.Contains("Permissions Violation", StringComparison.OrdinalIgnoreCase) &&
            message.Contains(subject, StringComparison.Ordinal)), token);
        await client.Connection.PingAsync(token).AsTask().WaitAsync(token);
    }

    private sealed class PermissionLog : ILoggerFactory, ILogger
    {
        internal ConcurrentQueue<string> Messages { get; } = new();
        public ILogger CreateLogger(string categoryName) => this;
        public void AddProvider(ILoggerProvider provider) => throw new NotSupportedException();
        public void Dispose() { }
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Messages.Enqueue(formatter(state, exception) + " " + exception?.Message);
    }

    public class FailOneWrite : DispatchProxy
    {
        internal INatsKVStore Inner { get; set; } = null!;
        internal string? FailKey { get; set; }
        protected override object? Invoke(MethodInfo? method, object?[]? args)
        {
            if (method!.Name == nameof(INatsKVStore.UpdateAsync) && args![0] as string == FailKey)
            {
                FailKey = null;
                return ValueTask.FromException<ulong>(new IOException("Injected report persistence failure."));
            }
            try { return method.Invoke(Inner, args); }
            catch (TargetInvocationException exception) when (exception.InnerException is { } inner)
            { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(inner).Throw(); throw; }
        }
    }
}
