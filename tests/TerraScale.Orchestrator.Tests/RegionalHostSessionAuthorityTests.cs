using System.Security.Cryptography;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using NATS.Client.Core;
using NATS.Client.JetStream.Models;
using NATS.Client.KeyValueStore;
using NATS.Net;
using TerraScale.Orchestrator.Bootstrap;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class RegionalHostSessionAuthorityTests
{
    [Test]
    public async Task Host_request_deadline_cancels_a_PING_when_the_server_never_returns_its_PONG()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var stopping = new CancellationTokenSource();
        var serving = ServeHandshakeOnlyAsync(listener, stopping.Token);
        try
        {
            await using var connection = new NatsConnection(NatsOpts.Default with
            {
                Url = $"nats://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}",
                PingInterval = TimeSpan.FromHours(1)
            });
            await connection.ConnectAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(3));
            using var material = new SessionMaterial();
            var enrollment = material.Enroll(1);
            var client = new NatsRegionalHostSessionClient(connection, "gru", enrollment.NodeId);
            using var deadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
            await Assert.That(async () => _ = await client.SendAsync(material.Request(enrollment), deadline.Token)
                .WaitAsync(TimeSpan.FromSeconds(2))).Throws<OperationCanceledException>();
        }
        finally
        {
            stopping.Cancel();
            await serving;
        }
    }

    private static async Task ServeHandshakeOnlyAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        try
        {
            using var peer = await listener.AcceptTcpClientAsync(cancellationToken);
            await using var stream = peer.GetStream();
            using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
            await using var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), leaveOpen: true)
                { AutoFlush = true, NewLine = "\r\n" };
            await writer.WriteLineAsync("INFO {\"server_id\":\"deadline-test\",\"version\":\"2.14.0\",\"proto\":1,\"max_payload\":1048576}".AsMemory(), cancellationToken);
            var handshaken = false;
            while (await reader.ReadLineAsync(cancellationToken) is { } line)
            {
                if (line != "PING" || handshaken) continue;
                await writer.WriteLineAsync("PONG".AsMemory(), cancellationToken);
                handshaken = true;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (IOException) when (cancellationToken.IsCancellationRequested) { }
    }

    [Test]
    public async Task Session_state_requires_non_expiring_non_evicting_R3_storage_without_tombstone_expiry()
    {
        var canonical = NatsOperationJournalStore.CanonicalKeyValueStream(new NatsTopology("gru", 3, "controller-1").NodeEnrollments);
        RegionalHostSessionAuthority.ValidateStoreConfiguration(canonical);
        foreach (var invalid in new[]
                 {
                     canonical with { MaxAge = TimeSpan.FromSeconds(1) }, canonical with { NumReplicas = 1 },
                     canonical with { Name = "KV_ORCH_RUNTIME" }, canonical with { NoAck = true },
                     canonical with { MaxMsgs = 1 }, canonical with { Discard = StreamConfigDiscard.Old },
                     canonical with { AllowMsgTTL = true }, canonical with { Storage = StreamConfigStorage.Memory },
                     canonical with { Retention = StreamConfigRetention.Interest },
                     canonical with { SubjectDeleteMarkerTTL = TimeSpan.FromSeconds(1) }
                 })
            await Assert.That(() => RegionalHostSessionAuthority.ValidateStoreConfiguration(invalid)).Throws<InvalidDataException>();
    }

    [Test]
    public async Task Enrollment_policy_requires_current_trust_and_signed_scope_and_distinguishes_bootstrap_expiry()
    {
        using var material = new SessionMaterial();
        var enrollment = material.Enroll(1, lifetime: TimeSpan.FromSeconds(5));
        var policy = material.Policy();
        await Assert.That(policy.AllowsFreshEnrollment(enrollment, material.Clock.GetUtcNow(), material.Clock.GetUtcNow().AddSeconds(30))).IsTrue();
        foreach (var scope in new[]
                 {
                     new RegionalNodeEnrollmentScope("staging", [AdmittedRole.TerraBaseMember]),
                     new RegionalNodeEnrollmentScope("production", [AdmittedRole.Orchestrator])
                 })
            await Assert.That(policy.AllowsFreshEnrollment(material.Enroll(1, scope: scope), material.Clock.GetUtcNow(), material.Clock.GetUtcNow().AddSeconds(30))).IsFalse();
        await Assert.That(policy.AllowsFreshEnrollment(enrollment with { Signature = "AQ==" }, material.Clock.GetUtcNow(), material.Clock.GetUtcNow().AddSeconds(30))).IsFalse();
        using var unrelated = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await Assert.That(material.Policy(enrollmentKey: unrelated).AllowsFreshEnrollment(enrollment, material.Clock.GetUtcNow(), material.Clock.GetUtcNow().AddSeconds(30))).IsFalse();
        var originalLeaseExpiry = material.Clock.GetUtcNow().AddSeconds(30);
        var boundedTrust = new RotatedBootstrapTrustBundle(1,
            [material.GrantIssuer.ExportPublicKey(material.Clock.GetUtcNow().AddSeconds(35))], "grant-key", 1);
        var boundedPolicy = material.Policy(trust: boundedTrust);
        await Assert.That(boundedPolicy.AllowsFreshEnrollment(enrollment, material.Clock.GetUtcNow(), originalLeaseExpiry)).IsTrue();
        material.Clock.Advance(TimeSpan.FromSeconds(6));
        await Assert.That(policy.AllowsFreshEnrollment(enrollment, material.Clock.GetUtcNow(), material.Clock.GetUtcNow().AddSeconds(30))).IsFalse();
        await Assert.That(policy.AllowsContinuingEnrollment(enrollment, material.Clock.GetUtcNow(), material.Clock.GetUtcNow().AddSeconds(30))).IsTrue();
        await Assert.That(boundedPolicy.AllowsContinuingEnrollment(enrollment, material.Clock.GetUtcNow(), originalLeaseExpiry)).IsTrue();
        await Assert.That(boundedPolicy.AllowsContinuingEnrollment(enrollment, material.Clock.GetUtcNow(), material.Clock.GetUtcNow().AddSeconds(30))).IsFalse();
        var expiredTrust = new RotatedBootstrapTrustBundle(1,
            [material.GrantIssuer.ExportPublicKey(enrollment.Grant.ParsePayload().ExpiresAt)], "grant-key", 1);
        await Assert.That(material.Policy(trust: expiredTrust).AllowsContinuingEnrollment(enrollment, material.Clock.GetUtcNow(), material.Clock.GetUtcNow().AddSeconds(30))).IsFalse();
    }

    [Test]
    public async Task R3_races_retries_renewals_and_process_restarts_preserve_one_lease_and_monotonic_epochs()
    {
        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await fixture.ProvisionAsync(deadline.Token);
        await using var one = await fixture.ConnectAsync(fixture.Controller, cancellationToken: deadline.Token);
        await using var two = await fixture.ConnectAsync(fixture.ControllerTwo, member: 1, cancellationToken: deadline.Token);
        var firstStore = await Store(one, deadline.Token);
        var secondStore = await Store(two, deadline.Token);
        using var material = new SessionMaterial();
        var first = new RegionalHostSessionAuthority(firstStore, material.Policy(), material.Clock);
        var second = new RegionalHostSessionAuthority(secondStore, material.Policy(), material.Clock);
        var enrollment = material.Enroll(1);
        var attempts = new[] { material.Request(enrollment), material.Request(enrollment) };
        var results = await Task.WhenAll(first.ProcessAsync(attempts[0], deadline.Token), second.ProcessAsync(attempts[1], deadline.Token));
        await Assert.That(results.Count(static result => result.Accepted)).IsEqualTo(1);
        // Both contenders signed at the same instant: once one commits, the other timestamp is stale.
        await Assert.That(results.Single(static result => !result.Accepted).Decision).IsEqualTo(RegionalHostSessionDecision.StaleRequest);
        var winningIndex = Array.FindIndex(results, static result => result.Accepted);
        var request = attempts[winningIndex];
        var accepted = results[winningIndex];
        await Assert.That(accepted.Epoch).IsEqualTo(1UL);
        material.Clock.Advance(TimeSpan.FromSeconds(1));
        var restartedController = new RegionalHostSessionAuthority(secondStore, material.Policy(), material.Clock);
        var retry = await restartedController.ProcessAsync(request, deadline.Token);
        await Assert.That(retry).IsEqualTo(accepted);
        var renew = material.Request(enrollment, request.SessionId, accepted.Epoch);
        var renewed = await first.ProcessAsync(renew, deadline.Token);
        await Assert.That(renewed.Accepted).IsTrue();
        await Assert.That(renewed.Epoch).IsEqualTo(accepted.Epoch);
        await Assert.That(renewed.ExpiresAt).IsEqualTo(renew.IssuedAt + RegionalHostSessionAuthority.LeaseLifetime);
        await Assert.That((await second.ProcessAsync(request, deadline.Token)).Decision).IsEqualTo(RegionalHostSessionDecision.StaleRequest);
        await Assert.That(await second.ProcessAsync(renew, deadline.Token)).IsEqualTo(renewed);
        material.Clock.Advance(TimeSpan.FromSeconds(31));
        var resumed = await restartedController.ProcessAsync(material.Request(enrollment), deadline.Token);
        await Assert.That(resumed.Accepted).IsTrue();
        await Assert.That(resumed.Epoch).IsEqualTo(2UL);
        material.Clock.Advance(TimeSpan.FromSeconds(1));
        var oldProcess = await first.ProcessAsync(material.Request(enrollment, request.SessionId, accepted.Epoch), deadline.Token);
        await Assert.That(oldProcess.Decision).IsEqualTo(RegionalHostSessionDecision.SessionMismatch);
        // The old one-use writer must not silently overwrite the new session format.
        await Assert.That(async () => _ = await new NatsRegionalNodeEnrollmentReplayStore(firstStore)
            .TryAcceptAsync(enrollment.NodeId, 20, "new-grant", "new-nonce", deadline.Token)).Throws<JsonException>();
    }

    [Test]
    public async Task Revocation_generation_supersession_and_all_live_grant_replays_survive_R3_restart()
    {
        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await fixture.ProvisionAsync(deadline.Token);
        await using var controller = await fixture.ConnectAsync(fixture.Controller, cancellationToken: deadline.Token);
        var store = await Store(controller, deadline.Token);
        using var material = new SessionMaterial();
        var authority = new RegionalHostSessionAuthority(store, material.Policy(), material.Clock);
        var oldEnrollment = material.Enroll(1);
        var request = material.Request(oldEnrollment);
        var initial = await authority.ProcessAsync(request, deadline.Token);
        await Assert.That(initial.Accepted).IsTrue();
        await Assert.That(await authority.RevokeAsync(oldEnrollment.NodeId, 1, initial.Epoch, deadline.Token)).IsTrue();
        var leader = (await store.GetStatusAsync(deadline.Token)).Info.Cluster?.Leader switch
        {
            "r3-l0c-1" => 0, "r3-l0c-2" => 1, "r3-l0c-3" => 2,
            _ => throw new InvalidOperationException("The R3 enrollment store did not report its leader.")
        };
        await fixture.KillMemberAsync(leader, deadline.Token);
        await fixture.RestartMemberAsync(leader, deadline.Token);
        authority = new(store, material.Policy(), material.Clock);
        RegionalHostSessionResponse recovered;
        do
        {
            recovered = await authority.ProcessAsync(request, deadline.Token);
            if (recovered.Decision == RegionalHostSessionDecision.StoreUnavailable) await Task.Delay(20, deadline.Token);
        } while (recovered.Decision == RegionalHostSessionDecision.StoreUnavailable);
        await Assert.That(recovered.Decision).IsEqualTo(RegionalHostSessionDecision.Revoked);
        using var replacementKey = new NatsAuthenticationFilesTests.SeedFile();
        var replacementAuthentication = NatsAuthenticationFiles.FromNKeyFile(replacementKey.Path);
        var replacement = material.Enroll(2, authentication: replacementAuthentication);
        material.Clock.Advance(TimeSpan.FromSeconds(1));
        await Assert.That((await authority.ProcessAsync(material.Request(replacement, authentication: replacementAuthentication), deadline.Token)).Decision)
            .IsEqualTo(RegionalHostSessionDecision.SessionHeld);
        material.Clock.Advance(TimeSpan.FromSeconds(30));
        var installed = await authority.ProcessAsync(material.Request(replacement, authentication: replacementAuthentication), deadline.Token);
        await Assert.That(installed.Accepted).IsTrue();
        await Assert.That(installed.Epoch).IsEqualTo(2UL);
        await Assert.That(await authority.RevokeAsync(oldEnrollment.NodeId, 1, 1, deadline.Token)).IsFalse();
        material.Clock.Advance(TimeSpan.FromSeconds(1));
        await Assert.That((await authority.ProcessAsync(material.Request(oldEnrollment), deadline.Token)).Decision).IsEqualTo(RegionalHostSessionDecision.StaleGeneration);
        var changedSameGeneration = material.Enroll(2, authentication: replacementAuthentication);
        await Assert.That((await authority.ProcessAsync(material.Request(changedSameGeneration, authentication: replacementAuthentication), deadline.Token)).Decision)
            .IsEqualTo(RegionalHostSessionDecision.GenerationConflict);
        material.Clock.Advance(TimeSpan.FromSeconds(30));
        var replayedGrant = material.Enroll(3, grant: oldEnrollment.Grant);
        await Assert.That((await authority.ProcessAsync(material.Request(replayedGrant), deadline.Token)).Decision)
            .IsEqualTo(RegionalHostSessionDecision.GenerationConflict);
        await store.DeleteAsync(RegionalHostSessionAuthority.Key(oldEnrollment.NodeId), cancellationToken: deadline.Token);
        await Assert.That((await authority.ProcessAsync(material.Request(material.Enroll(4)), deadline.Token)).Decision)
            .IsEqualTo(RegionalHostSessionDecision.InvalidStore);
        await Assert.That(async () => _ = await store.UpdateAsync(RegionalHostSessionAuthority.Key(oldEnrollment.NodeId), "resurrected", 0,
            cancellationToken: deadline.Token)).Throws<NatsKVWrongLastRevisionException>();
    }

    [Test]
    public async Task An_expired_bootstrap_grant_resumes_only_its_exact_durable_enrollment_and_revocation_still_wins()
    {
        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await fixture.ProvisionAsync(deadline.Token);
        await using var controller = await fixture.ConnectAsync(fixture.Controller, cancellationToken: deadline.Token);
        var store = await Store(controller, deadline.Token);
        using var material = new SessionMaterial();
        var authority = new RegionalHostSessionAuthority(store, material.Policy(), material.Clock);
        var enrollment = material.Enroll(1, lifetime: TimeSpan.FromSeconds(5));
        var neverAdmitted = material.Enroll(1, node: "never-admitted", lifetime: TimeSpan.FromSeconds(5));
        var request = material.Request(enrollment);
        var admitted = await authority.ProcessAsync(request, deadline.Token);
        await Assert.That(admitted.Accepted).IsTrue();
        material.Clock.Advance(TimeSpan.FromSeconds(6));
        var renewal = await authority.ProcessAsync(material.Request(enrollment, request.SessionId, admitted.Epoch), deadline.Token);
        await Assert.That(renewal.Accepted).IsTrue();
        await Assert.That((await authority.ProcessAsync(material.Request(neverAdmitted), deadline.Token)).Decision)
            .IsEqualTo(RegionalHostSessionDecision.EnrollmentDenied);
        material.Clock.Advance(TimeSpan.FromSeconds(31));
        authority = new(store, material.Policy(), material.Clock);
        var resumed = await authority.ProcessAsync(material.Request(enrollment), deadline.Token);
        await Assert.That(resumed.Accepted).IsTrue();
        await Assert.That(resumed.Epoch).IsEqualTo(2UL);
        await Assert.That(await authority.RevokeAsync(enrollment.NodeId, 1, resumed.Epoch, deadline.Token)).IsTrue();
        authority = new(store, material.Policy(), material.Clock);
        material.Clock.Advance(TimeSpan.FromSeconds(31));
        await Assert.That((await authority.ProcessAsync(material.Request(enrollment), deadline.Token)).Decision).IsEqualTo(RegionalHostSessionDecision.Revoked);
    }

    [Test]
    public async Task Restricted_JWT_mTLS_host_uses_real_R3_services_and_a_lost_reply_retries_without_extending_its_lease()
    {
        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await fixture.ProvisionAsync(deadline.Token);
        await using var one = await fixture.ConnectAsync(fixture.Controller, cancellationToken: deadline.Token);
        await using var two = await fixture.ConnectAsync(fixture.ControllerTwo, member: 1, cancellationToken: deadline.Token);
        await using var host = await fixture.ConnectAsync(fixture.HostAgent, member: 2, cancellationToken: deadline.Token);
        var store = await Store(one, deadline.Token);
        var authentication = NatsAuthenticationFiles.FromCredentialsFile(fixture.HostAgent.CredentialsFile, "test");
        using var material = new SessionMaterial(authentication, fixture.HostAgent.AccountPublicKey, "host-1", realTime: true);
        var authority = new RegionalHostSessionAuthority(store, material.Policy(), material.Clock);
        await using var service = await RegionalHostSessionService.StartAsync(one.Connection, authority, deadline.Token);
        await using var second = await RegionalHostSessionService.StartAsync(two.Connection,
            new(await Store(two, deadline.Token), material.Policy(), material.Clock), deadline.Token);
        var enrollment = material.Enroll(1);
        var request = material.Request(enrollment);
        // Publish without a subscriber, then observe the durable result before retrying through the real client.
        await host.PublishAsync(RegionalHostSessionRequest.Subject("gru", "host-1"), request.Serialize(),
            replyTo: RegionalHostSessionRequest.ReplySubject("gru", "host-1", request.RequestId), cancellationToken: deadline.Token);
        var committed = await WaitForRecord(store, "host-1", deadline.Token);
        var client = new NatsRegionalHostSessionClient(host.Connection, "gru", "host-1");
        var retry = await client.SendAsync(request, deadline.Token);
        await Assert.That(retry.Accepted).IsTrue();
        await Assert.That(retry.Revision).IsEqualTo(committed.Revision);
        await Assert.That(retry.ExpiresAt).IsEqualTo(request.IssuedAt + RegionalHostSessionAuthority.LeaseLifetime);
        var renewed = await client.SendAsync(material.Request(enrollment, request.SessionId, retry.Epoch), deadline.Token);
        await Assert.That(renewed.Accepted).IsTrue();
        await Assert.That(renewed.Epoch).IsEqualTo(retry.Epoch);
        await using (var denied = await fixture.ConnectAsync(fixture.HostAgent, cancellationToken: deadline.Token))
            await Assert.That(async () => _ = await Store(denied, deadline.Token)).Throws<NatsException>();
        var invalid = material.Request(enrollment);
        await host.PublishAsync(RegionalHostSessionRequest.Subject("gru", "host-1"), invalid.Serialize(),
            replyTo: "_INBOX.arbitrary", cancellationToken: deadline.Token);
        await WaitUntil(() => service.Snapshot.Rejected + second.Snapshot.Rejected > 0, deadline.Token);
        await Assert.That(await authority.RevokeAsync("host-1", 1, retry.Epoch, deadline.Token)).IsTrue();
        await Assert.That((await client.SendAsync(material.Request(enrollment, request.SessionId, retry.Epoch), deadline.Token)).Decision)
            .IsEqualTo(RegionalHostSessionDecision.Revoked);
        await WaitUntil(() => service.Snapshot.Renewed + second.Snapshot.Renewed > 0, deadline.Token);
        await Assert.That(service.Snapshot.RetryPending || second.Snapshot.RetryPending).IsFalse();
    }

    [Test]
    public async Task Replay_history_capacity_holds_new_generations_until_prior_grants_are_expired()
    {
        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await fixture.ProvisionAsync(deadline.Token);
        await using var controller = await fixture.ConnectAsync(fixture.Controller, cancellationToken: deadline.Token);
        var store = await Store(controller, deadline.Token);
        using var material = new SessionMaterial();
        var authority = new RegionalHostSessionAuthority(store, material.Policy(), material.Clock);
        var initialTime = material.Clock.GetUtcNow();
        for (ulong generation = 1; generation <= 16; generation++)
        {
            var enrollment = material.Enroll(generation, lifetime: TimeSpan.FromMinutes(14));
            var response = await authority.ProcessAsync(material.Request(enrollment), deadline.Token);
            await Assert.That(response.Accepted).IsTrue();
            material.Clock.Advance(TimeSpan.FromSeconds(31));
        }
        var pending = material.Enroll(17, lifetime: TimeSpan.FromMinutes(14));
        await Assert.That((await authority.ProcessAsync(material.Request(pending), deadline.Token)).Decision)
            .IsEqualTo(RegionalHostSessionDecision.ReplayCapacity);
        var before = await WaitForRecord(store, pending.NodeId, deadline.Token);
        var state = JsonSerializer.Deserialize<RegionalHostSessionRecord>(before.Value!, RegionalHostSessionAuthority.JsonOptions)!;
        await Assert.That(state.Generation).IsEqualTo(16UL);
        await Assert.That(state.ConsumedGrants.Count).IsEqualTo(16);
        material.Clock.Advance(initialTime.AddMinutes(14).AddSeconds(1) - material.Clock.GetUtcNow());
        var admitted = await authority.ProcessAsync(material.Request(pending), deadline.Token);
        await Assert.That(admitted.Accepted).IsTrue();
        await Assert.That(admitted.Generation).IsEqualTo(17UL);
    }

    private static async Task<INatsKVStore> Store(NatsClient client, CancellationToken cancellationToken) =>
        await client.CreateJetStreamContext().CreateKeyValueStoreContext().GetStoreAsync("ORCH_NODE_ENROLLMENTS", cancellationToken);

    private static async Task<NatsKVEntry<string>> WaitForRecord(INatsKVStore store, string node, CancellationToken cancellationToken)
    {
        while (true)
        {
            try { return await store.GetEntryAsync<string>(RegionalHostSessionAuthority.Key(node), cancellationToken: cancellationToken); }
            catch (NatsKVKeyNotFoundException) { await Task.Delay(20, cancellationToken); }
        }
    }

    private static async Task WaitUntil(Func<bool> condition, CancellationToken cancellationToken)
    {
        while (!condition()) await Task.Delay(20, cancellationToken);
    }
}

internal sealed class SessionMaterial : IDisposable
{
    private readonly NatsAuthenticationFilesTests.SeedFile seed = new();
    private readonly ECDsa enrollmentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly RegionalNodeEnrollmentSigner signer;
    private readonly string account;
    private readonly string node;
    private ulong nextGrant;
    internal SessionMaterial(NatsAuthenticationFiles? authentication = null, string? account = null, string? node = null, bool realTime = false)
    {
        Clock = new(realTime);
        Authentication = authentication ?? NatsAuthenticationFiles.FromNKeyFile(seed.Path);
        this.account = account ?? NKeys.PublicKeyFromSeed(NKeys.CreateAccountSeed());
        this.node = node ?? "ocid1.instance.oc1.sa-saopaulo-1.aaaaaaaaqualified";
        signer = new RegionalNodeEnrollmentSigner("enrollment-key", 1, enrollmentKey);
        GrantIssuer = new BootstrapGrantIssuer("grant-key", 1, BootstrapTrustKeyPurpose.GrantSigning, ECDsa.Create(ECCurve.NamedCurves.nistP256));
    }

    internal SessionClock Clock { get; }
    internal NatsAuthenticationFiles Authentication { get; }
    internal BootstrapGrantIssuer GrantIssuer { get; }
    internal BootstrapSystemProjectUlds Project { get; } = new(new("00000000000000000000000000"), new("00000000000000000000000001"), new("00000000000000000000000002"));
    internal RegionalNodeEnrollmentScope Scope { get; } = new("production", [AdmittedRole.TerraBaseMember]);
    internal RegionalHostEnrollmentPolicy Policy(RotatedBootstrapTrustBundle? trust = null, ECDsa? enrollmentKey = null) =>
        new("gru", account, "gru-cluster", new("production", [AdmittedRole.TerraBaseMember, AdmittedRole.Authentication]),
            "enrollment-key", 1, enrollmentKey ?? this.enrollmentKey,
            trust ?? new(1, [GrantIssuer.ExportPublicKey()], "grant-key", 1), Project,
            BootstrapGrantOperation.EnsureSystemProjectConfiguration, TimeSpan.FromMinutes(15));

    internal RegionalNodeEnrollmentEnvelope Enroll(ulong generation, SignedBootstrapGrant? grant = null,
        NatsAuthenticationFiles? authentication = null, RegionalNodeEnrollmentScope? scope = null, string? node = null, TimeSpan? lifetime = null)
    {
        node ??= this.node;
        var serial = ++nextGrant;
        grant ??= GrantIssuer.Sign(new BootstrapGrantPayload(serial.ToString("D26", System.Globalization.CultureInfo.InvariantCulture),
            serial.ToString("x64", System.Globalization.CultureInfo.InvariantCulture), "grant-key", 1,
            BootstrapKeyPurposeCodes.GrantSigning, Project, node, new BootstrapCertificateFingerprint(new string('b', 64)),
            Clock.GetUtcNow().AddSeconds(-1), Clock.GetUtcNow() + (lifetime ?? TimeSpan.FromMinutes(5)),
            [BootstrapGrantOperation.EnsureSystemProjectConfiguration]));
        return signer.Sign("GRU", node, generation, account, (authentication ?? Authentication).PublicKey,
            new string('c', 64), "gru-cluster", scope ?? Scope, grant);
    }

    internal RegionalHostSessionRequest Request(RegionalNodeEnrollmentEnvelope enrollment, string? session = null, ulong epoch = 0,
        NatsAuthenticationFiles? authentication = null) => RegionalHostSessionRequest.Sign(enrollment, authentication ?? Authentication,
        epoch == 0 ? RegionalHostSessionOperation.Acquire : RegionalHostSessionOperation.Renew,
        session ?? Guid.NewGuid().ToString("N"), epoch, Clock.GetUtcNow());

    public void Dispose() { signer.Dispose(); GrantIssuer.Dispose(); seed.Dispose(); }
}

internal sealed class SessionClock(bool realTime = false) : TimeProvider
{
    private long ticks = DateTimeOffset.UtcNow.UtcTicks;
    public override DateTimeOffset GetUtcNow() => realTime ? DateTimeOffset.UtcNow : new(Interlocked.Read(ref ticks), TimeSpan.Zero);
    internal void Advance(TimeSpan duration)
    {
        if (realTime) throw new InvalidOperationException("The wall clock cannot be advanced by a test.");
        Interlocked.Add(ref ticks, duration.Ticks);
    }
}
