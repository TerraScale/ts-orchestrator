using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using NATS.Client.KeyValueStore;
using NATS.Net;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

[NotInParallel(LocalNatsServerLease.SchedulingConstraint)]
public sealed class RegionalHostReportAuthorizationTests
{
    [Test]
    [Arguments("epoch")]
    [Arguments("session")]
    [Arguments("nonce")]
    [Arguments("role")]
    [Arguments("kind")]
    [Arguments("time")]
    [Arguments("digest")]
    [Arguments("signature")]
    [Arguments("enrollment")]
    public async Task Report_proof_binds_the_exact_enrollment_session_role_kind_payload_and_request(string mutation)
    {
        using var material = new SessionMaterial();
        var enrollment = material.Enroll(1);
        var payload = Encoding.UTF8.GetBytes("an exact report");
        var now = material.Clock.GetUtcNow();
        var proof = RegionalHostReportProof.Sign(enrollment, material.Authentication, new string('a', 32), 1,
            AdmittedRole.TerraBaseMember, RegionalHostReportKind.Admission, payload, now);
        await Assert.That(proof.Verifies("gru", AdmittedRole.TerraBaseMember, RegionalHostReportKind.Admission, payload, now)).IsTrue();
        var document = JsonNode.Parse(proof.Serialize())!;
        switch (mutation)
        {
            case "epoch": document["Epoch"] = 2; break;
            case "session": document["SessionId"] = new string('b', 32); break;
            case "nonce": document["RequestId"] = new string('c', 32); break;
            case "role": document["Role"] = (int)AdmittedRole.Authentication; break;
            case "kind": document["Kind"] = (int)RegionalHostReportKind.Runtime; break;
            case "time": document["IssuedAt"] = now.AddTicks(-1); break;
            case "digest": document["PayloadDigest"] = new string('d', 64); break;
            case "signature": document["Signature"] = Convert.ToBase64String(new byte[64]); break;
            case "enrollment": document["Enrollment"]!["CredentialBundleSha256"] = new string('e', 64); break;
        }
        var altered = JsonSerializer.Deserialize<RegionalHostReportProof>(document.ToJsonString(), RegionalHostSessionAuthority.JsonOptions)!;
        await Assert.That(altered.Verifies("gru", AdmittedRole.TerraBaseMember, RegionalHostReportKind.Admission, payload, now)).IsFalse();
    }

    [Test]
    public async Task Report_proofs_reject_wrong_target_freshness_role_key_and_unbounded_payloads()
    {
        using var material = new SessionMaterial();
        using var other = new SessionMaterial();
        var enrollment = material.Enroll(1);
        var payload = Encoding.UTF8.GetBytes("exact report");
        var now = material.Clock.GetUtcNow();
        var proof = RegionalHostReportProof.Sign(enrollment, material.Authentication, new string('a', 32), 1,
            AdmittedRole.TerraBaseMember, RegionalHostReportKind.Runtime, payload, now);
        foreach (var time in new[] { now.AddTicks(-1), now.AddSeconds(10) })
            await Assert.That(proof.Verifies("gru", proof.Role, proof.Kind, payload, time)).IsFalse();
        await Assert.That(proof.Verifies("fra", proof.Role, proof.Kind, payload, now)).IsFalse();
        await Assert.That(proof.Verifies("gru", AdmittedRole.Authentication, proof.Kind, payload, now)).IsFalse();
        await Assert.That(proof.Verifies("gru", proof.Role, RegionalHostReportKind.Admission, payload, now)).IsFalse();
        await Assert.That(proof.Verifies("gru", proof.Role, proof.Kind, Encoding.UTF8.GetBytes("changed report"), now)).IsFalse();
        await Assert.That(() => RegionalHostReportProof.Sign(enrollment, other.Authentication, proof.SessionId, 1,
            proof.Role, proof.Kind, payload, now)).Throws<InvalidOperationException>();
        await Assert.That(() => RegionalHostReportProof.Sign(enrollment, material.Authentication, proof.SessionId, 1,
            AdmittedRole.Authentication, proof.Kind, payload, now)).Throws<InvalidOperationException>();
        foreach (var bytes in new[] { Array.Empty<byte>(), new byte[RegionalHostReportProof.MaximumPayloadBytes + 1] })
            await Assert.That(() => RegionalHostReportProof.Sign(enrollment, material.Authentication, proof.SessionId, 1,
                proof.Role, proof.Kind, bytes, now)).Throws<ArgumentException>();
        foreach (var json in new[] { "{\"Unknown\":true," + proof.Serialize()[1..],
                     "{\"Epoch\":1," + proof.Serialize()[1..], proof.Serialize().Replace("\"Epoch\":1,", "", StringComparison.Ordinal) })
            await Assert.That(() => JsonSerializer.Deserialize<RegionalHostReportProof>(json, RegionalHostSessionAuthority.JsonOptions)).Throws<JsonException>();
    }

    [Test]
    public async Task R3_authorization_checks_report_scope_and_epoch_without_renewing_the_session()
    {
        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await fixture.ProvisionAsync(deadline.Token);
        await using var client = await fixture.ConnectAsync(fixture.Controller, cancellationToken: deadline.Token);
        var store = await Store(client, deadline.Token);
        using var material = new SessionMaterial();
        var authority = new RegionalHostSessionAuthority(store, material.Policy(), material.Clock);
        var enrollment = material.Enroll(1);
        var acquire = material.Request(enrollment);
        var lease = await authority.ProcessAsync(acquire, deadline.Token);
        await Assert.That(lease.Accepted).IsTrue();
        var before = await store.GetEntryAsync<string>(RegionalHostSessionAuthority.Key(enrollment.NodeId), cancellationToken: deadline.Token);
        material.Clock.Advance(TimeSpan.FromSeconds(1));
        var report = Admission(material, enrollment.NodeId);
        var proof = Proof(material, acquire, lease.Epoch, report);
        var result = await authority.AuthorizeAdmissionReportAsync(proof, report, deadline.Token);
        await Assert.That(result.Authorized).IsTrue();
        await Assert.That(result.ExpiresAt).IsEqualTo(proof.IssuedAt.AddSeconds(10));
        var after = await store.GetEntryAsync<string>(RegionalHostSessionAuthority.Key(enrollment.NodeId), cancellationToken: deadline.Token);
        await Assert.That(after.Revision).IsGreaterThan(before.Revision);
        await Assert.That(after.Value).IsEqualTo(before.Value);
        // CAS read barriers change storage revisions, never the stable lease response.
        await Assert.That(await authority.ProcessAsync(acquire, deadline.Token)).IsEqualTo(lease);
        foreach (var altered in new[] { report with { Instance = "foreign-node" }, report with { Cell = "fra" },
                     report with { Environment = "development" }, report with { ArtifactKey = "ts-auth" }, report with { Ready = false } })
            await Assert.That((await authority.AuthorizeAdmissionReportAsync(proof, altered, deadline.Token)).Authorized).IsFalse();
        var runtime = new HostConvergenceObservation(HostConvergenceObservation.CurrentSchemaVersion, "gru", enrollment.NodeId,
            "terrabase-server", report.Digest, "converged", "member.service", material.Clock.GetUtcNow());
        var runtimeProof = RegionalHostReportProof.Sign(enrollment, material.Authentication, acquire.SessionId, lease.Epoch,
            AdmittedRole.TerraBaseMember, RegionalHostReportKind.Runtime,
            JsonSerializer.SerializeToUtf8Bytes(runtime, HostConvergenceJsonContext.Default.HostConvergenceObservation), material.Clock.GetUtcNow());
        await Assert.That((await authority.AuthorizeRuntimeReportAsync(runtimeProof, runtime, deadline.Token)).Authorized).IsTrue();
        await Assert.That((await authority.AuthorizeRuntimeReportAsync(proof, runtime, deadline.Token)).Authorized).IsFalse();
        material.Clock.Advance(TimeSpan.FromSeconds(1));
        var renewed = await authority.ProcessAsync(material.Request(enrollment, acquire.SessionId, lease.Epoch), deadline.Token);
        await Assert.That(renewed.Accepted).IsTrue();
        await Assert.That((await authority.AuthorizeAdmissionReportAsync(proof, report, deadline.Token)).Authorized).IsTrue();
        material.Clock.Advance(TimeSpan.FromSeconds(31));
        report = Admission(material, enrollment.NodeId);
        await Assert.That((await authority.AuthorizeAdmissionReportAsync(Proof(material, acquire, lease.Epoch, report), report, deadline.Token)).Decision)
            .IsEqualTo(RegionalHostSessionDecision.LeaseExpired);
        var restart = material.Request(enrollment);
        var replacement = await authority.ProcessAsync(restart, deadline.Token);
        await Assert.That(replacement.Accepted).IsTrue();
        await Assert.That((await authority.AuthorizeAdmissionReportAsync(Proof(material, acquire, lease.Epoch, report), report, deadline.Token)).Decision)
            .IsEqualTo(RegionalHostSessionDecision.SessionMismatch);
        var oldObservation = report with { ObservedAt = report.ObservedAt.AddSeconds(-1) };
        await Assert.That((await authority.AuthorizeAdmissionReportAsync(Proof(material, restart, replacement.Epoch, oldObservation), oldObservation, deadline.Token)).Decision)
            .IsEqualTo(RegionalHostSessionDecision.StaleRequest);
    }

    [Test]
    public async Task Stale_replica_reads_cannot_reauthorize_a_revoked_report_or_return_an_accepted_lease_retry()
    {
        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await fixture.ProvisionAsync(deadline.Token);
        await using var first = await fixture.ConnectAsync(fixture.Controller, cancellationToken: deadline.Token);
        await using var second = await fixture.ConnectAsync(fixture.ControllerTwo, member: 1, cancellationToken: deadline.Token);
        var store = await Store(first, deadline.Token);
        var secondStore = await Store(second, deadline.Token);
        using var material = new SessionMaterial();
        var authority = new RegionalHostSessionAuthority(store, material.Policy(), material.Clock);
        var acquire = material.Request(material.Enroll(1));
        var lease = await authority.ProcessAsync(acquire, deadline.Token);
        await Assert.That(lease.Accepted).IsTrue();
        var stale = await store.GetEntryAsync<string>(RegionalHostSessionAuthority.Key(acquire.Enrollment.NodeId), cancellationToken: deadline.Token);
        await Assert.That(await authority.RevokeAsync(acquire.Enrollment.NodeId, 1, lease.Epoch, deadline.Token)).IsTrue();
        var proxy = DispatchProxy.Create<INatsKVStore, StaleReplica>();
        var intercepted = (StaleReplica)proxy;
        intercepted.Inner = secondStore;
        intercepted.Entry = stale;
        intercepted.RemainingStaleReads = 2;
        var reader = new RegionalHostSessionAuthority(proxy, material.Policy(), material.Clock);
        material.Clock.Advance(TimeSpan.FromSeconds(1));
        var report = Admission(material, acquire.Enrollment.NodeId);
        var proof = Proof(material, acquire, lease.Epoch, report);
        await Assert.That((await reader.AuthorizeAdmissionReportAsync(proof, report, deadline.Token)).Decision).IsEqualTo(RegionalHostSessionDecision.Revoked);
        await Assert.That(intercepted.Confirmations).IsEqualTo(2);
        intercepted.RemainingStaleReads = 2;
        await Assert.That((await reader.ProcessAsync(acquire, deadline.Token)).Decision).IsEqualTo(RegionalHostSessionDecision.Revoked);
        await Assert.That(intercepted.Confirmations).IsEqualTo(4);
        intercepted.RemainingStaleReads = 8;
        await Assert.That((await reader.AuthorizeAdmissionReportAsync(proof, report, deadline.Token)).Decision).IsEqualTo(RegionalHostSessionDecision.Contention);
        await Assert.That((await authority.AuthorizeAdmissionReportAsync(proof, report, deadline.Token)).Authorized).IsFalse();
    }

    [Test]
    public async Task Expired_bootstrap_evidence_continues_only_its_current_generation_and_scope_with_current_trust()
    {
        await using var fixture = await NatsControlR3L0cFixture.StartAsync();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        await fixture.ProvisionAsync(deadline.Token);
        await using var client = await fixture.ConnectAsync(fixture.Controller, cancellationToken: deadline.Token);
        var store = await Store(client, deadline.Token);
        using var material = new SessionMaterial();
        var authority = new RegionalHostSessionAuthority(store, material.Policy(), material.Clock);
        var first = material.Request(material.Enroll(1, lifetime: TimeSpan.FromSeconds(5)));
        var firstLease = await authority.ProcessAsync(first, deadline.Token);
        await Assert.That(firstLease.Accepted).IsTrue();
        material.Clock.Advance(TimeSpan.FromSeconds(6));
        var report = Admission(material, first.Enrollment.NodeId);
        await Assert.That((await authority.AuthorizeAdmissionReportAsync(Proof(material, first, firstLease.Epoch, report), report, deadline.Token)).Authorized).IsTrue();
        material.Clock.Advance(TimeSpan.FromSeconds(25));
        var replacement = material.Request(material.Enroll(2, scope: new("production", [AdmittedRole.Authentication])));
        var nextLease = await authority.ProcessAsync(replacement, deadline.Token);
        await Assert.That(nextLease.Accepted).IsTrue();
        report = Admission(material, first.Enrollment.NodeId);
        await Assert.That((await authority.AuthorizeAdmissionReportAsync(Proof(material, first, firstLease.Epoch, report), report, deadline.Token)).Decision)
            .IsEqualTo(RegionalHostSessionDecision.EnrollmentDenied);
        var authReport = report with { ArtifactKey = "ts-auth" };
        var authProof = RegionalHostReportProof.Sign(replacement.Enrollment, material.Authentication,
            replacement.SessionId, nextLease.Epoch, AdmittedRole.Authentication, RegionalHostReportKind.Admission,
            JsonSerializer.SerializeToUtf8Bytes(authReport, HostAdmissionObservationJsonContext.Default.HostAdmissionObservation), material.Clock.GetUtcNow());
        await Assert.That((await authority.AuthorizeAdmissionReportAsync(authProof, authReport, deadline.Token)).Authorized).IsTrue();
        await Assert.That((await authority.AuthorizeAdmissionReportAsync(authProof, report, deadline.Token)).Authorized).IsFalse();
        using var removedSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var replacedTrust = new RegionalHostSessionAuthority(store, material.Policy(enrollmentKey: removedSigner), material.Clock);
        await Assert.That((await replacedTrust.AuthorizeAdmissionReportAsync(authProof, authReport, deadline.Token)).Decision)
            .IsEqualTo(RegionalHostSessionDecision.EnrollmentDenied);
        await store.DeleteAsync(RegionalHostSessionAuthority.Key(replacement.Enrollment.NodeId), cancellationToken: deadline.Token);
        await Assert.That((await authority.AuthorizeAdmissionReportAsync(authProof, authReport, deadline.Token)).Decision)
            .IsEqualTo(RegionalHostSessionDecision.InvalidStore);
    }

    private static Task<INatsKVStore> Store(NatsClient client, CancellationToken cancellationToken) =>
        client.CreateJetStreamContext().CreateKeyValueStoreContext().GetStoreAsync("ORCH_NODE_ENROLLMENTS", cancellationToken).AsTask();

    private static HostAdmissionObservation Admission(SessionMaterial material, string node) =>
        new(HostAdmissionObservation.CurrentSchemaVersion, "gru", node, "production", "terrabase-server",
            "sha256:" + new string('a', 64), true, material.Clock.GetUtcNow());

    private static RegionalHostReportProof Proof(SessionMaterial material, RegionalHostSessionRequest acquire, ulong epoch,
        HostAdmissionObservation report) => RegionalHostReportProof.Sign(acquire.Enrollment, material.Authentication, acquire.SessionId,
        epoch, AdmittedRole.TerraBaseMember, RegionalHostReportKind.Admission,
        JsonSerializer.SerializeToUtf8Bytes(report, HostAdmissionObservationJsonContext.Default.HostAdmissionObservation), material.Clock.GetUtcNow());

    public class StaleReplica : DispatchProxy
    {
        internal INatsKVStore Inner { get; set; } = null!;
        internal NatsKVEntry<string> Entry { get; set; }
        internal int RemainingStaleReads { get; set; }
        internal int Confirmations { get; private set; }

        protected override object? Invoke(MethodInfo? method, object?[]? args)
        {
            if (method!.Name == nameof(INatsKVStore.GetEntryAsync) && RemainingStaleReads-- > 0)
                return ValueTask.FromResult(Entry);
            if (method.Name == nameof(INatsKVStore.UpdateAsync)) Confirmations++;
            try { return method.Invoke(Inner, args); }
            catch (TargetInvocationException exception) when (exception.InnerException is { } inner)
            { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(inner).Throw(); throw; }
        }
    }
}
