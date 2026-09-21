using System.Security.Cryptography;
using System.Text.Json.Nodes;
using NATS.Client.Core;
using TerraScale.Orchestrator.Bootstrap;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Runtime;

namespace TerraScale.Orchestrator.Tests;

public sealed class RegionalHostSessionRequestTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Signed_requests_bind_the_exact_enrollment_and_process_session(bool renew)
    {
        using var material = new HostSessionTestMaterial();
        var request = material.Request(renew);
        await Assert.That(Read(request.Serialize(), request, material.Now, out var parsed)).IsTrue();
        await Assert.That(parsed!.SessionId).IsEqualTo(request.SessionId);
        await Assert.That(parsed.Enrollment.Scope.Matches(material.Scope)).IsTrue();
        await Assert.That(parsed.EnrollmentDigest).IsEqualTo(request.EnrollmentDigest);
        await Assert.That(parsed.CanonicalBytes()).IsEquivalentTo(request.CanonicalBytes());
        await Assert.That(Read(request.Serialize(), request, material.Now.AddSeconds(9), out _)).IsTrue();
        await Assert.That(Read(request.Serialize(), request, material.Now.AddSeconds(10), out _)).IsFalse();
        await Assert.That(Read(request.Serialize(), request, material.Now.AddTicks(-1), out _)).IsFalse();
    }

    [Test]
    [Arguments("role")]
    [Arguments("environment")]
    [Arguments("node")]
    [Arguments("account")]
    [Arguments("cluster")]
    [Arguments("generation")]
    [Arguments("enrollment-signature")]
    [Arguments("session")]
    [Arguments("nonce")]
    [Arguments("epoch")]
    [Arguments("operation")]
    [Arguments("timestamp")]
    public async Task Changing_bound_fields_invalidates_the_proof_even_on_the_changed_route(string changed)
    {
        using var material = new HostSessionTestMaterial();
        var request = material.Request(renew: true);
        var document = JsonNode.Parse(request.Serialize())!.AsObject();
        var enrollment = document["Enrollment"]!.AsObject();
        switch (changed)
        {
            case "role": enrollment["Scope"]!["Roles"] = new JsonArray((int)AdmittedRole.Authentication); break;
            case "environment": enrollment["Scope"]!["Environment"] = "staging"; break;
            case "node": enrollment["NodeId"] = "other-node"; break;
            case "account": enrollment["NatsAccountPublicKey"] = NKeys.PublicKeyFromSeed(NKeys.CreateAccountSeed()); break;
            case "cluster": enrollment["ClusterName"] = "other-cluster"; break;
            case "generation": enrollment["BootstrapGeneration"] = 2; break;
            case "enrollment-signature": enrollment["Signature"] = "AQ=="; break;
            case "session": document["SessionId"] = new string('c', 32); break;
            case "nonce": document["RequestId"] = new string('d', 32); break;
            case "epoch": document["Epoch"] = 2; break;
            case "operation": document["Operation"] = (int)RegionalHostSessionOperation.Acquire; document["Epoch"] = 0; break;
            case "timestamp": document["IssuedAt"] = material.Now.AddTicks(-1); break;
            default: throw new ArgumentOutOfRangeException(nameof(changed));
        }
        await Assert.That(RegionalHostSessionRequest.TryRead(document.ToJsonString(),
            RegionalHostSessionRequest.Subject("gru", enrollment["NodeId"]!.GetValue<string>()),
            RegionalHostSessionRequest.ReplySubject("gru", enrollment["NodeId"]!.GetValue<string>(), document["RequestId"]!.GetValue<string>()),
            "gru", material.Now, out _)).IsFalse();
    }

    [Test]
    public async Task Request_routing_cannot_target_another_host_region_or_arbitrary_reply()
    {
        using var material = new HostSessionTestMaterial();
        var request = material.Request();
        var subject = RegionalHostSessionRequest.Subject("gru", request.Enrollment.NodeId);
        var reply = RegionalHostSessionRequest.ReplySubject("gru", request.Enrollment.NodeId, request.RequestId);
        foreach (var route in new[]
                 {
                     (RegionalHostSessionRequest.Subject("gru", "other"), reply, "gru"),
                     (subject, RegionalHostSessionRequest.ReplySubject("gru", "other", request.RequestId), "gru"),
                     (subject, RegionalHostSessionRequest.ReplySubject("gru", request.Enrollment.NodeId, new string('e', 32)), "gru"),
                     (subject, "_INBOX.arbitrary", "gru"), (subject, reply, "fra"), (subject, reply, "global")
                 })
            await Assert.That(RegionalHostSessionRequest.TryRead(request.Serialize(), route.Item1, route.Item2, route.Item3,
                material.Now, out _)).IsFalse();
    }

    [Test]
    public async Task Missing_duplicate_unknown_or_oversized_fields_are_rejected()
    {
        using var material = new HostSessionTestMaterial();
        var request = material.Request();
        var json = request.Serialize();
        foreach (var field in new[] { "SchemaVersion", "Enrollment", "Operation", "SessionId", "Epoch", "RequestId", "IssuedAt", "Signature" })
        {
            var missing = JsonNode.Parse(json)!.AsObject();
            missing.Remove(field);
            await Assert.That(Read(missing.ToJsonString(), request, material.Now, out _)).IsFalse();
        }
        foreach (var invalid in new[]
                 {
                     json.Insert(1, "\"SchemaVersion\":1,"), json.Insert(1, "\"Unknown\":1,"), "null", "{}", "[]",
                     new string(' ', RegionalHostSessionRequest.MaximumBytes + 1), json.Replace("\"Roles\":[", "\"Roles\":[999,", StringComparison.Ordinal),
                     json.Replace("\"Scope\":{", "\"Scope\":{\"Unknown\":1,", StringComparison.Ordinal),
                     json.Replace("\"Signature\":", "\"Signature\":null,\"Signature\":", StringComparison.Ordinal)
                 })
            await Assert.That(Read(invalid, request, material.Now, out _)).IsFalse();
    }

    [Test]
    public async Task The_previous_user_key_cannot_prove_possession_of_a_replacement_enrollment()
    {
        using var material = new HostSessionTestMaterial();
        using var oldSeed = new NatsAuthenticationFilesTests.SeedFile();
        var oldAuthentication = NatsAuthenticationFiles.FromNKeyFile(oldSeed.Path);
        await Assert.That(() => RegionalHostSessionRequest.Sign(material.Enrollment, oldAuthentication,
            RegionalHostSessionOperation.Acquire, new string('a', 32), 0, material.Now)).Throws<InvalidOperationException>();

        // A replaced node can copy the public envelope and publish on the same hashed subject.
        // Bypassing the honest signer still cannot produce a proof for the new enrolled key.
        var request = material.Request();
        var forged = new RegionalHostSessionRequest(1, request.Enrollment, request.Operation, request.SessionId,
            request.Epoch, request.RequestId, request.IssuedAt, Convert.ToBase64String(oldAuthentication.SignUserRequest(request.CanonicalBytes())));
        await Assert.That(Read(forged.Serialize(), forged, material.Now, out _)).IsFalse();
    }

    private static bool Read(string json, RegionalHostSessionRequest expected, DateTimeOffset now,
        out RegionalHostSessionRequest? parsed) => RegionalHostSessionRequest.TryRead(json,
        RegionalHostSessionRequest.Subject("gru", expected.Enrollment.NodeId),
        RegionalHostSessionRequest.ReplySubject("gru", expected.Enrollment.NodeId, expected.RequestId), "gru", now, out parsed);
}

internal sealed class HostSessionTestMaterial : IDisposable
{
    private readonly NatsAuthenticationFilesTests.SeedFile seed = new();
    internal HostSessionTestMaterial()
    {
        Authentication = NatsAuthenticationFiles.FromNKeyFile(seed.Path);
        using var grantKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var issuer = new BootstrapGrantIssuer("grant-key", 1, BootstrapTrustKeyPurpose.GrantSigning, grantKey);
        using var enrollmentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new RegionalNodeEnrollmentSigner("enrollment-key", 1, enrollmentKey);
        var project = new BootstrapSystemProjectUlds(new("00000000000000000000000000"), new("00000000000000000000000001"), new("00000000000000000000000002"));
        const string node = "ocid1.instance.oc1.sa-saopaulo-1.aaaaaaaaexample";
        var grant = issuer.Sign(new BootstrapGrantPayload("00000000000000000000000003", new string('a', 64),
            issuer.KeyId, issuer.KeyVersion, BootstrapKeyPurposeCodes.GrantSigning, project, node,
            new BootstrapCertificateFingerprint(new string('b', 64)), Now.AddSeconds(-1), Now.AddMinutes(5),
            [BootstrapGrantOperation.EnsureSystemProjectConfiguration]));
        Enrollment = signer.Sign("GRU", node, 1, NKeys.PublicKeyFromSeed(NKeys.CreateAccountSeed()), Authentication.PublicKey,
            new string('c', 64), "gru-cluster", Scope, grant);
    }

    internal DateTimeOffset Now { get; } = DateTimeOffset.UtcNow;
    internal NatsAuthenticationFiles Authentication { get; }
    internal RegionalNodeEnrollmentScope Scope { get; } = new("production", [AdmittedRole.TerraBaseMember]);
    internal RegionalNodeEnrollmentEnvelope Enrollment { get; }
    internal RegionalHostSessionRequest Request(bool renew = false) => RegionalHostSessionRequest.Sign(Enrollment,
        Authentication, renew ? RegionalHostSessionOperation.Renew : RegionalHostSessionOperation.Acquire,
        new string('a', 32), renew ? 1UL : 0, Now);
    public void Dispose() => seed.Dispose();
}
