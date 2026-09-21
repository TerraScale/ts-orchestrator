using System.Security.Cryptography;
using TerraScale.Orchestrator.Bootstrap;

namespace TerraScale.Orchestrator.Tests;

public sealed class RegionalNodeEnrollmentTests
{
    private static readonly RegionalNodeEnrollmentScope Scope = new("production", [Runtime.AdmittedRole.TerraBaseMember]);

    [Test]
    public async Task Signed_node_enrollment_is_region_and_generation_fenced()
    {
        var now = DateTimeOffset.UtcNow;
        using var grantKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var grantIssuer = new BootstrapGrantIssuer(
            "grant-key",
            1,
            BootstrapTrustKeyPurpose.GrantSigning,
            grantKey);
        var project = new BootstrapSystemProjectUlds(
            new BootstrapUlid("00000000000000000000000000"),
            new BootstrapUlid("00000000000000000000000001"),
            new BootstrapUlid("00000000000000000000000002"));
        var grant = grantIssuer.Sign(new BootstrapGrantPayload(
            "00000000000000000000000003",
            new string('a', 64),
            grantIssuer.KeyId,
            grantIssuer.KeyVersion,
            BootstrapKeyPurposeCodes.GrantSigning,
            project,
            "node-1",
            new BootstrapCertificateFingerprint(new string('b', 64)),
            now.AddSeconds(-1),
            now.AddMinutes(1),
            [BootstrapGrantOperation.EnsureSystemOrganization]));
        using var enrollmentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new RegionalNodeEnrollmentSigner("enrollment-key", 4, enrollmentKey);
        var envelope = signer.Sign(
            "GRU",
            "node-1",
            4,
            "A-account",
            "U-user",
            new string('c', 64),
            "regional-cluster",
            Scope,
            grant);
        using var verifierKey = ECDsa.Create();
        verifierKey.ImportSubjectPublicKeyInfo(signer.ExportSubjectPublicKeyInfo(), out _);
        var replay = new InMemoryRegionalNodeEnrollmentReplayStore();
        var authorizedGrant = new SignedBootstrapGrantVerification(
            SignedBootstrapGrantDecision.Authorized,
            grantIssuer.KeyId,
            grantIssuer.KeyVersion,
            true);

        var first = RegionalNodeEnrollmentVerifier.Verify(
            envelope,
            verifierKey,
            "GRU",
            "node-1",
            "A-account",
            "U-user",
            "enrollment-key",
            4,
            Scope,
            authorizedGrant,
            replay);
        var replayed = RegionalNodeEnrollmentVerifier.Verify(
            envelope,
            verifierKey,
            "GRU",
            "node-1",
            "A-account",
            "U-user",
            "enrollment-key",
            4,
            Scope,
            authorizedGrant,
            replay);

        await Assert.That(first.Authorized).IsTrue();
        await Assert.That(replayed.Decision).IsEqualTo(RegionalNodeEnrollmentDecision.ReplayDetected);
    }

    [Test]
    public async Task Wrong_region_and_wrong_identity_are_denied_before_replay_consumption()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new RegionalNodeEnrollmentSigner("enrollment-key", 1, key);
        using var grantKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var issuer = new BootstrapGrantIssuer("grant-key", 1, BootstrapTrustKeyPurpose.GrantSigning, grantKey);
        var now = DateTimeOffset.UtcNow;
        var grant = issuer.Sign(new BootstrapGrantPayload(
            "00000000000000000000000004",
            new string('d', 64),
            "grant-key",
            1,
            BootstrapKeyPurposeCodes.GrantSigning,
            new BootstrapSystemProjectUlds(
                new BootstrapUlid("00000000000000000000000000"),
                new BootstrapUlid("00000000000000000000000001"),
                new BootstrapUlid("00000000000000000000000002")),
            "node-2",
            new BootstrapCertificateFingerprint(new string('e', 64)),
            now.AddSeconds(-1),
            now.AddMinutes(1),
            [BootstrapGrantOperation.EnsureSystemProject]));
        var envelope = signer.Sign("SFO", "node-2", 1, "A-account", "U-user", new string('f', 64), "cluster", Scope, grant);
        using var verifier = ECDsa.Create();
        verifier.ImportSubjectPublicKeyInfo(signer.ExportSubjectPublicKeyInfo(), out _);
        var result = RegionalNodeEnrollmentVerifier.Verify(
            envelope,
            verifier,
            "GRU",
            "node-2",
            "A-account",
            "U-user",
            "enrollment-key",
            1,
            Scope,
            new SignedBootstrapGrantVerification(SignedBootstrapGrantDecision.Authorized, "grant-key", 1, true),
            new InMemoryRegionalNodeEnrollmentReplayStore());

        await Assert.That(result.Decision).IsEqualTo(RegionalNodeEnrollmentDecision.WrongRegion);
    }

    [Test]
    public async Task Durable_enrollment_verification_consumes_each_generation_once()
    {
        using var signerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new RegionalNodeEnrollmentSigner("enrollment-key", 3, signerKey);
        using var grantKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var issuer = new BootstrapGrantIssuer("grant-key", 1, BootstrapTrustKeyPurpose.GrantSigning, grantKey);
        var now = DateTimeOffset.UtcNow;
        var grant = issuer.Sign(new BootstrapGrantPayload(
            "00000000000000000000000005",
            new string('1', 64),
            "grant-key",
            1,
            BootstrapKeyPurposeCodes.GrantSigning,
            new BootstrapSystemProjectUlds(
                new BootstrapUlid("00000000000000000000000000"),
                new BootstrapUlid("00000000000000000000000001"),
                new BootstrapUlid("00000000000000000000000002")),
            "node-3",
            new BootstrapCertificateFingerprint(new string('2', 64)),
            now.AddSeconds(-1),
            now.AddMinutes(1),
            [BootstrapGrantOperation.EnsureSystemOrganization]));
        using var verifierKey = ECDsa.Create();
        verifierKey.ImportSubjectPublicKeyInfo(signer.ExportSubjectPublicKeyInfo(), out _);
        var envelope = signer.Sign(
            "GRU", "node-3", 9, "A-account", "U-user", new string('3', 64), "cluster", Scope, grant);
        var grantVerification = new SignedBootstrapGrantVerification(
            SignedBootstrapGrantDecision.Authorized, "grant-key", 1, true);
        var replay = new FakeDurableReplayStore();

        var first = await RegionalNodeEnrollmentVerifier.VerifyAsync(
            envelope, verifierKey, "GRU", "node-3", "A-account", "U-user",
            "enrollment-key", 3, Scope, grantVerification, replay, CancellationToken.None);
        var second = await RegionalNodeEnrollmentVerifier.VerifyAsync(
            envelope, verifierKey, "GRU", "node-3", "A-account", "U-user",
            "enrollment-key", 3, Scope, grantVerification, replay, CancellationToken.None);

        await Assert.That(first.Decision).IsEqualTo(RegionalNodeEnrollmentDecision.Authorized);
        await Assert.That(second.Decision).IsEqualTo(RegionalNodeEnrollmentDecision.ReplayDetected);
        await Assert.That(replay.Calls).IsEqualTo(2);
    }

    [Test]
    public async Task Scope_requires_a_unique_closed_role_set_and_snapshots_caller_storage()
    {
        var roles = new[] { Runtime.AdmittedRole.TerraBaseMember, Runtime.AdmittedRole.Authentication };
        var scope = new RegionalNodeEnrollmentScope("production", roles);
        roles[0] = Runtime.AdmittedRole.Orchestrator;
        await Assert.That(scope.Roles).DoesNotContain(Runtime.AdmittedRole.Orchestrator);
        await Assert.That(scope.Matches(new("production", [Runtime.AdmittedRole.Authentication, Runtime.AdmittedRole.TerraBaseMember]))).IsTrue();
        await Assert.That(() => new RegionalNodeEnrollmentScope("production", [])).Throws<ArgumentException>();
        await Assert.That(() => new RegionalNodeEnrollmentScope("production", [Runtime.AdmittedRole.Authentication, Runtime.AdmittedRole.Authentication]))
            .Throws<ArgumentException>();
        await Assert.That(() => new RegionalNodeEnrollmentScope("production", [(Runtime.AdmittedRole)999]))
            .Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new RegionalNodeEnrollmentScope("Production/other", [Runtime.AdmittedRole.Authentication]))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task Changing_a_signed_scope_cannot_authorize_a_different_workload_or_environment()
    {
        using var signerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new RegionalNodeEnrollmentSigner("enrollment-key", 3, signerKey);
        using var grantKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var issuer = new BootstrapGrantIssuer("grant-key", 1, BootstrapTrustKeyPurpose.GrantSigning, grantKey);
        var now = DateTimeOffset.UtcNow;
        var grant = issuer.Sign(new BootstrapGrantPayload(
            "00000000000000000000000006", new string('4', 64), "grant-key", 1,
            BootstrapKeyPurposeCodes.GrantSigning,
            new BootstrapSystemProjectUlds(new("00000000000000000000000000"), new("00000000000000000000000001"), new("00000000000000000000000002")),
            "node-4", new BootstrapCertificateFingerprint(new string('5', 64)),
            now.AddSeconds(-1), now.AddMinutes(1), [BootstrapGrantOperation.EnsureSystemOrganization]));
        var envelope = signer.Sign("GRU", "node-4", 10, "A-account", "U-user", new string('6', 64), "cluster", Scope, grant);
        using var verifier = ECDsa.Create();
        verifier.ImportSubjectPublicKeyInfo(signer.ExportSubjectPublicKeyInfo(), out _);
        var grantVerification = new SignedBootstrapGrantVerification(SignedBootstrapGrantDecision.Authorized, "grant-key", 1, true);
        foreach (var changed in new[]
                 {
                     new RegionalNodeEnrollmentScope("staging", Scope.Roles),
                     new RegionalNodeEnrollmentScope("production", [Runtime.AdmittedRole.Authentication]),
                 })
        {
            var replay = new FakeDurableReplayStore();
            var mismatch = await RegionalNodeEnrollmentVerifier.VerifyAsync(envelope, verifier, "GRU", "node-4",
                "A-account", "U-user", "enrollment-key", 3, changed, grantVerification, replay, CancellationToken.None);
            await Assert.That(mismatch.Decision).IsEqualTo(RegionalNodeEnrollmentDecision.ScopeMismatch);
            var forged = new RegionalNodeEnrollmentEnvelope(envelope.Region, envelope.NodeId, envelope.BootstrapGeneration,
                envelope.NatsAccountPublicKey, envelope.NatsUserPublicKey, envelope.CredentialBundleSha256,
                envelope.ClusterName, changed, envelope.Grant, envelope.SignerKeyId, envelope.SignerKeyVersion, envelope.Signature);
            var tampered = await RegionalNodeEnrollmentVerifier.VerifyAsync(forged, verifier, "GRU", "node-4",
                "A-account", "U-user", "enrollment-key", 3, changed, grantVerification, replay, CancellationToken.None);
            await Assert.That(tampered.Decision).IsEqualTo(RegionalNodeEnrollmentDecision.InvalidSignature);
            await Assert.That(replay.Calls).IsEqualTo(0);
        }
    }

    private sealed class FakeDurableReplayStore : IRegionalNodeEnrollmentDurableReplayStore
    {
        private readonly InMemoryRegionalNodeEnrollmentReplayStore inner = new();

        public int Calls { get; private set; }

        public ValueTask<bool> TryAcceptAsync(
            string nodeId,
            ulong generation,
            string grantId,
            string nonce,
            CancellationToken cancellationToken)
        {
            Calls++;
            return ValueTask.FromResult(inner.TryAccept(nodeId, generation, grantId, nonce));
        }
    }
}
