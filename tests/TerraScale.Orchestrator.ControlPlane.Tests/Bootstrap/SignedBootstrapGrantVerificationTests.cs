using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TUnit.Assertions;
using TUnit.Core;
using TerraScale.Orchestrator.Bootstrap;
using TerraScale.Orchestrator.Security.SystemProjectBootstrap;
using BootstrapTrustKey = TerraScale.Orchestrator.Bootstrap.BootstrapTrustBundleKey;
using SystemProjectBootstrapPolicy = TerraScale.Orchestrator.Security.SystemProjectBootstrap;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Bootstrap;

/// <summary>
/// Cold-bootstrap grant verification (qualification gap sweep row 31): the
/// Orchestrator issues a signed, audience- and certificate-bound,
/// short-lived, replay-protected BootstrapGrant over the fixed system Project
/// identities, and the Database API shape verifies it entirely from a local
/// rotated trust bundle. Wiring this verifier into TerraScale.Database is a
/// later cross-repository packet; these lanes exercise the Orchestrator-side
/// module only.
/// </summary>
public sealed class SignedBootstrapGrantVerificationTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 29, 12, 0, 0, TimeSpan.Zero);
    private static readonly string Audience = "terrascale-database-api-bootstrap";
    private static readonly string Nonce = string.Concat(Enumerable.Repeat("0f1e2d3c4b5a69788796a5b4c3d2e1f0", 2));
    private static readonly string GrantId = "01ARZ3NDEKTSV4RRFFQ69G5FAZ";
    private static readonly TimeSpan MaximumLifetime = TimeSpan.FromMinutes(15);
    private static readonly IReadOnlyList<string> DefaultOperations = [BootstrapGrantOperation.EnsureSystemProject];
    private static readonly BootstrapSystemProjectUlds SystemProject = new(
        new BootstrapUlid("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
        new BootstrapUlid("01ARZ3NDEKTSV4RRFFQ69G5FAW"),
        new BootstrapUlid("01ARZ3NDEKTSV4RRFFQ69G5FAX"));

    [Test]
    public async Task Valid_grant_verifies_from_the_local_bundle_only()
    {
        using var lab = new GrantLab();
        var grant = lab.SignCurrent();
        var result = Verify(lab, grant, lab.Request());

        await Assert.That(result.Authorized).IsTrue();
        await Assert.That(result.Decision).IsEqualTo(SignedBootstrapGrantDecision.Authorized);
        await Assert.That(result.VerifiedKeyId).IsEqualTo(GrantLab.CurrentKeyId);
        await Assert.That(result.VerifiedKeyVersion).IsEqualTo(2UL);
        await Assert.That(result.SignatureVerified).IsTrue();
    }

    [Test]
    public async Task Wrong_audience_fails_typed()
    {
        using var lab = new GrantLab();
        var result = Verify(lab, lab.SignCurrent(), lab.Request(expectedAudience: "other-database-audience"));

        await Assert.That(result.Decision).IsEqualTo(SignedBootstrapGrantDecision.AudienceMismatch);
        await Assert.That(result.Authorized).IsFalse();
    }

    [Test]
    public async Task Wrong_workload_certificate_fails_typed()
    {
        using var lab = new GrantLab();
        using var otherWorkload = TestWorkloadCertificateFactory.Issue(Now.AddMinutes(-5), Now.AddMinutes(30));
        var result = Verify(lab, lab.SignCurrent(), lab.Request(presentedFingerprint: otherWorkload.Fingerprint().Value));

        await Assert.That(result.Decision).IsEqualTo(SignedBootstrapGrantDecision.CertificateMismatch);
    }

    [Test]
    public async Task Expired_not_yet_valid_and_overlong_grants_fail_typed()
    {
        using var lab = new GrantLab();
        var expired = Verify(lab, lab.SignCurrent(expiresAt: Now.AddSeconds(-1)), lab.Request(now: Now.AddSeconds(1)));
        var notYet = Verify(lab, lab.SignCurrent(issuedAt: Now.AddMinutes(1)), lab.Request());
        var tooLong = Verify(lab, lab.SignCurrent(expiresAt: Now.AddMinutes(20)), lab.Request());

        await Assert.That(expired.Decision).IsEqualTo(SignedBootstrapGrantDecision.Expired);
        await Assert.That(notYet.Decision).IsEqualTo(SignedBootstrapGrantDecision.NotYetValid);
        await Assert.That(tooLong.Decision).IsEqualTo(SignedBootstrapGrantDecision.LifetimeExceeded);
    }

    [Test]
    public async Task Replayed_grant_fails_typed_and_consumes_the_nonce_exactly_once()
    {
        using var lab = new GrantLab();
        var grant = lab.SignCurrent();
        var journal = SharedJournal();
        var first = Verify(lab, grant, lab.Request(), journal: journal);
        var second = Verify(lab, grant, lab.Request(), journal: journal);

        await Assert.That(first.Authorized).IsTrue();
        await Assert.That(second.Decision).IsEqualTo(SignedBootstrapGrantDecision.ReplayDetected);
        await Assert.That(second.Authorized).IsFalse();
    }

    [Test]
    public async Task Missing_replay_journal_fails_closed()
    {
        using var lab = new GrantLab();
        var result = SignedBootstrapGrantVerifier.Verify(lab.SignCurrent(), lab.BundleWithRotation, lab.Request(), null);

        await Assert.That(result.Decision).IsEqualTo(SignedBootstrapGrantDecision.ReplayJournalUnavailable);
    }

    [Test]
    public async Task File_replay_journal_survives_the_restart_shape()
    {
        using var lab = new GrantLab();
        var directory = CreateTempDirectory();
        var journalPath = Path.Combine(directory.FullName, "replay.jsonl");
        var grant = lab.SignCurrent();
        try
        {
            var firstJournal = new FileBootstrapGrantReplayJournal(journalPath, Now);
            var first = SignedBootstrapGrantVerifier.Verify(grant, lab.BundleWithRotation, lab.Request(), firstJournal);
            firstJournal.Dispose();

            // A torn trailing line (crash during append, when no answer was returned) is skipped, not fatal.
            File.AppendAllText(journalPath, "{\"grantId\":\"01AR" + Environment.NewLine);
            using var restarted = new FileBootstrapGrantReplayJournal(journalPath, Now);
            var second = SignedBootstrapGrantVerifier.Verify(grant, lab.BundleWithRotation, lab.Request(), restarted);

            await Assert.That(first.Authorized).IsTrue();
            await Assert.That(second.Decision).IsEqualTo(SignedBootstrapGrantDecision.ReplayDetected);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Test]
    public async Task Expired_journal_entries_are_pruned_on_restart()
    {
        using var lab = new GrantLab();
        var directory = CreateTempDirectory();
        var journalPath = Path.Combine(directory.FullName, "replay.jsonl");
        var shortLived = lab.SignCurrent(nonce: Nonce.Replace('0', '1'), expiresAt: Now.AddMinutes(1));
        try
        {
            using (var journal = new FileBootstrapGrantReplayJournal(journalPath, Now))
            {
                var first = SignedBootstrapGrantVerifier.Verify(shortLived, lab.BundleWithRotation, lab.Request(), journal);
                await Assert.That(first.Authorized).IsTrue();
            }

            using var restarted = new FileBootstrapGrantReplayJournal(journalPath, Now.AddHours(1));
            var replay = SignedBootstrapGrantVerifier.Verify(shortLived, lab.BundleWithRotation, lab.Request(now: Now.AddHours(1)), restarted);

            // The expired entry was pruned on load: a longer-lived grant re-using the identity consumes cleanly again.
            var reissued = lab.SignCurrent(nonce: Nonce.Replace('0', '1'), issuedAt: Now.AddHours(1), expiresAt: Now.AddHours(1).AddMinutes(9));
            var reissuedResult = SignedBootstrapGrantVerifier.Verify(reissued, lab.BundleWithRotation, lab.Request(now: Now.AddHours(1)), restarted);

            await Assert.That(replay.Decision).IsEqualTo(SignedBootstrapGrantDecision.Expired);
            await Assert.That(reissuedResult.Authorized).IsTrue();
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Test]
    public async Task Unknown_signing_key_or_version_fails_typed()
    {
        using var lab = new GrantLab();
        var unknownKey = lab.SignArbitrary("untrusted-key", 2, lab.CurrentSigningKey);
        var unknownVersion = lab.SignArbitrary(GrantLab.CurrentKeyId, 3, lab.CurrentSigningKey);

        var unknownKeyResult = Verify(lab, unknownKey, lab.Request());
        var unknownVersionResult = Verify(lab, unknownVersion, lab.Request());

        await Assert.That(unknownKeyResult.Decision).IsEqualTo(SignedBootstrapGrantDecision.UnknownSigningKey);
        await Assert.That(unknownVersionResult.Decision).IsEqualTo(SignedBootstrapGrantDecision.UnknownSigningKey);
    }

    [Test]
    public async Task Tampered_payload_fails_typed_as_an_invalid_signature()
    {
        using var lab = new GrantLab();
        var grant = lab.SignCurrent();
        var retargeted = lab.SignCurrent(audience: "attacker-audience");
        var tampered = retargeted with { Signature = grant.Signature };

        var result = Verify(lab, tampered, lab.Request());

        await Assert.That(result.Decision).IsEqualTo(SignedBootstrapGrantDecision.InvalidSignature);
        await Assert.That(result.SignatureVerified).IsFalse();
    }

    [Test]
    public async Task Non_canonical_payload_text_fails_typed_before_signature_work()
    {
        using var lab = new GrantLab();
        var grant = lab.SignCurrent();
        var lengthTampered = new SignedBootstrapGrant(
            grant.PayloadText.Replace("26:01ARZ3NDEKTSV4RRFFQ69G5FAV;", "25:01ARZ3NDEKTSV4RRFFQ69G5FAV;", StringComparison.Ordinal),
            grant.Algorithm,
            grant.Signature);
        var unknownVersionPayload = new SignedBootstrapGrant(
            grant.PayloadText.Replace(BootstrapGrantPayload.PayloadVersion, "terrascale-bootstrap-grant-v0", StringComparison.Ordinal),
            grant.Algorithm,
            grant.Signature);

        var lengthResult = Verify(lab, lengthTampered, lab.Request());
        var versionResult = Verify(lab, unknownVersionPayload, lab.Request());

        await Assert.That(lengthResult.Decision).IsEqualTo(SignedBootstrapGrantDecision.NonCanonicalPayload);
        await Assert.That(versionResult.Decision).IsEqualTo(SignedBootstrapGrantDecision.NonCanonicalPayload);
    }

    [Test]
    public async Task Previous_bundle_version_grant_still_verifies_inside_the_pinned_rotation_window()
    {
        using var lab = new GrantLab();
        var insideWindow = lab.SignPrevious(expiresAt: Now.AddDays(1));
        var beyondWindow = lab.SignPrevious(expiresAt: Now.AddDays(5));

        var longWindow = TimeSpan.FromDays(7);
        var inside = Verify(lab, insideWindow, lab.Request(maximumLifetime: longWindow));
        var beyond = Verify(lab, beyondWindow, lab.Request(maximumLifetime: longWindow));

        await Assert.That(inside.Authorized).IsTrue();
        await Assert.That(inside.VerifiedKeyId).IsEqualTo(GrantLab.PreviousKeyId);
        await Assert.That(beyond.Decision).IsEqualTo(SignedBootstrapGrantDecision.RotationWindowExceeded);
    }

    [Test]
    public async Task After_rotation_advances_the_retired_key_is_unknown()
    {
        using var lab = new GrantLab();
        var result = Verify(lab, lab.SignPrevious(expiresAt: Now.AddDays(1)), lab.Request(maximumLifetime: TimeSpan.FromDays(7)), lab.RotatedForwardBundle);

        await Assert.That(result.Decision).IsEqualTo(SignedBootstrapGrantDecision.UnknownSigningKey);
    }

    [Test]
    public async Task Key_purpose_separation_is_enforced_on_both_issuance_and_verification()
    {
        using var lab = new GrantLab();
        var issuerRefusal = Assert.Throws<ArgumentException>(GrantLab.RefuseAttestationPurposeIssuer);
        var result = Verify(lab, lab.SignWithAttestationKey(), lab.Request(), lab.BundleWithAttestationKey);

        await Assert.That(issuerRefusal).IsNotNull();
        await Assert.That(result.Decision).IsEqualTo(SignedBootstrapGrantDecision.KeyPurposeMismatch);
    }

    [Test]
    public async Task Operation_allowlist_and_idempotence_fail_typed()
    {
        using var lab = new GrantLab();
        var notGranted = Verify(lab, lab.SignCurrent(), lab.Request(requestedOperation: BootstrapGrantOperation.EnsureSystemDatabase));
        var nonIdempotent = Verify(
            lab,
            lab.SignCurrent(operations: [BootstrapGrantOperation.EnsureSystemProject, BootstrapGrantOperation.ReadCustomerProject]),
            lab.Request(requestedOperation: BootstrapGrantOperation.ReadCustomerProject));

        await Assert.That(notGranted.Decision).IsEqualTo(SignedBootstrapGrantDecision.OperationNotAllowed);
        await Assert.That(nonIdempotent.Decision).IsEqualTo(SignedBootstrapGrantDecision.OperationNotIdempotent);
    }

    [Test]
    public async Task A_grant_for_a_different_system_project_fails_typed()
    {
        using var lab = new GrantLab();
        var otherProject = new BootstrapSystemProjectUlds(
            new BootstrapUlid("01ARZ3NDEKTSV4RRFFQ69G5FBA"),
            new BootstrapUlid("01ARZ3NDEKTSV4RRFFQ69G5FBW"),
            new BootstrapUlid("01ARZ3NDEKTSV4RRFFQ69G5FBX"));
        var result = Verify(lab, lab.SignCurrent(systemProject: otherProject), lab.Request());

        await Assert.That(result.Decision).IsEqualTo(SignedBootstrapGrantDecision.SystemProjectMismatch);
    }

    [Test]
    public async Task Issuance_refuses_malformed_grants()
    {
        using var lab = new GrantLab();
        var reversedWindow = Assert.Throws<ArgumentException>(() => lab.SignCurrent(issuedAt: Now.AddMinutes(5), expiresAt: Now.AddMinutes(1)));
        var lowercaseUlid = Assert.Throws<ArgumentException>(() => lab.SignCurrent(grantId: "01arz3ndektsv4rrffq69g5fav"));
        var badNonce = Assert.Throws<ArgumentException>(() => lab.SignCurrent(nonce: new string('z', 64)));

        await Assert.That(reversedWindow).IsNotNull();
        await Assert.That(lowercaseUlid).IsNotNull();
        await Assert.That(badNonce).IsNotNull();
    }

    [Test]
    public async Task Canonical_payload_is_deterministic_and_round_trips()
    {
        using var lab = new GrantLab();
        var left = lab.SignCurrent();
        var right = lab.SignCurrent();
        var roundTripped = BootstrapGrantPayload.Parse(left.PayloadText);

        await Assert.That(left.PayloadText).IsEqualTo(right.PayloadText);
        await Assert.That(roundTripped.Encode()).IsEqualTo(left.PayloadText);
        await Assert.That(string.Join(",", roundTripped.AllowedOperations))
            .IsEqualTo(BootstrapGrantOperation.EnsureSystemProject);
    }

    [Test]
    public async Task Cryptographic_layer_composes_with_the_landed_policy_engine()
    {
        using var lab = new GrantLab();
        var grant = lab.SignCurrent();
        var journal = new InMemoryBootstrapReplayJournal();
        var (crypto, payload) = SignedBootstrapGrantVerifier.VerifyCryptographic(grant, lab.BundleWithRotation, Now);
        var parsed = payload ?? grant.ParsePayload();

        var lowerSystem = new BootstrapSystemProjectIdentity(
            new BootstrapOrganizationId(parsed.SystemProject.OrganizationUlid.Value.ToLowerInvariant()),
            new BootstrapProjectId(parsed.SystemProject.ProjectUlid.Value.ToLowerInvariant()),
            new BootstrapDatabaseId(parsed.SystemProject.DatabaseUlid.Value.ToLowerInvariant()));
        var policyGrant = new BootstrapGrant(
            new BootstrapGrantId(parsed.GrantId.Value.ToLowerInvariant()),
            new BootstrapNonce(parsed.Nonce),
            new BootstrapAudience(parsed.Audience),
            new BootstrapCertificateThumbprint(parsed.CertificateFingerprint.Value),
            lowerSystem,
            BootstrapOperation.EnsureSystemProject,
            parsed.IssuedAt,
            parsed.ExpiresAt,
            new SystemProjectBootstrapPolicy.BootstrapTrustBundleKey(
                new BootstrapTrustBundleKeyId(crypto.VerifiedKeyId!),
                new BootstrapTrustBundleVersion(crypto.VerifiedKeyVersion!.Value)));
        var context = new BootstrapGrantVerificationContext(
            BootstrapOperation.EnsureSystemProject,
            new BootstrapAudience(Audience),
            new BootstrapCertificateThumbprint(parsed.CertificateFingerprint.Value),
            lowerSystem,
            new BootstrapSystemProjectAllowlist([lowerSystem]),
            new BootstrapTrustBundleRotation(
                new SystemProjectBootstrapPolicy.BootstrapTrustBundleKey(new BootstrapTrustBundleKeyId(GrantLab.CurrentKeyId), new BootstrapTrustBundleVersion(2)),
                new SystemProjectBootstrapPolicy.BootstrapTrustBundleKey(new BootstrapTrustBundleKeyId(GrantLab.PreviousKeyId), new BootstrapTrustBundleVersion(1))),
            Now,
            MaximumLifetime);
        var policy = BootstrapGrantVerifier.Verify(new BootstrapGrantVerificationInput(policyGrant, context, crypto.ToSignatureEvidence(), journal));

        await Assert.That(crypto.Authorized).IsTrue();
        await Assert.That(policy.Authorized).IsTrue();
        await Assert.That(policy.Code).IsEqualTo(BootstrapGrantDecisionCode.Authorized);
        await Assert.That(policy.Audit.TrustBundleKeyId).IsEqualTo(GrantLab.CurrentKeyId);
    }

    [Test]
    public async Task Verification_result_redacts_every_bound_value()
    {
        using var lab = new GrantLab();
        var grant = lab.SignCurrent();
        var result = Verify(lab, grant, lab.Request(expectedAudience: "other-audience"));
        var serialized = JsonSerializer.Serialize(result);
        var parsed = grant.ParsePayload();

        await Assert.That(serialized).DoesNotContain(Nonce);
        await Assert.That(serialized).DoesNotContain(parsed.GrantId.Value);
        await Assert.That(serialized).DoesNotContain(parsed.CertificateFingerprint.Value);
        await Assert.That(serialized).DoesNotContain(Audience);
        await Assert.That(parsed.CertificateFingerprint.ToString()).IsEqualTo("[redacted]");
    }


    private static DirectoryInfo CreateTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "terrascale-bootstrap-replay-" + RandomNumberGenerator.GetHexString(12, lowercase: true));
        return Directory.CreateDirectory(path);
    }

    private static SignedBootstrapGrantVerification Verify(
        GrantLab lab,
        SignedBootstrapGrant grant,
        BootstrapGrantVerificationRequest request,
        RotatedBootstrapTrustBundle? bundle = null,
        IBootstrapGrantReplayJournal? journal = null) =>
        SignedBootstrapGrantVerifier.Verify(grant, bundle ?? lab.BundleWithRotation, request, journal ?? new InMemoryBootstrapReplayJournal());

    private static IBootstrapGrantReplayJournal SharedJournal() => new InMemoryBootstrapReplayJournal();

    /// <summary>Issues real ECDSA P-256 keys and a real short-lived workload certificate for one test run.</summary>
    private sealed class GrantLab : IDisposable
    {
        public const string CurrentKeyId = "system-grant-key";
        public const string PreviousKeyId = "system-grant-key-previous";
        public const string AttestationKeyId = "system-workload-attestation";

        private readonly ECDsa currentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa previousKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa attestationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly BootstrapWorkloadCertificate workloadCertificate =
            TestWorkloadCertificateFactory.Issue(Now.AddMinutes(-5), Now.AddMinutes(30));
        private readonly BootstrapGrantIssuer currentIssuer;
        private readonly BootstrapGrantIssuer previousIssuer;

        public GrantLab()
        {
            currentIssuer = new BootstrapGrantIssuer(CurrentKeyId, 2, BootstrapTrustKeyPurpose.GrantSigning, currentKey);
            previousIssuer = new BootstrapGrantIssuer(PreviousKeyId, 1, BootstrapTrustKeyPurpose.GrantSigning, previousKey);
            BundleWithRotation = new RotatedBootstrapTrustBundle(
                3,
                [
                    currentIssuer.ExportPublicKey(),
                    previousIssuer.ExportPublicKey(acceptedUntil: Now.AddDays(2)),
                ],
                CurrentKeyId,
                2);
            BundleWithAttestationKey = new RotatedBootstrapTrustBundle(
                3,
                [
                    currentIssuer.ExportPublicKey(),
                    new BootstrapTrustKey(AttestationKeyId, 1, BootstrapTrustKeyPurpose.WorkloadAttestation, attestationKey.ExportSubjectPublicKeyInfo()),
                ],
                CurrentKeyId,
                2);
            RotatedForwardBundle = new RotatedBootstrapTrustBundle(4, [currentIssuer.ExportPublicKey()], CurrentKeyId, 2);
        }

        public RotatedBootstrapTrustBundle BundleWithRotation { get; }
        public RotatedBootstrapTrustBundle BundleWithAttestationKey { get; }
        public RotatedBootstrapTrustBundle RotatedForwardBundle { get; }
        public ECDsa CurrentSigningKey => currentKey;

        public BootstrapGrantVerificationRequest Request(
            DateTimeOffset? now = null,
            string? expectedAudience = null,
            string? presentedFingerprint = null,
            string? requestedOperation = null,
            TimeSpan? maximumLifetime = null) =>
            new(
                expectedAudience ?? Audience,
                presentedFingerprint ?? workloadCertificate.Fingerprint().Value,
                requestedOperation ?? BootstrapGrantOperation.EnsureSystemProject,
                SystemProject,
                now ?? Now,
                maximumLifetime ?? MaximumLifetime);

        public SignedBootstrapGrant SignCurrent(
            string? audience = null,
            DateTimeOffset? issuedAt = null,
            DateTimeOffset? expiresAt = null,
            IReadOnlyList<string>? operations = null,
            string? nonce = null,
            string? grantId = null,
            BootstrapSystemProjectUlds? systemProject = null) =>
            SignWith(currentIssuer, audience ?? Audience, issuedAt, expiresAt, operations, nonce, grantId, systemProject);

        public SignedBootstrapGrant SignPrevious(
            string? audience = null,
            DateTimeOffset? issuedAt = null,
            DateTimeOffset? expiresAt = null,
            IReadOnlyList<string>? operations = null,
            string? nonce = null,
            string? grantId = null,
            BootstrapSystemProjectUlds? systemProject = null) =>
            SignWith(previousIssuer, audience ?? Audience, issuedAt, expiresAt, operations, nonce, grantId, systemProject);

        public SignedBootstrapGrant SignArbitrary(string keyId, ulong keyVersion, ECDsa key) =>
            SignRaw(BuildPayload(keyId, keyVersion, BootstrapTrustKeyPurposeCodes.ToCode(BootstrapTrustKeyPurpose.GrantSigning), Audience, null, null, null, null), key);

        public SignedBootstrapGrant SignWithAttestationKey() =>
            SignRaw(
                BuildPayload(AttestationKeyId, 1, BootstrapTrustKeyPurposeCodes.ToCode(BootstrapTrustKeyPurpose.WorkloadAttestation), Audience, null, null, null, null),
                attestationKey);

        public static void RefuseAttestationPurposeIssuer()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            _ = new BootstrapGrantIssuer(CurrentKeyId, 2, BootstrapTrustKeyPurpose.WorkloadAttestation, key);
        }

        public void Dispose()
        {
            currentIssuer.Dispose();
            previousIssuer.Dispose();
            currentKey.Dispose();
            previousKey.Dispose();
            attestationKey.Dispose();
            workloadCertificate.Dispose();
        }

        private SignedBootstrapGrant SignWith(
            BootstrapGrantIssuer issuer,
            string audience,
            DateTimeOffset? issuedAt,
            DateTimeOffset? expiresAt,
            IReadOnlyList<string>? operations,
            string? nonce,
            string? grantId,
            BootstrapSystemProjectUlds? systemProject) =>
            issuer.Sign(BuildPayload(
                issuer.KeyId,
                issuer.KeyVersion,
                BootstrapTrustKeyPurposeCodes.ToCode(issuer.Purpose),
                audience,
                issuedAt,
                expiresAt,
                operations,
                nonce,
                grantId,
                systemProject));

        private BootstrapGrantPayload BuildPayload(
            string keyId,
            ulong keyVersion,
            string keyPurposeCode,
            string audience,
            DateTimeOffset? issuedAt,
            DateTimeOffset? expiresAt,
            IReadOnlyList<string>? operations,
            string? nonce,
            string? grantId = null,
            BootstrapSystemProjectUlds? systemProject = null) =>
            new(
                grantId ?? GrantId,
                nonce ?? Nonce,
                keyId,
                keyVersion,
                keyPurposeCode,
                systemProject ?? SystemProject,
                audience,
                workloadCertificate.Fingerprint(),
                issuedAt ?? Now.AddMinutes(-1),
                expiresAt ?? Now.AddMinutes(9),
                operations ?? DefaultOperations);

        private static SignedBootstrapGrant SignRaw(BootstrapGrantPayload payload, ECDsa key)
        {
            var payloadText = payload.Encode();
            var signature = Convert.ToBase64String(key.SignData(Encoding.UTF8.GetBytes(payloadText), HashAlgorithmName.SHA256));
            return new SignedBootstrapGrant(payloadText, SignedBootstrapGrant.SigningAlgorithm, signature);
        }
    }
}
