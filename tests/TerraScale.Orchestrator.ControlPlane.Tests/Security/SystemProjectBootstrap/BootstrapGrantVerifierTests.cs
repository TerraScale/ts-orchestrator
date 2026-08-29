using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;
using TerraScale.Orchestrator.Security.SystemProjectBootstrap;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Security.SystemProjectBootstrap;

public sealed class BootstrapGrantVerifierTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 29, 12, 0, 0, TimeSpan.Zero);
    private static readonly BootstrapSystemProjectIdentity SystemProject = new(
        new BootstrapOrganizationId("terrascale-system"),
        new BootstrapProjectId("terrascale-system-project"),
        new BootstrapDatabaseId("terrascale-system-database"));
    private static readonly BootstrapAudience Audience = new("database-api-bootstrap");
    private static readonly BootstrapCertificateThumbprint Certificate = new(new string('a', 64));
    private static readonly BootstrapTrustBundleKey CurrentKey = new(
        new BootstrapTrustBundleKeyId("bootstrap-key-current"), new BootstrapTrustBundleVersion(2));
    private static readonly BootstrapTrustBundleKey PreviousKey = new(
        new BootstrapTrustBundleKeyId("bootstrap-key-previous"), new BootstrapTrustBundleVersion(1));

    [Test]
    public async Task Exact_signed_grant_consumes_once_and_authorizes()
    {
        var replay = new ReplayConsumer();
        var result = Verify(replay);

        await Assert.That(result.Authorized).IsTrue();
        await Assert.That(result.Code).IsEqualTo(BootstrapGrantDecisionCode.Authorized);
        await Assert.That(result.Audit.ReplayOutcome).IsEqualTo(BootstrapReplayAuditOutcome.Consumed);
        await Assert.That(replay.Calls).IsEqualTo(1);
    }

    [Test]
    public async Task Operation_mismatch_and_non_idempotent_operation_are_denied()
    {
        var mismatch = Verify(new ReplayConsumer(), operation: BootstrapOperation.EnsureSystemDatabase,
            requestedOperation: BootstrapOperation.EnsureSystemProject);
        var customerAction = Verify(new ReplayConsumer(), operation: BootstrapOperation.ReadCustomerProject,
            requestedOperation: BootstrapOperation.ReadCustomerProject);

        await Assert.That(mismatch.Code).IsEqualTo(BootstrapGrantDecisionCode.OperationMismatch);
        await Assert.That(customerAction.Code).IsEqualTo(BootstrapGrantDecisionCode.OperationNotIdempotent);
    }

    [Test]
    public async Task Audience_and_certificate_mismatches_are_denied_before_replay()
    {
        var wrongAudience = Verify(new ReplayConsumer(), audience: new BootstrapAudience("other-audience"));
        var wrongCertificate = Verify(new ReplayConsumer(), certificate: new BootstrapCertificateThumbprint(new string('b', 64)));

        await Assert.That(wrongAudience.Code).IsEqualTo(BootstrapGrantDecisionCode.AudienceMismatch);
        await Assert.That(wrongCertificate.Code).IsEqualTo(BootstrapGrantDecisionCode.CertificateMismatch);
        await Assert.That(wrongAudience.Audit.AudienceMatched).IsFalse();
        await Assert.That(wrongCertificate.Audit.CertificateMatched).IsFalse();
    }

    [Test]
    public async Task Customer_target_is_explicitly_denied_and_other_system_target_does_not_match_request()
    {
        var customerProject = new BootstrapSystemProjectIdentity(
            new BootstrapOrganizationId("customer-org"), new BootstrapProjectId("customer-project"), new BootstrapDatabaseId("customer-db"));
        var customer = Verify(new ReplayConsumer(), target: customerProject);
        var otherSystem = new BootstrapSystemProjectIdentity(
            new BootstrapOrganizationId("other-system"), new BootstrapProjectId("other-system-project"), new BootstrapDatabaseId("other-system-db"));
        var mismatch = Verify(new ReplayConsumer(), target: otherSystem, allowlist: [SystemProject, otherSystem]);

        await Assert.That(customer.Code).IsEqualTo(BootstrapGrantDecisionCode.CustomerProjectDenied);
        await Assert.That(customer.Audit.CustomerProjectDenied).IsTrue();
        await Assert.That(mismatch.Code).IsEqualTo(BootstrapGrantDecisionCode.SystemProjectMismatch);
    }

    [Test]
    public async Task Current_and_previous_overlap_keys_are_accepted_but_unknown_key_or_version_is_denied()
    {
        var previous = Verify(new ReplayConsumer(), trustKey: PreviousKey, signatureKey: PreviousKey);
        var unknownKey = new BootstrapTrustBundleKey(new BootstrapTrustBundleKeyId("untrusted-key"), new BootstrapTrustBundleVersion(1));
        var unknown = Verify(new ReplayConsumer(), trustKey: unknownKey, signatureKey: unknownKey);
        var wrongVersion = new BootstrapTrustBundleKey(CurrentKey.KeyId, new BootstrapTrustBundleVersion(3));
        var version = Verify(new ReplayConsumer(), trustKey: wrongVersion, signatureKey: wrongVersion);

        await Assert.That(previous.Authorized).IsTrue();
        await Assert.That(unknown.Code).IsEqualTo(BootstrapGrantDecisionCode.TrustBundleKeyMismatch);
        await Assert.That(version.Code).IsEqualTo(BootstrapGrantDecisionCode.TrustBundleKeyMismatch);
    }

    [Test]
    public async Task Signature_key_mismatch_is_denied_without_consuming_nonce()
    {
        var replay = new ReplayConsumer();
        var result = Verify(replay, trustKey: CurrentKey, signatureKey: PreviousKey);

        await Assert.That(result.Code).IsEqualTo(BootstrapGrantDecisionCode.SignatureKeyMismatch);
        await Assert.That(replay.Calls).IsEqualTo(0);
    }

    [Test]
    public async Task Not_yet_valid_expired_invalid_and_too_long_windows_are_denied()
    {
        var notYet = Verify(new ReplayConsumer(), issuedAt: Now.AddSeconds(1));
        var expired = Verify(new ReplayConsumer(), expiresAt: Now);
        var invalid = Verify(new ReplayConsumer(), issuedAt: Now.AddMinutes(2), expiresAt: Now.AddMinutes(1));
        var tooLong = Verify(new ReplayConsumer(), expiresAt: Now.AddMinutes(11), maximumLifetime: TimeSpan.FromMinutes(10));

        await Assert.That(notYet.Code).IsEqualTo(BootstrapGrantDecisionCode.NotYetValid);
        await Assert.That(expired.Code).IsEqualTo(BootstrapGrantDecisionCode.Expired);
        await Assert.That(invalid.Code).IsEqualTo(BootstrapGrantDecisionCode.InvalidValidityWindow);
        await Assert.That(tooLong.Code).IsEqualTo(BootstrapGrantDecisionCode.LifetimeExceeded);
    }

    [Test]
    public async Task Replay_is_durable_boundary_and_second_attempt_is_denied()
    {
        var replay = new ReplayConsumer();
        var first = Verify(replay);
        var second = Verify(replay);

        await Assert.That(first.Authorized).IsTrue();
        await Assert.That(second.Code).IsEqualTo(BootstrapGrantDecisionCode.ReplayDetected);
        await Assert.That(second.Audit.ReplayOutcome).IsEqualTo(BootstrapReplayAuditOutcome.AlreadyConsumed);
    }

    [Test]
    public async Task Missing_signature_or_replay_port_fails_closed()
    {
        var missingSignature = Verify(new ReplayConsumer(), omitSignature: true);
        var missingReplay = Verify(null);

        await Assert.That(missingSignature.Code).IsEqualTo(BootstrapGrantDecisionCode.InvalidSignature);
        await Assert.That(missingReplay.Code).IsEqualTo(BootstrapGrantDecisionCode.ReplayConsumerUnavailable);
    }

    [Test]
    public async Task Audit_facts_are_redacted_and_contain_only_safe_policy_fields()
    {
        var result = Verify(new ReplayConsumer());
        var serialized = JsonSerializer.Serialize(result.Audit);

        await Assert.That(serialized).DoesNotContain("grant-1");
        await Assert.That(serialized).DoesNotContain("nonce-1");
        await Assert.That(serialized).DoesNotContain(Certificate.Value);
        await Assert.That(serialized).DoesNotContain(Audience.Value);
        await Assert.That(result.Audit.TrustBundleKeyId).IsEqualTo(CurrentKey.KeyId.Value);
        await Assert.That(result.Audit.TrustBundleVersion).IsEqualTo(2UL);
    }

    private static BootstrapGrantVerificationResult Verify(
        ReplayConsumer? replay,
        BootstrapOperation operation = BootstrapOperation.EnsureSystemProject,
        BootstrapOperation? requestedOperation = null,
        BootstrapAudience? audience = null,
        BootstrapCertificateThumbprint? certificate = null,
        BootstrapSystemProjectIdentity? target = null,
        IReadOnlyList<BootstrapSystemProjectIdentity>? allowlist = null,
        BootstrapTrustBundleKey? trustKey = null,
        BootstrapTrustBundleKey? signatureKey = null,
        DateTimeOffset? issuedAt = null,
        DateTimeOffset? expiresAt = null,
        TimeSpan? maximumLifetime = null,
        BootstrapGrantSignatureEvidence? signature = null,
        bool omitSignature = false)
    {
        var grant = new BootstrapGrant(
            new BootstrapGrantId("grant-1"), new BootstrapNonce("nonce-1"), audience ?? Audience,
            certificate ?? Certificate, target ?? SystemProject, operation,
            issuedAt ?? Now.AddMinutes(-1), expiresAt ?? Now.AddMinutes(9), trustKey ?? CurrentKey);
        var context = new BootstrapGrantVerificationContext(
            requestedOperation ?? operation, Audience, Certificate, SystemProject,
            new BootstrapSystemProjectAllowlist(allowlist ?? [SystemProject]),
            new BootstrapTrustBundleRotation(CurrentKey, PreviousKey), Now,
            maximumLifetime ?? TimeSpan.FromMinutes(10));
        var evidence = omitSignature
            ? null
            : signature ?? new BootstrapGrantSignatureEvidence(
                BootstrapGrantSignatureStatus.Valid, signatureKey ?? trustKey ?? CurrentKey);
        return BootstrapGrantVerifier.Verify(new BootstrapGrantVerificationInput(grant, context, evidence, replay));
    }

    private sealed class ReplayConsumer : IBootstrapGrantReplayConsumer
    {
        private readonly HashSet<BootstrapGrantReplayKey> consumed = [];
        public int Calls { get; private set; }

        public BootstrapReplayConsumeResult TryConsume(BootstrapGrantReplayKey key, DateTimeOffset expiresAt)
        {
            Calls++;
            return consumed.Add(key) ? BootstrapReplayConsumeResult.Consumed : BootstrapReplayConsumeResult.AlreadyConsumed;
        }
    }
}
