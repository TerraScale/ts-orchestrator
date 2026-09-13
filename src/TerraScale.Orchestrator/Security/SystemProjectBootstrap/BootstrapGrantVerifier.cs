namespace TerraScale.Orchestrator.Security.SystemProjectBootstrap;

public static class BootstrapGrantVerifier
{
    public static BootstrapGrantVerificationResult Verify(BootstrapGrantVerificationInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var grant = input.Grant;
        var context = input.Context;
        var signature = input.SignatureEvidence;
        var signatureStatus = signature?.Status ?? BootstrapGrantSignatureStatus.Unavailable;
        var audit = new BootstrapGrantAuditFacts(
            BootstrapGrantDecisionCode.InvalidSignature,
            grant.Operation,
            grant.TrustBundleKey.KeyId,
            grant.TrustBundleKey.Version.Value,
            context.SystemProjectAllowlist.Contains(grant.Target),
            !context.SystemProjectAllowlist.Contains(grant.Target),
            grant.Audience == context.ExpectedAudience,
            grant.CertificateThumbprint == context.ExpectedCertificateThumbprint,
            false,
            signatureStatus,
            BootstrapReplayAuditOutcome.NotAttempted);

        if (signature is null || signature.Status != BootstrapGrantSignatureStatus.Valid)
            return Deny(audit, BootstrapGrantDecisionCode.InvalidSignature);
        if (signature.VerifiedWith is null || signature.VerifiedWith != grant.TrustBundleKey)
            return Deny(audit, BootstrapGrantDecisionCode.SignatureKeyMismatch);
        if (grant.Operation != context.RequestedOperation)
            return Deny(audit, BootstrapGrantDecisionCode.OperationMismatch);
        if (!IsIdempotentBootstrapOperation(grant.Operation))
            return Deny(audit, BootstrapGrantDecisionCode.OperationNotIdempotent);
        if (grant.Audience != context.ExpectedAudience)
            return Deny(audit, BootstrapGrantDecisionCode.AudienceMismatch);
        if (grant.CertificateThumbprint != context.ExpectedCertificateThumbprint)
            return Deny(audit, BootstrapGrantDecisionCode.CertificateMismatch);

        var targetAllowlisted = context.SystemProjectAllowlist.Contains(grant.Target);
        if (!targetAllowlisted)
            return Deny(audit with { TargetAllowlisted = false, CustomerProjectDenied = true }, BootstrapGrantDecisionCode.CustomerProjectDenied);
        if (grant.Target != context.ExpectedTarget)
            return Deny(audit with { TargetAllowlisted = true, CustomerProjectDenied = false }, BootstrapGrantDecisionCode.SystemProjectMismatch);
        if (!context.TrustBundle.Accepts(grant.TrustBundleKey))
            return Deny(audit, BootstrapGrantDecisionCode.TrustBundleKeyMismatch);

        var timeWindow = ValidateTimeWindow(grant, context);
        if (timeWindow != BootstrapGrantDecisionCode.Authorized)
            return Deny(audit with { TimeWindowValid = false }, timeWindow);
        audit = audit with { TimeWindowValid = true };

        if (input.ReplayConsumer is null)
            return Deny(audit, BootstrapGrantDecisionCode.ReplayConsumerUnavailable);

        BootstrapReplayConsumeResult consumed;
        try
        {
            consumed = input.ReplayConsumer.TryConsume(new BootstrapGrantReplayKey(grant.GrantId, grant.Nonce), grant.ExpiresAt);
        }
        catch (Exception)
        {
            return Deny(audit with { ReplayOutcome = BootstrapReplayAuditOutcome.Unavailable }, BootstrapGrantDecisionCode.ReplayConsumerUnavailable);
        }

        return consumed switch
        {
            BootstrapReplayConsumeResult.Consumed => Allow(audit with { ReplayOutcome = BootstrapReplayAuditOutcome.Consumed }),
            BootstrapReplayConsumeResult.AlreadyConsumed => Deny(audit with { ReplayOutcome = BootstrapReplayAuditOutcome.AlreadyConsumed }, BootstrapGrantDecisionCode.ReplayDetected),
            BootstrapReplayConsumeResult.Rejected => Deny(audit with { ReplayOutcome = BootstrapReplayAuditOutcome.Rejected }, BootstrapGrantDecisionCode.ReplayRejected),
            BootstrapReplayConsumeResult.Unavailable => Deny(audit with { ReplayOutcome = BootstrapReplayAuditOutcome.Unavailable }, BootstrapGrantDecisionCode.ReplayConsumerUnavailable),
            _ => Deny(audit with { ReplayOutcome = BootstrapReplayAuditOutcome.Unavailable }, BootstrapGrantDecisionCode.ReplayConsumerUnavailable),
        };
    }

    private static bool IsIdempotentBootstrapOperation(BootstrapOperation operation) => operation is
        BootstrapOperation.EnsureSystemOrganization or
        BootstrapOperation.EnsureSystemProject or
        BootstrapOperation.EnsureSystemDatabase or
        BootstrapOperation.EnsureSystemProjectConfiguration;

    private static BootstrapGrantDecisionCode ValidateTimeWindow(BootstrapGrant grant, BootstrapGrantVerificationContext context)
    {
        if (grant.ExpiresAt <= grant.IssuedAt) return BootstrapGrantDecisionCode.InvalidValidityWindow;
        if (context.Now < grant.IssuedAt) return BootstrapGrantDecisionCode.NotYetValid;
        if (context.Now >= grant.ExpiresAt) return BootstrapGrantDecisionCode.Expired;
        if (grant.ExpiresAt - grant.IssuedAt > context.MaximumLifetime) return BootstrapGrantDecisionCode.LifetimeExceeded;
        return BootstrapGrantDecisionCode.Authorized;
    }

    private static BootstrapGrantVerificationResult Allow(BootstrapGrantAuditFacts audit) =>
        new(true, BootstrapGrantDecisionCode.Authorized, audit with { Code = BootstrapGrantDecisionCode.Authorized });

    private static BootstrapGrantVerificationResult Deny(BootstrapGrantAuditFacts audit, BootstrapGrantDecisionCode code) =>
        new(false, code, audit with { Code = code });
}

