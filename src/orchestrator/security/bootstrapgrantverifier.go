// This file ports Security/SystemProjectBootstrap/BootstrapGrantVerifier.cs.
package security

import "time"

// BootstrapGrantVerifier ports the static BootstrapGrantVerifier class; call it
// as security.BootstrapGrantVerifier.Verify(input) to mirror the C# call site.
var BootstrapGrantVerifier bootstrapGrantVerifier

type bootstrapGrantVerifier struct{}

// Verify runs the fail-closed bootstrap-grant decision.
func (bootstrapGrantVerifier) Verify(input *BootstrapGrantVerificationInput) (BootstrapGrantVerificationResult, error) {
	if input == nil {
		return BootstrapGrantVerificationResult{}, &ArgumentError{Param: "input"}
	}
	grant := input.Grant
	context := input.Context
	signature := input.SignatureEvidence
	signatureStatus := BootstrapGrantSignatureStatusUnavailable
	if signature != nil {
		signatureStatus = signature.Status
	}

	operation := grant.Operation
	version := grant.TrustBundleKey.Version.Value
	audit := newBootstrapGrantAuditFacts(
		BootstrapGrantDecisionCodeInvalidSignature,
		&operation,
		&grant.TrustBundleKey.KeyId,
		&version,
		context.SystemProjectAllowlist.Contains(grant.Target),
		!context.SystemProjectAllowlist.Contains(grant.Target),
		grant.Audience == context.ExpectedAudience,
		grant.CertificateThumbprint == context.ExpectedCertificateThumbprint,
		false,
		signatureStatus,
		BootstrapReplayAuditOutcomeNotAttempted)

	if signature == nil || signature.Status != BootstrapGrantSignatureStatusValid {
		return deny(audit, BootstrapGrantDecisionCodeInvalidSignature), nil
	}
	if signature.VerifiedWith == nil || *signature.VerifiedWith != grant.TrustBundleKey {
		return deny(audit, BootstrapGrantDecisionCodeSignatureKeyMismatch), nil
	}
	if grant.Operation != context.RequestedOperation {
		return deny(audit, BootstrapGrantDecisionCodeOperationMismatch), nil
	}
	if !isIdempotentBootstrapOperation(grant.Operation) {
		return deny(audit, BootstrapGrantDecisionCodeOperationNotIdempotent), nil
	}
	if grant.Audience != context.ExpectedAudience {
		return deny(audit, BootstrapGrantDecisionCodeAudienceMismatch), nil
	}
	if grant.CertificateThumbprint != context.ExpectedCertificateThumbprint {
		return deny(audit, BootstrapGrantDecisionCodeCertificateMismatch), nil
	}

	targetAllowlisted := context.SystemProjectAllowlist.Contains(grant.Target)
	if !targetAllowlisted {
		denied := audit
		denied.TargetAllowlisted = false
		denied.CustomerProjectDenied = true
		return deny(denied, BootstrapGrantDecisionCodeCustomerProjectDenied), nil
	}
	if grant.Target != context.ExpectedTarget {
		allowed := audit
		allowed.TargetAllowlisted = true
		allowed.CustomerProjectDenied = false
		return deny(allowed, BootstrapGrantDecisionCodeSystemProjectMismatch), nil
	}
	if !context.TrustBundle.Accepts(grant.TrustBundleKey) {
		return deny(audit, BootstrapGrantDecisionCodeTrustBundleKeyMismatch), nil
	}

	timeWindow := validateTimeWindow(grant, context)
	if timeWindow != BootstrapGrantDecisionCodeAuthorized {
		invalid := audit
		invalid.TimeWindowValid = false
		return deny(invalid, timeWindow), nil
	}
	audit.TimeWindowValid = true

	if input.ReplayConsumer == nil {
		return deny(audit, BootstrapGrantDecisionCodeReplayConsumerUnavailable), nil
	}

	consumed, consumeError := input.ReplayConsumer.TryConsume(
		BootstrapGrantReplayKey{GrantId: grant.GrantId, Nonce: grant.Nonce},
		grant.ExpiresAt)
	if consumeError != nil {
		unavailable := audit
		unavailable.ReplayOutcome = BootstrapReplayAuditOutcomeUnavailable
		return deny(unavailable, BootstrapGrantDecisionCodeReplayConsumerUnavailable), nil
	}

	switch consumed {
	case BootstrapReplayConsumeResultConsumed:
		allowed := audit
		allowed.ReplayOutcome = BootstrapReplayAuditOutcomeConsumed
		return newBootstrapGrantVerificationResult(
			true, BootstrapGrantDecisionCodeAuthorized, allowed), nil
	case BootstrapReplayConsumeResultAlreadyConsumed:
		detected := audit
		detected.ReplayOutcome = BootstrapReplayAuditOutcomeAlreadyConsumed
		return deny(detected, BootstrapGrantDecisionCodeReplayDetected), nil
	case BootstrapReplayConsumeResultRejected:
		rejected := audit
		rejected.ReplayOutcome = BootstrapReplayAuditOutcomeRejected
		return deny(rejected, BootstrapGrantDecisionCodeReplayRejected), nil
	default:
		unavailable := audit
		unavailable.ReplayOutcome = BootstrapReplayAuditOutcomeUnavailable
		return deny(unavailable, BootstrapGrantDecisionCodeReplayConsumerUnavailable), nil
	}
}

func isIdempotentBootstrapOperation(operation BootstrapOperation) bool {
	switch operation {
	case BootstrapOperationEnsureSystemOrganization,
		BootstrapOperationEnsureSystemProject,
		BootstrapOperationEnsureSystemDatabase,
		BootstrapOperationEnsureSystemProjectConfiguration:
		return true
	default:
		return false
	}
}

func validateTimeWindow(grant BootstrapGrant, context BootstrapGrantVerificationContext) BootstrapGrantDecisionCode {
	if !grant.ExpiresAt.After(grant.IssuedAt) {
		return BootstrapGrantDecisionCodeInvalidValidityWindow
	}
	if context.Now.Before(grant.IssuedAt) {
		return BootstrapGrantDecisionCodeNotYetValid
	}
	if !context.Now.Before(grant.ExpiresAt) {
		return BootstrapGrantDecisionCodeExpired
	}
	if grant.ExpiresAt.Sub(grant.IssuedAt) > context.MaximumLifetime {
		return BootstrapGrantDecisionCodeLifetimeExceeded
	}
	return BootstrapGrantDecisionCodeAuthorized
}

func deny(audit BootstrapGrantAuditFacts, code BootstrapGrantDecisionCode) BootstrapGrantVerificationResult {
	return newBootstrapGrantVerificationResult(false, code, audit)
}
