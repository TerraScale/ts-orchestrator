package security

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var bootstrapNow = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

func bootstrapSystemProject(t *testing.T) BootstrapSystemProjectIdentity {
	t.Helper()
	return BootstrapSystemProjectIdentity{
		OrganizationId: mustOrganizationId(t, "terrascale-system"),
		ProjectId:      mustProjectId(t, "terrascale-system-project"),
		DatabaseId:     mustDatabaseId(t, "terrascale-system-database"),
	}
}

func bootstrapAudience(t *testing.T) BootstrapAudience {
	return mustAudience(t, "database-api-bootstrap")
}

func bootstrapCertificate(t *testing.T) BootstrapCertificateThumbprint {
	return mustThumbprint(t, strings.Repeat("a", 64))
}

func bootstrapKey(t *testing.T, keyId string, version uint64) BootstrapTrustBundleKey {
	return BootstrapTrustBundleKey{
		KeyId:   mustTrustBundleKeyId(t, keyId),
		Version: mustTrustBundleVersion(t, version),
	}
}

func mustOrganizationId(t *testing.T, value string) BootstrapOrganizationId {
	t.Helper()
	id, err := NewBootstrapOrganizationId(value)
	if err != nil {
		t.Fatalf("organization id: %v", err)
	}
	return id
}

func mustProjectId(t *testing.T, value string) BootstrapProjectId {
	t.Helper()
	id, err := NewBootstrapProjectId(value)
	if err != nil {
		t.Fatalf("project id: %v", err)
	}
	return id
}

func mustDatabaseId(t *testing.T, value string) BootstrapDatabaseId {
	t.Helper()
	id, err := NewBootstrapDatabaseId(value)
	if err != nil {
		t.Fatalf("database id: %v", err)
	}
	return id
}

func mustAudience(t *testing.T, value string) BootstrapAudience {
	t.Helper()
	audience, err := NewBootstrapAudience(value)
	if err != nil {
		t.Fatalf("audience: %v", err)
	}
	return audience
}

func mustThumbprint(t *testing.T, value string) BootstrapCertificateThumbprint {
	t.Helper()
	thumbprint, err := NewBootstrapCertificateThumbprint(value)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return thumbprint
}

func mustTrustBundleKeyId(t *testing.T, value string) BootstrapTrustBundleKeyId {
	t.Helper()
	id, err := NewBootstrapTrustBundleKeyId(value)
	if err != nil {
		t.Fatalf("trust bundle key id: %v", err)
	}
	return id
}

func mustTrustBundleVersion(t *testing.T, value uint64) BootstrapTrustBundleVersion {
	t.Helper()
	version, err := NewBootstrapTrustBundleVersion(value)
	if err != nil {
		t.Fatalf("trust bundle version: %v", err)
	}
	return version
}

func mustGrantId(t *testing.T, value string) BootstrapGrantId {
	t.Helper()
	id, err := NewBootstrapGrantId(value)
	if err != nil {
		t.Fatalf("grant id: %v", err)
	}
	return id
}

func mustNonce(t *testing.T, value string) BootstrapNonce {
	t.Helper()
	nonce, err := NewBootstrapNonce(value)
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return nonce
}

type replayConsumer struct {
	consumed map[BootstrapGrantReplayKey]bool
	calls    int
}

func (c *replayConsumer) TryConsume(key BootstrapGrantReplayKey, expiresAt time.Time) (BootstrapReplayConsumeResult, error) {
	c.calls++
	if c.consumed == nil {
		c.consumed = map[BootstrapGrantReplayKey]bool{}
	}
	if c.consumed[key] {
		return BootstrapReplayConsumeResultAlreadyConsumed, nil
	}
	c.consumed[key] = true
	return BootstrapReplayConsumeResultConsumed, nil
}

type bootstrapVerifyOptions struct {
	replay             *replayConsumer
	operation          BootstrapOperation
	requestedOperation *BootstrapOperation
	audience           *BootstrapAudience
	certificate        *BootstrapCertificateThumbprint
	target             *BootstrapSystemProjectIdentity
	allowlist          []BootstrapSystemProjectIdentity
	trustKey           *BootstrapTrustBundleKey
	signatureKey       *BootstrapTrustBundleKey
	issuedAt           *time.Time
	expiresAt          *time.Time
	maximumLifetime    *time.Duration
	signature          *BootstrapGrantSignatureEvidence
	omitSignature      bool
}

func bootstrapVerify(t *testing.T, options bootstrapVerifyOptions) BootstrapGrantVerificationResult {
	t.Helper()
	systemProject := bootstrapSystemProject(t)
	audience := bootstrapAudience(t)
	certificate := bootstrapCertificate(t)
	currentKey := bootstrapKey(t, "bootstrap-key-current", 2)
	previousKey := bootstrapKey(t, "bootstrap-key-previous", 1)

	operation := options.operation
	if operation == 0 {
		operation = BootstrapOperationEnsureSystemProject
	}
	issuedAt := bootstrapNow.Add(-time.Minute)
	if options.issuedAt != nil {
		issuedAt = *options.issuedAt
	}
	expiresAt := bootstrapNow.Add(9 * time.Minute)
	if options.expiresAt != nil {
		expiresAt = *options.expiresAt
	}
	trustKey := currentKey
	if options.trustKey != nil {
		trustKey = *options.trustKey
	}
	target := systemProject
	if options.target != nil {
		target = *options.target
	}
	grant, err := NewBootstrapGrant(
		mustGrantId(t, "grant-1"),
		mustNonce(t, "nonce-1"),
		bootstrapAudienceOrDefault(options.audience, audience),
		bootstrapCertificateOrDefault(options.certificate, certificate),
		target,
		operation,
		issuedAt,
		expiresAt,
		trustKey)
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	requestedOperation := operation
	if options.requestedOperation != nil {
		requestedOperation = *options.requestedOperation
	}
	allowlist := options.allowlist
	if allowlist == nil {
		allowlist = []BootstrapSystemProjectIdentity{systemProject}
	}
	systemAllowlist, err := NewBootstrapSystemProjectAllowlist(allowlist)
	if err != nil {
		t.Fatalf("allowlist: %v", err)
	}
	rotation, err := NewBootstrapTrustBundleRotation(currentKey, &previousKey)
	if err != nil {
		t.Fatalf("rotation: %v", err)
	}
	maximumLifetime := 10 * time.Minute
	if options.maximumLifetime != nil {
		maximumLifetime = *options.maximumLifetime
	}
	context, err := NewBootstrapGrantVerificationContext(
		requestedOperation, audience, certificate, systemProject,
		systemAllowlist, rotation, bootstrapNow, maximumLifetime)
	if err != nil {
		t.Fatalf("context: %v", err)
	}
	var evidence *BootstrapGrantSignatureEvidence
	if !options.omitSignature {
		if options.signature != nil {
			evidence = options.signature
		} else {
			signatureKey := trustKey
			if options.signatureKey != nil {
				signatureKey = *options.signatureKey
			}
			signatureEvidence, evidenceErr := NewBootstrapGrantSignatureEvidence(
				BootstrapGrantSignatureStatusValid, &signatureKey)
			if evidenceErr != nil {
				t.Fatalf("signature evidence: %v", evidenceErr)
			}
			evidence = &signatureEvidence
		}
	}
	var replay BootstrapGrantReplayConsumer
	if options.replay != nil {
		replay = options.replay
	}
	input, err := NewBootstrapGrantVerificationInput(grant, context, evidence, replay)
	if err != nil {
		t.Fatalf("input: %v", err)
	}
	result, err := BootstrapGrantVerifier.Verify(input)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return result
}

func bootstrapAudienceOrDefault(value *BootstrapAudience, fallback BootstrapAudience) BootstrapAudience {
	if value != nil {
		return *value
	}
	return fallback
}

func bootstrapCertificateOrDefault(value *BootstrapCertificateThumbprint, fallback BootstrapCertificateThumbprint) BootstrapCertificateThumbprint {
	if value != nil {
		return *value
	}
	return fallback
}

func TestExactSignedGrantConsumesOnceAndAuthorizes(t *testing.T) {
	replay := &replayConsumer{}
	result := bootstrapVerify(t, bootstrapVerifyOptions{replay: replay})

	if !result.Authorized || result.Code != BootstrapGrantDecisionCodeAuthorized {
		t.Fatalf("unexpected result %+v", result)
	}
	if result.Audit.ReplayOutcome != BootstrapReplayAuditOutcomeConsumed {
		t.Fatalf("unexpected replay outcome %v", result.Audit.ReplayOutcome)
	}
	if replay.calls != 1 {
		t.Fatalf("expected one consume, got %d", replay.calls)
	}
}

func TestOperationMismatchAndNonIdempotentOperationAreDenied(t *testing.T) {
	requested := BootstrapOperationEnsureSystemProject
	mismatch := bootstrapVerify(t, bootstrapVerifyOptions{
		replay:             &replayConsumer{},
		operation:          BootstrapOperationEnsureSystemDatabase,
		requestedOperation: &requested,
	})
	customerAction := bootstrapVerify(t, bootstrapVerifyOptions{
		replay:    &replayConsumer{},
		operation: BootstrapOperationReadCustomerProject,
	})

	if mismatch.Code != BootstrapGrantDecisionCodeOperationMismatch {
		t.Fatalf("unexpected code %v", mismatch.Code)
	}
	if customerAction.Code != BootstrapGrantDecisionCodeOperationNotIdempotent {
		t.Fatalf("unexpected code %v", customerAction.Code)
	}
}

func TestAudienceAndCertificateMismatchesAreDeniedBeforeReplay(t *testing.T) {
	wrongAudienceValue := mustAudience(t, "other-audience")
	wrongAudience := bootstrapVerify(t, bootstrapVerifyOptions{
		replay:   &replayConsumer{},
		audience: &wrongAudienceValue,
	})
	wrongCertificateValue := mustThumbprint(t, strings.Repeat("b", 64))
	wrongCertificate := bootstrapVerify(t, bootstrapVerifyOptions{
		replay:      &replayConsumer{},
		certificate: &wrongCertificateValue,
	})

	if wrongAudience.Code != BootstrapGrantDecisionCodeAudienceMismatch {
		t.Fatalf("unexpected code %v", wrongAudience.Code)
	}
	if wrongCertificate.Code != BootstrapGrantDecisionCodeCertificateMismatch {
		t.Fatalf("unexpected code %v", wrongCertificate.Code)
	}
	if wrongAudience.Audit.AudienceMatched {
		t.Fatal("the audit must record the audience mismatch")
	}
	if wrongCertificate.Audit.CertificateMatched {
		t.Fatal("the audit must record the certificate mismatch")
	}
}

func TestCustomerTargetIsExplicitlyDeniedAndOtherSystemTargetDoesNotMatchRequest(t *testing.T) {
	systemProject := bootstrapSystemProject(t)
	customerProject := BootstrapSystemProjectIdentity{
		OrganizationId: mustOrganizationId(t, "customer-org"),
		ProjectId:      mustProjectId(t, "customer-project"),
		DatabaseId:     mustDatabaseId(t, "customer-db"),
	}
	customer := bootstrapVerify(t, bootstrapVerifyOptions{replay: &replayConsumer{}, target: &customerProject})
	otherSystem := BootstrapSystemProjectIdentity{
		OrganizationId: mustOrganizationId(t, "other-system"),
		ProjectId:      mustProjectId(t, "other-system-project"),
		DatabaseId:     mustDatabaseId(t, "other-system-db"),
	}
	mismatch := bootstrapVerify(t, bootstrapVerifyOptions{
		replay:    &replayConsumer{},
		target:    &otherSystem,
		allowlist: []BootstrapSystemProjectIdentity{systemProject, otherSystem},
	})

	if customer.Code != BootstrapGrantDecisionCodeCustomerProjectDenied {
		t.Fatalf("unexpected code %v", customer.Code)
	}
	if !customer.Audit.CustomerProjectDenied {
		t.Fatal("the audit must record the customer denial")
	}
	if mismatch.Code != BootstrapGrantDecisionCodeSystemProjectMismatch {
		t.Fatalf("unexpected code %v", mismatch.Code)
	}
}

func TestCurrentAndPreviousOverlapKeysAreAcceptedButUnknownKeyOrVersionIsDenied(t *testing.T) {
	previousKey := bootstrapKey(t, "bootstrap-key-previous", 1)
	previous := bootstrapVerify(t, bootstrapVerifyOptions{
		replay: &replayConsumer{}, trustKey: &previousKey, signatureKey: &previousKey,
	})
	unknownKeyValue := bootstrapKey(t, "untrusted-key", 1)
	unknown := bootstrapVerify(t, bootstrapVerifyOptions{
		replay: &replayConsumer{}, trustKey: &unknownKeyValue, signatureKey: &unknownKeyValue,
	})
	wrongVersion := bootstrapKey(t, "bootstrap-key-current", 3)
	version := bootstrapVerify(t, bootstrapVerifyOptions{
		replay: &replayConsumer{}, trustKey: &wrongVersion, signatureKey: &wrongVersion,
	})

	if !previous.Authorized {
		t.Fatalf("the overlap key must authorize: %+v", previous)
	}
	if unknown.Code != BootstrapGrantDecisionCodeTrustBundleKeyMismatch {
		t.Fatalf("unexpected code %v", unknown.Code)
	}
	if version.Code != BootstrapGrantDecisionCodeTrustBundleKeyMismatch {
		t.Fatalf("unexpected code %v", version.Code)
	}
}

func TestSignatureKeyMismatchIsDeniedWithoutConsumingNonce(t *testing.T) {
	replay := &replayConsumer{}
	currentKey := bootstrapKey(t, "bootstrap-key-current", 2)
	previousKey := bootstrapKey(t, "bootstrap-key-previous", 1)
	result := bootstrapVerify(t, bootstrapVerifyOptions{
		replay: replay, trustKey: &currentKey, signatureKey: &previousKey,
	})
	if result.Code != BootstrapGrantDecisionCodeSignatureKeyMismatch {
		t.Fatalf("unexpected code %v", result.Code)
	}
	if replay.calls != 0 {
		t.Fatalf("a signature mismatch must not consume the nonce, got %d calls", replay.calls)
	}
	if result.Audit.ReplayOutcome != BootstrapReplayAuditOutcomeNotAttempted {
		t.Fatal("replay must not be attempted on a signature mismatch")
	}
}

func TestNotYetValidExpiredInvalidAndTooLongWindowsAreDenied(t *testing.T) {
	notYetAt := bootstrapNow.Add(time.Second)
	expiredAt := bootstrapNow
	invalidIssued := bootstrapNow.Add(2 * time.Minute)
	invalidExpires := bootstrapNow.Add(time.Minute)
	tooLongExpires := bootstrapNow.Add(11 * time.Minute)
	tenMinutes := 10 * time.Minute

	notYet := bootstrapVerify(t, bootstrapVerifyOptions{replay: &replayConsumer{}, issuedAt: &notYetAt})
	expired := bootstrapVerify(t, bootstrapVerifyOptions{replay: &replayConsumer{}, expiresAt: &expiredAt})
	invalid := bootstrapVerify(t, bootstrapVerifyOptions{replay: &replayConsumer{}, issuedAt: &invalidIssued, expiresAt: &invalidExpires})
	tooLong := bootstrapVerify(t, bootstrapVerifyOptions{replay: &replayConsumer{}, expiresAt: &tooLongExpires, maximumLifetime: &tenMinutes})

	if notYet.Code != BootstrapGrantDecisionCodeNotYetValid {
		t.Fatalf("unexpected code %v", notYet.Code)
	}
	if expired.Code != BootstrapGrantDecisionCodeExpired {
		t.Fatalf("unexpected code %v", expired.Code)
	}
	if invalid.Code != BootstrapGrantDecisionCodeInvalidValidityWindow {
		t.Fatalf("unexpected code %v", invalid.Code)
	}
	if tooLong.Code != BootstrapGrantDecisionCodeLifetimeExceeded {
		t.Fatalf("unexpected code %v", tooLong.Code)
	}
}

func TestReplayIsDurableBoundaryAndSecondAttemptIsDenied(t *testing.T) {
	replay := &replayConsumer{}
	first := bootstrapVerify(t, bootstrapVerifyOptions{replay: replay})
	second := bootstrapVerify(t, bootstrapVerifyOptions{replay: replay})

	if !first.Authorized {
		t.Fatal("the first attempt must authorize")
	}
	if second.Code != BootstrapGrantDecisionCodeReplayDetected {
		t.Fatalf("unexpected code %v", second.Code)
	}
	if second.Audit.ReplayOutcome != BootstrapReplayAuditOutcomeAlreadyConsumed {
		t.Fatalf("unexpected replay outcome %v", second.Audit.ReplayOutcome)
	}
}

func TestMissingSignatureOrReplayPortFailsClosed(t *testing.T) {
	missingSignature := bootstrapVerify(t, bootstrapVerifyOptions{replay: &replayConsumer{}, omitSignature: true})
	missingReplay := bootstrapVerify(t, bootstrapVerifyOptions{})

	if missingSignature.Code != BootstrapGrantDecisionCodeInvalidSignature {
		t.Fatalf("unexpected code %v", missingSignature.Code)
	}
	if missingReplay.Code != BootstrapGrantDecisionCodeReplayConsumerUnavailable {
		t.Fatalf("unexpected code %v", missingReplay.Code)
	}
}

func TestAuditFactsAreRedactedAndContainOnlySafePolicyFields(t *testing.T) {
	result := bootstrapVerify(t, bootstrapVerifyOptions{replay: &replayConsumer{}})
	serialized, err := json.Marshal(result.Audit)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	dump := string(serialized)

	for _, forbidden := range []string{"grant-1", "nonce-1", strings.Repeat("a", 64), "database-api-bootstrap"} {
		if strings.Contains(dump, forbidden) {
			t.Fatalf("the audit must not carry %q: %s", forbidden, dump)
		}
	}
	if result.Audit.TrustBundleKeyId == nil || *result.Audit.TrustBundleKeyId != "bootstrap-key-current" {
		t.Fatalf("unexpected trust bundle key id %v", result.Audit.TrustBundleKeyId)
	}
	if result.Audit.TrustBundleVersion == nil || *result.Audit.TrustBundleVersion != 2 {
		t.Fatalf("unexpected trust bundle version %v", result.Audit.TrustBundleVersion)
	}
}
