package release

import (
	"fmt"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// VerifiedFunctionReceipt proves current signed metadata, never module execution
// authority. Module bytes must independently pass VerifyFunctionCurrent.
type VerifiedFunctionReceipt struct {
	claim FunctionClaim
	proof receiptProof
}

// VerifyFunctionReceiptCurrent checks the exact expected scope and durable floor
// without loading or authenticating the module bytes named by the receipt.
func VerifyFunctionReceiptCurrent(envelopeWire, delegationWire []byte, roots trust.Keyring,
	expected FunctionExpectation, now time.Time,
) (VerifiedFunctionReceipt, error) {
	if err := expected.validate(); err != nil {
		return VerifiedFunctionReceipt{}, err
	}
	claim, envelope, err := verifyFunctionReceipt(envelopeWire, delegationWire, roots, expected, now)
	if err != nil {
		return VerifiedFunctionReceipt{}, err
	}
	proof, err := proofFor(envelope)
	if err != nil {
		return VerifiedFunctionReceipt{}, err
	}
	return VerifiedFunctionReceipt{claim: claim, proof: proof}, nil
}

func (expected FunctionExpectation) validate() error {
	if !ValidEnvironment(expected.Environment) || !ValidRegion(expected.Cell) || !entityid.Valid(expected.TenantID) ||
		!serviceRolePattern.MatchString(expected.FunctionID) || !serviceRolePattern.MatchString(expected.Revision) ||
		!digestPattern.MatchString(expected.Digest) || expected.MinimumSequence == 0 {
		return fmt.Errorf("%w: invalid function expectation or missing durable sequence floor", ErrExpectationMismatch)
	}
	return nil
}

func verifyFunctionReceipt(envelopeWire, delegationWire []byte, roots trust.Keyring,
	expected FunctionExpectation, now time.Time,
) (FunctionClaim, trust.Envelope, error) {
	envelope, delegationEnvelope, err := decodeEnvelopePair(envelopeWire, delegationWire)
	if err != nil {
		return FunctionClaim{}, trust.Envelope{}, err
	}
	claim, err := decodeCanonicalPayload[FunctionClaim](envelope.Payload)
	if err != nil {
		return FunctionClaim{}, trust.Envelope{}, err
	}
	if err := claim.Validate(); err != nil {
		return FunctionClaim{}, trust.Envelope{}, err
	}
	if claim.Environment != expected.Environment || claim.Cell != expected.Cell || claim.TenantID != expected.TenantID ||
		claim.FunctionID != expected.FunctionID || claim.Revision != expected.Revision || claim.Digest != expected.Digest ||
		claim.Sequence < expected.MinimumSequence {
		return FunctionClaim{}, trust.Envelope{}, ErrExpectationMismatch
	}
	delegation, err := trust.VerifyDelegationCurrent(delegationEnvelope, roots, now, delegationPolicy())
	if err != nil {
		return FunctionClaim{}, trust.Envelope{}, fmt.Errorf("verify current function delegation: %w", err)
	}
	if _, err := trust.VerifyDelegatedCurrent(envelope, FunctionScope(claim), delegation, now, receiptPolicy()); err != nil {
		return FunctionClaim{}, trust.Envelope{}, fmt.Errorf("verify current function claim: %w", err)
	}
	return claim, envelope, nil
}

func (verified VerifiedFunctionReceipt) Claim() FunctionClaim {
	claim := verified.claim
	claim.Capabilities = slices.Clone(claim.Capabilities)
	return claim
}

func (verified VerifiedFunctionReceipt) Valid() bool {
	return verified.proof.verified && time.Now().Before(verified.proof.expiresAt)
}

func (verified VerifiedFunctionReceipt) ExpiresAt() time.Time   { return verified.proof.expiresAt }
func (verified VerifiedFunctionReceipt) EnvelopeSHA256() string { return verified.proof.envelopeSHA256 }
