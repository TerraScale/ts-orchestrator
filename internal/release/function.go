package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const (
	FunctionDomain         = "terrascale.release.function"
	FunctionSchema         = "terrascale.release.function.v1"
	FunctionABI            = "terrascale.function.command.v1"
	MaxFunctionModuleBytes = 8 << 20
)

// FunctionClaim binds portable bytes and the supported ABI to one tenant's
// function revision. Sequence orders releases in the environment's function-worker
// channel; revisions are labels, never release ordering authority.
type FunctionClaim struct {
	Schema       string   `json:"schema"`
	ABI          string   `json:"abi"`
	TenantID     string   `json:"tenant_id"`
	FunctionID   string   `json:"function_id"`
	Revision     string   `json:"revision"`
	Digest       string   `json:"digest"`
	Bytes        int64    `json:"bytes"`
	Capabilities []string `json:"capabilities"`
	Environment  string   `json:"environment"`
	Cell         string   `json:"cell"`
	Sequence     uint64   `json:"sequence"`
}

// FunctionExpectation comes from admitted control state, never guest input.
// MinimumSequence is the durable function-worker channel floor; zero is refused.
type FunctionExpectation struct {
	Environment     string
	Cell            string
	TenantID        string
	FunctionID      string
	Revision        string
	Digest          string
	MinimumSequence uint64
}

// VerifiedFunction owns the exact bytes admitted by the current signature and
// delegation checks. It does not qualify the worker host or runtime isolation.
// Its zero value grants no execution authority.
type VerifiedFunction struct {
	claim      FunctionClaim
	module     []byte
	envelope   []byte
	delegation []byte
	proof      receiptProof
}

func (claim FunctionClaim) Validate() error {
	if claim.Schema != FunctionSchema || claim.ABI != FunctionABI || !entityid.Valid(claim.TenantID) ||
		!serviceRolePattern.MatchString(claim.FunctionID) || !serviceRolePattern.MatchString(claim.Revision) ||
		!digestPattern.MatchString(claim.Digest) || claim.Bytes <= 0 || claim.Bytes > MaxFunctionModuleBytes ||
		len(claim.Capabilities) != 0 || !ValidEnvironment(claim.Environment) || !ValidRegion(claim.Cell) || claim.Sequence == 0 {
		return fmt.Errorf("%w: function ABI, identity, bytes, capabilities or release scope", ErrInvalidReceipt)
	}
	return nil
}

// FunctionScope keeps online signing grants specific to a tenant and function.
func FunctionScope(claim FunctionClaim) trust.Scope {
	return trust.Scope{
		Domain: FunctionDomain, DeploymentID: claim.TenantID, Cell: claim.Cell,
		Environment: claim.Environment, Role: "function-worker", Slot: claim.FunctionID,
	}
}

// SignFunctionClaim signs only bytes matching the claim and a current exact
// root delegation. The producer allocates Sequence durably before calling it.
func SignFunctionClaim(claim FunctionClaim, module []byte, delegation trust.Envelope, roots trust.Keyring,
	privateKey ed25519.PrivateKey, now time.Time, validFor time.Duration,
) (trust.Envelope, error) {
	if err := claim.validateModule(module); err != nil {
		return trust.Envelope{}, err
	}
	return signReceipt(claim, FunctionScope(claim), delegation, roots, privateKey, now, validFor)
}

// VerifyFunctionCurrent admits portable bytes only after checking the trusted
// roots, exact signing grant, validity, expected identity, sequence and digest.
func VerifyFunctionCurrent(envelopeWire, delegationWire, module []byte, roots trust.Keyring,
	expected FunctionExpectation, now time.Time,
) (VerifiedFunction, error) {
	if !ValidEnvironment(expected.Environment) || !ValidRegion(expected.Cell) || !entityid.Valid(expected.TenantID) ||
		!serviceRolePattern.MatchString(expected.FunctionID) || !serviceRolePattern.MatchString(expected.Revision) ||
		!digestPattern.MatchString(expected.Digest) || expected.MinimumSequence == 0 {
		return VerifiedFunction{}, fmt.Errorf("%w: invalid function expectation or missing durable sequence floor", ErrExpectationMismatch)
	}
	if len(module) == 0 || len(module) > MaxFunctionModuleBytes {
		return VerifiedFunction{}, fmt.Errorf("%w: function module size", ErrInvalidReceipt)
	}
	envelope, delegationEnvelope, err := decodeEnvelopePair(envelopeWire, delegationWire)
	if err != nil {
		return VerifiedFunction{}, err
	}
	claim, err := decodeCanonicalPayload[FunctionClaim](envelope.Payload)
	if err != nil {
		return VerifiedFunction{}, err
	}
	if err := claim.Validate(); err != nil {
		return VerifiedFunction{}, err
	}
	if claim.Environment != expected.Environment || claim.Cell != expected.Cell || claim.TenantID != expected.TenantID ||
		claim.FunctionID != expected.FunctionID || claim.Revision != expected.Revision || claim.Digest != expected.Digest ||
		claim.Sequence < expected.MinimumSequence {
		return VerifiedFunction{}, ErrExpectationMismatch
	}
	delegation, err := trust.VerifyDelegationCurrent(delegationEnvelope, roots, now, delegationPolicy())
	if err != nil {
		return VerifiedFunction{}, fmt.Errorf("verify current function delegation: %w", err)
	}
	if _, err := trust.VerifyDelegatedCurrent(envelope, FunctionScope(claim), delegation, now, receiptPolicy()); err != nil {
		return VerifiedFunction{}, fmt.Errorf("verify current function claim: %w", err)
	}
	// Retain the copy whose digest is checked, so callers cannot mutate admitted bytes.
	admitted := bytes.Clone(module)
	if err := claim.validateModule(admitted); err != nil {
		return VerifiedFunction{}, err
	}
	proof, err := proofFor(envelope)
	if err != nil {
		return VerifiedFunction{}, err
	}
	return VerifiedFunction{claim: claim, module: admitted, envelope: bytes.Clone(envelopeWire),
		delegation: bytes.Clone(delegationWire), proof: proof}, nil
}

func (claim FunctionClaim) validateModule(module []byte) error {
	if err := claim.Validate(); err != nil {
		return err
	}
	if int64(len(module)) != claim.Bytes {
		return fmt.Errorf("%w: function module size mismatch", ErrInvalidReceipt)
	}
	digest := sha256.Sum256(module)
	if hex.EncodeToString(digest[:]) != claim.Digest {
		return fmt.Errorf("%w: function module digest mismatch", ErrInvalidReceipt)
	}
	return nil
}

// Valid rejects both forged zero values and authority that expired after admission.
func (verified VerifiedFunction) Valid() bool {
	return verified.proof.verified && time.Now().Before(verified.proof.expiresAt)
}

func (verified VerifiedFunction) Claim() FunctionClaim {
	claim := verified.claim
	claim.Capabilities = slices.Clone(claim.Capabilities)
	return claim
}

func (verified VerifiedFunction) Module() []byte         { return bytes.Clone(verified.module) }
func (verified VerifiedFunction) Envelope() []byte       { return bytes.Clone(verified.envelope) }
func (verified VerifiedFunction) Delegation() []byte     { return bytes.Clone(verified.delegation) }
func (verified VerifiedFunction) ExpiresAt() time.Time   { return verified.proof.expiresAt }
func (verified VerifiedFunction) EnvelopeSHA256() string { return verified.proof.envelopeSHA256 }
