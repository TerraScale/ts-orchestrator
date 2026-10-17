package release

import (
	"errors"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const (
	ProductionQualificationDomain       = "terrascale.release.production-qualification"
	ProductionQualificationSchema       = "terrascale.release.production-qualification.v1"
	FoundationWriterQualificationSchema = "terrascale.release.production-qualification.v2"
	FoundationWriterRole                = "foundation-writer"
	RootCredentialBoundaryGate          = "root-credential-boundary"
	ProductionRuntime                   = "swarmkit-containerd"
	NetBirdProductionRuntime            = "netbird-containerd"
	MaxProductionEvidenceBytes          = 64 << 20
)

var ErrProductionQualification = errors.New("production qualification is missing or invalid")

// ProductionExpectation comes from inspected candidate bytes and the target's scope.
// Build provenance alone never establishes runtime or workload qualification.
type ProductionExpectation struct {
	ImageOCID           string `json:"image_ocid,omitempty"`
	SourceRevision      string `json:"source_revision"`
	ArtifactSHA256      string `json:"artifact_sha256"`
	QualificationSHA256 string `json:"qualification_sha256"`
	Cell                string `json:"cell"`
	Environment         string `json:"environment"`
	Runtime             string `json:"runtime"`
	Architecture        string `json:"architecture"`
	Role                string `json:"role"`
}

type ProductionGateEvidence struct {
	Gate        string    `json:"gate"`
	SHA256      string    `json:"sha256"`
	Bytes       int64     `json:"bytes"`
	CompletedAt time.Time `json:"completed_at"`
}

// ProductionQualification is a separate authority's statement that the required
// gates passed, bound to retained evidence bytes and one exact regional candidate.
type ProductionQualification struct {
	Schema    string                   `json:"schema"`
	Candidate ProductionExpectation    `json:"candidate"`
	Evidence  []ProductionGateEvidence `json:"evidence"`
}

func ProductionQualificationScope(candidate ProductionExpectation) trust.Scope {
	return trust.Scope{Domain: ProductionQualificationDomain, DeploymentID: entityid.Derive("build", candidate.SourceRevision),
		Cell: candidate.Cell, Environment: candidate.Environment, Role: candidate.Role,
		Slot: candidate.Runtime + "/linux-" + candidate.Architecture}
}

// VerifyProductionCurrent accepts a trusted root or an explicitly delegated
// qualification signer. An ordinary binary-release delegation grants no authority.
// The caller must also verify the referenced retained evidence bytes.
func VerifyProductionCurrent(wire, delegationWire []byte, roots trust.Keyring, expected ProductionExpectation, now time.Time) (ProductionQualification, error) {
	var qualification ProductionQualification
	gates := []string{"runtime-ha", "workload-safety"}
	schema := ProductionQualificationSchema
	if expected.Role == FoundationWriterRole {
		schema = FoundationWriterQualificationSchema
		gates = append(gates, RootCredentialBoundaryGate)
	}
	validRuntime := expected.Runtime == ProductionRuntime
	if expected.Role == FoundationWriterRole {
		validRuntime = validRuntime && ValidOCIImageIDForRegion(expected.ImageOCID, expected.Cell)
	}
	if expected.Role == "netbird-manager" || expected.Runtime == NetBirdProductionRuntime {
		validRuntime = expected.Role == "netbird-manager" && expected.Runtime == NetBirdProductionRuntime &&
			expected.Cell == "GRU" && expected.Architecture == "arm64"
		gates = []string{"netbird-foundation", "netbird-recovery"}
	}
	if !ValidSourceRevision(expected.SourceRevision) || !digestPattern.MatchString(expected.ArtifactSHA256) ||
		!digestPattern.MatchString(expected.QualificationSHA256) || !ValidRegion(expected.Cell) ||
		!ValidEnvironment(expected.Environment) || !validRuntime ||
		expected.Architecture != "amd64" && expected.Architecture != "arm64" || !serviceRolePattern.MatchString(expected.Role) {
		return qualification, fmt.Errorf("%w: candidate scope", ErrProductionQualification)
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return qualification, fmt.Errorf("%w: %w", ErrProductionQualification, err)
	}
	policy := trust.Policy{MaxLifetime: MaxUpdateReceiptLifetime}
	var payload []byte
	if len(delegationWire) == 0 {
		payload, err = trust.VerifyCurrent(envelope, ProductionQualificationScope(expected), roots, now, policy)
	} else {
		var delegationEnvelope trust.Envelope
		delegationEnvelope, err = trust.DecodeEnvelope(delegationWire)
		if err == nil {
			var delegation trust.VerifiedDelegation
			delegation, err = trust.VerifyDelegationCurrent(delegationEnvelope, roots, now, policy)
			if err == nil {
				payload, err = trust.VerifyDelegatedCurrent(envelope, ProductionQualificationScope(expected), delegation, now, policy)
			}
		}
	}
	if err != nil {
		return qualification, fmt.Errorf("%w: %w", ErrProductionQualification, err)
	}
	if err := protocol.DecodeStrict(payload, &qualification, trust.MaxPayloadBytes); err != nil {
		return qualification, fmt.Errorf("%w: %w", ErrProductionQualification, err)
	}
	if qualification.Schema != schema || qualification.Candidate != expected || len(qualification.Evidence) != len(gates) {
		return qualification, fmt.Errorf("%w: candidate or required gates", ErrProductionQualification)
	}
	for index, gate := range gates {
		evidence := qualification.Evidence[index]
		if evidence.Gate != gate || !digestPattern.MatchString(evidence.SHA256) ||
			evidence.Bytes <= 0 || evidence.Bytes > MaxProductionEvidenceBytes || evidence.CompletedAt.IsZero() ||
			evidence.CompletedAt.After(envelope.IssuedAt) {
			return qualification, fmt.Errorf("%w: %s evidence", ErrProductionQualification, gate)
		}
	}
	return qualification, nil
}
