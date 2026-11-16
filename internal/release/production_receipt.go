package release

import (
	"encoding/json/jsontext"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// ProductionProof is independently signed qualification; a release signing grant
// alone cannot authorize runtime admission.
type ProductionProof struct {
	Qualification jsontext.Value `json:"qualification"`
	Delegation    jsontext.Value `json:"delegation,omitempty"`
}

func productionBinaryExpectation(binary BinaryReceipt, expected UpdateExpectation) ProductionExpectation {
	return ProductionExpectation{SourceRevision: binary.SourceRevision, ArtifactSHA256: binary.SHA256,
		QualificationSHA256: binary.QualificationSHA256, Cell: expected.Cell, Environment: expected.Environment,
		Runtime: ProductionRuntime, Architecture: expected.Architecture, Role: "orchestrator"}
}

// VerifyQualifiedBinaryUpdateCurrent requires both release and qualification
// authority at the consumer's current time and own target scope.
func VerifyQualifiedBinaryUpdateCurrent(wire, delegationWire []byte, roots trust.Keyring, expected UpdateExpectation, now time.Time) (VerifiedBinary, error) {
	binary, err := VerifyBinaryUpdateCurrent(wire, delegationWire, roots, expected, now)
	if err != nil {
		return VerifiedBinary{}, err
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return VerifiedBinary{}, err
	}
	var receipt BinaryUpdateReceipt
	if err := protocol.DecodeStrict(envelope.Payload, &receipt, trust.MaxPayloadBytes); err != nil {
		return VerifiedBinary{}, err
	}
	if receipt.Production == nil {
		return VerifiedBinary{}, fmt.Errorf("%w: signed update contains no independent qualification", ErrProductionQualification)
	}
	if _, err := VerifyProductionCurrent(receipt.Production.Qualification, receipt.Production.Delegation, roots,
		productionBinaryExpectation(binary.Receipt(), expected), now); err != nil {
		return VerifiedBinary{}, err
	}
	qualification, err := trust.DecodeEnvelope(receipt.Production.Qualification)
	if err != nil {
		return VerifiedBinary{}, err
	}
	if qualification.ExpiresAt.Before(binary.proof.expiresAt) {
		binary.proof.expiresAt = qualification.ExpiresAt
	}
	if len(receipt.Production.Delegation) > 0 {
		delegation, err := trust.DecodeEnvelope(receipt.Production.Delegation)
		if err != nil {
			return VerifiedBinary{}, err
		}
		if delegation.ExpiresAt.Before(binary.proof.expiresAt) {
			binary.proof.expiresAt = delegation.ExpiresAt
		}
	}
	return binary, nil
}
