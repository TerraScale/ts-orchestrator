package release

import (
	"bytes"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func verifyImageProduction(receipt ImageReceipt, environment string, roots trust.Keyring, now time.Time) (time.Time, error) {
	if receipt.Production == nil {
		return time.Time{}, fmt.Errorf("%w: signed image contains no independent qualification", ErrProductionQualification)
	}
	expected := ProductionExpectation{SourceRevision: receipt.SourceRevision, ArtifactSHA256: receipt.ImageSHA256,
		QualificationSHA256: receipt.QualificationSHA256, Cell: receipt.OCIRegion, Environment: environment,
		Runtime: ProductionRuntime, Architecture: receipt.Architecture, Role: "orchestrator"}
	if _, err := VerifyProductionCurrent(receipt.Production.Qualification, receipt.Production.Delegation, roots, expected, now); err != nil {
		return time.Time{}, err
	}
	envelope, err := trust.DecodeEnvelope(receipt.Production.Qualification)
	if err != nil {
		return time.Time{}, err
	}
	expires := envelope.ExpiresAt
	if len(receipt.Production.Delegation) > 0 {
		delegation, err := trust.DecodeEnvelope(receipt.Production.Delegation)
		if err != nil {
			return time.Time{}, err
		}
		if delegation.ExpiresAt.Before(expires) {
			expires = delegation.ExpiresAt
		}
	}
	return expires, nil
}

func cloneImageReceipt(receipt ImageReceipt) ImageReceipt {
	if receipt.Production != nil {
		receipt.Production = &ProductionProof{Qualification: bytes.Clone(receipt.Production.Qualification),
			Delegation: bytes.Clone(receipt.Production.Delegation)}
	}
	return receipt
}
