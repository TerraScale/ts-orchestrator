package releasechannel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func ServiceQualificationObject(role, qualificationSHA256 string) string {
	return servicePrefix + role + "/qualifications/" + qualificationSHA256 + "/production.json"
}

func ServiceQualificationDelegationObject(role, qualificationSHA256 string) string {
	return servicePrefix + role + "/qualifications/" + qualificationSHA256 + "/delegation.json"
}

func ServiceQualificationEvidenceObject(role, qualificationSHA256, digest string) string {
	return servicePrefix + role + "/qualifications/" + qualificationSHA256 + "/objects/" + digest
}

// VerifyServiceQualification independently admits a native binary candidate from
// root-authorized records and retained evidence. The caller derives the expected
// source, digest, role and architecture from its verified claim and actual bytes.
func VerifyServiceQualification(ctx context.Context, location Location, roots trust.Keyring, expected release.ProductionExpectation, qualificationSHA256 string, now time.Time) error {
	wire, _, found, err := location.get(ctx, ServiceQualificationObject(expected.Role, qualificationSHA256), trust.MaxEnvelopeBytes)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%w: service record missing", release.ErrProductionQualification)
	}
	delegation, _, _, err := location.get(ctx, ServiceQualificationDelegationObject(expected.Role, qualificationSHA256), trust.MaxEnvelopeBytes)
	if err != nil {
		return err
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return err
	}
	fingerprint, err := trust.Fingerprint(envelope)
	if err != nil {
		return err
	}
	if fingerprint != qualificationSHA256 {
		return fmt.Errorf("%w: service qualification fingerprint", release.ErrProductionQualification)
	}
	qualification, err := release.VerifyProductionCurrent(wire, delegation, roots, expected, now)
	if err != nil {
		return err
	}
	for _, evidence := range qualification.Evidence {
		data, _, found, err := location.get(ctx, ServiceQualificationEvidenceObject(expected.Role, qualificationSHA256, evidence.SHA256), release.MaxProductionEvidenceBytes)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("%w: retained %s evidence missing", release.ErrProductionQualification, evidence.Gate)
		}
		sum := sha256.Sum256(data)
		if int64(len(data)) != evidence.Bytes || hex.EncodeToString(sum[:]) != evidence.SHA256 {
			return fmt.Errorf("%w: retained %s evidence bytes differ", release.ErrProductionQualification, evidence.Gate)
		}
	}
	return ctx.Err()
}
