package region

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/foundationbinding"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func validOriginalStartupRetentionID(ruleID string) bool {
	return ruleID != "" && len(ruleID) <= 1024 && !strings.ContainsAny(ruleID, " \t\r\n/")
}

func originalStartupAdmission(producer OriginalSourceProducerIntent, ruleID string) (bootstrap.OriginalStartupAdmissionIntent, error) {
	if !validOriginalStartupRetentionID(ruleID) {
		return bootstrap.OriginalStartupAdmissionIntent{}, ErrOriginalSourceProducerHold
	}
	producerDigest, err := foundationbinding.CanonicalDigest(producer)
	if err != nil {
		return bootstrap.OriginalStartupAdmissionIntent{}, err
	}
	return bootstrap.OriginalStartupAdmissionIntent{Purpose: bootstrap.OriginalStartupAdmissionPurpose, ProducerIntentSHA256: producerDigest, LedgerRetentionRuleID: ruleID}, nil
}

func validateOriginalStartupAdmissions(grant FoundationGrant) error {
	present := 0
	ruleID := ""
	for _, regional := range grant.Regions {
		material := regional.BootstrapMaterial
		if material == nil || material.OriginalStartupAdmission == nil {
			continue
		}
		present++
		intent := material.OriginalStartupAdmission
		if material.OriginalSourceProducer == nil || material.Startup == nil || material.Startup.ControllerConfigDerivation != bootstrap.ControllerConfigDerivationV2 {
			return ErrOriginalSourceProducerHold
		}
		expected, err := originalStartupAdmission(*material.OriginalSourceProducer, intent.LedgerRetentionRuleID)
		if err != nil || !sameOriginalSourceValue(*intent, expected) || ruleID != "" && ruleID != intent.LedgerRetentionRuleID {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
		ruleID = intent.LedgerRetentionRuleID
	}
	if present != 0 && (grant.SchemaVersion != 3 || grant.Generation != 1 || present != 3 || len(grant.Regions) != 3) {
		return ErrOriginalSourceProducerHold
	}
	return nil
}

// OriginalStartupTemplate rechecks the genuine actor and its prospective IAM
// before crossing the bootstrap verifier's independent-genesis trust boundary.
func (v VerifiedOriginalSourceActor) OriginalStartupTemplate(ctx context.Context) (bootstrap.VerifiedStartupTemplate, error) {
	if ctx == nil || !v.IsVerified() || v.proof.attestor.source == nil || v.proof.materialPublication == nil || (v.proof.materialPublication.Recipe.Purpose != originalMaterialIAMPurposeV3 && v.proof.materialPublication.Recipe.Purpose != originalMaterialIAMPurposeV4) {
		return bootstrap.VerifiedStartupTemplate{}, ErrOriginalSourceActorHold
	}
	_, factory, guarded, err := v.MaterialPublication(ctx)
	if err != nil {
		return bootstrap.VerifiedStartupTemplate{}, err
	}
	genesis, err := trust.DiscoveryGenesis()
	if err != nil {
		return bootstrap.VerifiedStartupTemplate{}, err
	}
	source := v.proof.attestor.source
	wire, err := source.readGrant(guarded)
	if err != nil {
		return bootstrap.VerifiedStartupTemplate{}, err
	}
	verified, err := bootstrap.VerifyBoundOriginalStartupTemplate(guarded, factory, wire, genesis, source.bootstrapAnchor, oci.Region(v.proof.scope.Cell), time.Now())
	if err != nil || !verified.IsVerified() || verified.ExpiresAt().After(v.proof.scope.Deadline) {
		return bootstrap.VerifiedStartupTemplate{}, errors.Join(ErrOriginalSourceActorHold, err)
	}
	if err := v.Guard(ctx); err != nil {
		return bootstrap.VerifiedStartupTemplate{}, err
	}
	return verified, nil
}
