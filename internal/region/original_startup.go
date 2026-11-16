package region

import (
	"errors"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/foundationbinding"
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
