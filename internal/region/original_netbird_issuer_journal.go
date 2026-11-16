package region

import (
	"slices"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

// OriginalNetBirdIssuerJournal uses only the GRU original manager child. It
// retains the existing OCIR operation, credential and wire history protocol.
type OriginalNetBirdIssuerJournal struct {
	session *OriginalNetBirdOCIRSession
	scope   VerifiedOCIRIssuer
}

func validateOriginalNetBirdOCIRJournal(manager *OriginalFoundationNetBirdManager) error {
	if manager == nil {
		return nil
	}
	if len(manager.OCIRIssuances) > 3 {
		return ErrOriginalSourceProducerHold
	}
	if len(manager.OCIRIssuances) == 0 {
		return nil
	}
	if manager.Intent.Material == nil || manager.Intent.Components == nil {
		return ErrOriginalSourceProducerHold
	}
	material := manager.Intent.Material.Context
	allowed := map[string]OCIRIssuerIntent{}
	for _, component := range *manager.Intent.Components {
		key, err := (VerifiedOCIRIssuer{intent: component.Issuer, tenancyID: material.TenancyID, installationID: material.InstallationID, generation: 1, grantDigest: manager.GrantSHA256}).JournalKey()
		if err != nil {
			return err
		}
		allowed[key] = component.Issuer
	}
	if len(allowed) != 3 {
		return ErrOriginalSourceProducerHold
	}
	operation := entityid.Derive("regional-foundation", material.TenancyID, "GRU", "1")
	for key, entry := range manager.OCIRIssuances {
		issuer, ok := allowed[key]
		if !ok || entry.Origin.GrantSHA256 != manager.GrantSHA256 || entry.Origin.Generation != 1 || entry.Origin.Epoch != 1 || entry.Origin.FoundationOperation != operation ||
			entry.State.GrantDigest != manager.GrantSHA256 || entry.State.Generation != 1 {
			return ErrOriginalSourceProducerHold
		}
		if entry.State.TokenOperation != "" {
			attempt, found := entry.Attempts[entry.State.TokenOperation]
			if !found || attempt.OperationID != entry.State.OperationID || !attempt.TokenStarted.Equal(entry.State.TokenStarted) ||
				!attempt.ExpiresAt.Equal(entry.State.TokenExpires) || !slices.Equal(attempt.BeforeTokens, entry.State.BeforeTokens) {
				return ErrOriginalSourceProducerHold
			}
		}
		for _, request := range entry.Requests {
			if request.GrantSHA256 != manager.GrantSHA256 || request.Epoch != 1 || request.Deadline.After(entry.Origin.ExpiresAt) {
				return ErrOriginalSourceProducerHold
			}
		}
		for _, attempt := range entry.Attempts {
			if attempt.GrantSHA256 != manager.GrantSHA256 || attempt.Generation != 1 || attempt.FoundationOperation != operation || attempt.Epoch != 1 ||
				attempt.VaultID != issuer.VaultTarget.VaultID || attempt.SecretName != issuer.SecretName {
				return ErrOriginalSourceProducerHold
			}
		}
	}
	return (FoundationRecord{Generation: 1, OCIRIssuances: manager.OCIRIssuances}).validateOCIRIssuances()
}

func retainOriginalNetBirdOCIRJournal(old, next *OriginalFoundationNetBirdManager) error {
	if old == nil {
		if next != nil && len(next.OCIRIssuances) != 0 {
			return ErrOriginalSourceProducerHold
		}
		return validateOriginalNetBirdOCIRJournal(next)
	}
	if next == nil {
		return ErrOriginalSourceProducerHold
	}
	if err := validateOriginalNetBirdOCIRJournal(next); err != nil {
		return err
	}
	return (FoundationRecord{OCIRIssuances: old.OCIRIssuances}).retainOCIRIssuances(FoundationRecord{OCIRIssuances: next.OCIRIssuances})
}
