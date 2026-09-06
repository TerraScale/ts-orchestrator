package controltransition

import (
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
)

var ErrPreparationMissing = errors.New("controltransition: complete preparation barrier is not implemented")

// Delivery is embedded in the original owner-signed component configuration.
// It has no plan digest: the later plan signs that configuration's manifest.
// The original bootstrap proof supplies the owner key, never this document.
type Delivery struct {
	TransitionID          string `json:"transitionId"`
	PlanFile              string `json:"planFile"`
	ReceiptPrivateKeyFile string `json:"receiptPrivateKeyFile"`
}

func (d Delivery) Validate(protectedPaths ...string) error {
	if d == (Delivery{}) {
		return nil
	}
	if !token(d.TransitionID) || !separatePaths(d.PlanFile, d.ReceiptPrivateKeyFile) || len(d.PlanFile) > 4096 || len(d.ReceiptPrivateKeyFile) > 4096 {
		return errors.New("controltransition: invalid plan delivery location")
	}
	for _, path := range protectedPaths {
		if path != "" && (hostmanifest.PathsOverlap(d.PlanFile, path) || hostmanifest.PathsOverlap(d.ReceiptPrivateKeyFile, path)) {
			return errors.New("controltransition: plan delivery overlaps component storage or admission")
		}
	}
	return nil
}
