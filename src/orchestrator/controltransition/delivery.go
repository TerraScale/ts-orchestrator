package controltransition

import (
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
)

var ErrPreparationMissing = errors.New("controltransition: complete preparation barrier is not implemented")

// Delivery is embedded in the original owner-signed component configuration.
// It has no plan digest: the later plan signs that configuration's manifest.
// The original bootstrap proof supplies the owner key, never this document.
type Delivery struct {
	TransitionID          string `json:"transitionId"`
	PlanFile              string `json:"planFile"`
	ReceiptPrivateKeyFile string `json:"receiptPrivateKeyFile"`
	// OCIQualification is an explicit owner-signed test endpoint. Nil uses
	// production instance principals in the region fixed by the signed plan.
	OCIQualification *ociinstance.QualificationConfig `json:"ociQualification,omitempty"`
	// PlanObject optionally names the initial remote delivery location. Its
	// digest cannot be embedded here because the plan binds this manifest.
	PlanObject *PlanDeliveryObject `json:"planObject,omitempty"`
}

// PlanDeliveryObject is bound by the original bootstrap owner. The plan is
// fetched from Objects.Prefix + "/plan.json" with instance principals.
type PlanDeliveryObject struct {
	Region  string         `json:"region"`
	Objects ObjectLocation `json:"objects"`
}

func (o PlanDeliveryObject) Validate() error {
	if o.Region != "gru" && o.Region != "sfo" && o.Region != "fra" || !o.Objects.valid(o.Region) {
		return errors.New("controltransition: invalid plan object location")
	}
	return nil
}

func (d Delivery) Validate(protectedPaths ...string) error {
	if d == (Delivery{}) {
		return nil
	}
	if !token(d.TransitionID) || !separatePaths(d.PlanFile, d.ReceiptPrivateKeyFile) || len(d.PlanFile) > 4096 || len(d.ReceiptPrivateKeyFile) > 4096 {
		return errors.New("controltransition: invalid plan delivery location")
	}
	if d.PlanObject != nil {
		if err := d.PlanObject.Validate(); err != nil {
			return err
		}
	}
	if q := d.OCIQualification; q != nil {
		// Qualification validation is independent of region. The later verified
		// plan supplies the actual host region before any identity is acquired.
		if ociinstance.ValidateConfig(ociinstance.Config{Region: "sa-saopaulo-1", Qualification: q}) != nil || !separatePaths(d.PlanFile, d.ReceiptPrivateKeyFile, q.ClientPrivateKeyFile) {
			return errors.New("controltransition: invalid qualification identity")
		}
		for _, path := range protectedPaths {
			if path != "" && hostmanifest.PathsOverlap(q.ClientPrivateKeyFile, path) {
				return errors.New("controltransition: qualification key overlaps protected storage")
			}
		}
	}
	for _, path := range protectedPaths {
		if path != "" && (hostmanifest.PathsOverlap(d.PlanFile, path) || hostmanifest.PathsOverlap(d.ReceiptPrivateKeyFile, path)) {
			return errors.New("controltransition: plan delivery overlaps component storage or admission")
		}
	}
	return nil
}
