package bootstrap

import (
	"fmt"
	"maps"
	"slices"
)

// ControllerFailureDomain is an exact signed OCI placement tuple, not a label grant.
type ControllerFailureDomain struct {
	Region, AvailabilityDomain, FaultDomain string
}

func (verified VerifiedFounderPlan) ControllerFailureDomains() (map[string]ControllerFailureDomain, error) {
	if !verified.IsVerified() {
		return nil, ErrFounderPlanAuthorization
	}
	return controllerFailureDomains(verified.snapshot())
}

func (verified DerivedFounderPlan) ControllerFailureDomains() (map[string]ControllerFailureDomain, error) {
	if !verified.IsVerified() {
		return nil, ErrFounderPlanAuthorization
	}
	return controllerFailureDomains(verified.snapshotValue)
}

func (verified VerifiedCompletedFounderPlan) ControllerFailureDomains() (map[string]ControllerFailureDomain, error) {
	if !verified.IsVerified() || len(verified.failureDomains) != 3 {
		return nil, ErrFounderPlanAuthorization
	}
	return maps.Clone(verified.failureDomains), nil
}

func (verified DerivedCompletedFounderPlan) ControllerFailureDomains() (map[string]ControllerFailureDomain, error) {
	if !verified.IsVerified() || len(verified.failureDomains) != 3 {
		return nil, ErrFounderPlanAuthorization
	}
	return maps.Clone(verified.failureDomains), nil
}

func controllerFailureDomains(snapshot founderPlanSnapshot) (map[string]ControllerFailureDomain, error) {
	plan := snapshot.plan
	slots := []string{"controller-a", "controller-b", "controller-c"}
	region, err := plan.Cell.OCIRegion()
	if err != nil || !slices.Equal(plan.ControllerSlots, slots) || !slices.Contains(slots, plan.SeedSlot) || len(snapshot.manifests) != len(slots) {
		return nil, fmt.Errorf("%w: execution requires the canonical three controller slots", ErrFounderPlanAuthorization)
	}
	domains := make(map[string]ControllerFailureDomain, len(slots))
	for _, slot := range slots {
		startup := snapshot.manifests[slot]
		if err := validateStartupAuthority(startup); err != nil {
			return nil, err
		}
		manifest := startup.Manifest()
		if manifest.Slot != slot || manifest.DeploymentID != plan.DeploymentID || manifest.Cell != plan.Cell ||
			manifest.Environment != plan.Environment || manifest.OCIRegion != region || manifest.SeedSlot != plan.SeedSlot ||
			!slices.Equal(manifest.ControllerSlots, slots) || len(manifest.Profiles) != len(slots) {
			return nil, fmt.Errorf("%w: controller manifest topology differs from the verified plan", ErrFounderPlanAuthorization)
		}
		for _, target := range slots {
			profile, ok := startup.Profile(target)
			if !ok {
				return nil, fmt.Errorf("%w: controller slot has no verified launch profile", ErrFounderPlanAuthorization)
			}
			domain := ControllerFailureDomain{Region: region, AvailabilityDomain: profile.AvailabilityDomain, FaultDomain: profile.FaultDomain}
			if previous, exists := domains[target]; exists && previous != domain {
				return nil, fmt.Errorf("%w: controller manifests disagree on a signed failure domain", ErrFounderPlanAuthorization)
			}
			domains[target] = domain
		}
	}
	seen := make(map[ControllerFailureDomain]bool, len(domains))
	for _, slot := range slots {
		domain := domains[slot]
		if seen[domain] {
			return nil, fmt.Errorf("%w: controller failure domains must be distinct", ErrFounderPlanAuthorization)
		}
		seen[domain] = true
	}
	for _, row := range plan.Peers {
		domain, ok := domains[row.Slot]
		if !ok || row.AvailabilityDomain != domain.AvailabilityDomain || row.FaultDomain != domain.FaultDomain {
			return nil, fmt.Errorf("%w: peer row differs from its signed failure domain", ErrFounderPlanAuthorization)
		}
	}
	return domains, nil
}
