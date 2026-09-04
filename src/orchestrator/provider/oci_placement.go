package provider

import (
	"fmt"
	"sort"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// Placement is the residency guarantee (D-52). These checks are the seam the
// placement code calls before it places, replicates, restores, exports, or
// branches a database; every one of those paths must refuse rather than widen.

// PlacementMinimumMemberHosts is the D-65 launch floor: placement refuses a
// Region below two member hosts.
const PlacementMinimumMemberHosts = 2

// PlacementLock is a database's immutable residency scope: eu-only, br-only,
// and explicit region lists all resolve to one canonical set before they
// reach these checks.
type PlacementLock struct {
	Regions []string
}

// PlacementError names the region and rule that refused a placement decision.
type PlacementError struct {
	Region string
	Rule   string
}

func (e *PlacementError) Error() string {
	return fmt.Sprintf("placement refused region %s: %s", e.Region, e.Rule)
}

// NewPlacementLock validates a lock's region codes: canonical, non-empty, and
// duplicate-free.
func NewPlacementLock(regions []string) (PlacementLock, error) {
	if len(regions) == 0 || len(regions) > 20 {
		return PlacementLock{}, &errs.Argument{Message: "placement lock must name between 1 and 20 regions"}
	}
	seen := make(map[string]struct{}, len(regions))
	for _, region := range regions {
		if len(region) < 1 || len(region) > 63 || !regionPattern.MatchString(region) {
			return PlacementLock{}, &errs.Argument{Message: "placement lock region code is invalid"}
		}
		if _, exists := seen[region]; exists {
			return PlacementLock{}, &errs.Argument{Message: "placement lock region code is duplicated"}
		}
		seen[region] = struct{}{}
	}
	return PlacementLock{Regions: regions}, nil
}

// CheckPlacementWidening enforces that a placement lock set at creation is
// never widened (D-52): every updated region must already be in the prior
// lock. Narrowing (removing a region) is allowed; the bytes leave through the
// normal delete path, not through lock mutation.
func CheckPlacementWidening(prior, updated PlacementLock) error {
	allowed := make(map[string]struct{}, len(prior.Regions))
	for _, region := range prior.Regions {
		allowed[region] = struct{}{}
	}
	for _, region := range updated.Regions {
		if _, exists := allowed[region]; !exists {
			return &PlacementError{Region: region, Rule: "placement lock cannot be widened"}
		}
	}
	return nil
}

// CheckPlacement validates one placement decision: every candidate region is
// inside the database's lock, and every candidate region currently has at
// least PlacementMinimumMemberHosts member hosts (D-65). memberHosts maps
// region code to the count of live member hosts observed there.
func CheckPlacement(lock PlacementLock, candidate []string, memberHosts map[string]int) error {
	if len(candidate) == 0 {
		return &errs.Argument{Message: "placement candidate must name at least one region"}
	}
	resident := make(map[string]struct{}, len(lock.Regions))
	for _, region := range lock.Regions {
		resident[region] = struct{}{}
	}
	seenCandidate := make(map[string]struct{}, len(candidate))
	for _, region := range candidate {
		if _, exists := seenCandidate[region]; exists {
			return &PlacementError{Region: region, Rule: "placement candidate region is duplicated"}
		}
		seenCandidate[region] = struct{}{}
		if _, exists := resident[region]; !exists {
			return &PlacementError{Region: region, Rule: "region is outside the placement lock"}
		}
		if hosts := memberHosts[region]; hosts < PlacementMinimumMemberHosts {
			return &PlacementError{Region: region, Rule: fmt.Sprintf("region has %d member hosts, placement requires %d", hosts, PlacementMinimumMemberHosts)}
		}
	}
	return nil
}

// PlacementLockRegions returns the lock's region codes in stable sorted order.
func (l PlacementLock) PlacementLockRegions() []string {
	regions := append([]string(nil), l.Regions...)
	sort.Strings(regions)
	return regions
}
