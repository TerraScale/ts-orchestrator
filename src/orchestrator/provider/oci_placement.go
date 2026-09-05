package provider

import (
	"fmt"
	"sort"
	"strings"

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
	Regions             []string
	Policy              string
	Generation          uint64
	PlacementGeneration uint64
	RegisteredRegions   []string
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
		if len(region) < 1 || len(region) > 63 || !ValidOCIRegion(region) {
			return PlacementLock{}, &errs.Argument{Message: "placement lock region code is invalid"}
		}
		if _, exists := seen[region]; exists {
			return PlacementLock{}, &errs.Argument{Message: "placement lock region code is duplicated"}
		}
		seen[region] = struct{}{}
	}
	return PlacementLock{Regions: append([]string(nil), regions...), Policy: "explicit", Generation: 1, PlacementGeneration: 1}, nil
}

// ResolveNamedPlacementLock resolves eu-only/br-only against the explicitly
// registered Region catalog. It never invents a Region from provider data.
func ResolveNamedPlacementLock(policy string, registered []string, generation uint64) (PlacementLock, error) {
	policy = strings.ToLower(strings.TrimSpace(policy))
	if policy != "eu-only" && policy != "br-only" && policy != "explicit" {
		return PlacementLock{}, &errs.Argument{Message: "placement lock policy is invalid"}
	}
	if generation == 0 {
		generation = 1
	}
	if policy == "explicit" {
		return NewPlacementLock(registered)
	}
	regions := make([]string, 0, len(registered))
	for _, region := range registered {
		region = strings.ToLower(region)
		matches := policy == "eu-only" && (strings.HasPrefix(region, "eu-") || region == "fra" || strings.HasSuffix(region, "-eu"))
		matches = matches || policy == "br-only" && (strings.HasPrefix(region, "br-") || region == "gru" || strings.HasSuffix(region, "-br"))
		if matches {
			regions = append(regions, region)
		}
	}
	lock, err := NewPlacementLock(regions)
	if err != nil {
		return PlacementLock{}, err
	}
	lock.Policy, lock.Generation, lock.PlacementGeneration = policy, generation, generation
	lock.RegisteredRegions = append([]string(nil), registered...)
	return lock, nil
}

// NewPlacementLockForPolicy is the descriptive constructor used by
// placement/replication/backup callers.
func NewPlacementLockForPolicy(policy string, regions, registered []string, generation uint64) (PlacementLock, error) {
	if policy == "explicit" {
		lock, err := NewPlacementLock(regions)
		if err != nil {
			return PlacementLock{}, err
		}
		lock.RegisteredRegions = append([]string(nil), registered...)
		lock.Generation = generation
		if lock.Generation == 0 {
			lock.Generation = 1
		}
		lock.PlacementGeneration = lock.Generation
		return lock, nil
	}
	return ResolveNamedPlacementLock(policy, registered, generation)
}

// CheckPlacementWidening enforces that a placement lock set at creation is
// never widened (D-52): every updated region must already be in the prior
// lock. Narrowing (removing a region) is allowed; the bytes leave through the
// normal delete path, not through lock mutation.
func CheckPlacementWidening(prior, updated PlacementLock) error {
	if prior.Policy != "" && updated.Policy != "" && prior.Policy != updated.Policy {
		return &PlacementError{Rule: "placement lock policy cannot be changed"}
	}
	allowed := make(map[string]struct{}, len(prior.Regions))
	for _, region := range prior.Regions {
		allowed[region] = struct{}{}
	}
	for _, region := range updated.Regions {
		if _, exists := allowed[region]; !exists {
			return &PlacementError{Region: region, Rule: "placement lock cannot be widened"}
		}
	}
	priorGeneration, updatedGeneration := prior.Generation, updated.Generation
	if priorGeneration == 0 {
		priorGeneration = prior.PlacementGeneration
	}
	if updatedGeneration == 0 {
		updatedGeneration = updated.PlacementGeneration
	}
	if priorGeneration > 0 && updatedGeneration > 0 {
		if updatedGeneration < priorGeneration {
			return &PlacementError{Rule: "placement lock generation cannot regress"}
		}
		if !samePlacementRegions(prior.Regions, updated.Regions) && updatedGeneration == priorGeneration {
			return &PlacementError{Rule: "placement lock generation must advance"}
		}
	}
	return nil
}

func samePlacementRegions(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
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
	if len(lock.RegisteredRegions) > 0 {
		registered := make(map[string]struct{}, len(lock.RegisteredRegions))
		for _, region := range lock.RegisteredRegions {
			registered[region] = struct{}{}
		}
		for _, region := range lock.Regions {
			if _, ok := registered[region]; !ok {
				return &PlacementError{Region: region, Rule: "region is not registered"}
			}
		}
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
