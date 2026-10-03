package placement

import (
	"fmt"
	"strconv"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

// MinSeatsPerRegion is the TerraBase quorum floor: one permanent and at least
// one elastic member on distinct failure domains in every active region.
const MinSeatsPerRegion = 2

// SeatsPerRegion is the member count the current schema admits. The signed
// canonical roster, managed material and the single-peer replication runtime
// manifest still bind exactly two members per region, so a larger count
// requires a new intent schema before it can be used; RegionSeats already
// produces the generalized layout.
const SeatsPerRegion = MinSeatsPerRegion

// ElasticSeatID names a region's elastic seat by ordinal. Ordinal 1 keeps the
// original "elastic-<region>" ID so existing members and rosters are stable;
// later ordinals are "elastic-<region>-<ordinal>".
func ElasticSeatID(region oci.Region, ordinal int) string {
	if ordinal <= 1 {
		return elasticMember(region)
	}
	return elasticMember(region) + "-" + strconv.Itoa(ordinal)
}

// RegionSeats returns one region's seats in placement order: the permanent
// seat on the first configured fault domain, then elastic seats 1..count-1.
// Members of one region never share a fault domain, so count is bounded by
// the configured distinct fault domains as well as below by the quorum floor.
func RegionSeats(region oci.Region, faultDomains []string, count int) ([]Seat, error) {
	if !knownRegion(region) {
		return nil, fmt.Errorf("%w: unsupported region %q", ErrInvalidIntent, region)
	}
	if count < MinSeatsPerRegion {
		return nil, fmt.Errorf("%w: region %s needs at least %d seats", ErrInvalidIntent, region, MinSeatsPerRegion)
	}
	if len(faultDomains) < count {
		return nil, fmt.Errorf("%w: region %s needs %d distinct configured fault domains", ErrInvalidIntent, region, count)
	}
	seen := make(map[string]struct{}, count)
	for _, domain := range faultDomains[:count] {
		if !validFailureDomain(domain) {
			return nil, fmt.Errorf("%w: region %s has an invalid fault domain", ErrInvalidIntent, region)
		}
		if _, exists := seen[domain]; exists {
			return nil, fmt.Errorf("%w: region %s needs %d distinct configured fault domains", ErrInvalidIntent, region, count)
		}
		seen[domain] = struct{}{}
	}
	permanentID := permanentMember(region)
	if permanentID == "" {
		return nil, fmt.Errorf("%w: region %s has no permanent member mapping", ErrInvalidIntent, region)
	}
	seats := make([]Seat, 0, count)
	seats = append(seats, Seat{MemberID: permanentID, Region: region, FailureDomain: faultDomains[0], Kind: MemberPermanent})
	for ordinal := 1; ordinal < count; ordinal++ {
		seats = append(seats, Seat{MemberID: ElasticSeatID(region, ordinal), Region: region,
			FailureDomain: faultDomains[ordinal], Kind: MemberElastic})
	}
	return seats, nil
}
