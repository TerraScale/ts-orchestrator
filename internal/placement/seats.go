package placement

import (
	"fmt"
	"strconv"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
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
// later ordinals are "elastic-<region>-<ordinal>". Ordinals start at 1; only
// ordinal 1 maps to the base ID, so an off-by-one caller gets a distinct
// (and visibly wrong) ID instead of silently aliasing ordinal 1's member.
func ElasticSeatID(region oci.Region, ordinal int) string {
	if ordinal == 1 {
		return elasticMember(region)
	}
	return elasticMember(region) + "-" + strconv.Itoa(ordinal)
}

// seatMemberName is a seat's static member name in placement order: the
// permanent seat is member 1 and elastic seat k is member k+1, e.g.
// gru-1-db-2 for elastic-gru. Host attempts and generations never change it.
func seatMemberName(region oci.Region, memberID string) (string, error) {
	n := 0
	switch suffix, elastic := strings.CutPrefix(memberID, elasticMember(region)+"-"); {
	case !knownRegion(region):
	case memberID == permanentMember(region):
		n = 1
	case memberID == elasticMember(region):
		n = 2
	case elastic:
		if ordinal, err := strconv.Atoi(suffix); err == nil && ordinal > 1 && ElasticSeatID(region, ordinal) == memberID {
			n = ordinal + 1
		}
	}
	if n == 0 {
		return "", fmt.Errorf("%w: seat %q has no member name", ErrInvalidIntent, memberID)
	}
	return naming.RegionCell(string(region)).Server(naming.Member, n)
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
