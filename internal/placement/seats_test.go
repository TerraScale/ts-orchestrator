package placement

import (
	"errors"
	"reflect"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

func TestRegionSeatsGeneralizesTheTwoSeatTopology(t *testing.T) {
	domains := []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2", "FAULT-DOMAIN-3"}
	two, err := RegionSeats(oci.RegionGRU, domains, SeatsPerRegion)
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := RegionSeatIDs(oci.RegionGRU)
	if len(two) != 2 || two[0].MemberID != ids[0] || two[1].MemberID != ids[1] ||
		two[0].Kind != MemberPermanent || two[1].Kind != MemberElastic ||
		two[0].FailureDomain != domains[0] || two[1].FailureDomain != domains[1] {
		t.Fatalf("two-seat layout changed: %#v", two)
	}
	three, err := RegionSeats(oci.RegionGRU, domains, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(three[:2], two) || three[2] != (Seat{MemberID: "elastic-gru-2", Region: oci.RegionGRU,
		FailureDomain: "FAULT-DOMAIN-3", Kind: MemberElastic}) {
		t.Fatalf("three-seat layout = %#v", three)
	}
	for name, call := range map[string]func() ([]Seat, error){
		"below quorum floor":   func() ([]Seat, error) { return RegionSeats(oci.RegionGRU, domains, 1) },
		"more seats than FDs":  func() ([]Seat, error) { return RegionSeats(oci.RegionGRU, domains, 4) },
		"shared fault domain":  func() ([]Seat, error) { return RegionSeats(oci.RegionGRU, []string{"FD-1", "FD-1"}, 2) },
		"invalid fault domain": func() ([]Seat, error) { return RegionSeats(oci.RegionGRU, []string{"FD 1", "FD-2"}, 2) },
		"unknown region":       func() ([]Seat, error) { return RegionSeats("XYZ", domains, 2) },
	} {
		if _, err := call(); !errors.Is(err, ErrInvalidIntent) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if ElasticSeatID(oci.RegionFRA, 1) != "elastic-fra" || ElasticSeatID(oci.RegionFRA, 3) != "elastic-fra-3" {
		t.Fatal("elastic seat IDs changed")
	}
}
