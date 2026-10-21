package placement

import (
	"errors"
	"reflect"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
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
	if !reflect.DeepEqual(three[:2], two) || three[2] != (Seat{MemberID: ElasticSeatID(oci.RegionGRU, 2), Region: oci.RegionGRU,
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
	if ElasticSeatID(oci.RegionFRA, 1) != "0000000000DRX0N2BW96GK619K" || ElasticSeatID(oci.RegionFRA, 3) != ElasticSeatID(oci.RegionFRA, 3) ||
		ElasticSeatID(oci.RegionFRA, 0) == ElasticSeatID(oci.RegionFRA, 1) {
		t.Fatal("elastic seat IDs changed")
	}
}

func TestSeatMemberNamesFollowPlacementOrderAndIgnoreAttempts(t *testing.T) {
	seats, err := RegionSeats(oci.RegionSJC, []string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2", "FAULT-DOMAIN-3"}, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i, seat := range seats {
		name, err := seatMemberName(seat.Region, seat.MemberID)
		if want := []string{"sjc-1-db-1", "sjc-1-db-2", "sjc-1-db-3"}[i]; err != nil || name != want {
			t.Fatalf("seat %s is %q, %v; want %q", seat.MemberID, name, err, want)
		}
	}
	for _, rejected := range []string{"", "000000000082AXF7GZQT1D126Y", "elastic-sjc-1", "elastic-sjc-0", "elastic-sjc-02", "elastic-sjc--2", "0000000000XG8SBD7XGE97V28G"} {
		if name, err := seatMemberName(oci.RegionSJC, rejected); !errors.Is(err, ErrInvalidIntent) || name != "" {
			t.Fatalf("seat %q got name %q, %v", rejected, name, err)
		}
	}
	// A replacement host is a new attempt with a new create key; its name stays.
	state := MemberState{Region: oci.RegionGRU, MemberID: "0000000000XG8SBD7XGE97V28G", HostAttempt: 1, CreateKey: "00000000000P03P510Z3XY8HWE"}
	first := pinnedEnsureRequest(state)
	state.HostAttempt, state.CreateKey = 2, "th-second"
	if second := pinnedEnsureRequest(state); first.Name != "gru-1-db-2" || second.Name != first.Name {
		t.Fatalf("host attempts changed the name: %q then %q", first.Name, second.Name)
	}
}
