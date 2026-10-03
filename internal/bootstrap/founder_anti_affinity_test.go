package bootstrap

import (
	"errors"
	"testing"
)

func TestCheckControllerAntiAffinity(t *testing.T) {
	seed := ControllerPlacement{AvailabilityDomain: "Abcd:SA-SAOPAULO-1-AD-1", FaultDomain: "FAULT-DOMAIN-1"}
	row := func(slot, ad, fd string) FounderPeerRow {
		return FounderPeerRow{Slot: slot, AvailabilityDomain: ad, FaultDomain: fd}
	}
	cases := []struct {
		name  string
		seed  ControllerPlacement
		peers []FounderPeerRow
		ok    bool
	}{
		{"distinct fault domains", seed, []FounderPeerRow{
			row("controller-b", "SA-SAOPAULO-1-AD-1", "FAULT-DOMAIN-2"),
			row("controller-c", "SA-SAOPAULO-1-AD-1", "FAULT-DOMAIN-3")}, true},
		{"distinct availability domains reuse a fault domain", seed, []FounderPeerRow{
			row("controller-b", "SA-SAOPAULO-1-AD-2", "FAULT-DOMAIN-1"),
			row("controller-c", "SA-SAOPAULO-1-AD-3", "FAULT-DOMAIN-1")}, true},
		{"peer shares the seed fault domain across AD spellings", seed, []FounderPeerRow{
			row("controller-b", "sa-saopaulo-1-ad-1", "FAULT-DOMAIN-1"),
			row("controller-c", "SA-SAOPAULO-1-AD-1", "FAULT-DOMAIN-3")}, false},
		{"peers share a fault domain", seed, []FounderPeerRow{
			row("controller-b", "SA-SAOPAULO-1-AD-1", "FAULT-DOMAIN-2"),
			row("controller-c", "SA-SAOPAULO-1-AD-1", "FAULT-DOMAIN-2")}, false},
		{"unknown seed placement", ControllerPlacement{}, []FounderPeerRow{
			row("controller-b", "SA-SAOPAULO-1-AD-1", "FAULT-DOMAIN-2")}, false},
		{"incomplete peer placement", seed, []FounderPeerRow{row("controller-b", "", "FAULT-DOMAIN-2")}, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := CheckControllerAntiAffinity(test.seed, test.peers)
			if test.ok && err != nil {
				t.Fatal(err)
			}
			if !test.ok && !errors.Is(err, ErrControllerAntiAffinity) {
				t.Fatalf("co-located controllers were accepted: %v", err)
			}
		})
	}
}
