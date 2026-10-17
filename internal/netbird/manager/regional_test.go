package manager

import (
	"slices"
	"testing"
)

func TestRegionalIntentKeepsEnrollmentAndAccessWithinItsRegion(t *testing.T) {
	for _, scenario := range []struct {
		cell, region, subnet, address, node, servers string
	}{
		{"GRU", "sa-saopaulo-1", "10.251.0.0/25", "10.251.0.11", "ts-gru-1", "gru-servers"},
		{"SFO", "us-sanjose-1", "10.252.0.0/25", "10.252.0.11", "ts-sfo-1", "sfo-servers"},
		{"FRA", "eu-frankfurt-1", "10.253.0.0/25", "10.253.0.11", "ts-fra-1", "fra-servers"},
	} {
		t.Run(scenario.cell, func(t *testing.T) {
			desired, err := Regional(scenario.cell, scenario.subnet, []Slot{{Name: scenario.node, IP: scenario.address, Role: "controller"}})
			if err != nil {
				t.Fatal(err)
			}
			if desired.Region != scenario.region || desired.ServersGroup != scenario.servers || desired.SetupKeyName != scenario.servers || desired.PeerNames()[scenario.address] != scenario.node {
				t.Fatalf("regional enrollment differs: %+v", desired)
			}
			if !slices.ContainsFunc(desired.Policies, func(policy PolicySpec) bool {
				return policy.Name == "operators-to-"+scenario.servers+"-ssh" && slices.Equal(policy.Destinations, []string{scenario.servers})
			}) {
				t.Fatal("regional operator access is missing")
			}
			if !slices.ContainsFunc(desired.Policies, func(policy PolicySpec) bool {
				return policy.Name == "netbird-managers-to-"+scenario.servers+"-control" && policy.Protocol == "tcp" &&
					slices.Equal(policy.Ports, []string{"4222"}) && slices.Equal(policy.Sources, []string{"netbird-managers"}) &&
					slices.Equal(policy.Destinations, []string{scenario.servers})
			}) {
				t.Fatal("dedicated manager cannot read its regional control source")
			}
			if _, err := Regional(scenario.cell, "10.250.0.0/25", nil); err == nil {
				t.Fatal("foreign private subnet was accepted")
			}
		})
	}
	if _, err := Regional("gru", "10.251.0.0/25", nil); err == nil {
		t.Fatal("noncanonical source cell was accepted")
	}
	if _, err := Regional("SFO", "10.252.0.0/25", []Slot{{Name: "ts-sfo-1", IP: "10.252.0.11", Role: "operator"}}); err == nil {
		t.Fatal("caller-created host role was accepted")
	}
}
