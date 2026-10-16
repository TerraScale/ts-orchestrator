package networkplan

import (
	"net/netip"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

func TestReservationsAreDisjointAndCoverEveryFoundedCell(t *testing.T) {
	ranges := []string{Mesh, MeshIPv6, Tailscale, TailscaleIPv6, BridgePool,
		"10.250.0.0/16", "10.0.0.0/24", "10.10.0.0/16", "10.11.99.0/24",
		"192.168.0.0/16", "172.17.0.0/16", "10.88.0.0/16", "fdaa:2:ebb9::/48"}
	for _, entry := range catalog.Founded() {
		p, err := RegionReservation(entry.Cell)
		if err != nil || !netip.MustParsePrefix(RegionPool).Contains(p.Addr()) {
			t.Fatalf("%s reservation %s: %v", entry.Cell, p, err)
		}
		ranges = append(ranges, p.String())
	}
	for i, a := range ranges {
		for _, b := range ranges[i+1:] {
			if netip.MustParsePrefix(a).Overlaps(netip.MustParsePrefix(b)) {
				t.Fatalf("%s overlaps %s", a, b)
			}
		}
	}
}

func TestRejectOverlapAndWrongRegionalOwnership(t *testing.T) {
	for _, cidr := range []string{Tailscale, Mesh, BridgePool, "10.250.0.0/16", "10.252.0.0/24",
		"10.0.0.0/8", "10.10.0.0/16", "192.168.0.0/16", "172.17.0.0/16",
		"10.251.0.1/24", "10.251.0.0/15", "fd9c:200:2182:65f2::/64", "bad"} {
		if err := ValidateRegion("GRU", cidr); err == nil {
			t.Errorf("accepted GRU network %s", cidr)
		}
	}
	for _, cidr := range []string{"10.251.0.0/16", "10.251.0.0/24", "10.251.0.0/25", "10.251.1.0/24"} {
		if err := ValidateRegion("GRU", cidr); err != nil {
			t.Error(err)
		}
	}
	for _, cidr := range []string{Tailscale, "10.251.0.0/16", "10.200.0.0/15", "10.200.1.0/24", ""} {
		if err := ValidateMesh(cidr); err == nil {
			t.Errorf("accepted mesh %s", cidr)
		}
	}
	if err := ValidateMesh(Mesh); err != nil {
		t.Fatal(err)
	}
}
