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
