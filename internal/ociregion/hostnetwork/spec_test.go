package hostnetwork

import (
	"slices"
	"strconv"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/core"
)

func TestDesiredGRU(t *testing.T) {
	s, err := desired("gru-1")
	if err != nil {
		t.Fatal(err)
	}
	if s.region != "sa-saopaulo-1" || s.compartment != "gru-1-control" || s.host != "gru-1-ctl-1" || s.node != "ts-gru-1" ||
		s.vcn != "10.251.0.0/24" || s.publicSubnet != "10.251.0.0/25" || s.privateSubnet != "10.251.0.192/26" {
		t.Fatalf("spec = %+v", s)
	}
	// The internet reaches only the edge ports and release NATS; SSH is NetBird-only.
	var public []string
	for _, g := range s.nsgs {
		for _, r := range g.rules {
			if !r.egress && r.cidr != s.vcn && r.proto != "1" {
				public = append(public, r.proto+":"+r.cidr+":"+strconv.Itoa(r.port))
			}
		}
	}
	want := []string{"6:0.0.0.0/0:80", "6:0.0.0.0/0:443", "17:0.0.0.0/0:3478", "17:0.0.0.0/0:51820", "6:0.0.0.0/0:4222", "6:0.0.0.0/0:7222", "6:0.0.0.0/0:5432", "6:0.0.0.0/0:7464"}
	if !slices.Equal(public, want) {
		t.Fatalf("public ingress = %v, want %v", public, want)
	}
}

// A rule round-trips through its SDK form; drift is added and removed.
func TestDiff(t *testing.T) {
	s, _ := desired("gru-1")
	want := s.nsgs[0].rules
	var live []core.SecurityRule
	for i, r := range want[1:] {
		a := r.add()
		live = append(live, core.SecurityRule{Id: new(strconv.Itoa(i)), Direction: core.SecurityRuleDirectionEnum(a.Direction), Protocol: a.Protocol,
			Source: a.Source, SourceType: core.SecurityRuleSourceTypeEnum(a.SourceType), Destination: a.Destination,
			DestinationType: core.SecurityRuleDestinationTypeEnum(a.DestinationType), IsStateless: a.IsStateless,
			TcpOptions: a.TcpOptions, UdpOptions: a.UdpOptions, IcmpOptions: a.IcmpOptions})
	}
	live = append(live, core.SecurityRule{Id: new("stale"), Direction: core.SecurityRuleDirectionIngress, Protocol: new("6"),
		Source: new("0.0.0.0/0"), SourceType: core.SecurityRuleSourceTypeCidrBlock,
		TcpOptions: &core.TcpOptions{DestinationPortRange: &core.PortRange{Min: new(22), Max: new(22)}}})
	add, remove := diff(live, want)
	if len(add) != 1 || add[0] != want[0] || !slices.Equal(remove, []string{"stale"}) {
		t.Fatalf("add %v remove %v", add, remove)
	}
	if add, remove := diff(live[:len(live)-1], want[1:]); len(add)+len(remove) != 0 {
		t.Fatalf("converged rules drift: add %v remove %v", add, remove)
	}
}

// A default route table inherits the VCN's claim and is re-keyed; another
// owner's claim is refused.
func TestTagsInheritedFromVCN(t *testing.T) {
	r := &reconciler{s: spec{code: "SJC"}}
	vcn, err := r.tags("vcn", "vcn", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.tags("route-table", "public-routes", vcn)
	if err != nil || got["terrascale-resource-key"] == vcn["terrascale-resource-key"] {
		t.Fatalf("tags = %v, %v", got, err)
	}
	if _, err := r.tags("route-table", "public-routes", map[string]string{"terrascale-managed-by": "someone"}); err == nil {
		t.Fatal("foreign claim adopted")
	}
}
