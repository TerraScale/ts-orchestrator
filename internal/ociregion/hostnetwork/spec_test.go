package hostnetwork

import (
	"slices"
	"strconv"
	"testing"
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
