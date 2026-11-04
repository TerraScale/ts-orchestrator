package publicapi

import (
	"context"
	"testing"
	"time"
)

func reviewedEdge(t *testing.T) (Desired, *fakeOCI, Provisioner, Cloudflare, string) {
	t.Helper()
	d := testDesired(t, testPlan)
	f := newFakeOCI(t)
	_, cloudflare := newFakeCloudflare(t)
	for kind, name := range map[string]string{"internet-gateway": d.Names.IGW, "route-table": d.Names.Routes,
		"security-list": d.Names.Security, "subnet": d.Names.Subnet, "nsg": d.Names.NSG} {
		f.network[kind] = map[string]any{"id": kind, "display-name": name, "lifecycle-state": "AVAILABLE",
			"compartment-id": d.Network, "vcn-id": d.VCN}
	}
	f.network["internet-gateway"]["is-enabled"] = true
	f.network["route-table"]["route-rules"] = []any{map[string]any{"destination": "0.0.0.0/0",
		"destination-type": "CIDR_BLOCK", "network-entity-id": "internet-gateway"}}
	f.network["security-list"]["ingress-security-rules"] = []any{}
	f.network["security-list"]["egress-security-rules"] = []any{reviewedEgress(9465), reviewedEgress(8080)}
	subnet := f.network["subnet"]
	subnet["cidr-block"], subnet["dns-label"] = "10.251.0.128/26", "public"
	subnet["prohibit-public-ip-on-vnic"], subnet["prohibit-internet-ingress"] = false, false
	subnet["route-table-id"], subnet["security-list-ids"] = "route-table", []any{"security-list"}
	members := testCA(t)
	args := []string{"lb", "load-balancer", "create", "--compartment-id", d.Network, "--display-name", d.Names.LB,
		"--shape-name", "flexible", "--subnet-ids", `["subnet"]`, "--is-private", "false", "--network-security-group-ids", `["nsg"]`}
	for flag, value := range d.loadBalancer("ORIGIN", "KEY", members, "") {
		args = append(args, "--"+flag, value)
	}
	if _, err := f.Call(t.Context(), args...); err != nil {
		t.Fatal(err)
	}
	p := Provisioner{Client: f, PollAttempts: 2, Pause: func(context.Context, time.Duration) error { return nil }}
	if _, err := p.Provision(t.Context(), d, cloudflare, members, ""); err != nil {
		t.Fatalf("reviewed fixture was rejected: %v", err)
	}
	f.calls = nil
	return d, f, p, cloudflare, members
}

func reviewedEgress(port int) map[string]any {
	return map[string]any{"protocol": "6", "destination": "10.251.0.0/25", "destination-type": "CIDR_BLOCK", "is-stateless": false,
		"tcp-options": map[string]any{"destination-port-range": map[string]any{"min": port, "max": port}}}
}
