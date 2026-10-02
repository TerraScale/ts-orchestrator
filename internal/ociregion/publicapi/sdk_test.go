package publicapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/networkloadbalancer"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
)

// TestSDKDecodesEveryCreateTheProvisionerSends runs the provisioner against a
// recording fake and decodes each create's JSON flags into the SDK request
// types, so the in-binary path accepts exactly what the provisioner emits.
func TestSDKDecodesEveryCreateTheProvisionerSends(t *testing.T) {
	plan := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(plan, []byte(`{"resource_ids":{"network_compartment":"network","vcn":"vcn"},"subnet_cidr":"10.251.0.0/26"}`), 0644); err != nil {
		t.Fatal(err)
	}
	created := false
	f := &fakeOCI{}
	f.call = func(args []string) (map[string]any, error) {
		switch {
		case args[0] == "network" && args[1] == "nsg":
			return data([]any{}), nil
		case args[0] == "network" && args[2] == "list":
			return data([]any{}), nil
		case args[0] == "network":
			return data(map[string]any{"id": args[1], "display-name": Prefix, "lifecycle-state": "AVAILABLE"}), nil
		case args[2] == "create":
			created = true
			return map[string]any{}, nil
		case args[2] == "list" && created:
			return data(map[string]any{"items": []any{map[string]any{"id": "nlb", "display-name": Prefix, "lifecycle-state": "ACTIVE"}}}), nil
		case args[2] == "list":
			return data(map[string]any{"items": []any{}}), nil
		default:
			return data(map[string]any{"id": "nlb", "lifecycle-state": "ACTIVE", "ip-addresses": []any{}}), nil
		}
	}
	_, err := (Provisioner{Client: f, Pause: func(context.Context, time.Duration) error { return nil }}).Provision(t.Context(),
		Options{Plan: plan, Members: "10.251.0.10,10.251.0.11", WorkloadNSG: "nsg", SubnetCIDR: "10.251.0.128/26", ClientPort: 9465})
	if err != nil {
		t.Fatal(err)
	}
	decoded := map[string]bool{}
	for _, args := range f.calls {
		command, err := sdkcli.Parse(args)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if _, ok := creators[command.Path]; !ok {
			continue
		}
		switch command.Path {
		case "network route-table create":
			var rules []core.RouteRule
			if err := jsonFlag(command, "route-rules", &rules); err != nil || *rules[0].NetworkEntityId != "internet-gateway" ||
				rules[0].DestinationType != core.RouteRuleDestinationTypeCidrBlock {
				t.Fatalf("route rules=%+v err=%v", rules, err)
			}
		case "network security-list create":
			var ingress []core.IngressSecurityRule
			var egress []core.EgressSecurityRule
			if err := jsonFlag(command, "ingress-security-rules", &ingress); err != nil || *ingress[0].TcpOptions.DestinationPortRange.Min != 443 {
				t.Fatalf("ingress=%+v err=%v", ingress, err)
			}
			if err := jsonFlag(command, "egress-security-rules", &egress); err != nil || *egress[0].Destination != "10.251.0.0/26" {
				t.Fatalf("egress=%+v err=%v", egress, err)
			}
		case "network subnet create":
			var lists []string
			if err := jsonFlag(command, "security-list-ids", &lists); err != nil || len(lists) != 1 {
				t.Fatalf("lists=%v err=%v", lists, err)
			}
			if prohibit, err := boolFlag(command, "prohibit-public-ip-on-vnic"); err != nil || prohibit == nil || *prohibit {
				t.Fatalf("prohibit=%v err=%v", prohibit, err)
			}
		case "network nsg rules add":
			var rules []core.AddSecurityRuleDetails
			if err := jsonFlag(command, "security-rules", &rules); err != nil || *rules[0].Source != "10.251.0.128/26" ||
				*rules[0].TcpOptions.DestinationPortRange.Max != 9465 {
				t.Fatalf("nsg rules=%+v err=%v", rules, err)
			}
		case "nlb network-load-balancer create":
			var sets map[string]networkloadbalancer.BackendSetDetails
			var listeners map[string]networkloadbalancer.ListenerDetails
			if err := jsonFlag(command, "backend-sets", &sets); err != nil || len(sets["terrabase-https"].Backends) != 2 ||
				*sets["terrabase-https"].HealthChecker.Port != 9465 {
				t.Fatalf("sets=%+v err=%v", sets, err)
			}
			if err := jsonFlag(command, "listeners", &listeners); err != nil || *listeners["https"].Port != 443 {
				t.Fatalf("listeners=%+v err=%v", listeners, err)
			}
		}
		decoded[command.Path] = true
	}
	for path := range creators {
		if !decoded[path] {
			t.Errorf("provisioner never exercised %s", path)
		}
	}
}

func TestNewClientPinsThePlanRegion(t *testing.T) {
	plan := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(plan, []byte(`{"region":"uk-london-1"}`), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(sdkcli.BackendEnv, "")
	if _, err := newClient(plan); err == nil {
		t.Fatal("accepted a plan region outside the catalog")
	}
	t.Setenv(sdkcli.BackendEnv, "cli")
	if client, err := newClient(plan); err != nil || client == nil {
		t.Fatalf("cli backend: %v", err)
	}
}
