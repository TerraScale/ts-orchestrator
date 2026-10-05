package ociregion

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"testing"
)

// TestPublicSubnetReachesControllersOnlyOnTSAuthPort admits the public API
// load balancer's subnet to the controllers on TSAuthPort alone: another
// port, a port range or the workload NSG are refused.
func TestPublicSubnetReachesControllersOnlyOnTSAuthPort(t *testing.T) {
	wire, err := os.ReadFile(filepath.Join("..", "..", "deploy", "oci-region", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	load := func(list string, low, high int) error {
		var plan map[string]any
		if err := json.Unmarshal(wire, &plan); err != nil {
			t.Fatal(err)
		}
		security := plan["network_security"].(map[string]any)
		rules := []any{}
		for _, rule := range security["nsg_rules"].([]any) {
			if rule.(map[string]any)["source"] != "10.251.0.128/26" {
				rules = append(rules, rule)
			}
		}
		security["nsg_rules"] = rules
		security[list] = append(security[list].([]any), map[string]any{"direction": "INGRESS", "protocol": "6",
			"source": "10.251.0.128/26", "source_type": "CIDR_BLOCK", "destination": nil, "destination_type": nil,
			"tcp_min": low, "tcp_max": high, "udp_min": nil, "udp_max": nil, "stateless": false})
		data, err := json.Marshal(plan)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "plan.json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err = LoadPlan(path)
		return err
	}
	if err := load("nsg_rules", TSAuthPort, TSAuthPort); err != nil {
		t.Fatal(err)
	}
	for _, refused := range []struct {
		list      string
		low, high int
	}{{"nsg_rules", TSAuthPort + 1, TSAuthPort + 1}, {"nsg_rules", TSAuthPort, TSAuthPort + 1},
		{"nsg_rules", 22, 22}, {"workload_nsg_rules", TSAuthPort, TSAuthPort}} {
		if err := load(refused.list, refused.low, refused.high); err == nil {
			t.Errorf("public API subnet admitted to %s on %d-%d", refused.list, refused.low, refused.high)
		}
	}
}
