package tsauth_test

import (
	"fmt"
	"reflect"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/tsauth"
)

func TestBackendSet(t *testing.T) {
	if tsauth.Port != ociregion.TSAuthPort {
		t.Fatal("ts-auth port differs from the plan firewall port")
	}
	host := func(slot, ip string) ociregion.Object { return ociregion.Object{"slot": slot, "private_ip": ip} }
	hosts := []any{host("controller-a", "10.251.0.11"), host("controller-b", "10.251.0.12"), host("controller-c", "10.251.0.13"),
		host("0000000000WM3QQGQPMW5X58P9", "10.251.0.21")}
	for cell, hostname := range map[string]string{"GRU": "gru.auth.terrascale.tech", "SFO": "sfo.auth.terrascale.tech"} {
		set, err := tsauth.BackendSet(ociregion.Object{"cell": cell, "hosts": hosts})
		want := tsauth.LoadBalancer{Hostname: hostname, Backends: []string{"10.251.0.11", "10.251.0.12", "10.251.0.13"},
			Port: 8080, HealthPath: "/readyz"}
		if err != nil || !reflect.DeepEqual(set, want) {
			t.Fatalf("%s backend set %+v: %v", cell, set, err)
		}
	}
	if _, err := tsauth.BackendSet(ociregion.Object{"cell": "XXX", "hosts": hosts}); err == nil {
		t.Fatal("accepted a cell outside the catalog")
	}
	if _, err := tsauth.BackendSet(ociregion.Object{"cell": "GRU", "hosts": []any{host("controller-a", "10.251.0.11"), host("0000000000WM3QQGQPMW5X58P9", "10.251.0.21")}}); err == nil {
		t.Fatal("accepted one controller")
	}
	if _, err := tsauth.BackendSet(ociregion.Object{"cell": "GRU", "hosts": []any{host("controller-a", "10.251.0.11"), host("controller-b", "")}}); err == nil {
		t.Fatal("accepted a controller without IP")
	}
	plan, err := ociregion.LoadPlan("../../deploy/oci-region/plan.json")
	if err != nil {
		t.Fatal(err)
	}
	if set, err := tsauth.BackendSet(plan); err != nil || set.Hostname != "gru.auth.terrascale.tech" || len(set.Backends) != 3 {
		t.Fatalf("plan backend set %+v: %v", set, err)
	}
	// The plan admits the load balancer's subnet on the backend port.
	subnet := plan["public_api"].(ociregion.Object)["subnet_cidr"]
	admitted := false
	for _, value := range plan["network_security"].(ociregion.Object)["nsg_rules"].([]any) {
		rule := value.(ociregion.Object)
		admitted = admitted || rule["source"] == subnet && fmt.Sprint(rule["tcp_min"]) == "8080" && fmt.Sprint(rule["tcp_max"]) == "8080"
	}
	if !admitted {
		t.Fatalf("controller NSG does not admit the load balancer subnet %v on %d", subnet, tsauth.Port)
	}
}
