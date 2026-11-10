package mesh

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

func TestMeshStartsWithRejectedStoredSpec(t *testing.T) {
	dir := t.TempDir()
	whoami := swarmruntime.ServiceSpec{Name: "whoami", Image: "docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764",
		Port: 8099, Replicas: 1, Regions: []string{"gru"}}
	rejected := swarmruntime.ServiceSpec{Name: "ts-auth", Image: "ghcr.io/terrascale/ts-auth@sha256:" + strings.Repeat("a", 64),
		Port: 8080, Replicas: 1, Regions: []string{"gru"},
		Secrets: map[string]vaultsecret.Ref{"STRIPE_SECRET_KEY_FILE": {
			Vault: "ocid1.vault.oc1.sa-saopaulo-1.abc123.cap", Name: "gru-1-stripe-secret-key"}}}
	stored := map[string]desiredState{
		"whoami":  stateFor(Entry{Generation: 1, Spec: &whoami}),
		"ts-auth": stateFor(Entry{Generation: 5, Spec: &rejected}),
	}
	data, err := protocol.EncodeJSON(stored)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "desired.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	ca, err := DeriveCA(bytes.Repeat([]byte{57}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ports := freePorts(t, 2)
	applier := &fakeApplier{running: map[string]int64{"ts-auth": 4}}
	node, err := start(config{region: "gru", server: "gru-1", dir: dir, clusterHost: "127.0.0.1",
		clusterPort: ports[0], localPort: ports[1], ca: ca, terrabaseToken: testTerraBaseToken,
		applier: applier, peersDir: t.TempDir(), peersEvery: time.Hour,
		address: func() (string, error) { return "10.200.0.1", nil }})
	if err != nil {
		t.Fatalf("mesh start refused the region for one rejected spec: %v", err)
	}
	t.Cleanup(node.Close)
	node.sync(t.Context())
	if got := applier.generation("whoami"); got != 1 {
		t.Fatalf("the valid service was not applied: generation %d", got)
	}
	if got := applier.generation("ts-auth"); got != 4 {
		t.Fatalf("the rejected service's running task was touched: generation %d", got)
	}
	var metrics bytes.Buffer
	node.writePeerMetrics(&metrics)
	if !strings.Contains(metrics.String(), `ts_orch_service_spec_invalid{service="ts-auth"} 1`) {
		t.Fatalf("the rejected spec is not reported:\n%s", metrics.String())
	}
	if strings.Contains(metrics.String(), `service="whoami"`) && strings.Contains(metrics.String(), "ts_orch_service_spec_invalid") &&
		strings.Contains(metrics.String(), `ts_orch_service_spec_invalid{service="whoami"}`) {
		t.Fatal("the valid service is reported invalid")
	}
	if _, err := node.apply(t.Context(), ApplyRequest{Name: "ts-auth", Entry: Entry{Generation: 6, Spec: &rejected}}); err == nil {
		t.Fatal("a new invalid spec was accepted through apply")
	}
	fixed := rejected
	fixed.Secrets = nil
	fixed.Generation = 0
	if applied, err := node.apply(t.Context(), ApplyRequest{Name: "ts-auth", Entry: Entry{Generation: 6, Spec: &fixed}}); err != nil || applied.result != "applied" {
		t.Fatalf("a fixed spec did not restore the service: %+v %v", applied, err)
	}
	metrics.Reset()
	node.writePeerMetrics(&metrics)
	if strings.Contains(metrics.String(), "ts_orch_service_spec_invalid") {
		t.Fatalf("the fixed service is still reported invalid:\n%s", metrics.String())
	}
	if got := applier.generation("ts-auth"); got != 6 {
		t.Fatalf("the fixed service did not roll out: generation %d", got)
	}
}
