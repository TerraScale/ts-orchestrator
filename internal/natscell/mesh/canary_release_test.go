package mesh

import (
	"strings"
	"testing"
	"time"
)

func TestAppCanaryFirstSignedReleaseNeedsNoOperatorApply(t *testing.T) {
	nodes := stateTestNodesWithAppliers(t, func(string) Applier {
		return &evidenceApplier{fakeApplier: fakeApplier{running: map[string]int64{}}, revision: strings.Repeat("b", 40)}
	}, "gru", "sjc", "fra")
	image := "ghcr.io/terrascale/app-canary@sha256:" + strings.Repeat("a", 64)
	deployment := &Deployment{Repository: "TerraScale/ts-orchestrator", RunID: "100", Revision: strings.Repeat("b", 40), Image: image}
	rows, err := releaseDeployment(t.Context(), nodes[0].conn, "app-canary", image, deployment, time.Second, time.Second)
	if err != nil || len(rows) != len(nodes) {
		t.Fatalf("first canary release: rows=%+v err=%v", rows, err)
	}
	for _, row := range rows {
		if row.Region != "gru" && (row.Image != image || row.Revision != deployment.Revision || len(row.Tasks) != 1 || !row.Tasks[0].Ready) {
			t.Fatalf("canary release lacks running image/revision/task evidence: %+v", row)
		}
	}
	for _, node := range nodes {
		node.mu.Lock()
		entry := node.desired["app-canary"].entry()
		node.mu.Unlock()
		if entry.Spec == nil || entry.Spec.Image != image || entry.Deployment == nil || *entry.Deployment != *deployment {
			t.Fatalf("%s lost canary spec or signed provenance: %+v", node.cfg.region, entry)
		}
		if entry.Spec.Port != 8097 || entry.Spec.Replicas != 1 || entry.Spec.MilliCPU != 50 || entry.Spec.MemoryMiB != 32 {
			t.Fatalf("bootstrap changed the bounded canary workload: %+v", entry.Spec)
		}
		applier := node.cfg.applier.(*evidenceApplier)
		applier.mu.Lock()
		running := applier.running["app-canary"]
		applier.mu.Unlock()
		if (running != 0) != (node.cfg.region != "gru") {
			t.Fatalf("canary placement %s running=%d", node.cfg.region, running)
		}
	}
	if _, err := releaseDeployment(t.Context(), nodes[0].conn, "unknown", image, deployment, time.Second, time.Second); err == nil {
		t.Fatal("arbitrary missing service was bootstrapped")
	}
}

func TestAppCanaryFailedCreationRollsBackAndPreservesAuthority(t *testing.T) {
	nodes := stateTestNodesWithAppliers(t, func(string) Applier {
		return &evidenceApplier{fakeApplier: fakeApplier{running: map[string]int64{}}, revision: strings.Repeat("b", 40)}
	}, "gru", "sjc", "fra")
	image := "ghcr.io/terrascale/app-canary@sha256:" + strings.Repeat("a", 64)
	deployment := &Deployment{Repository: "TerraScale/ts-orchestrator", RunID: "100", Revision: strings.Repeat("b", 40), Image: image}
	applier := nodes[1].cfg.applier.(*evidenceApplier)
	applier.mu.Lock()
	applier.unready = image
	applier.mu.Unlock()
	rows, err := releaseDeployment(t.Context(), nodes[0].conn, "app-canary", image, deployment, time.Second, time.Second)
	if err == nil || !strings.Contains(err.Error(), "rolled back to absence") || len(rows) != 2*len(nodes) {
		t.Fatalf("failed first creation: rows=%+v err=%v", rows, err)
	}
	for _, node := range nodes {
		node.mu.Lock()
		state := node.desired["app-canary"]
		node.mu.Unlock()
		if state.entry().Spec != nil || state.Floor == nil || *state.Floor != *deployment {
			t.Fatalf("%s failed creation left a workload or lost its floor: %+v", node.cfg.region, state)
		}
	}
	older := *deployment
	older.RunID = "99"
	if _, err := releaseDeployment(t.Context(), nodes[0].conn, "app-canary", image, &older, time.Second, time.Second); err == nil {
		t.Fatal("an old signed run bypassed the failed creation's floor")
	}
	applier.mu.Lock()
	applier.unready = ""
	applier.mu.Unlock()
	deployment.RunID = "101"
	if _, err := releaseDeployment(t.Context(), nodes[0].conn, "app-canary", image, deployment, time.Second, time.Second); err != nil {
		t.Fatalf("new run could not recover failed creation: %v", err)
	}
	if _, err := send(t.Context(), nodes[0].conn, ApplyRequest{Name: "app-canary", Entry: Entry{Generation: time.Now().UnixNano()}}, time.Second); err != nil {
		t.Fatal(err)
	}
	deployment.RunID = "102"
	if _, err := releaseDeployment(t.Context(), nodes[0].conn, "app-canary", image, deployment, time.Second, time.Second); err != nil {
		t.Fatalf("new signed canary run did not restore the fixed spec after removal: %v", err)
	}
}
