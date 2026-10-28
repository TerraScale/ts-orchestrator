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
	// A fresh release caller (including one after handler restart) must reuse
	// durable bake evidence for the same authenticated deployment and image.
	before, err := desiredStates(t.Context(), nodes[0].conn)
	if err != nil {
		t.Fatal(err)
	}
	generation := before["app-canary"].entry().Generation
	verdict, err := nodes[1].readBake("app-canary", generation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := releaseDeployment(t.Context(), nodes[0].conn, "app-canary", image, deployment, time.Second, time.Second); err != nil {
		t.Fatalf("identical signed retry failed: %v", err)
	}
	for _, node := range nodes {
		node.mu.Lock()
		entry := node.desired["app-canary"].entry()
		node.mu.Unlock()
		if entry.Generation != generation {
			t.Fatalf("%s restarted the same deployment's bake: %d -> %d", node.cfg.region, generation, entry.Generation)
		}
	}
	again, err := nodes[1].readBake("app-canary", generation)
	if err != nil || !again.Bake.Finished.Equal(verdict.Bake.Finished) {
		t.Fatalf("retry replaced persisted bake evidence: %+v %v", again, err)
	}
	newer := *deployment
	newer.RunID = "101"
	if _, err := releaseDeployment(t.Context(), nodes[0].conn, "app-canary", image, &newer, time.Second, time.Second); err != nil {
		t.Fatalf("new signed run failed: %v", err)
	}
	nodes[0].mu.Lock()
	nextGeneration := nodes[0].desired["app-canary"].entry().Generation
	nodes[0].mu.Unlock()
	if nextGeneration <= generation {
		t.Fatal("new signed run reused the previous run's generation")
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
	// Simulate a fresh handler after rollback: healthy dependencies must not
	// allow the failed signed run to become a new successful deployment.
	before, err := desiredStates(t.Context(), nodes[0].conn)
	if err != nil {
		t.Fatal(err)
	}
	generation := before["app-canary"].entry().Generation
	if _, err := releaseDeployment(t.Context(), nodes[0].conn, "app-canary", image, deployment, time.Second, time.Second); err == nil || !strings.Contains(err.Error(), "newer signed run") {
		t.Fatalf("identical signed retry escaped terminal rollback: %v", err)
	}
	for _, node := range nodes {
		node.mu.Lock()
		state := node.desired["app-canary"]
		node.mu.Unlock()
		if state.entry().Generation != generation || state.entry().Spec != nil || state.Floor == nil || *state.Floor != *deployment {
			t.Fatalf("%s identical retry changed rolled-back state: %+v", node.cfg.region, state)
		}
	}
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

func TestAppCanaryFailedUpdateCannotRetrySignedRun(t *testing.T) {
	for _, mode := range []string{"different-image", "same-image"} {
		t.Run(mode, func(t *testing.T) {
			nodes := stateTestNodesWithAppliers(t, func(string) Applier {
				return &evidenceApplier{fakeApplier: fakeApplier{running: map[string]int64{}}, revision: strings.Repeat("b", 40)}
			}, "gru", "sjc", "fra")
			oldImage := "ghcr.io/terrascale/app-canary@sha256:" + strings.Repeat("a", 64)
			deployment := &Deployment{Repository: "TerraScale/ts-orchestrator", RunID: "99", Revision: strings.Repeat("b", 40), Image: oldImage}
			if _, err := releaseDeployment(t.Context(), nodes[0].conn, "app-canary", oldImage, deployment, time.Second, time.Second); err != nil {
				t.Fatal(err)
			}
			image := "ghcr.io/terrascale/app-canary@sha256:" + strings.Repeat("c", 64)
			if mode == "same-image" {
				image = oldImage
			}
			failed := *deployment
			failed.RunID, failed.Image = "100", image
			applier := nodes[1].cfg.applier.(*evidenceApplier)
			applier.mu.Lock()
			applier.unready = image
			applier.mu.Unlock()
			if _, err := releaseDeployment(t.Context(), nodes[0].conn, "app-canary", image, &failed, time.Second, time.Second); err == nil || !strings.Contains(err.Error(), "rollback") && !strings.Contains(err.Error(), "rolled back") {
				t.Fatalf("failed update did not roll back: %v", err)
			}
			before, err := desiredStates(t.Context(), nodes[0].conn)
			if err != nil {
				t.Fatal(err)
			}
			generation := before["app-canary"].entry().Generation
			if before["app-canary"].entry().RollbackOf == 0 {
				t.Fatal("test did not retain a rollback entry")
			}
			applier.mu.Lock()
			applier.unready = ""
			applier.mu.Unlock()
			if _, err := releaseDeployment(t.Context(), nodes[0].conn, "app-canary", image, &failed, time.Second, time.Second); err == nil || !strings.Contains(err.Error(), "newer signed run") {
				t.Fatalf("identical update retry escaped terminal rollback: %v", err)
			}
			for _, node := range nodes {
				node.mu.Lock()
				state := node.desired["app-canary"]
				node.mu.Unlock()
				entry := state.entry()
				if entry.Generation != generation || entry.Spec == nil || entry.Spec.Image != oldImage || state.Floor == nil || *state.Floor != failed {
					t.Fatalf("%s retry changed rolled-back image or authority: %+v", node.cfg.region, state)
				}
			}
			failed.RunAttempt = 2
			failed.Image = "ghcr.io/terrascale/app-canary@sha256:" + strings.Repeat("d", 64)
			if _, err := releaseDeployment(t.Context(), nodes[0].conn, "app-canary", failed.Image, &failed, time.Second, time.Second); err != nil {
				t.Fatalf("rerun after rollback rejected: %v", err)
			}
			// A later attempt of the same run retries it with its rebuilt image.
			failed.RunAttempt = 3
			failed.Image = image
			if _, err := releaseDeployment(t.Context(), nodes[0].conn, "app-canary", image, &failed, time.Second, time.Second); err != nil {
				t.Fatalf("a later attempt of the serving run was refused: %v", err)
			}
			failed.RunAttempt = 2
			if _, err := releaseDeployment(t.Context(), nodes[0].conn, "app-canary", image, &failed, time.Second, time.Second); err == nil {
				t.Fatal("an older attempt replaced a newer one")
			}
		})
	}
}
