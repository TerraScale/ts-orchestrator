package mesh

import (
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/testwait"
)

func regionalReleaseFixture(t *testing.T, name, hold string) ([]*Node, swarmruntime.ServiceSpec) {
	t.Helper()
	nodes := stateTestNodesWithAppliers(t, func(string) Applier {
		return &evidenceApplier{fakeApplier: fakeApplier{running: map[string]int64{}}, revision: strings.Repeat("b", 40)}
	}, "gru", "sjc", "fra")
	packageName := name
	if name == "ts-dashboard" {
		packageName = "terrascale-dashboard"
	}
	// Model the persisted placement, rather than applying the new declaration.
	spec := swarmruntime.ServiceSpec{Name: name, Image: "ghcr.io/terrascale/" + packageName + "@sha256:" + strings.Repeat("a", 64),
		Port: 8090, ReadyPath: "/readyz", Replicas: 1, Regions: []string{"gru"}, MilliCPU: 500, MemoryMiB: 2048,
		Env: map[string]string{"LISTEN": "http://127.0.0.1:${PORT}"}, Hostnames: []string{"custom.example.com"}}
	if _, err := send(t.Context(), nodes[0].conn, ApplyRequest{Name: name, Entry: Entry{Generation: 10, Spec: &spec, HoldAfter: hold}}, testwait.Budget(t)); err != nil {
		t.Fatal(err)
	}
	return nodes, spec
}

func regionalDeployment(spec swarmruntime.ServiceSpec) *Deployment {
	return &Deployment{Repository: "TerraScale/terrascale", RunID: "100", Revision: strings.Repeat("b", 40), Image: repository(spec.Image) + "@sha256:" + strings.Repeat("c", 64)}
}

func TestSignedDashboardReleaseExpandsPersistedPlacement(t *testing.T) {
	if testing.Short() {
		t.Skip("heavy provisioning, recovery or multi-node integration runs in Slow")
	}
	const name = "ts-dashboard"
	nodes, previous := regionalReleaseFixture(t, name, "")
	deployment := regionalDeployment(previous)
	rows, err := releaseDeployment(t.Context(), nodes[0].conn, name, deployment.Image, deployment, testwait.Budget(t), testwait.Budget(t), unreported{})
	if err != nil || len(rows) != len(nodes) {
		t.Fatalf("release: %+v, %v", rows, err)
	}
	for _, row := range rows {
		if row.Image != deployment.Image || row.Revision != deployment.Revision || len(row.Tasks) != 1 || !row.Tasks[0].Ready {
			t.Fatalf("missing per-region release evidence: %+v", row)
		}
	}
	states, err := desiredStates(t.Context(), nodes[0].conn)
	if err != nil {
		t.Fatal(err)
	}
	before := states[name].entry()
	expected := previous
	expected.Image, expected.Regions, expected.MilliCPU = deployment.Image, nil, 200
	// The declared env moves the dashboard onto its task's ${PORT} (start-first).
	expected.Env = map[string]string{"ASPNETCORE_URLS": "http://127.0.0.1:${PORT}", "DOTNET_BUNDLE_EXTRACT_BASE_DIR": "/tmp", "TS_DASHBOARD_TERRABASE_URL": "http://127.0.0.1:8081"}
	if !reflect.DeepEqual(before.Spec, &expected) {
		t.Fatalf("release changed fields outside image/placement/budget/env: %+v", before.Spec)
	}
	verdict, err := nodes[0].readBake(name, before.Generation)
	if err != nil {
		t.Fatal(err)
	}
	// Fresh release caller after a binary/handler restart: no new generation or bake.
	if _, err := releaseDeployment(t.Context(), nodes[0].conn, name, deployment.Image, deployment, testwait.Budget(t), testwait.Budget(t), unreported{}); err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		node.mu.Lock()
		entry := node.desired[name].entry()
		node.mu.Unlock()
		if entry.Generation != before.Generation || !reflect.DeepEqual(entry.Spec, &expected) {
			t.Fatalf("%s retry changed generation/spec: %+v", node.cfg.region, entry)
		}
	}
	again, err := nodes[0].readBake(name, before.Generation)
	if err != nil || !again.Bake.Finished.Equal(verdict.Bake.Finished) {
		t.Fatalf("retry replaced bake: %+v, %v", again, err)
	}
	// Every later signed release stays all-region even if an old operator spec
	// has put placement back to gru between releases.
	restored := previous
	if _, err := send(t.Context(), nodes[0].conn, ApplyRequest{Name: name, Entry: Entry{Generation: before.Generation + 1, Spec: &restored}}, testwait.Budget(t)); err != nil {
		t.Fatal(err)
	}
	newer := *deployment
	newer.RunID = "101"
	if _, err := releaseDeployment(t.Context(), nodes[0].conn, name, newer.Image, &newer, testwait.Budget(t), testwait.Budget(t), unreported{}); err != nil {
		t.Fatal(err)
	}
	states, err = desiredStates(t.Context(), nodes[0].conn)
	if err != nil || !reflect.DeepEqual(states[name].entry().Spec, &expected) {
		t.Fatalf("later release lost all-region placement: %+v, %v", states[name], err)
	}
}

func TestRegionalAppReleaseRollbackRestoresPlacementAndBudgets(t *testing.T) {
	if testing.Short() {
		t.Skip("heavy provisioning, recovery or multi-node integration runs in Slow")
	}
	nodes, previous := regionalReleaseFixture(t, "ts-dashboard", "")
	deployment := regionalDeployment(previous)
	// sjc is first, fra fails, gru must retain/restore its original workload.
	applier := nodes[2].cfg.applier.(*evidenceApplier)
	applier.mu.Lock()
	applier.unready = deployment.Image
	applier.mu.Unlock()
	progress := &recordedProgress{}
	started := time.Now()
	_, err := releaseDeployment(t.Context(), nodes[0].conn, previous.Name, deployment.Image, deployment, time.Second, time.Second, progress)
	if err == nil || !strings.Contains(err.Error(), "fra (test image not ready)") {
		t.Fatalf("failed regional rollout did not roll back with its cause: %v", err)
	}
	progress.mu.Lock()
	events := strings.Join(progress.events, "\n")
	progress.mu.Unlock()
	failure, rollback := strings.Index(events, "fra failed after"), strings.Index(events, "rolling back to "+previous.Image)
	if !progress.deadline.After(started) || !strings.HasPrefix(events, previous.Name+" "+deployment.Image+" rolls out to sjc, fra, gru") ||
		!strings.Contains(events, "sjc applied in") || failure < 0 || rollback < failure || !strings.Contains(events[failure:rollback], "test image not ready") ||
		!strings.Contains(events[rollback:], "rollback sjc ") {
		t.Fatalf("release progress missing deadline, region outcomes or cause: %s %s", progress.deadline, events)
	}
	for _, node := range nodes {
		node.mu.Lock()
		state := node.desired[previous.Name]
		node.mu.Unlock()
		if !reflect.DeepEqual(state.entry().Spec, &previous) || state.Floor == nil || *state.Floor != *deployment {
			t.Fatalf("%s lost rollback spec/floor: %+v", node.cfg.region, state)
		}
		applier := node.cfg.applier.(*evidenceApplier)
		applier.mu.Lock()
		running, image := applier.running[previous.Name], applier.images[previous.Name]
		applier.mu.Unlock()
		if node.cfg.region == "gru" {
			if running == 0 || image != previous.Image {
				t.Fatalf("gru failed to restore old image: %s", image)
			}
		} else if running != 0 {
			t.Fatalf("rollback left candidate running in %s", node.cfg.region)
		}
	}
}

type recordedProgress struct {
	mu       sync.Mutex
	deadline time.Time
	events   []string
}

func (p *recordedProgress) Deadline(deadline time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deadline = deadline
}

func (p *recordedProgress) Event(event string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, event)
}
