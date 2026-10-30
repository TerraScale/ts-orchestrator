package mesh

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
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
	if _, err := send(t.Context(), nodes[0].conn, ApplyRequest{Name: name, Entry: Entry{Generation: 10, Spec: &spec, HoldAfter: hold}}, time.Second); err != nil {
		t.Fatal(err)
	}
	return nodes, spec
}

func regionalDeployment(spec swarmruntime.ServiceSpec) *Deployment {
	return &Deployment{Repository: "TerraScale/terrascale", RunID: "100", Revision: strings.Repeat("b", 40), Image: repository(spec.Image) + "@sha256:" + strings.Repeat("c", 64)}
}

func TestSignedDashboardReleaseExpandsPersistedPlacement(t *testing.T) {
	const name = "ts-dashboard"
	nodes, previous := regionalReleaseFixture(t, name, "")
	deployment := regionalDeployment(previous)
	rows, err := releaseDeployment(t.Context(), nodes[0].conn, name, deployment.Image, deployment, time.Second, time.Second)
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
	if _, err := releaseDeployment(t.Context(), nodes[0].conn, name, deployment.Image, deployment, time.Second, time.Second); err != nil {
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
	if _, err := send(t.Context(), nodes[0].conn, ApplyRequest{Name: name, Entry: Entry{Generation: before.Generation + 1, Spec: &restored}}, time.Second); err != nil {
		t.Fatal(err)
	}
	newer := *deployment
	newer.RunID = "101"
	if _, err := releaseDeployment(t.Context(), nodes[0].conn, name, newer.Image, &newer, time.Second, time.Second); err != nil {
		t.Fatal(err)
	}
	states, err = desiredStates(t.Context(), nodes[0].conn)
	if err != nil || !reflect.DeepEqual(states[name].entry().Spec, &expected) {
		t.Fatalf("later release lost all-region placement: %+v, %v", states[name], err)
	}
}

func TestRegionalReleasePreservesHeldUnsignedAndUnrelatedPlacement(t *testing.T) {
	for _, test := range []struct {
		name, hold string
		unsigned   bool
	}{
		{name: "ts-auth", hold: "gru"}, {name: "ts-dashboard", hold: "gru"},
		{name: "ts-auth", unsigned: true}, {name: "ts-dashboard", unsigned: true},
		{name: "ts-auth"}, {name: "unrelated"}, {name: "app-canary"},
	} {
		t.Run(test.name+"/"+test.hold+"/"+map[bool]string{true: "unsigned", false: "signed"}[test.unsigned], func(t *testing.T) {
			nodes, previous := regionalReleaseFixture(t, test.name, test.hold)
			deployment := regionalDeployment(previous)
			image := deployment.Image
			if test.unsigned {
				deployment = nil
			}
			if _, err := releaseDeployment(t.Context(), nodes[0].conn, test.name, image, deployment, time.Second, time.Second); err != nil {
				t.Fatal(err)
			}
			for _, node := range nodes {
				node.mu.Lock()
				entry := node.desired[test.name].entry()
				node.mu.Unlock()
				expected := previous
				expected.Image = image
				hold := test.hold
				if !test.unsigned {
					hold = "" // a signed release advances past the canary through bake gating
				}
				if entry.HoldAfter != hold || !reflect.DeepEqual(entry.Spec, &expected) {
					t.Fatalf("%s changed held/unsigned/unrelated spec: %+v", node.cfg.region, entry)
				}
				applier := node.cfg.applier.(*evidenceApplier)
				applier.mu.Lock()
				running := applier.running[test.name]
				applier.mu.Unlock()
				if running != 0 && !slices.Contains(previous.Regions, node.cfg.region) {
					t.Fatalf("expanded preserved placement to %s", node.cfg.region)
				}
			}
		})
	}
}

func TestRegionalAppReleaseRollbackRestoresPlacementAndBudgets(t *testing.T) {
	nodes, previous := regionalReleaseFixture(t, "ts-dashboard", "")
	deployment := regionalDeployment(previous)
	// sjc is first, fra fails, gru must retain/restore its original workload.
	applier := nodes[2].cfg.applier.(*evidenceApplier)
	applier.mu.Lock()
	applier.unready = deployment.Image
	applier.mu.Unlock()
	if _, err := releaseDeployment(t.Context(), nodes[0].conn, previous.Name, deployment.Image, deployment, time.Second, time.Second); err == nil {
		t.Fatal("failed regional rollout did not roll back")
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

func TestIdenticalSignedRegionalReceiptRetainsOldPlacement(t *testing.T) {
	nodes, previous := regionalReleaseFixture(t, "ts-dashboard", "")
	deployment := regionalDeployment(previous)
	deployment.Image = previous.Image
	// A receipt accepted before this binary kept the old gru-only spec.
	const generation = 20
	if _, err := send(t.Context(), nodes[0].conn, ApplyRequest{Name: previous.Name, Entry: Entry{Generation: generation, Spec: &previous, Deployment: deployment}}, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := releaseDeployment(t.Context(), nodes[0].conn, previous.Name, previous.Image, deployment, time.Second, time.Second); err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		node.mu.Lock()
		entry := node.desired[previous.Name].entry()
		node.mu.Unlock()
		if entry.Generation != generation || !reflect.DeepEqual(entry.Spec, &previous) {
			t.Fatalf("%s replay expanded an old signed receipt: %+v", node.cfg.region, entry)
		}
	}
}

// 2026-10-28: terrabase's gru bake failed while auth was down; every retry
// resumed that generation and replayed its failed verdict.
func TestSignedReleaseRetryRebakesAFailedGeneration(t *testing.T) {
	const name = "ts-dashboard"
	nodes, previous := regionalReleaseFixture(t, name, "")
	deployment := regionalDeployment(previous)
	if _, err := releaseDeployment(t.Context(), nodes[0].conn, name, deployment.Image, deployment, time.Second, time.Second); err != nil {
		t.Fatal(err)
	}
	states, err := desiredStates(t.Context(), nodes[0].conn)
	if err != nil {
		t.Fatal(err)
	}
	before := states[name].entry()
	record, err := nodes[0].readBake(name, before.Generation)
	if err != nil {
		t.Fatal(err)
	}
	record.Bake.Reason = "bake ts-auth readiness: HTTP 503"
	if err := nodes[0].saveBake(nodes[0].bakePath(name, before.Generation), record); err != nil {
		t.Fatal(err)
	}
	if _, err := releaseDeployment(t.Context(), nodes[0].conn, name, deployment.Image, deployment, time.Second, time.Second); err != nil {
		t.Fatal(err)
	}
	states, err = desiredStates(t.Context(), nodes[0].conn)
	if err != nil || states[name].entry().Generation <= before.Generation {
		t.Fatalf("retry replayed failed generation %d: %+v, %v", before.Generation, states[name].entry(), err)
	}
}

func TestSignedDashboardPackageCutover(t *testing.T) {
	nodes, previous := regionalReleaseFixture(t, "ts-dashboard", "")
	previous.Image = "ghcr.io/terrascale/ts-dashboard@sha256:" + strings.Repeat("a", 64)
	if _, err := send(t.Context(), nodes[0].conn, ApplyRequest{Name: previous.Name, Entry: Entry{Generation: 20, Spec: &previous}}, time.Second); err != nil {
		t.Fatal(err)
	}
	deployment := regionalDeployment(previous)
	deployment.Image = "ghcr.io/terrascale/terrascale-dashboard@sha256:" + strings.Repeat("c", 64)
	if _, err := releaseDeployment(t.Context(), nodes[0].conn, previous.Name, deployment.Image, nil, time.Second, time.Second); err == nil {
		t.Fatal("unsigned package move accepted")
	}
	unrelated := *deployment
	unrelated.Repository = "TerraScale/unrelated"
	if _, err := releaseDeployment(t.Context(), nodes[0].conn, previous.Name, unrelated.Image, &unrelated, time.Second, time.Second); err == nil {
		t.Fatal("unrelated repository moved package")
	}
	rows, err := releaseDeployment(t.Context(), nodes[0].conn, previous.Name, deployment.Image, deployment, time.Second, time.Second)
	if err != nil || len(rows) != len(nodes) {
		t.Fatalf("signed package move: %+v, %v", rows, err)
	}
	for _, row := range rows {
		if row.Image != deployment.Image || row.Revision != deployment.Revision {
			t.Fatalf("wrong regional artifact: %+v", row)
		}
	}
	reverse := *deployment
	reverse.RunID = "101"
	reverse.Image = previous.Image
	if _, err := releaseDeployment(t.Context(), nodes[0].conn, previous.Name, reverse.Image, &reverse, time.Second, time.Second); err == nil {
		t.Fatal("retired package restored by a release")
	}
}
