package mesh

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

func stateTestNodes(t *testing.T, regions ...string) []*Node {
	t.Helper()
	ca, err := DeriveCA(bytes.Repeat([]byte{57}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ports := freePorts(t, 2*len(regions))
	var nodes []*Node
	for i, region := range regions {
		gateways := map[string]string{}
		for j, peer := range regions {
			if i != j {
				gateways[peer] = fmt.Sprintf("nats://127.0.0.1:%d", ports[2*j])
			}
		}
		node, err := start(config{region: region, server: region + "-1", dir: t.TempDir(), host: "127.0.0.1",
			gatewayPort: ports[2*i], localPort: ports[2*i+1], ca: ca, gateways: gateways,
			applier: &fakeApplier{running: map[string]int64{}}, peersDir: t.TempDir(),
			address: func() (string, error) { return "10.200.0.1", nil }})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(node.Close)
		nodes = append(nodes, node)
	}
	eventually(t, "all test mesh nodes to answer", func() bool {
		seen := map[string]bool{}
		_ = collect(t.Context(), nodes[0].conn, PingSubject, nil, len(nodes), time.Second, func(data []byte) bool {
			var reply Reply
			if protocol.DecodeTolerant(data, &reply, maxWire) == nil {
				seen[reply.Region] = true
			}
			return true
		})
		return len(seen) == len(nodes)
	})
	return nodes
}

func TestPartialRollbackSyncPreservesInterveningApply(t *testing.T) {
	for _, scenario := range []string{"operator update", "operator removal", "rollback removal", "new signed run"} {
		t.Run(scenario, func(t *testing.T) {
			nodes := stateTestNodes(t, "gru", "sjc")
			spec := swarmruntime.ServiceSpec{Name: "web", Image: "ghcr.io/terrascale/web@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1}
			approved := &Deployment{Repository: "TerraScale/terrascale", RunID: "100", Revision: strings.Repeat("b", 40), Image: spec.Image}
			rollout := ApplyRequest{Name: spec.Name, Entry: Entry{Generation: 10, Spec: &spec, Deployment: approved}}
			for _, node := range nodes {
				if _, err := node.apply(t.Context(), rollout); err != nil {
					t.Fatal(err)
				}
			}
			operatorSpec := spec
			operatorSpec.Replicas = 2
			operator := ApplyRequest{Name: spec.Name, Entry: Entry{Generation: 11, Spec: &operatorSpec}}
			if scenario == "operator removal" {
				operator.Entry.Spec = nil
			}
			if scenario == "new signed run" {
				newRun := *approved
				newRun.RunID = "101"
				operator.Entry.Deployment = &newRun
			}
			if _, err := nodes[1].apply(t.Context(), operator); err != nil {
				t.Fatal(err)
			}
			previous := spec
			previous.Image = "ghcr.io/terrascale/web@sha256:" + strings.Repeat("c", 64)
			rollback := ApplyRequest{Name: spec.Name, ExpectedGeneration: 10, Entry: Entry{Generation: 12, Spec: &previous, Deployment: approved}}
			if scenario == "rollback removal" {
				rollback.Entry.Spec = nil
			}
			if _, err := nodes[0].apply(t.Context(), rollback); err != nil {
				t.Fatal(err)
			}
			if _, err := nodes[1].apply(t.Context(), rollback); err == nil {
				t.Fatal("direct rollback accepted over intervening operator apply")
			}
			selected, err := desiredEntries(t.Context(), nodes[0].conn)
			if err != nil || selected[spec.Name].Generation != 11 {
				t.Fatalf("release state read selected rollback over operator: %+v, %v", selected, err)
			}
			// B rejected the direct CAS; peer sync must not bypass that decision.
			nodes[1].sync(t.Context())
			nodes[0].sync(t.Context())
			for _, node := range nodes {
				got, err := loadDesired(node.cfg.dir)
				if err != nil {
					t.Fatal(err)
				}
				entry := got[spec.Name]
				if entry.Generation != 11 || !reflect.DeepEqual(entry.Spec, operator.Entry.Spec) {
					t.Fatalf("%s sync replaced the operator apply: %+v", node.cfg.region, entry)
				}
				wantRun := "100"
				if scenario == "new signed run" {
					wantRun = "101"
				}
				if floor := entry.deploymentFloor(); floor == nil || floor.RunID != wantRun {
					t.Fatalf("%s lost signed-run watermark: %+v", node.cfg.region, floor)
				}
				wantGeneration := int64(11)
				if operator.Entry.Spec == nil {
					wantGeneration = 0
				}
				if got := node.cfg.applier.(*fakeApplier).generation(spec.Name); got != wantGeneration {
					t.Fatalf("%s runs generation %d, want %d", node.cfg.region, got, wantGeneration)
				}
			}
		})
	}
}

func TestOperatorSyncConvergesAcrossUnequalDeploymentFloors(t *testing.T) {
	for _, removal := range []bool{false, true} {
		t.Run(fmt.Sprintf("removed=%t", removal), func(t *testing.T) {
			nodes := stateTestNodes(t, "gru", "sjc")
			spec := swarmruntime.ServiceSpec{Name: "web", Image: "ghcr.io/terrascale/web@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1}
			approved := &Deployment{Repository: "TerraScale/terrascale", RunID: "100", Revision: strings.Repeat("b", 40), Image: spec.Image}
			older := *approved
			older.RunID = "99"
			for i, deployment := range []*Deployment{approved, &older} {
				if _, err := nodes[i].apply(t.Context(), ApplyRequest{Name: spec.Name, Entry: Entry{Generation: int64(10 - i), Spec: &spec, Deployment: deployment}}); err != nil {
					t.Fatal(err)
				}
			}
			operatorSpec := spec
			operatorSpec.Replicas = 2
			operator := Entry{Generation: 11, Spec: &operatorSpec}
			if removal {
				operator.Spec = nil
			}
			if _, err := nodes[1].apply(t.Context(), ApplyRequest{Name: spec.Name, Entry: operator}); err != nil {
				t.Fatal(err)
			}
			previous := spec
			previous.Image = "ghcr.io/terrascale/web@sha256:" + strings.Repeat("c", 64)
			rollback := ApplyRequest{Name: spec.Name, ExpectedGeneration: 10, Entry: Entry{Generation: 12, Spec: &previous, Deployment: approved}}
			if _, err := nodes[0].apply(t.Context(), rollback); err != nil {
				t.Fatal(err)
			}
			if _, err := nodes[1].apply(t.Context(), rollback); err == nil {
				t.Fatal("rollback overwrote the intervening operator entry")
			}
			selected, err := desiredEntries(t.Context(), nodes[0].conn)
			if entry := selected[spec.Name]; err != nil || entry.Generation != 11 || entry.Deployment != nil || entry.deploymentFloor() == nil || *entry.deploymentFloor() != *approved {
				t.Fatalf("release state read lost operator winner or highest floor: %+v, %v", entry, err)
			}
			if !removal {
				rows, err := releaseDeployment(t.Context(), nodes[0].conn, spec.Name, spec.Image, &older, time.Second, time.Second)
				if rows != nil || err == nil || !strings.Contains(err.Error(), "stale") {
					t.Fatalf("release preflight bypassed the losing rollback's floor: %+v, %v", rows, err)
				}
			}
			// B must save the losing rollback's higher floor; A must save the winning operator entry.
			for _, node := range []*Node{nodes[1], nodes[0]} {
				before, err := loadDesired(node.cfg.dir)
				if err != nil {
					t.Fatal(err)
				}
				running := node.cfg.applier.(*fakeApplier).generation(spec.Name)
				blocked := filepath.Join(node.cfg.dir, "desired.json.tmp"+strconv.Itoa(os.Getpid()))
				if err := os.Mkdir(blocked, 0o700); err != nil {
					t.Fatal(err)
				}
				node.sync(t.Context())
				node.mu.Lock()
				restored := reflect.DeepEqual(node.desired, before)
				node.mu.Unlock()
				if !restored || node.cfg.applier.(*fakeApplier).generation(spec.Name) != running {
					t.Fatal("failed sync save changed authority or reconciled unsaved state")
				}
				if err := os.Remove(blocked); err != nil {
					t.Fatal(err)
				}
				node.sync(t.Context())
			}
			for _, node := range nodes {
				reloaded, err := loadDesired(node.cfg.dir)
				if err != nil {
					t.Fatal(err)
				}
				entry := reloaded[spec.Name]
				if entry.Generation != 11 || !reflect.DeepEqual(entry.Spec, operator.Spec) || entry.Deployment != nil || entry.deploymentFloor() == nil || *entry.deploymentFloor() != *approved {
					t.Fatalf("%s did not converge durably: %+v", node.cfg.region, entry)
				}
				wantGeneration := int64(11)
				if removal {
					wantGeneration = 0
				}
				if got := node.cfg.applier.(*fakeApplier).generation(spec.Name); got != wantGeneration {
					t.Fatalf("%s runs %d, want %d", node.cfg.region, got, wantGeneration)
				}
				node.mu.Lock()
				node.desired = reloaded
				node.mu.Unlock()
				for _, mutate := range []func(*Deployment){
					func(d *Deployment) { d.RunID = "99" },
					func(d *Deployment) { d.Revision = strings.Repeat("d", 40) },
					func(d *Deployment) { d.Image = "ghcr.io/terrascale/web@sha256:" + strings.Repeat("d", 64) },
					func(d *Deployment) { d.Repository = "TerraScale/another" },
				} {
					stale := *approved
					mutate(&stale)
					candidate := Entry{Generation: 20, Spec: &spec, Deployment: &stale}
					if _, err := node.apply(t.Context(), ApplyRequest{Name: spec.Name, Entry: candidate}); err == nil {
						t.Fatal("reloaded floor accepted stale or equivocal release")
					}
					if merged := mergeEntry(entry, candidate); !reflect.DeepEqual(merged, entry) {
						t.Fatal("peer merge bypassed the signed-run floor")
					}
				}
			}
		})
	}
}

func TestRollbackSyncCatchesUpNodeThatMissedFailedRollout(t *testing.T) {
	spec := swarmruntime.ServiceSpec{Name: "web", Image: "ghcr.io/terrascale/web@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1}
	for _, previous := range []*swarmruntime.ServiceSpec{&spec, nil} {
		t.Run(fmt.Sprintf("removed=%t", previous == nil), func(t *testing.T) {
			nodes := stateTestNodes(t, "gru", "sjc")
			if _, err := nodes[0].apply(t.Context(), ApplyRequest{Name: spec.Name, Entry: Entry{Generation: 10, Spec: &spec}}); err != nil {
				t.Fatal(err)
			}
			if _, err := nodes[0].apply(t.Context(), ApplyRequest{Name: spec.Name, ExpectedGeneration: 10, Entry: Entry{Generation: 12, Spec: previous}}); err != nil {
				t.Fatal(err)
			}
			nodes[1].sync(t.Context())
			for _, node := range nodes {
				stored, err := loadDesired(node.cfg.dir)
				if err != nil || stored[spec.Name].Generation != 12 || stored[spec.Name].RollbackOf != 10 || !reflect.DeepEqual(stored[spec.Name].Spec, previous) {
					t.Fatalf("%s lost replicated rollback ancestry: %+v, %v", node.cfg.region, stored, err)
				}
			}
		})
	}
}

func TestFailedDesiredSaveCannotApplyOrAdvertiseUnsavedAuthority(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing=%t", existing), func(t *testing.T) {
			node := stateTestNodes(t, "gru")[0]
			spec := swarmruntime.ServiceSpec{Name: "web", Image: "ghcr.io/terrascale/web@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1}
			approved := &Deployment{Repository: "TerraScale/terrascale", RunID: "100", Revision: strings.Repeat("b", 40), Image: spec.Image}
			if existing {
				if _, err := node.apply(t.Context(), ApplyRequest{Name: spec.Name, Entry: Entry{Generation: 10, Spec: &spec, Deployment: approved}}); err != nil {
					t.Fatal(err)
				}
			}
			before, err := loadDesired(node.cfg.dir)
			if err != nil {
				t.Fatal(err)
			}
			// Block the atomic temporary file even when the test runs as root.
			blocked := filepath.Join(node.cfg.dir, "desired.json.tmp"+strconv.Itoa(os.Getpid()))
			if err := os.Mkdir(blocked, 0o700); err != nil {
				t.Fatal(err)
			}
			unsaved := *approved
			unsaved.RunID = "101"
			if _, err := node.apply(t.Context(), ApplyRequest{Name: spec.Name, Entry: Entry{Generation: 11, Spec: &spec, Deployment: &unsaved}}); err == nil {
				t.Fatal("apply ignored desired-state save failure")
			}
			node.sync(t.Context())
			if got := node.cfg.applier.(*fakeApplier).generation(spec.Name); got != before[spec.Name].Generation {
				t.Fatalf("sync applied unsaved generation %d", got)
			}
			message, err := node.conn.Request(StateSubject, nil, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			var advertised stateReply
			if err := protocol.DecodeTolerant(message.Data, &advertised, maxWire); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(advertised.Desired, before) {
				t.Fatalf("advertised unsaved authority: %+v", advertised.Desired)
			}
			reloaded, err := loadDesired(node.cfg.dir)
			if err != nil || !reflect.DeepEqual(reloaded, before) {
				t.Fatalf("reload changed durable authority: %+v, %v", reloaded, err)
			}
			if err := os.Remove(blocked); err != nil {
				t.Fatal(err)
			}
			if _, err := node.apply(t.Context(), ApplyRequest{Name: spec.Name, Entry: Entry{Generation: 11, Spec: &spec, Deployment: &unsaved}}); err != nil {
				t.Fatalf("retry after restoring persistence: %v", err)
			}
			reloaded, err = loadDesired(node.cfg.dir)
			if err != nil || reloaded[spec.Name].Generation != 11 || reloaded[spec.Name].Deployment == nil || reloaded[spec.Name].Deployment.RunID != "101" {
				t.Fatalf("successful retry did not persist authority: %+v, %v", reloaded, err)
			}
		})
	}
}
