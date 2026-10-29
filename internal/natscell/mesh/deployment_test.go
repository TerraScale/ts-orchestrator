package mesh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

func TestDeploymentFloorSurvivesRollbackAndOperatorApply(t *testing.T) {
	dir := t.TempDir()
	spec := swarmruntime.ServiceSpec{Name: "web", Image: "ghcr.io/terrascale/web@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1, Regions: []string{"gru"}}
	approved := &Deployment{Repository: "TerraScale/terrascale", RunID: "100", Revision: strings.Repeat("b", 40), Image: spec.Image}
	node := &Node{cfg: config{dir: dir, region: "gru", server: "gru-1", applier: &fakeApplier{running: map[string]int64{}}},
		desired: map[string]desiredState{}, peers: &peers{root: t.TempDir(), region: "gru", node: "gru-1", address: func() (string, error) { return "10.200.0.1", nil }}}
	apply := func(generation int64, deployment *Deployment, expected int64) error {
		_, err := node.apply(t.Context(), ApplyRequest{Name: spec.Name, ExpectedGeneration: expected,
			Entry: Entry{Generation: generation, Spec: &spec, Deployment: deployment}})
		return err
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := node.apply(cancelled, ApplyRequest{Name: spec.Name, Entry: Entry{Generation: 5, Spec: &spec, Deployment: approved}}); err == nil || len(node.desired) != 0 {
		t.Fatal("cancelled release changed desired state")
	}

	if err := apply(10, approved, 0); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Deployment){
		func(d *Deployment) { d.RunID = "99" },
		func(d *Deployment) { d.Image = "ghcr.io/terrascale/web@sha256:" + strings.Repeat("c", 64) },
		func(d *Deployment) { d.Revision = strings.Repeat("c", 40) },
		func(d *Deployment) { d.Repository = "TerraScale/another" },
	} {
		stale := *approved
		mutate(&stale)
		if err := apply(100, &stale, 0); err == nil {
			t.Fatal("stale or equivocal signed run replaced the approved deployment")
		}
	}
	// Rolling back the image retains the accepted signed-run watermark.
	spec.Image = "ghcr.io/terrascale/web@sha256:" + strings.Repeat("d", 64)
	if err := apply(11, approved, 10); err != nil {
		t.Fatal(err)
	}
	if err := apply(12, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := apply(13, approved, 11); err == nil {
		t.Fatal("rollback overwrote a later operator apply")
	}
	restored, err := loadDesired(dir)
	if err != nil || restored[spec.Name].entry().Deployment != nil || restored[spec.Name].Floor == nil || *restored[spec.Name].Floor != *approved {
		t.Fatalf("persisted deployment watermark lost: %+v, %v", restored, err)
	}
}

func TestDeploymentFloorAcceptsOnlyNewerOrIdenticalRun(t *testing.T) {
	current := Deployment{Repository: "TerraScale/terrascale", RunID: "9", Revision: strings.Repeat("a", 40), Image: "ghcr.io/terrascale/web@sha256:" + strings.Repeat("b", 64)}
	for _, run := range []string{"9", "10"} {
		next := current
		next.RunID = run
		if err := current.Accepts(&next); err != nil {
			t.Fatalf("run %s rejected: %v", run, err)
		}
	}
	next := current
	next.RunID = "18446744073709551616"
	if err := current.Accepts(&next); err == nil {
		t.Fatal("overflowing run ID accepted")
	}
}

func TestOlderRunIsSupersededOnlyWhileTheNewerRunServes(t *testing.T) {
	floor := Deployment{Repository: "TerraScale/ts-dashboard", RunID: "10", Revision: strings.Repeat("a", 40), Image: "ghcr.io/terrascale/web@sha256:" + strings.Repeat("b", 64)}
	older := floor
	older.RunID, older.Image = "9", "ghcr.io/terrascale/web@sha256:"+strings.Repeat("c", 64)
	serving := swarmruntime.ServiceSpec{Name: "web", Image: floor.Image, Port: 8080, Replicas: 1}
	if err := (desiredState{Signed: &Entry{Generation: 2, Spec: &serving, Deployment: &floor}, Floor: &floor}).accepts(&older); !errors.Is(err, swarmruntime.ErrSupersededDeployment) {
		t.Fatalf("older run beside a serving newer run: %v", err)
	}
	previous := serving
	previous.Image = "ghcr.io/terrascale/web@sha256:" + strings.Repeat("d", 64)
	err := (desiredState{Operator: &Entry{Generation: 3, Spec: &previous, RollbackOf: 2}, Floor: &floor}).accepts(&older)
	if err == nil || errors.Is(err, swarmruntime.ErrSupersededDeployment) || !strings.Contains(err.Error(), "re-run it") {
		t.Fatalf("older run beside a rolled-back newer run reported done: %v", err)
	}
}

func TestStateMergeRetainsCandidatesInEveryOrder(t *testing.T) {
	spec := swarmruntime.ServiceSpec{Name: "web", Image: "ghcr.io/terrascale/web@sha256:" + strings.Repeat("b", 64), Port: 8080, Replicas: 1}
	approved := &Deployment{Repository: "TerraScale/terrascale", RunID: "100", Revision: strings.Repeat("a", 40), Image: spec.Image}
	older := *approved
	older.RunID = "99"
	for _, removal := range []bool{false, true} {
		operator := stateFor(Entry{Generation: 11, Spec: &spec})
		operator.Floor = &older
		if removal {
			operator.Operator.Spec = nil
		}
		signed := stateFor(Entry{Generation: 13, Spec: &spec, Deployment: &older})
		rollback := stateFor(Entry{Generation: 12, RollbackOf: 10, Spec: &spec, Deployment: approved})
		states := []desiredState{operator, signed, rollback}
		want := desiredState{Operator: operator.Operator, Signed: rollback.Signed, Floor: approved}
		for _, order := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
			t.Run(fmt.Sprintf("removed=%t/order=%v", removal, order), func(t *testing.T) {
				dir := t.TempDir()
				var got desiredState
				for _, index := range order {
					var err error
					got, err = mergeState(got, states[index])
					if err != nil {
						t.Fatal(err)
					}
					if err := saveDesired(dir, map[string]desiredState{spec.Name: got}); err != nil {
						t.Fatal(err)
					}
					reloaded, err := loadDesired(dir)
					if err != nil {
						t.Fatal(err)
					}
					got = reloaded[spec.Name]
				}
				if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(got.entry(), *operator.Operator) {
					t.Fatalf("lost candidate or selected wrong authority: got %+v / %+v, want %+v", got, got.entry(), want)
				}
				right, err := mergeState(states[order[1]], states[order[2]])
				if err != nil {
					t.Fatal(err)
				}
				grouped, err := mergeState(states[order[0]], right)
				if err != nil || !reflect.DeepEqual(grouped, got) {
					t.Fatalf("merge is not associative: %+v, %v", grouped, err)
				}
				repeated, err := mergeState(got, got)
				if err != nil || !reflect.DeepEqual(repeated, got) {
					t.Fatalf("merge is not idempotent: %+v, %v", repeated, err)
				}
			})
		}
	}
}

func TestStateMergeRejectsEquivocationAndInvalidComponents(t *testing.T) {
	d := &Deployment{Repository: "TerraScale/terrascale", RunID: "100", Revision: strings.Repeat("a", 40), Image: "ghcr.io/terrascale/web@sha256:" + strings.Repeat("b", 64)}
	operator := stateFor(Entry{Generation: 11})
	operator.Floor = d
	for _, change := range []func(*Deployment){
		func(d *Deployment) { d.Revision = strings.Repeat("c", 40) },
		func(d *Deployment) { d.Image = "ghcr.io/terrascale/web@sha256:" + strings.Repeat("c", 64) },
		func(d *Deployment) { d.Repository = "TerraScale/another" },
	} {
		equivocal := *d
		change(&equivocal)
		other := stateFor(Entry{Generation: 20, Deployment: &equivocal})
		for _, pair := range [][2]desiredState{{operator, other}, {other, operator}} {
			got, err := mergeState(pair[0], pair[1])
			if err == nil || !reflect.DeepEqual(got, pair[0]) {
				t.Fatalf("equivocation changed state: %+v, %v", got, err)
			}
		}
	}
	for _, state := range []desiredState{{}, {Floor: d}, {Operator: new(Entry{Generation: 1, Deployment: d})}, {Signed: new(Entry{Generation: 1})}, {Signed: new(Entry{Generation: 1, Deployment: d})}} {
		if err := validState("web", state); err == nil {
			t.Fatalf("invalid components accepted: %+v", state)
		}
	}
	// Equal causal timestamps need the same winner in either direction.
	a, b := stateFor(Entry{Generation: 3}), stateFor(Entry{Generation: 3, Spec: &swarmruntime.ServiceSpec{Name: "web"}})
	ab, err := mergeState(a, b)
	if err != nil {
		t.Fatal(err)
	}
	ba, err := mergeState(b, a)
	if err != nil || !reflect.DeepEqual(ab, ba) {
		t.Fatalf("timestamp tie depends on reply order: %+v / %+v, %v", ab, ba, err)
	}
}

type evidenceApplier struct {
	fakeApplier
	revision    string
	waiting     func(swarmruntime.ServiceSpec)
	waitFailure error
}

func (a *evidenceApplier) Wait(_ context.Context, spec swarmruntime.ServiceSpec, _ *api.Service) (swarmruntime.ServiceRollout, error) {
	a.mu.Lock()
	unready := spec.Image == a.unready
	a.mu.Unlock()
	if unready {
		return swarmruntime.ServiceRollout{}, fmt.Errorf("test image not ready")
	}
	if a.waiting != nil {
		a.waiting(spec)
	}
	return swarmruntime.ServiceRollout{Revision: a.revision, Tasks: []swarmruntime.ServiceTaskEvidence{{Machine: spec.Node, Image: spec.Image, Generation: spec.Generation, Ready: true}}}, a.waitFailure
}

func TestMeshApplyChecksRevisionAndSupersededReadiness(t *testing.T) {
	ca, err := DeriveCA(bytes.Repeat([]byte{31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ports := freePorts(t, 2)
	applier := &evidenceApplier{fakeApplier: fakeApplier{running: map[string]int64{}}, revision: strings.Repeat("b", 40)}
	node, err := start(config{region: "gru", server: "gru-1", dir: t.TempDir(), clusterHost: "127.0.0.1",
		localPort: ports[0], clusterPort: ports[1], ca: ca, applier: applier, peersDir: t.TempDir(), address: func() (string, error) { return "10.200.0.1", nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(node.Close)
	spec := swarmruntime.ServiceSpec{Name: "web", Image: "ghcr.io/terrascale/web@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1, Regions: []string{"gru"}}
	d := &Deployment{Repository: "TerraScale/terrascale", RunID: "100", Revision: applier.revision, Image: spec.Image}
	apply := func(generation int64, deployment *Deployment) Reply {
		t.Helper()
		payload, err := protocol.EncodeJSON(ApplyRequest{Name: spec.Name, Entry: Entry{Generation: generation, Spec: &spec, Deployment: deployment}})
		if err != nil {
			t.Fatal(err)
		}
		message, err := node.conn.Request(ApplySubject, payload, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		var reply Reply
		if err := protocol.DecodeTolerant(message.Data, &reply, maxWire); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	applier.waiting = func(got swarmruntime.ServiceSpec) {
		if got.Generation != 10 || got.Region != "gru" || got.Node != "gru-1" || !reflect.DeepEqual(got.Deployment, d) || !reflect.DeepEqual(got.DeploymentFloor, d) {
			t.Error("readiness lost the requested target/generation")
		}
	}
	if reply := apply(10, d); reply.Error != "" || reply.Revision != d.Revision || len(reply.Tasks) != 1 || reply.Tasks[0].Generation != 10 {
		t.Fatalf("exact evidence: %+v", reply)
	}
	applier.waiting = nil
	applier.revision = strings.Repeat("c", 40)
	if reply := apply(11, d); !strings.Contains(reply.Error, "signed release commit") {
		t.Fatalf("unrelated image revision accepted: %+v", reply)
	}
	applier.revision = d.Revision
	applier.waiting = func(s swarmruntime.ServiceSpec) {
		node.mu.Lock()
		current := node.desired[s.Name]
		updated := *current.Signed
		updated.Generation++
		current.Signed = &updated
		node.desired[s.Name] = current
		node.mu.Unlock()
	}
	if reply := apply(12, d); !strings.Contains(reply.Error, "superseded") {
		t.Fatalf("overlapping release reported successful readiness: %+v", reply)
	}
	applier.waiting = func(got swarmruntime.ServiceSpec) {
		if got.Deployment != nil || !reflect.DeepEqual(got.DeploymentFloor, d) {
			t.Error("operator readiness confused inherited floor with signed authority")
		}
	}
	if reply := apply(14, nil); reply.Error != "" {
		t.Fatalf("operator readiness with inherited floor: %+v", reply)
	}
	applier.waiting = func(s swarmruntime.ServiceSpec) {
		node.mu.Lock()
		defer node.mu.Unlock()
		floor := *d
		floor.RunID = node.desired[s.Name].Floor.RunID + "1"
		current := node.desired[s.Name]
		current.Floor, current.Signed = &floor, nil
		node.desired[s.Name] = current
	}
	if reply := apply(15, nil); !strings.Contains(reply.Error, "superseded") {
		t.Fatalf("floor changed during readiness without being detected: %+v", reply)
	}
	applier.waitFailure = fmt.Errorf("requested service spec was superseded before metadata completion")
	if reply := apply(16, nil); reply.Error != swarmruntime.ErrSupersededDuringBake.Error() {
		t.Fatalf("metadata completion overlap lost #194's error: %+v", reply)
	}
}

func TestStateMergeAlgebraAndSignedCandidateSelection(t *testing.T) {
	spec := &swarmruntime.ServiceSpec{Name: "web", Image: "ghcr.io/terrascale/web@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1}
	older := &Deployment{Repository: "TerraScale/terrascale", RunID: "99", Revision: strings.Repeat("b", 40), Image: spec.Image}
	approved := *older
	approved.RunID = "100"
	rollout := stateFor(Entry{Generation: 10, Spec: spec, Deployment: &approved})
	rollback := stateFor(Entry{Generation: 12, RollbackOf: 10, Spec: spec, Deployment: &approved})
	states := []desiredState{{}, stateFor(Entry{Generation: 11, Spec: spec}), stateFor(Entry{Generation: 13, Spec: spec, Deployment: older}), rollout, rollback}
	for i, a := range states {
		for j, b := range states {
			ab, err := mergeState(a, b)
			if err != nil {
				t.Fatal(err)
			}
			ba, err := mergeState(b, a)
			if err != nil || !reflect.DeepEqual(ab, ba) {
				t.Fatalf("commutativity %d/%d: %+v / %+v, %v", i, j, ab, ba, err)
			}
			for k, c := range states {
				left, err := mergeState(ab, c)
				if err != nil {
					t.Fatal(err)
				}
				bc, err := mergeState(b, c)
				if err != nil {
					t.Fatal(err)
				}
				right, err := mergeState(a, bc)
				if err != nil || !reflect.DeepEqual(left, right) {
					t.Fatalf("associativity %d/%d/%d: %+v / %+v, %v", i, j, k, left, right, err)
				}
			}
		}
	}
	got, err := mergeState(rollout, rollback)
	if err != nil || !reflect.DeepEqual(got, rollback) {
		t.Fatalf("newest same-run rollback lost: %+v, %v", got, err)
	}
	got, err = mergeState(got, states[2])
	if err != nil || !reflect.DeepEqual(got, rollback) {
		t.Fatalf("higher-generation lower run regained authority: %+v, %v", got, err)
	}
}

func TestLoadDesiredPreservesRootOperatorRecords(t *testing.T) {
	spec := &swarmruntime.ServiceSpec{Name: "web", Image: "ghcr.io/terrascale/web@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1}
	for _, tc := range []struct {
		name string
		wire string
		spec *swarmruntime.ServiceSpec
	}{
		{"service", `{"web":{"generation":1,"spec":{"name":"web","image":"ghcr.io/terrascale/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","port":8080,"replicas":1}}}`, spec},
		{"removal", `{"web":{"generation":1,"spec":null}}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := writePrivate(filepath.Join(dir, "desired.json"), []byte(tc.wire)); err != nil {
				t.Fatal(err)
			}
			want := map[string]desiredState{"web": {Operator: new(Entry{Generation: 1, Spec: tc.spec})}}
			loaded, err := loadDesired(dir)
			if err != nil || !reflect.DeepEqual(loaded, want) {
				t.Fatalf("root operator record lost: %+v, %v", loaded, err)
			}
			if err := saveDesired(dir, loaded); err != nil {
				t.Fatal(err)
			}
			reloaded, err := loadDesired(dir)
			if err != nil || !reflect.DeepEqual(reloaded, want) {
				t.Fatalf("root operator record changed on reload: %+v, %v", reloaded, err)
			}
			data, err := os.ReadFile(filepath.Join(dir, "desired.json"))
			if err != nil {
				t.Fatal(err)
			}
			root, err := protocol.EncodeJSON(map[string]Entry{"web": {Generation: 1, Spec: tc.spec}})
			if err != nil || !bytes.Equal(data, root) {
				t.Fatalf("root operator schema changed: %s, %v", data, err)
			}
		})
	}
}

func TestDesiredStateSchemaRoundTrip(t *testing.T) {
	spec := &swarmruntime.ServiceSpec{Name: "web", Image: "ghcr.io/terrascale/web@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1}
	floor := &Deployment{Repository: "TerraScale/terrascale", RunID: "100", Revision: strings.Repeat("b", 40), Image: spec.Image}
	signed := new(Entry{Generation: 12, Spec: spec, Deployment: floor, RollbackOf: 10})
	for _, operator := range []*Entry{nil, new(Entry{Generation: 11, Spec: spec}), new(Entry{Generation: 11})} {
		t.Run(fmt.Sprintf("operator=%t/removal=%t", operator != nil, operator != nil && operator.Spec == nil), func(t *testing.T) {
			want := map[string]desiredState{"web": {Operator: operator, Signed: signed, Floor: floor}}
			dir := t.TempDir()
			if err := saveDesired(dir, want); err != nil {
				t.Fatal(err)
			}
			loaded, err := loadDesired(dir)
			if err != nil || !reflect.DeepEqual(loaded, want) {
				t.Fatalf("candidate state changed on reload: %+v, %v", loaded, err)
			}
			wire, err := protocol.EncodeJSON(stateReply{Region: "gru", Desired: loaded})
			if err != nil {
				t.Fatal(err)
			}
			var reply stateReply
			if err := protocol.DecodeStrict(wire, &reply, maxWire); err != nil || !reflect.DeepEqual(reply.Desired, want) {
				t.Fatalf("peer reply changed candidate state: %+v, %v", reply, err)
			}
			var fields struct {
				Region  string `json:"region"`
				Desired map[string]struct {
					Generation int64                     `json:"generation"`
					Spec       *swarmruntime.ServiceSpec `json:"spec"`
					Signed     *Entry                    `json:"signed"`
					Floor      *Deployment               `json:"floor"`
				} `json:"desired"`
			}
			if err := protocol.DecodeStrict(wire, &fields, maxWire); err != nil {
				t.Fatalf("peer reply changed the root operator/signed/floor schema: %s, %v", wire, err)
			}
			if operator != nil && (fields.Desired["web"].Generation != operator.Generation || !reflect.DeepEqual(fields.Desired["web"].Spec, operator.Spec)) {
				t.Fatalf("peer reply lost root operator fields: %s", wire)
			}
		})
	}
}

func TestLoadDesiredRejectsNullAndIncompleteCandidates(t *testing.T) {
	dir := t.TempDir()
	for _, wire := range []string{`null`, `{"web":null}`, `{"web":{}}`, `{"web":{"operator":null,"signed":null}}`, `{"web":{"generation":0,"spec":null}}`, `{"web":{"generation":-1,"spec":null}}`} {
		if err := writePrivate(filepath.Join(dir, "desired.json"), []byte(wire)); err != nil {
			t.Fatal(err)
		}
		if _, err := loadDesired(dir); err == nil {
			t.Fatalf("invalid persisted candidates accepted: %s", wire)
		}
	}
	if err := writePrivate(filepath.Join(dir, "desired.json"), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if state, err := loadDesired(dir); err != nil || state == nil || len(state) != 0 {
		t.Fatalf("empty desired map rejected: %+v, %v", state, err)
	}
}
