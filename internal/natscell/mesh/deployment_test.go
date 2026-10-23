package mesh

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

func TestDeploymentFloorSurvivesRollbackAndOperatorApply(t *testing.T) {
	dir := t.TempDir()
	spec := swarmruntime.ServiceSpec{Name: "web", Image: "ghcr.io/terrascale/web@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1}
	approved := &Deployment{Repository: "TerraScale/terrascale", RunID: "100", Revision: strings.Repeat("b", 40), Image: spec.Image}
	node := &Node{cfg: config{dir: dir, region: "gru", applier: &fakeApplier{running: map[string]int64{}}},
		desired: map[string]Entry{}, peers: &peers{root: t.TempDir(), region: "gru", node: "gru-1", address: func() (string, error) { return "10.200.0.1", nil }}}
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
	if err != nil || restored[spec.Name].Deployment == nil || *restored[spec.Name].Deployment != *approved {
		t.Fatalf("persisted deployment watermark lost: %+v, %v", restored, err)
	}
}

func TestDeploymentFloorAcceptsOnlyNewerOrIdenticalRun(t *testing.T) {
	current := Deployment{Repository: "TerraScale/terrascale", RunID: "9", Revision: strings.Repeat("a", 40), Image: "ghcr.io/terrascale/web@sha256:" + strings.Repeat("b", 64)}
	for _, run := range []string{"9", "10"} {
		next := current
		next.RunID = run
		if err := acceptsDeployment(&current, &next); err != nil {
			t.Fatalf("run %s rejected: %v", run, err)
		}
	}
	next := current
	next.RunID = "18446744073709551616"
	if err := acceptsDeployment(&current, &next); err == nil {
		t.Fatal("overflowing run ID accepted")
	}
}

type evidenceApplier struct {
	fakeApplier
	revision string
	waiting  func(swarmruntime.ServiceSpec)
}

func (a *evidenceApplier) Wait(_ context.Context, spec swarmruntime.ServiceSpec) (swarmruntime.ServiceRollout, error) {
	if a.waiting != nil {
		a.waiting(spec)
	}
	return swarmruntime.ServiceRollout{Revision: a.revision, Tasks: []swarmruntime.ServiceTaskEvidence{{Machine: spec.Node, Image: spec.Image, Generation: spec.Generation, Ready: true}}}, nil
}

func TestMeshApplyChecksRevisionAndSupersededReadiness(t *testing.T) {
	ca, err := DeriveCA(bytes.Repeat([]byte{31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ports := freePorts(t, 2)
	applier := &evidenceApplier{fakeApplier: fakeApplier{running: map[string]int64{}}, revision: strings.Repeat("b", 40)}
	node, err := start(config{region: "gru", server: "gru-1", dir: t.TempDir(), host: "127.0.0.1",
		localPort: ports[0], gatewayPort: ports[1], ca: ca, applier: applier, peersDir: t.TempDir(), address: func() (string, error) { return "10.200.0.1", nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(node.Close)
	spec := swarmruntime.ServiceSpec{Name: "web", Image: "ghcr.io/terrascale/web@sha256:" + strings.Repeat("a", 64), Port: 8080, Replicas: 1}
	d := &Deployment{Repository: "TerraScale/terrascale", RunID: "100", Revision: applier.revision, Image: spec.Image}
	apply := func(generation int64) Reply {
		t.Helper()
		payload, err := protocol.EncodeJSON(ApplyRequest{Name: spec.Name, Entry: Entry{Generation: generation, Spec: &spec, Deployment: d}})
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
		if got.Generation != 10 || got.Region != "gru" || got.Node != "gru-1" {
			t.Error("readiness lost the requested target/generation")
		}
	}
	if reply := apply(10); reply.Error != "" || reply.Revision != d.Revision || len(reply.Tasks) != 1 || reply.Tasks[0].Generation != 10 {
		t.Fatalf("exact evidence: %+v", reply)
	}
	applier.waiting = nil
	applier.revision = strings.Repeat("c", 40)
	if reply := apply(11); !strings.Contains(reply.Error, "signed release commit") {
		t.Fatalf("unrelated image revision accepted: %+v", reply)
	}
	applier.revision = d.Revision
	applier.waiting = func(s swarmruntime.ServiceSpec) {
		node.mu.Lock()
		current := node.desired[s.Name]
		current.Generation++
		node.desired[s.Name] = current
		node.mu.Unlock()
	}
	if reply := apply(12); !strings.Contains(reply.Error, "superseded") {
		t.Fatalf("overlapping release reported successful readiness: %+v", reply)
	}
}
