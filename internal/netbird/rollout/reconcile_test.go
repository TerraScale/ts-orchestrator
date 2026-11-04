package rollout

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
)

type rolloutFixture struct {
	t             *testing.T
	now           time.Time
	journal       []byte
	statuses      map[string]Status
	previous      map[string]string
	drained       map[string]bool
	healthError   map[string]error
	returnError   map[string]error
	actionError   map[string]string
	effects       []string
	commands      []Command
	nodes         []string
	confirmClears bool
	deferActions  bool
	loseReply     string
}

func rolloutTarget(version string) Target {
	target := Target{Pin: client.Pin{Version: version}, Enrollment: netbird.Config{ManagementURL: netbird.DefaultManagementURL,
		Region: netbird.DefaultRegion, SetupKeySecretID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.aaaaaaaa.testsecret",
		PeerNames: map[string]string{"10.251.0.11": "gru-1-ctl-1", "10.251.0.12": "gru-1-ctl-2", "10.251.0.13": "gru-1-ctl-3"}}}
	archive := func(arch string) client.Archive {
		return client.Archive{URL: fmt.Sprintf("https://github.com/netbirdio/netbird/releases/download/v%s/netbird_%s_linux_%s.tar.gz", version, version, arch),
			Bytes: 100, SHA256: strings.Repeat("a", 64), BinarySHA256: strings.Repeat("b", 64)}
	}
	target.Pin.Archives.Arm64, target.Pin.Archives.AMD64 = archive("arm64"), archive("amd64")
	return target
}

func newRolloutFixture(t *testing.T) *rolloutFixture {
	t.Helper()
	f := &rolloutFixture{t: t, now: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC),
		statuses: map[string]Status{}, previous: map[string]string{}, drained: map[string]bool{},
		healthError: map[string]error{}, returnError: map[string]error{}, actionError: map[string]string{}, nodes: []string{"gru-1-ctl-1", "gru-1-ctl-2", "gru-1-ctl-3"}}
	for i, node := range f.nodes {
		f.statuses[node] = Status{Version: "0.79.0", Connected: true, IP: fmt.Sprintf("100.87.0.%d", i+1), DNS: node + ".nb.ts.internal"}
		f.previous[node] = "0.79.0"
	}
	return f
}

func (f *rolloutFixture) record() Record {
	f.t.Helper()
	var record Record
	if len(f.journal) != 0 {
		if err := json.Unmarshal(f.journal, &record, json.RejectUnknownMembers(true)); err != nil {
			f.t.Fatal(err)
		}
	}
	return record
}

// Every tick gets a fresh reconciler. Only serialized journal bytes and node
// observations survive, as they do when another controller becomes leader.
func (f *rolloutFixture) reconciler() *Reconciler {
	return &Reconciler{
		Now:  func() time.Time { return f.now },
		Load: func(context.Context) (Record, error) { return f.record(), nil },
		Save: func(_ context.Context, record Record) error {
			wire, err := json.Marshal(record)
			if err == nil {
				f.journal = wire
			}
			return err
		},
		Status: func(_ context.Context, node string) (Status, error) {
			status := f.statuses[node]
			status.ObservedAt = f.now
			return status, nil
		},
		Preflight: func(_ context.Context, node string) error {
			f.effects = append(f.effects, "preflight:"+node)
			return nil
		},
		Drain: func(_ context.Context, node string) error {
			for other, drained := range f.drained {
				if drained && other != node {
					f.t.Fatalf("drained %s while %s is still drained", node, other)
				}
			}
			f.drained[node] = true
			f.effects = append(f.effects, "drain:"+node)
			return nil
		},
		Healthy: func(_ context.Context, node string, status Status, _ time.Time) error {
			if err := f.healthError[node]; err != nil {
				return err
			}
			if !status.Connected || status.IP == "" || status.DNS == "" {
				return errors.New("mesh and application probes failed")
			}
			return nil
		},
		Return: func(_ context.Context, node string) error {
			// Restored absence needs ordinary role/LB return checks, not mesh.
			if !f.statuses[node].Missing && (f.healthError[node] != nil || !f.statuses[node].Connected) {
				f.t.Fatalf("returned unhealthy node %s", node)
			}
			f.drained[node] = false
			f.effects = append(f.effects, "return:"+node)
			return f.returnError[node]
		},
		Send: func(_ context.Context, node string, command Command) error {
			if !f.drained[node] {
				f.t.Fatalf("sent %s to serving node %s without a drain", command.Action, node)
			}
			record := f.record()
			if !entityid.Valid(record.ID) || !entityid.Valid(command.ID) || command.ID != CommandID(record.ID, command.Action) {
				f.t.Fatalf("invalid transaction/command identity: %+v %+v", record, command)
			}
			if record.Node != node || record.ID != command.Transaction || !reflect.DeepEqual(record.Target, command.Target) {
				f.t.Fatalf("effect did not use persisted transaction: %#v %#v", record, command)
			}
			f.commands = append(f.commands, command)
			f.effects = append(f.effects, command.Action+":"+node)
			if !f.deferActions {
				f.apply(node, command)
			}
			if f.loseReply == command.Action {
				f.loseReply = ""
				return errors.New("controller lost the worker response")
			}
			return nil
		},
	}
}

func (f *rolloutFixture) apply(node string, command Command) {
	status := f.statuses[node]
	status.ActionID, status.Error = command.ID, f.actionError[command.Action]
	switch command.Action {
	case "install":
		status.Version, status.Pending = command.Target.Pin.Version, command.Transaction
		status.Missing = false
	case "confirm":
		if status.Error == "" || f.confirmClears {
			status.Pending = ""
		}
		if status.Error == "" {
			status.AppliedTargetHash = Hash(command.Target)
		}
	case "rollback":
		if status.Error == "" {
			status.Version, status.Pending, status.AppliedTargetHash = f.previous[node], "", ""
			status.Missing = status.Version == ""
			if status.Missing {
				status.Connected, status.IP, status.DNS = false, "", ""
			}
		}
	}
	f.statuses[node] = status
}

func (f *rolloutFixture) tick(target Target) error {
	return f.reconciler().Tick(f.t.Context(), target, f.nodes)
}

func (f *rolloutFixture) advance(target Target, phase string) {
	f.t.Helper()
	for range 24 {
		if f.record().Phase == phase {
			return
		}
		if err := f.tick(target); err != nil {
			f.t.Fatalf("advance to %s failed in %s: %v", phase, f.record().Phase, err)
		}
	}
	f.t.Fatalf("did not reach %s; record=%#v effects=%v", phase, f.record(), f.effects)
}

func TestRolloutDrainsAndConfirmsOneNodeBeforeSelectingAnother(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "check")
	first := f.record().Node
	if first != f.nodes[0] || !f.drained[first] || f.statuses[f.nodes[1]].Version != "0.79.0" {
		t.Fatalf("more than the first node changed: record=%#v statuses=%#v", f.record(), f.statuses)
	}
	if slices.Index(f.effects, "drain:"+first) >= slices.Index(f.effects, "install:"+first) {
		t.Fatalf("installation preceded drain: %v", f.effects)
	}
	f.advance(target, "done")
	if f.drained[first] || f.statuses[first].Pending != "" {
		t.Fatal("completed node remained drained or unconfirmed")
	}
	if err := f.tick(target); err != nil {
		t.Fatal(err)
	}
	if f.record().Node != f.nodes[1] || f.record().Phase != "drain" {
		t.Fatalf("next node was not selected after confirmed return: %#v", f.record())
	}
}

func TestFailedMeshHealthRollsBackAndKeepsDrainUntilPreviousBinaryIsHealthy(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "check")
	node := f.record().Node
	f.healthError[node] = errors.New("TerraBase is unavailable over mesh")
	if err := f.tick(target); err == nil || !f.drained[node] {
		t.Fatalf("failed health released the node: drained=%t error=%v", f.drained[node], err)
	}
	f.now = f.record().Deadline.Add(time.Second)
	f.advance(target, "rollback-check")
	if f.statuses[node].Version != "0.79.0" || f.statuses[node].Pending != "" {
		t.Fatalf("previous binary not restored: %#v", f.statuses[node])
	}
	if err := f.tick(target); err != nil || !f.drained[node] || f.record().Phase != "rollback-check" {
		t.Fatalf("unhealthy rollback released drain: %#v %v", f.record(), err)
	}
	delete(f.healthError, node)
	f.advance(target, "failed")
	if f.drained[node] {
		t.Fatal("healthy rollback was not returned")
	}
	before := len(f.effects)
	if err := f.tick(target); err == nil || len(f.effects) != before || f.statuses[f.nodes[1]].Version != "0.79.0" {
		t.Fatalf("failed pin continued to another node: %v %v", f.effects, err)
	}
	if err := f.tick(rolloutTarget("0.80.1")); err != nil || f.record().Phase != "drain" {
		t.Fatalf("recovered rollback did not permit an explicit new pin: %#v %v", f.record(), err)
	}
}
