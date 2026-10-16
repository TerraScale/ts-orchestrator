package rollout

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type rolloutFixture struct {
	t             *testing.T
	now           time.Time
	storeDir      string
	broker        *server.Server
	connection    *nats.Conn
	workerHandled chan struct{}
	kv            jetstream.KeyValue
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
	f := &rolloutFixture{t: t, workerHandled: make(chan struct{}, 1), storeDir: t.TempDir(), now: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC),
		statuses: map[string]Status{}, previous: map[string]string{}, drained: map[string]bool{},
		healthError: map[string]error{}, returnError: map[string]error{}, actionError: map[string]string{}, nodes: []string{"gru-1-ctl-1", "gru-1-ctl-2", "gru-1-ctl-3"}}
	for i, node := range f.nodes {
		f.statuses[node] = Status{Version: "0.79.0", Connected: true, IP: fmt.Sprintf("100.87.0.%d", i+1), DNS: node + ".nb.ts.internal"}
		f.previous[node] = "0.79.0"
	}
	t.Cleanup(func() {
		if f.connection != nil {
			f.connection.Close()
		}
		if f.broker != nil {
			f.broker.Shutdown()
			f.broker.WaitForShutdown()
		}
	})
	f.startBroker()
	return f
}

func (f *rolloutFixture) journalBytes() []byte {
	f.t.Helper()
	entry, err := f.kv.Get(f.t.Context(), "current")
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return entry.Value()
}

func (f *rolloutFixture) loadRecord(ctx context.Context) (Record, error) {
	entry, err := f.kv.Get(ctx, "current")
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return Record{}, nil
	}
	if err != nil {
		return Record{}, err
	}
	var record Record
	err = json.Unmarshal(entry.Value(), &record, json.RejectUnknownMembers(true))
	return record, err
}

func (f *rolloutFixture) record() Record {
	f.t.Helper()
	var record Record
	if wire := f.journalBytes(); len(wire) != 0 {
		if err := json.Unmarshal(wire, &record, json.RejectUnknownMembers(true)); err != nil {
			f.t.Fatal(err)
		}
	}
	return record
}

// The simulator keeps node observations outside the regional broker, as independent workers do.
func (f *rolloutFixture) worker() *Reconciler {
	return &Reconciler{
		Now:  func() time.Time { return f.now },
		Load: f.loadRecord,
		Save: func(ctx context.Context, record Record) error {
			wire, err := json.Marshal(record)
			if err == nil {
				_, err = f.kv.Put(ctx, "current", wire)
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

func TestLateMeshHealthGetsASeparateConfirmationWindow(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "check")
	f.now = f.record().Deadline.Add(-time.Second)
	r := f.reconciler()
	healthy := r.Healthy
	r.Healthy = func(ctx context.Context, node string, status Status, since time.Time) error {
		f.now = f.now.Add(2 * time.Second)
		return healthy(ctx, node, status, since)
	}
	if err := r.Tick(t.Context(), target, f.nodes); err != nil {
		t.Fatal(err)
	}
	if record := f.record(); record.Phase != "confirm" || !record.Deadline.Equal(f.now.Add(2*time.Minute)) {
		t.Fatalf("late health did not start a fresh confirmation window: %+v", record)
	}
	f.now = f.now.Add(2 * time.Second)
	if err := f.tick(target); err != nil {
		t.Fatal(err)
	}
	if record := f.record(); record.Phase != "confirm" || f.commands[len(f.commands)-1].Action != "confirm" {
		t.Fatalf("healthy agent rolled back before confirmation was sent: %+v commands=%v", record, f.commands)
	}
}

func TestRolloutIntegrationValidatesObservedVersionsBeforePersistingIntent(t *testing.T) {
	for _, version := range []string{"v0.80.0", " 0.80.0 ", "0.80.9", "0.80.10", "", "0.80", "0.80.0-rc.1", "0.080.0", "0.80.-1", "0.80.4294967296"} {
		t.Run(version, func(t *testing.T) {
			f := newRolloutFixture(t)
			target := rolloutTarget("0.80.0")
			for node, status := range f.statuses {
				status.Version = version
				status.AppliedTargetHash = Hash(target)
				f.statuses[node] = status
			}
			err := f.tick(target)
			valid := version == "v0.80.0" || version == " 0.80.0 " || version == "0.80.9" || version == "0.80.10" || version == ""
			if valid != (err == nil) {
				t.Fatalf("observed version %q: %v", version, err)
			}
			if !valid && len(f.journalBytes()) != 0 {
				t.Fatal("invalid worker version persisted rollout")
			}
		})
	}
}

func TestRolloutIntegrationEquivalentTargetSurvivesPersistedRoundTrip(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "done")
	first := f.record()
	for node, status := range f.statuses {
		status.Version = target.Pin.Version
		status.AppliedTargetHash = first.PinHash
		f.statuses[node] = status
	}
	equivalent := rolloutTarget("0.80.0")
	equivalent.Enrollment.PeerNames = map[string]string{"10.251.0.13": "gru-1-ctl-3", "10.251.0.11": "gru-1-ctl-1", "10.251.0.12": "gru-1-ctl-2"}
	before := len(f.effects)
	if err := f.tick(equivalent); err != nil || f.record().ID != first.ID || len(f.effects) != before {
		t.Fatalf("equivalent target repeated rollout: %v", err)
	}
	if err := f.tick(rolloutTarget("0.80.1")); err != nil || f.record().ID == first.ID {
		t.Fatalf("changed target failed to start: %v", err)
	}
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

func TestPostConfirmationMeshFailureRollsBackBeforeAnotherNode(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "return")
	node := f.record().Node
	f.healthError[node] = errors.New("mesh failed after confirmation")
	if err := f.tick(target); err == nil || !f.drained[node] {
		t.Fatal("post-confirmation failure did not hold the node drained")
	}
	f.now = f.record().Deadline.Add(time.Second)
	if err := f.tick(target); err != nil || f.record().Phase != "rollback" {
		t.Fatalf("failed return did not initiate rollback: phase=%s error=%v", f.record().Phase, err)
	}
	delete(f.healthError, node)
	f.advance(target, "failed")
	if f.statuses[node].Version != "0.79.0" || f.drained[node] || f.statuses[f.nodes[1]].Version != "0.79.0" {
		t.Fatal("rollback did not recover the previous agent before another node")
	}
}

func TestFailedLBReturnReDrainsBeforeRollback(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "return")
	node := f.record().Node
	f.returnError[node] = errors.New("LB health failed after backends returned")
	if err := f.tick(target); err == nil || !f.drained[node] {
		t.Fatal("failed LB return was not immediately re-drained")
	}
	f.now = f.record().Deadline.Add(time.Second)
	if err := f.tick(target); err != nil || f.record().Phase != "rollback" {
		t.Fatalf("failed LB return did not initiate rollback: %v", err)
	}
	if err := f.tick(target); err != nil || !f.drained[node] || f.statuses[node].Version != "0.79.0" {
		t.Fatalf("rollback restarted an undrained node: %v", err)
	}
	f.now = f.record().Deadline.Add(time.Second)
	if err := f.tick(target); err != nil || f.record().Phase != "failed" || !f.drained[node] {
		t.Fatalf("failed rollback return did not hold node drained: record=%+v error=%v", f.record(), err)
	}
}

func returnPhaseFixture(t *testing.T, phase string) (*rolloutFixture, Target) {
	t.Helper()
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	if phase == "return" {
		f.advance(target, phase)
	} else {
		f.advance(target, "install")
		f.now = f.record().Deadline.Add(time.Second)
		f.advance(target, phase)
	}
	return f, target
}

func TestReturnPhasesReDrainBeforeDeadlineAndRetryFailedDrain(t *testing.T) {
	for _, phase := range []string{"return", "rollback-check"} {
		for _, failDrain := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/drain-fails=%t", phase, failDrain), func(t *testing.T) {
				f, target := returnPhaseFixture(t, phase)
				node := f.record().Node
				returnErr, drainErr := errors.New("LB health failed"), errors.New("drain quorum unavailable")
				f.returnError[node] = returnErr
				r := f.reconciler()
				if failDrain {
					r.Drain = func(context.Context, string) error { return drainErr }
				}
				if err := r.Tick(t.Context(), target, f.nodes); (err == nil || !strings.Contains(err.Error(), returnErr.Error())) ||
					failDrain && !errors.Is(err, drainErr) || f.drained[node] == failDrain ||
					f.record().RecoveryReturning != failDrain || f.record().RecoveryComplete || f.record().Phase != phase {
					t.Fatalf("failed return lost its fence or retry intent: record=%+v effects=%v error=%v", f.record(), f.effects, err)
				}
				r = f.reconciler()
				r.Status = func(context.Context, string) (Status, error) {
					if !f.drained[node] {
						t.Fatal("recovery observed status before re-draining failed return")
					}
					return Status{}, errors.New("worker became unavailable")
				}
				_ = r.Tick(t.Context(), rolloutTarget("0.80.1"), f.nodes)
				if !f.drained[node] || f.record().RecoveryReturning || f.record().RecoveryComplete || f.record().Phase != phase {
					t.Fatalf("failed observation abandoned return recovery: record=%+v effects=%v", f.record(), f.effects)
				}
			})
		}
	}
}

func TestReturnPhasesReDrainInterruptedReturnBeforeHealth(t *testing.T) {
	for _, phase := range []string{"return", "rollback-check"} {
		t.Run(phase, func(t *testing.T) {
			f, target := returnPhaseFixture(t, phase)
			node := f.record().Node
			r := f.reconciler()
			save := r.Save
			completionErr := errors.New("leader lost completion journal")
			r.Save = func(ctx context.Context, record Record) error {
				if record.Phase != phase {
					return completionErr
				}
				return save(ctx, record)
			}
			if err := r.Tick(t.Context(), target, f.nodes); !errors.Is(err, completionErr) || f.drained[node] ||
				!f.record().RecoveryReturning || f.record().Phase != phase || f.record().RecoveryComplete {
				t.Fatalf("interrupted return lost its durable intent: record=%+v error=%v", f.record(), err)
			}
			before := len(f.effects)
			r = f.reconciler()
			r.Healthy = func(context.Context, string, Status, time.Time) error {
				if !f.drained[node] {
					t.Fatal("new leader checked recovery health before re-draining")
				}
				return errors.New("mesh became unhealthy")
			}
			_ = r.Tick(t.Context(), target, f.nodes)
			if !f.drained[node] || f.record().RecoveryReturning || f.record().RecoveryComplete ||
				f.record().Phase != phase || f.effects[before] != "drain:"+node {
				t.Fatalf("new leader abandoned interrupted return: record=%+v effects=%v", f.record(), f.effects)
			}
		})
	}
}

func TestMatchingPinSkipsDrainAndInvalidDaemonVersionHolds(t *testing.T) {
	target := rolloutTarget("0.80.0")
	f := newRolloutFixture(t)
	for node, status := range f.statuses {
		status.Version = "v0.80.0"
		status.AppliedTargetHash = Hash(target)
		f.statuses[node] = status
	}
	if err := f.tick(target); err != nil || len(f.effects) != 0 || len(f.journalBytes()) != 0 {
		t.Fatalf("matching daemon versions caused effects: %v %v", f.effects, err)
	}
	status := f.statuses[f.nodes[0]]
	status.Version = "garbled"
	f.statuses[f.nodes[0]] = status
	if err := f.tick(target); err == nil || len(f.effects) != 0 {
		t.Fatalf("invalid observed version authorized a rollout: %v %v", f.effects, err)
	}
}

func TestSameVersionNeedsTheCompleteAppliedTarget(t *testing.T) {
	for _, change := range []string{"unproven", "binary", "enrollment"} {
		t.Run(change, func(t *testing.T) {
			f := newRolloutFixture(t)
			before, target := rolloutTarget("0.80.0"), rolloutTarget("0.80.0")
			for node, status := range f.statuses {
				status.Version, status.AppliedTargetHash = before.Pin.Version, Hash(before)
				if change == "unproven" {
					status.AppliedTargetHash = ""
				}
				f.statuses[node] = status
			}
			switch change {
			case "binary":
				target.Pin.Archives.Arm64.BinarySHA256 = strings.Repeat("c", 64)
			case "enrollment":
				target.Enrollment.SetupKeySecretID = "ocid1.vaultsecret.oc1.sa-saopaulo-1.aaaaaaaa.changedsecret"
			}
			f.advance(target, "done")
			node := f.record().Node
			if node != f.nodes[0] || f.statuses[node].AppliedTargetHash != Hash(target) ||
				len(f.commands) == 0 || f.commands[0].Action != "install" || !reflect.DeepEqual(f.commands[0].Target, target) {
				t.Fatalf("same-version target was skipped or incompletely applied: record=%+v status=%+v commands=%+v", f.record(), f.statuses[node], f.commands)
			}
			if err := f.tick(target); err != nil || f.record().Node != f.nodes[1] || f.record().Phase != "drain" {
				t.Fatalf("same-version change did not continue one node at a time: record=%+v error=%v", f.record(), err)
			}
		})
	}
}

func TestRollbackWaitsForAnAcknowledgedEffectInsteadOfFreshPreinstallStatus(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "install")
	node := f.record().Node
	f.deferActions = true
	if err := f.tick(target); err != nil {
		t.Fatal(err)
	}
	install := f.commands[0]
	f.now = f.record().Deadline.Add(time.Second)
	f.advance(target, "rollback-check")
	// Sending a command only persists it. The worker can keep publishing fresh,
	// healthy pre-install observations while installation is still queued.
	if err := f.tick(target); err != nil || f.record().Phase != "rollback-check" || !f.drained[node] || slices.Contains(f.effects, "return:"+node) {
		t.Fatalf("fresh old status returned a node before rollback was applied: record=%+v effects=%v error=%v", f.record(), f.effects, err)
	}
	// An install already read by the worker can finish after rollback was sent.
	f.apply(node, install)
	if err := f.tick(target); err != nil || f.record().Phase != "rollback-check" || !f.drained[node] {
		t.Fatalf("late installation released the rollback fence: record=%+v error=%v", f.record(), err)
	}
	rollback := f.commands[len(f.commands)-1]
	f.apply(node, rollback)
	if err := f.tick(target); err != nil || f.record().Phase != "failed" || f.drained[node] {
		t.Fatalf("successful acknowledged rollback did not return the recovered node: record=%+v status=%+v error=%v", f.record(), f.statuses[node], err)
	}
}

func TestRollbackAcknowledgmentWithAnErrorKeepsTheFence(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "install")
	f.deferActions = true
	f.now = f.record().Deadline.Add(time.Second)
	f.advance(target, "rollback-check")
	node := f.record().Node
	status := f.statuses[node]
	status.ActionID, status.Error = CommandID(f.record().ID, "rollback"), "previous binary restart failed"
	f.statuses[node] = status
	if err := f.tick(target); err != nil || f.record().Phase != "rollback-check" || !f.drained[node] || slices.Contains(f.effects, "return:"+node) {
		t.Fatalf("errored rollback acknowledgment returned the node: record=%+v effects=%v error=%v", f.record(), f.effects, err)
	}
}

func TestFailedRollbackKeepsAcknowledgmentRequirementAcrossPinChanges(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "install")
	f.deferActions = true
	f.now = f.record().Deadline.Add(time.Second)
	f.advance(target, "rollback-check")
	f.now = f.record().Deadline.Add(time.Second)
	f.advance(target, "failed")
	failed := f.record()
	if failed.RollbackRequired == nil || !*failed.RollbackRequired {
		t.Fatal("failed rollback lost its persisted acknowledgment requirement")
	}
	node := failed.Node
	before := len(f.effects)
	changed := rolloutTarget("0.80.1")
	if err := f.tick(changed); err == nil || len(f.effects) != before || !f.drained[node] || f.record().ID != failed.ID {
		t.Fatalf("pin change released a rollback the worker never applied: record=%+v effects=%v error=%v", f.record(), f.effects, err)
	}
	f.apply(node, f.commands[len(f.commands)-1])
	if err := f.tick(changed); err != nil || f.drained[node] || f.record().Phase != "drain" || f.record().ID == failed.ID {
		t.Fatalf("acknowledged recovered rollback did not allow the new target: record=%+v status=%+v error=%v", f.record(), f.statuses[node], err)
	}
}

func TestFailedSamePinRecoversFenceWithoutRetryingThePin(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "install")
	f.deferActions = true
	f.now = f.record().Deadline.Add(time.Second)
	f.advance(target, "rollback-check")
	f.now = f.record().Deadline.Add(time.Second)
	f.advance(target, "failed")
	failed := f.record()
	before := len(f.effects)
	if err := f.tick(target); err == nil || f.record().RecoveryComplete || !f.drained[failed.Node] || len(f.effects) != before {
		t.Fatalf("same pin abandoned unacknowledged rollback: record=%+v effects=%v error=%v", f.record(), f.effects, err)
	}
	f.apply(failed.Node, f.commands[len(f.commands)-1])
	if err := f.tick(target); err == nil || !f.record().RecoveryComplete || f.drained[failed.Node] || f.record().ID != failed.ID {
		t.Fatalf("repaired worker did not release its fence while keeping pin held: record=%+v effects=%v error=%v", f.record(), f.effects, err)
	}
	before = len(f.effects)
	if err := f.tick(target); err == nil || len(f.effects) != before || f.record().ID != failed.ID {
		t.Fatalf("completed recovery returned or retried again: record=%+v effects=%v error=%v", f.record(), f.effects, err)
	}
}

func TestFailedRecoveryPersistsCompletionAfterReturnSucceeds(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "install")
	record := f.record()
	record.Phase, record.RollbackRequired = "failed", new(true)
	if err := f.reconciler().Save(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	status := f.statuses[record.Node]
	status.ActionID = CommandID(record.ID, "rollback")
	f.statuses[record.Node] = status
	f.returnError[record.Node] = errors.New("LB return incomplete")
	if err := f.tick(target); (err == nil || !strings.Contains(err.Error(), f.returnError[record.Node].Error())) || f.record().RecoveryComplete || !f.drained[record.Node] {
		t.Fatalf("failed Return did not preserve the fence: record=%+v effects=%v error=%v", f.record(), f.effects, err)
	}
	if got := f.effects[len(f.effects)-2:]; !slices.Equal(got, []string{"return:" + record.Node, "drain:" + record.Node}) {
		t.Fatalf("failed Return was not immediately re-drained: %v", got)
	}
	f.healthError[record.Node] = errors.New("recovered agent became unhealthy")
	before := len(f.effects)
	if err := f.tick(rolloutTarget("0.80.1")); err == nil || !f.drained[record.Node] || f.record().RecoveryComplete || len(f.effects) != before {
		t.Fatalf("unhealthy recovery after failed Return released the fence: record=%+v error=%v", f.record(), err)
	}
	delete(f.healthError, record.Node)
	delete(f.returnError, record.Node)
	r := f.reconciler()
	save := r.Save
	r.Save = func(ctx context.Context, record Record) error {
		if record.RecoveryComplete {
			return errors.New("leader lost authority before recovery journal")
		}
		return save(ctx, record)
	}
	if err := r.Tick(t.Context(), target, f.nodes); err == nil || f.record().RecoveryComplete {
		t.Fatalf("lost recovery journal disabled future recovery: record=%+v error=%v", f.record(), err)
	}
	before = len(f.effects)
	if err := f.tick(target); err == nil || !f.record().RecoveryComplete {
		t.Fatalf("new leader did not persist the successful return: record=%+v error=%v", f.record(), err)
	}
	if got := f.effects[before:]; !slices.Equal(got, []string{"drain:" + record.Node, "return:" + record.Node}) {
		t.Fatalf("new leader did not fence the interrupted return before retry: %v", got)
	}
}

func TestFailedRecoveryRetriesDrainBeforeUnhealthyStatus(t *testing.T) {
	for _, observation := range []string{"status", "health"} {
		t.Run(observation, func(t *testing.T) {
			f := newRolloutFixture(t)
			target := rolloutTarget("0.80.0")
			f.advance(target, "install")
			record := f.record()
			record.Phase, record.RollbackRequired = "failed", new(true)
			if err := f.reconciler().Save(t.Context(), record); err != nil {
				t.Fatal(err)
			}
			status := f.statuses[record.Node]
			status.ActionID = CommandID(record.ID, "rollback")
			f.statuses[record.Node] = status
			returnErr, drainErr := errors.New("LB health check failed"), errors.New("quorum unavailable")
			f.returnError[record.Node] = returnErr
			r := f.reconciler()
			r.Drain = func(context.Context, string) error { return drainErr }
			if err := r.Tick(t.Context(), target, f.nodes); (err == nil || !strings.Contains(err.Error(), returnErr.Error())) || !errors.Is(err, drainErr) ||
				!f.record().RecoveryReturning || f.record().RecoveryComplete || f.drained[record.Node] {
				t.Fatalf("failed re-drain lost retry intent: record=%+v error=%v", f.record(), err)
			}
			before := len(f.effects)
			r = f.reconciler()
			if observation == "status" {
				r.Status = func(context.Context, string) (Status, error) { return Status{}, errors.New("worker unavailable") }
			} else {
				f.healthError[record.Node] = errors.New("mesh unhealthy")
			}
			if err := r.Tick(t.Context(), rolloutTarget("0.80.1"), f.nodes); err == nil || !f.drained[record.Node] ||
				f.record().RecoveryReturning || f.record().RecoveryComplete || f.record().ID != record.ID {
				t.Fatalf("unhealthy recovery blocked re-drain retry: record=%+v error=%v", f.record(), err)
			}
			if got := f.effects[before:]; !slices.Equal(got, []string{"drain:" + record.Node}) {
				t.Fatalf("recovery did not retry only the held-node drain: %v", got)
			}
		})
	}
}

func TestDrainTimeoutWithoutMutationNeedsNoRollbackAcknowledgment(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "drain")
	f.now = f.record().Deadline.Add(time.Second)
	f.advance(target, "failed")
	record := f.record()
	if record.RollbackRequired == nil || *record.RollbackRequired || len(f.commands) != 0 {
		t.Fatal("a pre-install timeout unexpectedly required a worker rollback")
	}
	if err := f.tick(rolloutTarget("0.80.1")); err != nil || f.record().Phase != "drain" {
		t.Fatalf("no-mutation timeout could not be retried: record=%+v error=%v", f.record(), err)
	}
}

func TestDrainGraceDoesNotConsumeInstallationAcknowledgmentWindow(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "drain")
	r := f.reconciler()
	drain := r.Drain
	r.Drain = func(ctx context.Context, node string) error {
		f.now = f.now.Add(5 * time.Minute)
		return drain(ctx, node)
	}
	if err := r.Tick(t.Context(), target, f.nodes); err != nil || f.record().Phase != "install" || f.record().Deadline != f.now.Add(3*time.Minute) {
		t.Fatalf("long drain consumed install window: record=%+v error=%v", f.record(), err)
	}
}

func TestRollbackWaitsForSafeRedrainAndRenewsAcknowledgmentWindow(t *testing.T) {
	f := newRolloutFixture(t)
	f.deferActions = true
	target := rolloutTarget("0.80.0")
	f.advance(target, "install")
	f.now = f.record().Deadline.Add(time.Second)
	f.advance(target, "rollback")
	node := f.record().Node
	f.drained[node] = false // A partial LB return must be safely re-drained.
	f.now = f.record().Deadline.Add(time.Minute)
	r := f.reconciler()
	drain := r.Drain
	r.Drain = func(context.Context, string) error { return context.DeadlineExceeded }
	if err := r.Tick(t.Context(), target, f.nodes); !errors.Is(err, context.DeadlineExceeded) || f.record().Phase != "rollback" || len(f.commands) != 0 {
		t.Fatalf("unsafe redrain sent rollback or abandoned recovery: record=%+v commands=%v error=%v", f.record(), f.commands, err)
	}
	r.Drain = func(ctx context.Context, node string) error {
		f.now = f.now.Add(5 * time.Minute)
		return drain(ctx, node)
	}
	if err := r.Tick(t.Context(), target, f.nodes); err != nil || f.record().Phase != "rollback-check" || f.record().Deadline != f.now.Add(6*time.Minute) || len(f.commands) != 1 {
		t.Fatalf("repaired quorum failed to start fresh rollback window: record=%+v commands=%v error=%v", f.record(), f.commands, err)
	}
	if err := f.tick(target); err != nil || f.record().Phase != "rollback-check" || !f.drained[node] {
		t.Fatalf("new rollback timed out before its acknowledgment window: record=%+v error=%v", f.record(), err)
	}
	f.apply(node, f.commands[0])
	if err := f.tick(target); err != nil || f.record().Phase != "failed" || !f.record().RecoveryComplete || f.drained[node] {
		t.Fatalf("acknowledged rollback did not finish recovery: record=%+v error=%v", f.record(), err)
	}
}

func TestFirstInstallRollbackReturnsRestoredAbsence(t *testing.T) {
	f := newRolloutFixture(t)
	node := f.nodes[0]
	f.statuses[node], f.previous[node] = Status{Missing: true}, ""
	target := rolloutTarget("0.80.0")
	f.advance(target, "check")
	f.healthError[node] = errors.New("new enrollment failed mesh checks")
	f.now = f.record().Deadline.Add(time.Second)
	f.advance(target, "rollback-check")
	rolledBack := f.statuses[node]
	if !rolledBack.Missing || rolledBack.Version != "" || rolledBack.ActionID != CommandID(f.record().ID, "rollback") {
		t.Fatalf("first install did not restore acknowledged absence: %+v", rolledBack)
	}
	f.returnError[node] = errors.New("ordinary role/LB health is not ready")
	if err := f.tick(target); err == nil || f.record().RecoveryComplete {
		t.Fatalf("restored absence bypassed the ordinary return gate: record=%+v error=%v", f.record(), err)
	}
	delete(f.returnError, node)
	if err := f.tick(target); err != nil || f.record().Phase != "failed" || !f.record().RecoveryComplete || f.drained[node] {
		t.Fatalf("acknowledged absence could not release bootstrap fence: record=%+v effects=%v error=%v", f.record(), f.effects, err)
	}
	before := len(f.effects)
	if err := f.tick(target); err == nil || len(f.effects) != before {
		t.Fatalf("failed first-install pin retried another node: record=%+v effects=%v error=%v", f.record(), f.effects, err)
	}
}

func TestFailedFirstInstallRecoveryKeepsProofAcrossPinChangesAndRemoval(t *testing.T) {
	for _, amendment := range []string{"same", "changed", "removed"} {
		t.Run(amendment, func(t *testing.T) {
			f := newRolloutFixture(t)
			node := f.nodes[0]
			f.statuses[node], f.previous[node] = Status{Missing: true}, ""
			target := rolloutTarget("0.80.0")
			f.advance(target, "install")
			f.deferActions = true
			f.now = f.record().Deadline.Add(time.Second)
			f.advance(target, "rollback-check")
			f.now = f.record().Deadline.Add(time.Second)
			f.advance(target, "failed")
			failed := f.record()
			desired, nodes := target, f.nodes
			if amendment == "changed" {
				desired = rolloutTarget("0.80.1")
			} else if amendment == "removed" {
				desired, nodes = Target{}, nil
			}
			before := len(f.effects)
			if err := f.reconciler().Tick(t.Context(), desired, nodes); err == nil || len(f.effects) != before || !f.drained[node] {
				t.Fatalf("%s pin released unacknowledged absence: record=%+v effects=%v error=%v", amendment, f.record(), f.effects, err)
			}
			f.apply(node, f.commands[len(f.commands)-1])
			if err := f.reconciler().Tick(t.Context(), desired, nodes); amendment == "same" && err == nil || amendment != "same" && err != nil {
				t.Fatalf("%s pin could not recover acknowledged absence: record=%+v error=%v", amendment, f.record(), err)
			}
			if f.drained[node] || amendment == "changed" && (f.record().Phase != "drain" || f.record().ID == failed.ID) ||
				amendment != "changed" && (!f.record().RecoveryComplete || f.record().ID != failed.ID) {
				t.Fatalf("%s pin did not retain completed recovery or select changed target: record=%+v effects=%v", amendment, f.record(), f.effects)
			}
		})
	}
}

func TestMissingPriorDaemonDrainTimeoutReturnsWithoutRollback(t *testing.T) {
	f := newRolloutFixture(t)
	node := f.nodes[0]
	f.statuses[node], f.previous[node] = Status{Missing: true}, ""
	target := rolloutTarget("0.80.0")
	f.advance(target, "drain")
	f.drained[node] = true // The leader may have lost its reply after draining.
	f.now = f.record().Deadline.Add(time.Second)
	f.advance(target, "failed")
	if err := f.tick(target); err == nil || !f.record().RecoveryComplete || f.drained[node] || len(f.commands) != 0 {
		t.Fatalf("pre-install timeout could not return original absence: record=%+v effects=%v error=%v", f.record(), f.effects, err)
	}
}

func TestFirstInstallRecoveryRejectsUnprovenAbsence(t *testing.T) {
	for _, phase := range []string{"rollback-check", "failed"} {
		for _, invalid := range []string{"not-missing", "installed", "stale", "future", "zero-time", "wrong-action", "error", "pending"} {
			t.Run(phase+"/"+invalid, func(t *testing.T) {
				f := newRolloutFixture(t)
				node := f.nodes[0]
				f.statuses[node], f.previous[node] = Status{Missing: true}, ""
				target := rolloutTarget("0.80.0")
				f.advance(target, "install")
				record := f.record()
				record.Phase, record.RollbackRequired = phase, new(true)
				if err := f.reconciler().Save(t.Context(), record); err != nil {
					t.Fatal(err)
				}
				status := Status{Missing: true, ActionID: CommandID(record.ID, "rollback"), ObservedAt: f.now}
				switch invalid {
				case "not-missing":
					status.Missing = false
				case "installed":
					status.Version = target.Pin.Version
				case "stale":
					status.ObservedAt = f.now.Add(-16 * time.Second)
				case "future":
					status.ObservedAt = f.now.Add(3 * time.Second)
				case "zero-time":
					status.ObservedAt = time.Time{}
				case "wrong-action":
					status.ActionID = CommandID("2VP7F78J0ZNFE8BE3RYC7BNX9T", "rollback")
				case "error":
					status.Error = "rollback failed"
				case "pending":
					status.Pending = record.ID
				}
				r := f.reconciler()
				r.Status = func(context.Context, string) (Status, error) { return status, nil }
				f.deferActions = true
				_ = r.Tick(t.Context(), target, f.nodes)
				if f.record().RecoveryComplete || !f.drained[node] || slices.Contains(f.effects, "return:"+node) {
					t.Fatalf("%s accepted %s absence proof: record=%+v effects=%v", phase, invalid, f.record(), f.effects)
				}
			})
		}
	}
}

func TestLegacyFailedRecordsRequireRollbackAcknowledgmentOnPinChanges(t *testing.T) {
	for _, reason := range []string{
		"agent did not acknowledge installation; previous binary did not recover (node remains drained)",
		"confirmed NetBird agent failed return health checks; previous binary failed return health checks (node remains drained)",
		"drain timed out",
	} {
		t.Run(reason, func(t *testing.T) {
			f := newRolloutFixture(t)
			target := rolloutTarget("0.80.0")
			f.advance(target, "install")
			record := f.record()
			record.Phase, record.Reason = "failed", reason
			record.RollbackRequired = nil // The field is absent from an old journal.
			if err := f.reconciler().Save(t.Context(), record); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(f.journalBytes()), "rollback_required") {
				t.Fatal("legacy journal unexpectedly contains the new marker")
			}
			node := record.Node
			before := len(f.effects)
			changed := rolloutTarget("0.80.1")
			if err := f.tick(changed); err == nil || len(f.effects) != before || !f.drained[node] || f.record().ID != record.ID {
				t.Fatalf("legacy failure bypassed recovery proof: record=%+v effects=%v error=%v", f.record(), f.effects, err)
			}
			status := f.statuses[node]
			status.ActionID = CommandID(record.ID, "rollback")
			f.statuses[node] = status
			if err := f.tick(changed); err != nil || f.drained[node] || f.record().Phase != "drain" || f.record().ID == record.ID {
				t.Fatalf("acknowledged legacy recovery could not proceed: record=%+v error=%v", f.record(), err)
			}
		})
	}
}

func TestLegacyRollbackReturnFailureKeepsRecoveryProofAcrossPinChanges(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "install")
	f.now = f.record().Deadline.Add(time.Second)
	f.advance(target, "rollback-check")
	record := f.record()
	record.RollbackRequired = nil
	if err := f.reconciler().Save(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	node := record.Node
	f.returnError[node] = errors.New("LB health check failed")
	f.now = record.Deadline.Add(time.Second)
	f.advance(target, "failed")
	if !f.drained[node] {
		t.Fatal("failed legacy return released the drain")
	}
	delete(f.returnError, node)
	status := f.statuses[node]
	status.ActionID = "" // Fresh healthy old status alone cannot prove rollback.
	f.statuses[node] = status
	before := len(f.effects)
	if err := f.tick(rolloutTarget("0.80.1")); err == nil || len(f.effects) != before || !f.drained[node] || f.record().ID != record.ID {
		t.Fatalf("legacy rollback return bypassed recovery proof: record=%+v effects=%v error=%v", f.record(), f.effects, err)
	}
}

func TestConfirmationRequiresTheAppliedTargetIdentity(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "confirm")
	f.deferActions = true
	node := f.record().Node
	status := f.statuses[node]
	status.ActionID, status.Pending = CommandID(f.record().ID, "confirm"), ""
	status.AppliedTargetHash = Hash(rolloutTarget("0.80.1"))
	f.statuses[node] = status
	if err := f.tick(target); err != nil || f.record().Phase != "confirm" || !f.drained[node] || slices.Contains(f.effects, "return:"+node) {
		t.Fatalf("confirmation for another target released the node: record=%+v effects=%v error=%v", f.record(), f.effects, err)
	}
}

func TestPendingNodeAnywhereBlocksNewRollout(t *testing.T) {
	f := newRolloutFixture(t)
	status := f.statuses[f.nodes[2]]
	status.Pending = "earlier-unresolved-update"
	f.statuses[f.nodes[2]] = status
	if err := f.tick(rolloutTarget("0.80.0")); err == nil {
		t.Fatalf("started %s while %s has an unresolved update", f.record().Node, f.nodes[2])
	}
	if len(f.journalBytes()) != 0 || len(f.effects) != 0 {
		t.Fatalf("pending transaction caused another rollout: %#v %v", f.record(), f.effects)
	}
}

func TestLeaderResumesOriginalPinAfterPinChangesAndInstallReplyIsLost(t *testing.T) {
	f := newRolloutFixture(t)
	before, after := rolloutTarget("0.80.0"), rolloutTarget("0.80.1")
	f.advance(before, "install")
	original := f.record()
	f.loseReply = "install"
	if err := f.tick(after); err == nil {
		t.Fatal("lost installation response was not simulated")
	}
	if f.record().ID != original.ID || f.record().Phase != "install" || f.commands[0].Target.Pin.Version != before.Pin.Version {
		t.Fatalf("pin change replaced in-flight intent: %#v %#v", f.record(), f.commands)
	}
	f.advance(after, "done")
	installs := 0
	for _, command := range f.commands {
		if command.Transaction != original.ID || command.Target.Pin.Version != before.Pin.Version {
			t.Fatalf("resumed leader changed transaction/pin: %#v", command)
		}
		if command.Action == "install" {
			installs++
		}
	}
	if installs != 1 {
		t.Fatalf("lost reply caused repeated install: %v", f.commands)
	}
	if err := f.tick(after); err != nil {
		t.Fatal(err)
	}
	if f.record().Target.Pin.Version != after.Pin.Version || f.record().ID == original.ID {
		t.Fatalf("new pin was not selected after prior return: %#v", f.record())
	}
}

func TestLeaderResumesDrainedNodeWhenPersistingInstallPhaseFails(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "drain")
	original := f.record()
	r := f.reconciler()
	save := r.Save
	r.Save = func(ctx context.Context, record Record) error {
		if record.Phase == "install" {
			return errors.New("leader lost KV authority after draining")
		}
		return save(ctx, record)
	}
	if err := r.Tick(t.Context(), target, f.nodes); err == nil {
		t.Fatal("lost authority was not simulated")
	}
	if !f.drained[original.Node] || f.record().Phase != "drain" || len(f.commands) != 0 {
		t.Fatalf("install happened without persisted intent: %#v %v", f.record(), f.effects)
	}
	f.advance(target, "check")
	if f.record().ID != original.ID || f.record().Node != original.Node {
		t.Fatalf("new leader selected a second node: %#v", f.record())
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

func TestUnresolvedRollbackKeepsCellHeldAcrossPinChanges(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "check")
	node := f.record().Node
	f.healthError[node] = errors.New("mesh lost")
	f.actionError["rollback"] = "previous binary restart failed"
	f.now = f.record().Deadline.Add(time.Second)
	f.advance(target, "rollback-check")
	f.now = f.record().Deadline.Add(time.Second)
	f.advance(target, "failed")
	if !f.drained[node] {
		t.Fatal("failed rollback returned node to serving")
	}
	before := len(f.effects)
	for _, pin := range []Target{target, rolloutTarget("0.80.1")} {
		if err := f.tick(pin); err == nil || len(f.effects) != before {
			t.Fatalf("unresolved rollback released cell: %#v %v", f.record(), err)
		}
	}
}

func TestFailedWatchdogConfirmationDoesNotReleaseDrainEvenWhenPendingClears(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "confirm")
	node := f.record().Node
	f.actionError["confirm"], f.confirmClears = "watchdog timer cancellation failed", true
	for range 2 {
		if err := f.tick(target); err != nil {
			t.Fatal(err)
		}
	}
	if !f.drained[node] || f.record().Phase != "confirm" || slices.Contains(f.effects, "return:"+node) {
		t.Fatalf("failed confirmation released serving traffic: %#v %v", f.record(), f.effects)
	}
	f.now = f.record().Deadline.Add(time.Second)
	f.advance(target, "rollback")
	if !f.drained[node] {
		t.Fatal("confirmation timeout released drain before rollback")
	}
}

func TestReturnRefusesAReportedPendingTransaction(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "return")
	node := f.record().Node
	status := f.statuses[node]
	status.Pending = "unresolved-local-transaction"
	f.statuses[node] = status
	before := len(f.effects)
	if err := f.tick(target); err == nil || !f.drained[node] || len(f.effects) != before {
		t.Fatalf("returned node with pending network mutation: %#v %v %v", f.record(), f.effects, err)
	}
}

func TestReconcilerRejectsOldTransactionWithoutEffects(t *testing.T) {
	f := newRolloutFixture(t)
	r := f.reconciler()
	if err := r.Save(t.Context(), Record{ID: "old-transaction", Phase: "install"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Tick(t.Context(), rolloutTarget("0.80.0"), f.nodes); err == nil || len(f.effects) != 0 {
		t.Fatalf("invalid transaction reached effects: %v %v", err, f.effects)
	}
}

type workerRequest struct {
	Node    string    `json:"node"`
	Status  Status    `json:"status"`
	Since   time.Time `json:"since"`
	Command Command   `json:"command"`
}

type workerResponse struct {
	Status Status `json:"status"`
	Error  string `json:"error"`
}

func (f *rolloutFixture) startBroker() {
	f.t.Helper()
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: f.storeDir, NoLog: true, NoSigs: true})
	if err != nil {
		f.t.Fatal(err)
	}
	f.broker = broker
	go broker.Start()
	if !broker.ReadyForConnections(5 * time.Second) {
		f.t.Fatal("regional NATS did not start")
	}
	connection, err := nats.Connect(broker.ClientURL(), nats.Timeout(5*time.Second), nats.NoReconnect())
	if err != nil {
		f.t.Fatal(err)
	}
	f.connection = connection
	js, err := jetstream.New(connection)
	if err != nil {
		f.t.Fatal(err)
	}
	f.kv, err = js.CreateOrUpdateKeyValue(f.t.Context(), jetstream.KeyValueConfig{Bucket: "NETBIRD_ROLLOUT", Storage: jetstream.FileStorage, History: 64})
	if err != nil {
		f.t.Fatal(err)
	}
	_, err = connection.Subscribe("netbird.worker.*", func(message *nats.Msg) {
		defer func() { f.workerHandled <- struct{}{} }()
		var request workerRequest
		var response workerResponse
		if err := json.Unmarshal(message.Data, &request, json.RejectUnknownMembers(true)); err != nil {
			response.Error = err.Error()
		} else {
			worker := f.worker()
			var err error
			switch strings.TrimPrefix(message.Subject, "netbird.worker.") {
			case "status":
				response.Status, err = worker.Status(f.t.Context(), request.Node)
			case "preflight":
				err = worker.Preflight(f.t.Context(), request.Node)
			case "drain":
				err = worker.Drain(f.t.Context(), request.Node)
			case "healthy":
				err = worker.Healthy(f.t.Context(), request.Node, request.Status, request.Since)
			case "return":
				err = worker.Return(f.t.Context(), request.Node)
			case "send":
				err = worker.Send(f.t.Context(), request.Node, request.Command)
			default:
				err = errors.New("unknown worker request")
			}
			if err != nil {
				response.Error = err.Error()
			}
		}
		if response.Error == "controller lost the worker response" {
			return
		}
		wire, err := json.Marshal(response)
		if err != nil {
			f.t.Error(err)
			return
		}
		if err := message.Respond(wire); err != nil {
			f.t.Error(err)
		}
	})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := connection.FlushTimeout(5 * time.Second); err != nil {
		f.t.Fatal(err)
	}
}

func (f *rolloutFixture) request(ctx context.Context, action string, request workerRequest) (Status, error) {
	wire, err := json.Marshal(request)
	if err != nil {
		return Status{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	message, err := f.connection.RequestWithContext(bounded, "netbird.worker."+action, wire)
	// A dropped network reply must still finish its simulated worker before state assertions.
	select {
	case <-f.workerHandled:
	case <-time.After(5 * time.Second):
		return Status{}, errors.New("worker did not finish request")
	}
	if err != nil {
		return Status{}, err
	}
	var response workerResponse
	if err := json.Unmarshal(message.Data, &response, json.RejectUnknownMembers(true)); err != nil {
		return Status{}, err
	}
	if response.Error != "" {
		return Status{}, errors.New(response.Error)
	}
	return response.Status, nil
}

func (f *rolloutFixture) reconciler() *Reconciler {
	reconciler := f.worker()
	reconciler.Status = func(ctx context.Context, node string) (Status, error) {
		return f.request(ctx, "status", workerRequest{Node: node})
	}
	reconciler.Preflight = func(ctx context.Context, node string) error {
		_, err := f.request(ctx, "preflight", workerRequest{Node: node})
		return err
	}
	reconciler.Drain = func(ctx context.Context, node string) error {
		_, err := f.request(ctx, "drain", workerRequest{Node: node})
		return err
	}
	reconciler.Healthy = func(ctx context.Context, node string, status Status, since time.Time) error {
		_, err := f.request(ctx, "healthy", workerRequest{Node: node, Status: status, Since: since})
		return err
	}
	reconciler.Return = func(ctx context.Context, node string) error {
		_, err := f.request(ctx, "return", workerRequest{Node: node})
		return err
	}
	reconciler.Send = func(ctx context.Context, node string, command Command) error {
		_, err := f.request(ctx, "send", workerRequest{Node: node, Command: command})
		return err
	}
	return reconciler
}

func TestRolloutIntegrationRestartsJetStreamAfterLostInstallReply(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "install")
	original := f.record()
	f.loseReply = "install"
	if err := f.tick(target); err == nil {
		t.Fatal("lost install reply was not reported")
	}
	f.connection.Close()
	f.broker.Shutdown()
	f.broker.WaitForShutdown()
	files, err := os.ReadDir(filepath.Join(f.storeDir, "jetstream"))
	if err != nil || len(files) == 0 {
		t.Fatalf("JetStream journal has no disk state: %v", err)
	}
	f.startBroker()
	if recovered := f.record(); recovered.ID != original.ID || recovered.Node != original.Node || recovered.Phase != "install" {
		t.Fatalf("restart lost intent: %+v", recovered)
	}
	f.advance(rolloutTarget("0.80.1"), "done")
	installs := 0
	for _, command := range f.commands {
		if command.Action == "install" {
			installs++
		}
		if command.Transaction != original.ID || command.Target.Pin.Version != target.Pin.Version {
			t.Fatalf("restart replaced in-flight command: %+v", command)
		}
	}
	if installs != 1 || f.drained[original.Node] {
		t.Fatalf("restart repeated install or failed return: installs=%d drained=%t", installs, f.drained[original.Node])
	}
}

func TestRolloutIntegrationJournalOutageAfterDrainPreservesOriginalIntent(t *testing.T) {
	f := newRolloutFixture(t)
	target := rolloutTarget("0.80.0")
	f.advance(target, "drain")
	original := f.record()
	reconciler := f.reconciler()
	drain := reconciler.Drain
	reconciler.Drain = func(ctx context.Context, node string) error {
		if err := drain(ctx, node); err != nil {
			return err
		}
		f.connection.Close()
		f.broker.Shutdown()
		f.broker.WaitForShutdown()
		return nil
	}
	if err := reconciler.Tick(t.Context(), target, f.nodes); err == nil {
		t.Fatal("closed journal accepted install intent")
	}
	if !f.drained[original.Node] || len(f.commands) != 0 {
		t.Fatal("journal outage installed or returned drained worker")
	}
	f.startBroker()
	if recovered := f.record(); recovered.ID != original.ID || recovered.Phase != "drain" {
		t.Fatalf("journal outage lost drain intent: %+v", recovered)
	}
	f.advance(target, "check")
	if recovered := f.record(); recovered.ID != original.ID || recovered.Node != original.Node || len(f.commands) != 1 {
		t.Fatalf("recovery changed node or duplicated install: %+v commands=%v", recovered, f.commands)
	}
}
