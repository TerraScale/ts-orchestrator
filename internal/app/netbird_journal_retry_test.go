package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	network "github.com/TerraScale/ts-orchestrator/internal/netbird/rollout"
)

func TestNetBirdRecoverySaveSurvivesUnchangedIssuanceDuringHealthAndReturn(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	n := netbirdRollout{cell: "gru", key: key, services: &specRegistry{},
		fence: &releaseFence{kv: fenceKV(t), fencer: &fenceLease{}}}
	target := network.Target{Enrollment: netbird.Config{PeerNames: map[string]string{
		"10.0.0.1": "ts-gru-1", "10.0.0.2": "ts-gru-2", "10.0.0.3": "ts-gru-3",
	}}}
	now := time.Now().UTC()
	record := network.Record{ID: "7E5HKSCCJSQJGMM2DVVHCQDQFV", Node: "node-a", Previous: "0.79.0", Target: target,
		PinHash: network.Hash(target), Phase: "rollback-check", RollbackRequired: new(true),
		StartedAt: now.Add(-time.Minute), Deadline: now.Add(time.Minute)}
	if err := saveNetBirdTestRecord(t.Context(), &n, 3, record); err != nil {
		t.Fatal(err)
	}
	command := network.Command{ID: network.CommandID(record.ID, "rollback"), Transaction: record.ID, Action: "rollback", Target: target}
	if err := saveNetBirdTestCommand(t.Context(), &n, 3, record.Node, command); err != nil {
		t.Fatal(err)
	}
	status := network.Status{Version: record.Previous, ActionID: command.ID, ObservedAt: now}
	issuances := 0
	issue := func(ctx context.Context) error {
		step, err := n.Exchange(ctx, host.Registration{Node: record.Node}, status)
		if err == nil && len(step) == 0 {
			return errors.New("unchanged recovery command was not issued")
		}
		issuances++
		return err
	}
	var snapshot netbirdState
	r := network.Reconciler{
		Load: func(ctx context.Context) (network.Record, error) {
			var err error
			snapshot, err = n.state(ctx)
			return snapshot.Record, err
		},
		Save: func(ctx context.Context, record network.Record) error {
			return n.saveRecordAt(ctx, 3, &snapshot, record)
		},
		Status:  func(context.Context, string) (network.Status, error) { return status, nil },
		Healthy: func(ctx context.Context, _ string, _ network.Status, _ time.Time) error { return issue(ctx) },
		Return: func(ctx context.Context, _ string) error {
			current, err := n.state(ctx)
			if err != nil {
				return err
			}
			if !current.Record.RecoveryReturning {
				return errors.New("return began without durable intent")
			}
			return issue(ctx)
		},
	}
	before, err := n.state(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Tick(t.Context(), target, nil); err != nil {
		t.Fatalf("rollback-check recovery did not persist: %v", err)
	}
	actual, err := n.state(t.Context())
	if err != nil || !actual.Record.RecoveryComplete || actual.Command.ID != "" || issuances != 2 || actual.Revision != before.Revision+4 || !reflect.DeepEqual(actual, snapshot) {
		t.Fatalf("issuance revisions starved recovery completion: state=%+v snapshot=%+v issuances=%d error=%v", actual, snapshot, issuances, err)
	}
}

func TestNetBirdJournalRetryRejectsChangedOriginalPayload(t *testing.T) {
	for name, change := range map[string]func(*netbirdState){
		"phase":   func(state *netbirdState) { state.Record.Phase = "confirm" },
		"command": func(state *netbirdState) { state.Command.Generation++ },
		"node":    func(state *netbirdState) { state.Record.Node = "node-b" },
		"fence":   func(state *netbirdState) { state.Record.Fence = []byte(`{"drain_grace_seconds":30}`) },
	} {
		t.Run(name, func(t *testing.T) {
			n := netbirdRollout{fence: &releaseFence{fencer: &fenceLease{}}}
			original := netbirdState{Record: network.Record{ID: "7E5HKSCCJSQJGMM2DVVHCQDQFV", Node: "node-a", Phase: "install"}}
			snapshot := netbirdState{}
			if err := n.commitStateAt(t.Context(), 3, &snapshot, original); err != nil {
				t.Fatal(err)
			}
			original = snapshot
			concurrent := snapshot
			change(&concurrent)
			if err := n.commitStateAt(t.Context(), 3, &concurrent, concurrent); err != nil {
				t.Fatal(err)
			}
			// Equality with the desired next state must not authorize stale
			// effects whose ORIGINAL snapshot was changed by another tick.
			if err := n.commitStateAt(t.Context(), 3, &snapshot, concurrent); !errors.Is(err, authority.ErrConflict) {
				t.Fatalf("changed original payload was accepted: %v", err)
			}
			if !reflect.DeepEqual(snapshot, original) {
				t.Fatal("failed retry mutated the caller's snapshot")
			}
		})
	}
}

type netbirdConflictingLease struct {
	*fenceLease
	attempts int
	fence    bool
}

func (l *netbirdConflictingLease) CommitNetBirdState(ctx context.Context, epoch uint64, operation string, expected uint64, wire []byte) (uint64, error) {
	l.attempts++
	if l.fence && l.attempts > 1 {
		l.mu.Lock()
		l.lost = true
		l.mu.Unlock()
		return l.fenceLease.CommitNetBirdState(ctx, epoch, operation, expected, wire)
	}
	return 0, authority.ErrConflict
}

func TestNetBirdJournalRetryRemainsBoundedAndFenced(t *testing.T) {
	for _, fenced := range []bool{false, true} {
		t.Run(map[bool]string{false: "bounded", true: "fenced"}[fenced], func(t *testing.T) {
			lease := &netbirdConflictingLease{fenceLease: &fenceLease{}, fence: fenced}
			n := netbirdRollout{fence: &releaseFence{fencer: lease}}
			original := netbirdState{Record: network.Record{ID: "7E5HKSCCJSQJGMM2DVVHCQDQFV", Node: "node-a", Phase: "install"}}
			wire, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			original.Revision, err = lease.fenceLease.CommitNetBirdState(t.Context(), 3, "initial", 0, wire)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, next := original, original
			next.Record.Phase = "check"
			want, attempts := authority.ErrConflict, 3
			if fenced {
				want, attempts = authority.ErrFenced, 2
			}
			if err := n.commitStateAt(t.Context(), 3, &snapshot, next); !errors.Is(err, want) || lease.attempts != attempts {
				t.Fatalf("retry escaped authority or attempt limit: attempts=%d error=%v", lease.attempts, err)
			}
			if !reflect.DeepEqual(snapshot, original) {
				t.Fatal("failed retry advanced the caller's revision")
			}
		})
	}
}
