package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"slices"
	"sync/atomic"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	network "git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/rollout"
)

func (l *fenceLease) ReadNetBirdState(context.Context) (authority.LogEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.netbird.Sequence == 0 {
		return authority.LogEntry{}, authority.ErrNotFound
	}
	entry := l.netbird
	entry.Payload = slices.Clone(entry.Payload)
	return entry, nil
}

func (l *fenceLease) CommitNetBirdState(ctx context.Context, epoch uint64, operation string, expected uint64, wire []byte) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if l.lost || epoch != 3 {
		return 0, authority.ErrFenced
	}
	if l.netbird.Sequence != expected {
		return 0, authority.ErrConflict
	}
	l.netbird = authority.LogEntry{Epoch: epoch, Sequence: expected + 1, OperationID: operation, Payload: slices.Clone(wire)}
	return l.netbird.Sequence, nil
}

func saveNetBirdTestRecord(ctx context.Context, n *netbirdRollout, epoch uint64, record network.Record) error {
	state, err := n.state(ctx)
	if err != nil {
		return err
	}
	next := state
	if state.Record.ID != record.ID || state.Record.Node != record.Node {
		next.Command = network.Command{}
	}
	next.Record = record
	return n.commitStateAt(ctx, epoch, &state, next)
}

func saveNetBirdTestAdmission(ctx context.Context, n *netbirdRollout, epoch uint64, record network.Record) error {
	state, err := n.state(ctx)
	if err != nil {
		return err
	}
	return n.saveRecordAt(ctx, epoch, &state, record)
}

func saveNetBirdTestCommand(ctx context.Context, n *netbirdRollout, epoch uint64, node string, command network.Command) error {
	state, err := n.state(ctx)
	if err != nil {
		return err
	}
	return n.sendAt(ctx, epoch, &state, node, command)
}

func TestNetBirdStaleTickCannotOverwriteJournalOrCommand(t *testing.T) {
	n := netbirdRollout{fence: &releaseFence{fencer: &fenceLease{}}}
	record := network.Record{ID: "upgrade", Node: "node-a", Phase: "install"}
	if err := saveNetBirdTestRecord(t.Context(), &n, 3, record); err != nil {
		t.Fatal(err)
	}
	stale, err := n.state(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	current := stale
	record.Phase = "rollback"
	if err := n.saveRecordAt(t.Context(), 3, &current, record); err != nil {
		t.Fatal(err)
	}
	command := network.Command{ID: "upgrade.rollback", Transaction: "upgrade", Action: "rollback"}
	if err := n.sendAt(t.Context(), 3, &current, record.Node, command); err != nil {
		t.Fatal(err)
	}
	if err := n.saveRecordAt(t.Context(), 3, &stale, stale.Record); !errors.Is(err, authority.ErrConflict) {
		t.Fatalf("stale journal transition accepted: %v", err)
	}
	old := command
	old.Action, old.ID = "install", "upgrade.install"
	if err := n.sendAt(t.Context(), 3, &stale, record.Node, old); !errors.Is(err, authority.ErrConflict) {
		t.Fatalf("stale command accepted: %v", err)
	}
	actual, err := n.state(t.Context())
	if err != nil || actual.Record.Phase != "rollback" || actual.Command.ID != command.ID {
		t.Fatalf("stale tick replaced recovery intent: %+v %v", actual, err)
	}
}

func TestNetBirdNewTransactionDropsPreviousNodeCommand(t *testing.T) {
	n := netbirdRollout{fence: &releaseFence{fencer: &fenceLease{}}}
	record := network.Record{ID: "old", Node: "node-a", Phase: "install"}
	if err := saveNetBirdTestRecord(t.Context(), &n, 3, record); err != nil {
		t.Fatal(err)
	}
	state, err := n.state(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := n.sendAt(t.Context(), 3, &state, "node-a", network.Command{ID: "old.install", Transaction: "old", Action: "install"}); err != nil {
		t.Fatal(err)
	}
	record.ID, record.Node = "new", "node-b"
	if err := n.saveRecordAt(t.Context(), 3, &state, record); err != nil {
		t.Fatal(err)
	}
	var command network.Command
	if err := n.load(t.Context(), "netbird.command.node-b", &command); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("previous node command transferred to new transaction")
	}
	if state.Command.ID != "" {
		t.Fatal("previous command retained in new journal")
	}
}

func TestNetBirdRollbackCannotResignPreviousConfirmation(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	n := netbirdRollout{cell: "gru", key: key, services: &specRegistry{current: cellspec.Spec{NetBird: &cellspec.NetBird{}}},
		fence: &releaseFence{fencer: &fenceLease{}}}
	record := network.Record{ID: "upgrade", Node: "node-a", Phase: "confirm"}
	if err := saveNetBirdTestRecord(t.Context(), &n, 3, record); err != nil {
		t.Fatal(err)
	}
	state, err := n.state(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	confirm := network.Command{ID: "upgrade.confirm", Transaction: "upgrade", Action: "confirm"}
	if err := n.sendAt(t.Context(), 3, &state, record.Node, confirm); err != nil {
		t.Fatal(err)
	}
	record.Phase = "rollback"
	if err := n.saveRecordAt(t.Context(), 3, &state, record); err != nil {
		t.Fatal(err)
	}
	if state.Command.ID != "" {
		t.Fatal("rollback retained obsolete confirmation")
	}
	if err := n.sendAt(t.Context(), 3, &state, record.Node, confirm); err == nil {
		t.Fatal("rollback accepted obsolete confirmation")
	}
	// Delivery also rejects invalid persisted commands independently of the
	// writer, including a state restored by a restarted controller.
	next := state
	next.Command = confirm
	if err := n.commitStateAt(t.Context(), 3, &state, next); err != nil {
		t.Fatal(err)
	}
	step, err := n.Exchange(t.Context(), host.Registration{Node: record.Node}, network.Status{})
	if err != nil || len(step) != 0 {
		t.Fatalf("rollback re-signed obsolete confirmation: %q %v", step, err)
	}
	rollback := network.Command{ID: "upgrade.rollback", Transaction: "upgrade", Action: "rollback"}
	if err := n.sendAt(t.Context(), 3, &state, record.Node, rollback); err != nil {
		t.Fatal(err)
	}
	record.Phase = "rollback-check"
	if err := n.saveRecordAt(t.Context(), 3, &state, record); err != nil {
		t.Fatal(err)
	}
	step, err = n.Exchange(t.Context(), host.Registration{Node: record.Node}, network.Status{})
	if err != nil || len(step) == 0 {
		t.Fatalf("rollback-check lost its recovery command: %q %v", step, err)
	}
}

type netbirdIssuanceRace struct {
	*fenceLease
	armed        atomic.Bool
	beforeCommit func() error
}

func (l *netbirdIssuanceRace) CommitNetBirdState(ctx context.Context, epoch uint64, operation string, expected uint64, wire []byte) (uint64, error) {
	if l.armed.Swap(false) {
		if err := l.beforeCommit(); err != nil {
			return 0, err
		}
	}
	return l.fenceLease.CommitNetBirdState(ctx, epoch, operation, expected, wire)
}

func TestNetBirdExchangeRejectsConcurrentRollbackBeforeCommandIssuance(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	lease := &netbirdIssuanceRace{fenceLease: &fenceLease{}}
	n := netbirdRollout{cell: "gru", key: key, services: &specRegistry{current: cellspec.Spec{NetBird: &cellspec.NetBird{}}},
		fence: &releaseFence{fencer: lease}}
	record := network.Record{ID: "upgrade", Node: "node-a", Phase: "confirm"}
	if err := saveNetBirdTestRecord(t.Context(), &n, 3, record); err != nil {
		t.Fatal(err)
	}
	if err := saveNetBirdTestCommand(t.Context(), &n, 3, record.Node,
		network.Command{ID: "upgrade.confirm", Transaction: "upgrade", Action: "confirm"}); err != nil {
		t.Fatal(err)
	}
	lease.beforeCommit = func() error {
		state, err := n.state(t.Context())
		if err != nil {
			return err
		}
		record.Phase = "rollback"
		return n.saveRecordAt(t.Context(), 3, &state, record)
	}
	lease.armed.Store(true)
	step, err := n.Exchange(t.Context(), host.Registration{Node: record.Node}, network.Status{})
	if !errors.Is(err, authority.ErrConflict) || len(step) != 0 {
		t.Fatalf("superseded confirmation issued: %q %v", step, err)
	}
	state, err := n.state(t.Context())
	if err != nil || state.Record.Phase != "rollback" || state.Command.ID != "" {
		t.Fatalf("failed issuance replaced rollback intent: %+v %v", state, err)
	}
}
