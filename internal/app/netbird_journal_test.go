package app

import (
	"context"
	"slices"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	network "github.com/TerraScale/ts-orchestrator/internal/netbird/rollout"
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
