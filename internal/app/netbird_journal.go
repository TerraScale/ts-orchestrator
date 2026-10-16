package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	network "github.com/TerraScale/ts-orchestrator/internal/netbird/rollout"
)

type netbirdStateReader interface {
	ReadNetBirdState(context.Context) (authority.LogEntry, error)
}

type netbirdStateStore interface {
	netbirdStateReader
	CommitNetBirdState(context.Context, uint64, string, uint64, []byte) (uint64, error)
}

// Journal and command share one revision, so a stale tick cannot publish a
// command after another controller advances the transaction.
type netbirdState struct {
	Record   network.Record  `json:"record"`
	Command  network.Command `json:"command"`
	Revision uint64          `json:"-"`
}

func netbirdCommandAllowed(record network.Record, action string) bool {
	if record.RecoveryComplete {
		return false
	}
	switch record.Phase {
	case "install", "confirm":
		return action == record.Phase
	case "rollback", "rollback-check":
		return action == "rollback"
	case "failed":
		return action == "rollback" && (record.RollbackRequired == nil || *record.RollbackRequired)
	default:
		return false
	}
}

func (state netbirdState) commandFor(node string) (network.Command, bool, error) {
	command := state.Command
	if state.Record.Node != node || command.ID == "" || !netbirdCommandAllowed(state.Record, command.Action) {
		return network.Command{}, false, nil
	}
	if command.Transaction != state.Record.ID || command.ID != network.CommandID(state.Record.ID, command.Action) ||
		network.Hash(command.Target) != network.Hash(state.Record.Target) {
		return network.Command{}, false, errors.New("NetBird command does not match the active transaction")
	}
	return command, true, nil
}

func readNetBirdState(ctx context.Context, reader netbirdStateReader) (netbirdState, error) {
	entry, err := reader.ReadNetBirdState(ctx)
	if errors.Is(err, authority.ErrNotFound) {
		return netbirdState{}, nil
	}
	if err != nil {
		return netbirdState{}, err
	}
	var state netbirdState
	if entry.Sequence == 0 || entry.Epoch == 0 {
		return state, errors.New("invalid NetBird journal revision")
	}
	if err := json.Unmarshal(entry.Payload, &state, json.RejectUnknownMembers(true)); err != nil {
		return state, err
	}
	if (state.Record.ID != "" || state.Record.Phase != "" || state.Record.Node != "") && !entityid.Valid(state.Record.ID) {
		return state, errors.New("invalid NetBird journal identity")
	}
	state.Revision = entry.Sequence
	return state, nil
}

func (n *netbirdRollout) state(ctx context.Context) (netbirdState, error) {
	reader, ok := n.fence.fencer.(netbirdStateReader)
	if !ok {
		return netbirdState{}, errors.New("NetBird requires an authority journal reader")
	}
	return readNetBirdState(ctx, reader)
}

func (n *netbirdRollout) commitStateAt(ctx context.Context, epoch uint64, state *netbirdState, next netbirdState) error {
	store, ok := n.fence.fencer.(netbirdStateStore)
	if !ok {
		return errors.New("NetBird requires an authority journal writer")
	}
	if (next.Record.ID != "" || next.Record.Phase != "" || next.Record.Node != "") && !entityid.Valid(next.Record.ID) {
		return errors.New("invalid NetBird journal identity")
	}
	original, err := json.Marshal(*state, json.Deterministic(true))
	if err != nil {
		return err
	}
	wire, err := json.Marshal(next, json.Deterministic(true))
	if err != nil {
		return err
	}
	expected, operation := state.Revision, entityid.New()
	for attempt := range 3 {
		revision, err := store.CommitNetBirdState(ctx, epoch, operation, expected, wire)
		if err == nil {
			next.Revision = revision
			*state = next
			return nil
		}
		if !errors.Is(err, authority.ErrConflict) || attempt == 2 {
			return err
		}
		current, err := readNetBirdState(ctx, store)
		if err != nil {
			return err
		}
		currentWire, err := json.Marshal(current, json.Deterministic(true))
		if err != nil {
			return err
		}
		// Issuance changes only the revision; a changed intent invalidates
		// the original tick's health, drain and return decisions.
		if !bytes.Equal(original, currentWire) {
			return authority.ErrConflict
		}
		expected = current.Revision
	}
	return authority.ErrConflict
}

func (n *netbirdRollout) sendAt(ctx context.Context, epoch uint64, state *netbirdState, node string, command network.Command) error {
	if state.Revision == 0 || state.Record.Node != node || state.Record.ID != command.Transaction ||
		command.ID != network.CommandID(state.Record.ID, command.Action) || network.Hash(command.Target) != network.Hash(state.Record.Target) ||
		!netbirdCommandAllowed(state.Record, command.Action) {
		return errors.New("NetBird command does not match its journal snapshot")
	}
	next := *state
	next.Command = command
	return n.commitStateAt(ctx, epoch, state, next)
}

func (n *netbirdRollout) loadIntent(ctx context.Context, key string, value any) error {
	state, err := n.state(ctx)
	if err != nil {
		return err
	}
	if state.Revision == 0 {
		return os.ErrNotExist
	}
	var intent any = state.Record
	if key != netbirdRecordKey {
		if key != "netbird.command."+state.Record.Node {
			return os.ErrNotExist
		}
		command, found, err := state.commandFor(state.Record.Node)
		if err != nil {
			return err
		}
		if !found {
			return os.ErrNotExist
		}
		intent = command
	}
	wire, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	return json.Unmarshal(wire, value, json.RejectUnknownMembers(true))
}
