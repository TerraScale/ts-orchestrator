package membership

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/membership/clusterhealth"
)

const (
	// DefaultClusterHealthFile is where a production controller keeps its
	// latest cluster health view for local operator tools. It lives under
	// the controller unit's StateDirectory.
	DefaultClusterHealthFile = "/var/lib/terrascale-orchestrator-controller/membership/cluster-health.json"
	// DefaultRefoundPendingFile records the slot break-glass refound last
	// relaunched until that slot reports current.
	DefaultRefoundPendingFile = "/var/lib/terrascale-orchestrator-controller/membership/refound-pending.json"
	// RefoundHealthFreshness is how old the controller's cluster health view
	// may be when refound relies on it.
	RefoundHealthFreshness = time.Minute
)

// RefoundPending is the slot a break-glass refound relaunched and has not yet
// seen report current in the survivor's metadata group.
type RefoundPending struct {
	Cell       string    `json:"cell"`
	Slot       string    `json:"slot"`
	ServerName string    `json:"server_name"`
	Attempt    uint64    `json:"attempt"`
	StartedAt  time.Time `json:"started_at"`
}

// RefoundGuard keeps break-glass re-founding to one slot at a time: a slot
// is re-founded only when no other slot has an incomplete successor attempt
// in the ledger and the previously re-founded slot reports current. Two
// empty replacements in the metadata group at once could otherwise outvote
// the data-bearing survivor.
type RefoundGuard struct {
	PendingPath string
	HealthPath  string
	Now         func() time.Time
}

func (guard RefoundGuard) now() time.Time {
	if guard.Now != nil {
		return guard.Now().UTC()
	}
	return time.Now().UTC()
}

// Admit refuses to re-found slot while another slot is mid-replacement.
func (guard RefoundGuard) Admit(cell, slot string, ledger map[string]LedgerSlot) error {
	others := make([]string, 0, len(ledger))
	for other := range ledger {
		others = append(others, other)
	}
	slices.Sort(others)
	for _, other := range others {
		head := ledger[other]
		if other != slot && !head.Complete && head.Attempt >= 2 {
			return fmt.Errorf("slot %s has an incomplete re-founded attempt %d; wait until it completes and reports current before re-founding %s",
				other, head.Attempt, slot)
		}
	}
	pending, err := guard.readPending()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read the pending refound record %s: %w", guard.PendingPath, err)
	}
	if pending.Cell != cell || pending.Slot == slot {
		// A record of another cell is stale; the same slot may be retried.
		return nil
	}
	if err := guard.current(pending.ServerName); err != nil {
		return fmt.Errorf("slot %s re-founded at %s is not current yet (%v); re-found one slot at a time",
			pending.Slot, pending.StartedAt.Format(time.RFC3339), err)
	}
	return guard.Clear()
}

// Begin records slot as the re-found in progress before any launch.
func (guard RefoundGuard) Begin(pending RefoundPending) error {
	wire, err := json.Marshal(pending)
	if err != nil {
		return err
	}
	return writeOwnerOnly(guard.PendingPath, wire)
}

// Clear removes the pending record.
func (guard RefoundGuard) Clear() error {
	if err := os.Remove(guard.PendingPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// WaitCurrent polls the controller's cluster health until serverName is an
// online, caught-up metadata peer, then clears the pending record. On
// timeout the record stays, so no other slot is re-founded meanwhile.
func (guard RefoundGuard) WaitCurrent(ctx context.Context, serverName string, poll, timeout time.Duration,
	out io.Writer,
) error {
	deadline := guard.now().Add(timeout)
	last := ""
	for {
		err := guard.current(serverName)
		if err == nil {
			return guard.Clear()
		}
		if err.Error() != last {
			last = err.Error()
			fmt.Fprintf(out, "waiting for %s to report current: %v\n", serverName, err)
		}
		if !guard.now().Before(deadline) {
			return fmt.Errorf("%s did not report current within %s (%v); rerun refound for the same slot to keep waiting before re-founding another",
				serverName, timeout, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

func (guard RefoundGuard) current(serverName string) error {
	status, err := clusterhealth.ReadStatusFile(guard.HealthPath)
	if err != nil {
		return fmt.Errorf("read the controller's cluster health %s: %w", guard.HealthPath, err)
	}
	return status.PeerCurrent(serverName, guard.now().Add(-RefoundHealthFreshness))
}

func (guard RefoundGuard) readPending() (RefoundPending, error) {
	info, err := os.Lstat(guard.PendingPath)
	if err != nil {
		return RefoundPending{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4<<10 {
		return RefoundPending{}, errors.New("pending refound record must be a small regular file")
	}
	wire, err := os.ReadFile(guard.PendingPath)
	if err != nil {
		return RefoundPending{}, err
	}
	var pending RefoundPending
	if err := json.Unmarshal(wire, &pending); err != nil || pending.Slot == "" || pending.ServerName == "" {
		return RefoundPending{}, errors.New("pending refound record is malformed")
	}
	return pending, nil
}

func writeOwnerOnly(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".refound-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}
