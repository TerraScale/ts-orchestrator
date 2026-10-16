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
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/membership/clusterhealth"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
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

func (pending RefoundPending) validate() error {
	serverName, err := naming.RegionCell(pending.Cell).ControllerSlot(pending.Slot)
	if err != nil || pending.ServerName != serverName || pending.Attempt < 2 || pending.StartedAt.IsZero() {
		return errors.New("pending refound record lacks an exact regional slot, successor attempt or start time")
	}
	return nil
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
	if pending.Cell != cell {
		return fmt.Errorf("pending refound belongs to cell %s, not %s", pending.Cell, cell)
	}
	if pending.Slot == slot {
		// The same slot may be retried after interruption.
		return nil
	}
	if err := guard.current(pending); err != nil {
		return fmt.Errorf("slot %s re-founded at %s is not current yet (%v); re-found one slot at a time",
			pending.Slot, pending.StartedAt.Format(time.RFC3339), err)
	}
	return guard.Clear()
}

// Begin records slot as the re-found in progress before any launch.
func (guard RefoundGuard) Begin(pending RefoundPending) error {
	if err := pending.validate(); err != nil {
		return err
	}
	wire, err := json.Marshal(pending)
	if err != nil {
		return err
	}
	return writeOwnerOnly(guard.PendingPath, wire)
}

// Clear removes the pending record.
func (guard RefoundGuard) Clear() error {
	if err := os.Remove(guard.PendingPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return syncDir(filepath.Dir(guard.PendingPath))
}

// WaitCurrent polls the controller's cluster health until the pending
// slot's server is an online, caught-up metadata peer in a view observed
// after the relaunch began, then clears the pending record. On timeout the
// record stays, so no other slot is re-founded meanwhile.
func (guard RefoundGuard) WaitCurrent(ctx context.Context, pending RefoundPending, poll, timeout time.Duration,
	out io.Writer,
) error {
	serverName := pending.ServerName
	deadline := guard.now().Add(timeout)
	last := ""
	for {
		err := guard.current(pending)
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

// current judges the pending slot from a cluster view that is both fresh and
// observed after the relaunch began: the successor reuses the lost
// instance's server name, so an earlier view says nothing about it.
func (guard RefoundGuard) current(pending RefoundPending) error {
	if err := pending.validate(); err != nil {
		return err
	}
	status, err := clusterhealth.ReadStatusFile(guard.HealthPath)
	if err != nil {
		return fmt.Errorf("read the controller's cluster health %s: %w", guard.HealthPath, err)
	}
	notBefore := guard.now().Add(-RefoundHealthFreshness)
	if pending.StartedAt.After(notBefore) {
		notBefore = pending.StartedAt
	}
	return status.PeerCurrent(pending.ServerName, notBefore)
}

// Lock takes the host-wide refound lock without waiting and holds it until
// release is called, so two refound commands can never interleave
// admission, relaunch and the wait for currency (each would otherwise pass
// Admit on the same old ledger and launch two empty replacements).
func (guard RefoundGuard) Lock() (release func(), err error) {
	path := guard.PendingPath + ".lock"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open the refound lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("another break-glass refound is running on this host; re-found one slot at a time")
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		file.Close()
	}, nil
}

func (guard RefoundGuard) readPending() (RefoundPending, error) {
	file, err := os.OpenFile(guard.PendingPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return RefoundPending{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return RefoundPending{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > 4<<10 {
		return RefoundPending{}, errors.New("pending refound record must be a small owner-only regular file")
	}
	wire, err := io.ReadAll(io.LimitReader(file, (4<<10)+1))
	if err != nil {
		return RefoundPending{}, err
	}
	var pending RefoundPending
	if err := protocol.DecodeStrict(wire, &pending, 4<<10); err != nil {
		return RefoundPending{}, errors.New("pending refound record is malformed")
	}
	if err := pending.validate(); err != nil {
		return RefoundPending{}, err
	}
	return pending, nil
}

func writeOwnerOnly(path string, data []byte) error {
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := syncDir(filepath.Dir(dir)); err != nil {
			return err
		}
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
	if err := os.Rename(temporary.Name(), path); err != nil {
		return err
	}
	// The record gates the next slot after a crash, so its directory entry
	// must be durable before the caller launches anything.
	return syncDir(dir)
}

func syncDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}
