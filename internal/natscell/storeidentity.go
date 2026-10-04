package natscell

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ErrStoreIdentity reports a JetStream store that belongs to another server
// name. JetStream derives a server's Raft node ID from its name, so reopening
// the store under a new name strands its persisted metadata peers.
var ErrStoreIdentity = errors.New("NATS store belongs to another server name")

// storeIdentityFile records the server name a store was created under.
const storeIdentityFile = "server-name"

// pinStoreIdentity fails closed when dir belongs to another server name: a
// recorded different name, or JetStream state from before the record whose
// legacy <cell>-<instance> name the static scheme has changed. Such a cell is
// rebuilt, not renamed in place (TS-470). Otherwise it records name.
func pinStoreIdentity(dir, name, legacy string) error {
	path := filepath.Join(dir, storeIdentityFile)
	recorded, err := os.ReadFile(path)
	if err == nil {
		if owner := strings.TrimSuffix(string(recorded), "\n"); owner != name {
			return fmt.Errorf("%w: store %s belongs to %q, not %q; the cell must be rebuilt (TS-470)", ErrStoreIdentity, dir, owner, name)
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read NATS store identity: %w", err)
	}
	if name != legacy {
		entries, err := os.ReadDir(filepath.Join(dir, "jetstream"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("read NATS store: %w", err)
		}
		if len(entries) > 0 {
			return fmt.Errorf("%w: store %s holds JetStream state of %q, not %q; the cell must be rebuilt (TS-470)", ErrStoreIdentity, dir, legacy, name)
		}
	}
	temp, err := os.CreateTemp(dir, storeIdentityFile+".*")
	if err != nil {
		return fmt.Errorf("record NATS store identity: %w", err)
	}
	defer os.Remove(temp.Name())
	if _, err := temp.WriteString(name + "\n"); err != nil {
		temp.Close()
		return fmt.Errorf("record NATS store identity: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("record NATS store identity: %w", err)
	}
	return os.Rename(temp.Name(), path)
}
