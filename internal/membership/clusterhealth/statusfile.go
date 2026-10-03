package clusterhealth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// maxStatusFileBytes bounds one status file.
const maxStatusFileBytes = 64 << 10

// StatusFile is a Reporter that keeps the latest status in an owner-only
// file, so local operator tools (break-glass recovery) can see the running
// controller's cluster view without a NATS client listener. It is
// informational only: nothing the controller decides reads it back.
type StatusFile struct {
	Path   string
	Logger *slog.Logger
	once   sync.Once
}

func (file *StatusFile) ReportClusterHealth(status Status) {
	if err := WriteStatusFile(file.Path, status); err != nil && file.Logger != nil {
		file.once.Do(func() {
			file.Logger.Warn("cluster health status file is not writable", "path", file.Path, "error", err)
		})
	}
}

// WriteStatusFile atomically replaces path with status at mode 0600.
func WriteStatusFile(path string, status Status) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("cluster health status file path must be absolute")
	}
	wire, err := json.Marshal(status)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".cluster-health-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(wire); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}

// ReadStatusFile reads a status written by WriteStatusFile. The file must be
// a bounded regular file that is not a symbolic link.
func ReadStatusFile(path string) (Status, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Status{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxStatusFileBytes {
		return Status{}, errors.New("cluster health status must be a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return Status{}, err
	}
	defer file.Close()
	wire, err := io.ReadAll(io.LimitReader(file, maxStatusFileBytes+1))
	if err != nil {
		return Status{}, err
	}
	if len(wire) > maxStatusFileBytes {
		return Status{}, errors.New("cluster health status must be a bounded regular file")
	}
	var status Status
	if err := json.Unmarshal(wire, &status); err != nil {
		return Status{}, fmt.Errorf("decode cluster health status: %w", err)
	}
	return status, nil
}

// PeerCurrent reports whether serverName is an online, caught-up member of a
// metadata group that has a leader, as of a status observed no earlier than
// notBefore.
func (status Status) PeerCurrent(serverName string, notBefore time.Time) error {
	switch {
	case status.ObservedAt.Before(notBefore):
		return fmt.Errorf("cluster health was last observed at %s; is the controller running?",
			status.ObservedAt.Format(time.RFC3339))
	case status.MetaLeader == "":
		return errors.New("the metadata group has no leader")
	case slices.Contains(status.Missing, serverName):
		return fmt.Errorf("%s has not joined the metadata group", serverName)
	case slices.Contains(status.Offline, serverName) || !slices.Contains(status.Online, serverName):
		return fmt.Errorf("%s is offline", serverName)
	case slices.ContainsFunc(status.Lagging, func(peer LaggingPeer) bool { return peer.Name == serverName }):
		return fmt.Errorf("%s is still catching up", serverName)
	case !slices.Contains(status.CaughtUp, serverName):
		// Not lagging is not caught up: a lag within the alert threshold,
		// or a follower's view of another follower, proves nothing.
		return fmt.Errorf("%s has not been reported current with zero lag by the metadata leader in this controller's view",
			serverName)
	}
	return nil
}
