package vmqual

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

// CleanJournal replays only exact resources recorded by a vmqual journal. It
// never scans process tables, network interfaces, or a broad directory.
func CleanJournal(ctx context.Context, path string, runner vmnet.Runner) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("vmqual: cleanup journal path must be absolute")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var journal Journal
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&journal); err != nil {
		return fmt.Errorf("vmqual: decode cleanup journal: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err == nil {
		return errors.New("vmqual: cleanup journal has trailing JSON")
	} else if !errors.Is(err, io.EOF) {
		return fmt.Errorf("vmqual: decode cleanup journal trailer: %w", err)
	}
	if journal.Version != 1 || journal.Marker != OwnershipMarker {
		return errors.New("vmqual: cleanup journal ownership marker is invalid")
	}
	if journal.StateRoot == "" || !filepath.IsAbs(journal.StateRoot) {
		return errors.New("vmqual: cleanup state root is invalid")
	}
	if err := ownedDirectory(journal.StateRoot); err != nil {
		return fmt.Errorf("vmqual: cleanup state root: %w", err)
	}
	if len(journal.Network.Cleanup.Commands) > 0 && runner == nil {
		return errors.New("vmqual: cleanup network runner is required")
	}
	if len(journal.Network.Cleanup.Commands) > 0 || journal.Network.Version != 0 {
		if err := validateNetworkJournal(journal.Network); err != nil {
			return err
		}
	}
	var first error
	if len(journal.Network.Cleanup.Commands) > 0 {
		if err := journal.Network.Cleanup.Run(context.WithoutCancel(ctx), runner); err != nil {
			first = err
		}
	}
	seen := make(map[string]struct{}, len(journal.VMs))
	for _, resource := range journal.VMs {
		if _, exists := seen[resource.ID]; exists {
			if first == nil {
				first = fmt.Errorf("vmqual: duplicate cleanup resource %q", resource.ID)
			}
			continue
		}
		seen[resource.ID] = struct{}{}
		if resource.ID == "" || resource.StateDir == "" || !pathWithin(journal.StateRoot, resource.StateDir) || filepath.Base(resource.StateDir) != resource.ID {
			if first == nil {
				first = fmt.Errorf("vmqual: cleanup resource %q is outside ownership root", resource.ID)
			}
			continue
		}
		if err := ownedDirectory(resource.StateDir); err != nil {
			if first == nil {
				first = fmt.Errorf("vmqual: cleanup resource %q: %w", resource.ID, err)
			}
			continue
		}
		owned, readErr := os.ReadFile(filepath.Join(resource.StateDir, "ownership.json"))
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) {
				continue
			}
			if first == nil {
				first = readErr
			}
			continue
		}
		var marker struct {
			Marker string `json:"marker"`
			ID     string `json:"id"`
		}
		if json.Unmarshal(owned, &marker) != nil || marker.Marker != "terrascale-sandboxvm-v1" || marker.ID != resource.ID {
			if first == nil {
				first = fmt.Errorf("vmqual: refusing unowned resource %s", resource.ID)
			}
			continue
		}
		if err := os.RemoveAll(resource.StateDir); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func ownedDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("not an owned directory")
	}
	return nil
}

func pathWithin(root, candidate string) bool {
	root, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(root, candidate)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
