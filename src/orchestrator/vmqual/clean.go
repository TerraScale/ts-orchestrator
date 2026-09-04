package vmqual

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&journal); err != nil {
		return fmt.Errorf("vmqual: decode cleanup journal: %w", err)
	}
	if journal.Version != 1 || journal.Marker != OwnershipMarker {
		return errors.New("vmqual: cleanup journal ownership marker is invalid")
	}
	if journal.StateRoot == "" || !filepath.IsAbs(journal.StateRoot) {
		return errors.New("vmqual: cleanup state root is invalid")
	}
	var first error
	if runner != nil && len(journal.Network.Cleanup.Commands) > 0 {
		if err := journal.Network.Cleanup.Run(context.WithoutCancel(ctx), runner); err != nil {
			first = err
		}
	}
	for _, resource := range journal.VMs {
		if resource.ID == "" || resource.StateDir == "" || !pathWithin(journal.StateRoot, resource.StateDir) || filepath.Base(resource.StateDir) != resource.ID {
			if first == nil {
				first = fmt.Errorf("vmqual: cleanup resource %q is outside ownership root", resource.ID)
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
