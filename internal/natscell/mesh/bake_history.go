package mesh

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func (n *Node) journalLocal(name string, state desiredState) error {
	entry := state.entry()
	if entry.Spec == nil {
		if state.Floor == nil {
			return nil
		}
		if previous := state.Signed; previous != nil && previous.Spec != nil && len(previous.Spec.Regions) != 0 && !slices.Contains(previous.Spec.Regions, n.cfg.region) {
			return nil
		}
	} else if len(entry.Spec.Regions) != 0 && !slices.Contains(entry.Spec.Regions, n.cfg.region) {
		return nil
	}
	path := filepath.Join(n.cfg.dir, "history-"+name+"-"+strconv.FormatInt(entry.Generation, 10)+".json")
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := protocol.EncodeJSON(state)
	if err != nil {
		return err
	}
	return writePrivate(path, data)
}

func (n *Node) needsBake(name string, entry Entry) bool {
	if entry.Spec == nil || entry.Deployment == nil {
		return false
	}
	entries, err := os.ReadDir(n.cfg.dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return true
	}
	for _, file := range entries {
		suffix, matches := strings.CutPrefix(file.Name(), "history-"+name+"-")
		if !matches {
			continue
		}
		generation, err := strconv.ParseInt(strings.TrimSuffix(suffix, ".json"), 10, 64)
		if err == nil && generation < entry.Generation {
			return true
		}
	}
	for _, file := range entries {
		service, generation, ok := parseBakeFile(file.Name())
		if ok && service == name && generation < entry.Generation {
			return true
		}
	}
	return false
}

func (n *Node) heldRelease(name string, generation int64) *Deployment {
	state := n.desired[name]
	for _, entry := range []*Entry{state.Signed, state.Operator} {
		if entry != nil && entry.Generation == generation && entry.Deployment != nil {
			return entry.Deployment
		}
	}
	data, err := os.ReadFile(filepath.Join(n.cfg.dir, "history-"+name+"-"+strconv.FormatInt(generation, 10)+".json"))
	if err != nil {
		return nil
	}
	var stored desiredState
	if protocol.DecodeTolerant(data, &stored, maxWire) != nil {
		return nil
	}
	for _, entry := range []*Entry{stored.Signed, stored.Operator} {
		if entry != nil && entry.Generation == generation && entry.Deployment != nil {
			return entry.Deployment
		}
	}
	return nil
}
