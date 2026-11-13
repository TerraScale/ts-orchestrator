package mesh

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

type bakeRecord struct {
	Generation    int64               `json:"generation"`
	Interruptions int                 `json:"interruptions"`
	Image         string              `json:"image"`
	Release       *Deployment         `json:"release,omitempty"`
	Identity      [32]byte            `json:"identity"`
	Rollout       bakeRuntime         `json:"runtime"`
	Bake          rollout.BakeVerdict `json:"bake"`
	ReplacedBy    *bakeReplacement    `json:"replacedBy,omitempty"`
}

type bakeRuntime struct {
	Running, Ready int64 // elapsed nanoseconds; protocol JSON has no implicit duration encoding
	Tasks          []swarmruntime.ServiceTaskEvidence
	Revision       string
	StopFirst      bool `json:",omitzero"` // the start-first candidate did not fit beside the old task
}

func (n *Node) bakePath(name string, generation int64) string {
	return filepath.Join(n.cfg.dir, fmt.Sprintf("bake-%s-%d.json", name, generation))
}

func (n *Node) readBake(name string, generation int64) (record bakeRecord, err error) {
	data, err := os.ReadFile(n.bakePath(name, generation))
	if err == nil {
		err = protocol.DecodeTolerant(data, &record, maxWire)
	}
	return record, err
}

// Retain terminal observations even when the disk temporarily refuses writes.
// Reconciliation retries persistence, never the observation of this candidate.
func (n *Node) saveBake(key string, record bakeRecord) error {
	err := writeBake(key, record)
	if err != nil {
		if n.bakeUnsaved == nil {
			n.bakeUnsaved = map[string]bakeRecord{}
		}
		record.Bake.Unsaved = true
		n.bakeUnsaved[key] = record
	} else {
		delete(n.bakeUnsaved, key)
	}
	n.publishUnsaved()
	return err
}

func (n *Node) publishUnsaved() {
	pending := maps.Clone(n.bakeUnsaved)
	n.stateUnsaved.Store(&pending)
}

func writeBake(key string, record bakeRecord) error {
	record.Bake.Unsaved = false
	data, err := protocol.EncodeJSON(record)
	if err == nil {
		err = writePrivate(key, data)
	}
	return err
}

func bakeIdentity(state desiredState) ([32]byte, error) {
	data, err := protocol.EncodeJSON(struct {
		Entry Entry
		Floor *Deployment
	}{state.entry(), state.Floor})
	return sha256.Sum256(data), err
}

func (n *Node) bakeState(state *stateReply) {
	if state.Failed == nil {
		state.Failed = map[string]int64{}
	}
	state.BakeRequired = map[string]bool{}
	pending := map[string]bakeRecord{}
	if snapshot := n.stateUnsaved.Load(); snapshot != nil {
		pending = *snapshot
	}
	for name, desired := range state.Desired {
		entry := desired.entry()
		key := n.bakePath(name, entry.Generation)
		record, err := n.readBake(name, entry.Generation)
		_, unsaved := pending[key]
		if retained, exists := pending[key]; exists {
			record, err = retained, nil
		}
		state.BakeRequired[name] = entry.Spec != nil
		if !state.BakeRequired[name] {
			delete(state.Failed, name)
			continue
		}
		identity, identityErr := bakeIdentity(desired)
		if err != nil || identityErr != nil || record.Identity != identity || record.Bake.Finished.IsZero() || record.Bake.Reason != "" || unsaved {
			delete(state.Ready, name)
		}
		if !unsaved && err == nil && identityErr == nil && record.Identity == identity && !record.Bake.Finished.IsZero() && record.Bake.Reason == "" {
			delete(state.Failed, name)
		}
		if record.Bake.Reason != "" {
			state.Failed[name] = entry.Generation
			if record.Bake.Unsaved {
				if state.Unsaved == nil {
					state.Unsaved = map[string]int64{}
				}
				state.Unsaved[name] = entry.Generation
			}
		}
	}
}

func (n *Node) evaluate(ctx context.Context, applied applyResult) (bakeRecord, error) {
	spec, original := applied.spec, applied.service
	identity, err := bakeIdentity(applied.state)
	if err != nil {
		return bakeRecord{}, err
	}
	key := n.bakePath(spec.Name, spec.Generation)
	n.mu.Lock()
	delete(n.starting, spec.Name)
	current := n.desired[spec.Name]
	if !reflect.DeepEqual(current.entry(), applied.state.entry()) || !reflect.DeepEqual(current.Floor, applied.state.Floor) {
		n.mu.Unlock()
		return bakeRecord{}, swarmruntime.ErrSupersededDuringBake
	}
	if done := n.baking[key]; done != nil {
		n.mu.Unlock()
		select {
		case <-ctx.Done():
			return bakeRecord{}, ctx.Err()
		case <-done:
		}
		return n.evaluate(ctx, applied)
	}
	record, err := n.readBake(spec.Name, spec.Generation)
	if pending, exists := n.bakeUnsaved[key]; exists {
		record, err = pending, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		n.mu.Unlock()
		return record, err
	}
	metadataChanged := record.Identity != identity
	record.Generation, record.Image, record.Identity = spec.Generation, spec.Image, identity
	if record.Release == nil {
		record.Release = applied.state.entry().Deployment
	}
	if n.baking == nil {
		n.baking = map[string]chan struct{}{}
	}
	done := make(chan struct{})
	n.baking[key] = done
	n.mu.Unlock()
	defer func() { n.mu.Lock(); delete(n.baking, key); close(done); n.mu.Unlock() }()
	if record.Bake.Reason != "" {
		err := n.retainBakeFailure(n.ctx, spec.Name, key, record)
		return record, errors.Join(errors.New(record.Bake.Reason), err)
	}

	if !record.Bake.Finished.IsZero() {
		if metadataChanged {
			n.mu.Lock()
			err := n.saveBake(key, record)
			n.mu.Unlock()
			return record, err
		}
		return record, nil
	}
	ctx, cancel := context.WithTimeout(ctx, regionWindow(&spec))
	defer cancel()
	ready, err := n.cfg.applier.Wait(ctx, spec, original)
	record.Rollout = bakeRuntime{int64(ready.Running), int64(ready.Ready), ready.Tasks, ready.Revision, ready.StopFirst}
	if err == nil && spec.Deployment != nil && spec.Image == spec.Deployment.Image && record.Rollout.Revision != spec.Deployment.Revision {
		err = errors.New("running image revision does not match the signed release commit")
	}
	if err == nil {
		n.mu.Lock()
		if !record.Bake.Started.IsZero() {
			record.Interruptions++
			slog.WarnContext(ctx, "interrupted regional bake may have an unsaved failure", "service", spec.Name, "generation", spec.Generation, "interruptions", record.Interruptions)
		}
		if record.Interruptions >= maxBakeInterruptions {
			record.Bake.Reason, record.Bake.Finished = "bake could not complete within three attempts", time.Now()
		} else {
			record.Bake.Started = time.Now()
		}
		advanceErr := n.saveBake(key, record)
		if advanceErr != nil {
			record.Bake.Reason, record.Bake.Finished, record.Bake.Unsaved = "bake attempt budget could not be saved", time.Now(), true
			n.bakeUnsaved[key] = record
			n.publishUnsaved()
		}
		n.mu.Unlock()
		if advanceErr != nil {
			return record, advanceErr
		}
		if record.Bake.Reason != "" {
			return record, errors.New(record.Bake.Reason)
		}
		record.Bake, err = n.cfg.applier.Bake(ctx, spec, ready, record.Bake, func(verdict rollout.BakeVerdict) error {
			record.Bake = verdict
			if verdict.Reason != "" {
				return n.retainBakeFailure(n.ctx, spec.Name, key, record)
			}
			n.mu.Lock()
			defer n.mu.Unlock()
			return n.saveBake(key, record)
		})
	} else if n.ctx.Err() == nil && !errors.Is(err, context.Canceled) {
		record.Bake.Reason, record.Bake.Finished = err.Error(), time.Now().UTC()
		err = errors.Join(err, n.retainBakeFailure(n.ctx, spec.Name, key, record))
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if current := n.desired[spec.Name]; !reflect.DeepEqual(current.entry(), applied.state.entry()) || !reflect.DeepEqual(current.Floor, applied.state.Floor) {
		return record, swarmruntime.ErrSupersededDuringBake
	}
	if err == nil {
		n.collectImages(ctx)
	}
	slog.InfoContext(ctx, "regional rollout bake verdict", "region", n.cfg.region, "service", spec.Name, "generation", spec.Generation, "image", spec.Image, "bake", record.Bake)
	return record, err
}

func bakeHeld(rows []Reply, service string) bool {
	if service == "terrabase" {
		return true
	} // A storage format is never rolled back automatically.
	for _, row := range rows {
		if row.Error == noReply || row.Bake != nil && !row.Bake.Started.IsZero() && row.Bake.Reason != "" {
			return true
		}
	}
	return false
}

func bakePhase(v rollout.BakeVerdict) string {
	if v.Finished.IsZero() {
		return fmt.Sprintf(", bake unfinished (%d samples)", v.Samples)
	}
	return fmt.Sprintf(", bake %s (%d samples)", v.Finished.Sub(v.Started), v.Samples)
}

// keptBakes is how many of a service's newest bake records stay beside the
// ones desired state still names: gru had kept 1044 (2026-10-28).
const keptBakes = 5

// pruneBakes deletes old bake records; the caller holds n.mu. Records of a
// desired generation (either candidate) or of a running bake always stay.
func (n *Node) pruneBakes() {
	entries, err := os.ReadDir(n.cfg.dir)
	if err != nil {
		return
	}
	generations := map[string][]int64{}
	for _, entry := range entries {
		name, generation, ok := parseBakeFile(entry.Name())
		if ok {
			generations[name] = append(generations[name], generation)
		}
	}
	for name, list := range generations {
		slices.Sort(list)
		keep := map[int64]bool{}
		for _, generation := range list[max(len(list)-keptBakes, 0):] {
			keep[generation] = true
		}
		for _, entry := range []*Entry{n.desired[name].Operator, n.desired[name].Signed} {
			if entry != nil {
				keep[entry.Generation] = true
			}
		}
		for _, generation := range list {
			path := n.bakePath(name, generation)
			_, unsaved := n.bakeUnsaved[path]
			if keep[generation] || n.baking[path] != nil || unsaved {
				continue
			}
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				slog.Warn("bake record not pruned", "service", name, "generation", generation, "error", err)
			}
		}
	}
}

// parseBakeFile reads "bake-<service>-<generation>.json"; service names may
// contain dashes.
func parseBakeFile(file string) (string, int64, bool) {
	rest, ok := strings.CutPrefix(file, "bake-")
	if !ok {
		return "", 0, false
	}
	rest, ok = strings.CutSuffix(rest, ".json")
	i := strings.LastIndexByte(rest, '-')
	if !ok || i <= 0 {
		return "", 0, false
	}
	generation, err := strconv.ParseInt(rest[i+1:], 10, 64)
	if err != nil || generation <= 0 {
		return "", 0, false
	}
	return rest[:i], generation, true
}

const maxBakeInterruptions = 3
