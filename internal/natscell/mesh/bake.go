package mesh

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

// One local record per generation retains evidence across restarts and later
// fix-forward releases. Only a completed successful bake admits the next region.
type bakeRecord struct {
	Generation int64               `json:"generation"`
	Image      string              `json:"image"`
	Identity   [32]byte            `json:"identity"`
	Rollout    bakeRuntime         `json:"runtime"`
	Bake       rollout.BakeVerdict `json:"bake"`
}

type bakeRuntime struct {
	Running, Ready int64 // elapsed nanoseconds; protocol JSON has no implicit duration encoding
	Tasks          []swarmruntime.ServiceTaskEvidence
	Revision       string
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
		n.bakeUnsaved[key] = record
	} else {
		delete(n.bakeUnsaved, key)
	}
	return err
}

func writeBake(key string, record bakeRecord) error {
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

// bakeState is called with n.mu held. Readiness alone never releases a region.
func (n *Node) bakeState(state *stateReply) {
	if state.Failed == nil {
		state.Failed = map[string]int64{}
	}
	for name, desired := range n.desired {
		entry := desired.entry()
		if entry.Spec == nil {
			continue
		}
		record, err := n.readBake(name, entry.Generation)
		_, unsaved := n.bakeUnsaved[n.bakePath(name, entry.Generation)]
		identity, identityErr := bakeIdentity(desired)
		if unsaved || err != nil || identityErr != nil || record.Identity != identity || record.Bake.Finished.IsZero() || record.Bake.Reason != "" {
			delete(state.Ready, name)
		}
		if err == nil && record.Bake.Reason != "" && n.baking[n.bakePath(name, entry.Generation)] == nil {
			state.Failed[name] = entry.Generation
		}
		if !unsaved && err == nil && identityErr == nil && record.Identity == identity && !record.Bake.Finished.IsZero() && record.Bake.Reason == "" {
			delete(state.Failed, name)
		}
	}
}

// evaluate coalesces CLI and anti-entropy work. An interrupted bake restarts
// its full window; a failed one stays held until a new generation fixes forward.
func (n *Node) evaluate(ctx context.Context, applied applyResult) (bakeRecord, error) {
	spec, original := applied.spec, applied.service
	identity, err := bakeIdentity(applied.state)
	if err != nil {
		return bakeRecord{}, err
	}
	key := n.bakePath(spec.Name, spec.Generation)
	n.mu.Lock()
	current := n.desired[spec.Name]
	if !reflect.DeepEqual(current.entry(), applied.state.entry()) || !reflect.DeepEqual(current.Floor, applied.state.Floor) {
		n.mu.Unlock()
		return bakeRecord{}, errors.New("release superseded before bake")
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
	if record, ok := n.bakeUnsaved[key]; ok {
		err := n.saveBake(key, record)
		n.mu.Unlock()
		if record.Bake.Reason != "" {
			err = errors.Join(err, errors.New(record.Bake.Reason))
		}
		return record, err
	}
	record, err := n.readBake(spec.Name, spec.Generation)
	if err == nil && record.Identity == identity && (!record.Bake.Finished.IsZero() || record.Bake.Reason != "") {
		n.mu.Unlock()
		if record.Bake.Reason != "" {
			return record, errors.New(record.Bake.Reason)
		}
		return record, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		n.mu.Unlock()
		return record, err
	}
	if n.baking == nil {
		n.baking = map[string]chan struct{}{}
	}
	done := make(chan struct{})
	n.baking[key] = done
	n.mu.Unlock()
	defer func() { n.mu.Lock(); delete(n.baking, key); close(done); n.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(ctx, regionWindow(&spec))
	defer cancel()
	record = bakeRecord{Generation: spec.Generation, Image: spec.Image, Identity: identity}
	// Persist a fail-closed latch before observing the candidate. A crash or
	// failed verdict write must never erase a detected regression on restart.
	record.Bake = rollout.BakeVerdict{Started: time.Now().UTC(), Reason: "bake interrupted before durable verdict; publish a new generation"}
	if err := writeBake(key, record); err != nil {
		return record, err
	}
	record.Bake = rollout.BakeVerdict{} // The bake starts only after readiness succeeds.
	ready, err := n.cfg.applier.Wait(ctx, spec, original)
	record.Rollout = bakeRuntime{int64(ready.Running), int64(ready.Ready), ready.Tasks, ready.Revision}
	if err == nil && spec.Deployment != nil && spec.Image == spec.Deployment.Image && record.Rollout.Revision != spec.Deployment.Revision {
		err = errors.New("running image revision does not match the signed release commit")
	}
	if err == nil {
		record.Bake, err = n.cfg.applier.Bake(ctx, spec, ready)
	}
	if n.ctx.Err() != nil && (err == nil || errors.Is(err, context.Canceled)) {
		record.Bake = rollout.BakeVerdict{} // A clean shutdown can restart its window.
		return record, errors.Join(n.ctx.Err(), writeBake(key, record))
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if current := n.desired[spec.Name]; !reflect.DeepEqual(current.entry(), applied.state.entry()) || !reflect.DeepEqual(current.Floor, applied.state.Floor) {
		err = errors.New("release superseded during bake")
	}
	if err != nil {
		record.Bake.Reason = err.Error()
	}
	if record.Bake.Finished.IsZero() {
		record.Bake.Finished = time.Now().UTC()
	}
	saveErr := n.saveBake(key, record)
	slog.InfoContext(ctx, "regional rollout bake verdict", "region", n.cfg.region, "service", spec.Name, "generation", spec.Generation, "image", spec.Image, "bake", record.Bake, "save_error", saveErr)
	return record, errors.Join(err, saveErr)
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
