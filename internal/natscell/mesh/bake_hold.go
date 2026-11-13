package mesh

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"
)

type bakeReplacement struct {
	Generation int64      `json:"generation"`
	Release    Deployment `json:"release"`
}

func (n *Node) heldBakeGeneration(name string) int64 {
	current := n.desired[name].entry()
	if !current.needsBake() {
		return 0
	}
	record, _ := n.readBake(name, current.Generation)
	if pending, exists := n.bakeUnsaved[n.bakePath(name, current.Generation)]; exists {
		record = pending
	}
	if record.Bake.Reason != "" {
		return current.Generation
	}
	return 0
}

func (n *Node) checkBakeAdmission(name string, entry Entry) error {
	held := n.heldBakeGeneration(name)
	if held == 0 {
		return nil
	}
	record, err := n.readBake(name, held)
	if pending, exists := n.bakeUnsaved[n.bakePath(name, held)]; exists {
		record, err = pending, nil
	}
	if err != nil {
		return err
	}
	previous, next := record.Release, entry.Deployment
	newer := false
	if previous != nil && next != nil && previous.Accepts(next) == nil {
		oldRun, _ := strconv.ParseUint(previous.RunID, 10, 64)
		newRun, _ := strconv.ParseUint(next.RunID, 10, 64)
		newer = newRun > oldRun || newRun == oldRun && next.RunAttempt > previous.RunAttempt
	}
	if entry.Generation <= held || entry.FirstInstall || !newer {
		return fmt.Errorf("%s held at failed generation %d by release %+v; refused release %+v; repair the cause and release again from a strictly newer signed run or attempt", name, held, previous, next)
	}
	return nil
}

func (n *Node) acceptBakeReplacement(name string, entry Entry) error {
	if err := n.checkBakeAdmission(name, entry); err != nil {
		return err
	}
	held := n.heldBakeGeneration(name)
	if held == 0 {
		return nil
	}
	key := n.bakePath(name, held)
	record, err := n.readBake(name, held)
	if pending, exists := n.bakeUnsaved[key]; exists {
		record, err = pending, nil
	}
	if err != nil {
		return err
	}
	record.ReplacedBy = &bakeReplacement{Generation: entry.Generation, Release: *entry.Deployment}
	return n.saveBake(key, record)
}

func (n *Node) retainBakeFailure(ctx context.Context, name, key string, record bakeRecord) error {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		n.mu.Lock()
		latest, _ := n.readBake(name, record.Generation)
		if pending, exists := n.bakeUnsaved[key]; exists {
			latest = pending
		}
		if latest.ReplacedBy != nil {
			record.ReplacedBy = latest.ReplacedBy
		}
		err := n.saveBake(key, record)
		n.mu.Unlock()
		if err == nil {
			return nil
		}
		slog.Error("regional bake failed, unsaved", "service", name, "generation", record.Generation, "error", err)
		select {
		case <-ctx.Done():
			return errors.Join(err, ctx.Err())
		case <-tick.C:
		}
	}
}
