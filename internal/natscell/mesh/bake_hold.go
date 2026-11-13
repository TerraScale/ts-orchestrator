package mesh

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

type bakeReplacement struct {
	Generation int64      `json:"generation"`
	Release    Deployment `json:"release"`
}

func (n *Node) heldBakeGeneration(name string) int64 {
	current := n.desired[name].entry()
	if current.Deployment == nil {
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
	if held != 0 && (entry.Deployment == nil || entry.Generation <= held) {
		return fmt.Errorf("%s held at failed generation %d; repair the cause and release again with the same digest or a corrected image", name, held)
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
