package app

import (
	"context"
	"sync"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

type switchingFencer struct {
	mu       sync.Mutex
	snapshot authority.Snapshot
}

func (fencer *switchingFencer) Current() authority.Snapshot {
	fencer.mu.Lock()
	defer fencer.mu.Unlock()
	return fencer.snapshot
}

func (*switchingFencer) Guard(context.Context, uint64) error { return nil }

func (fencer *switchingFencer) set(snapshot authority.Snapshot) {
	fencer.mu.Lock()
	fencer.snapshot = snapshot
	fencer.mu.Unlock()
}
