package app

import (
	"sync"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

// hostTelemetry owns collection freshness even when no scaling policy uses it.
type hostTelemetry struct {
	mu     sync.Mutex
	fencer authority.Fencer
	load   *hostload.Aggregator
	epoch  uint64
}

// current is called with mu held before accepting or charting reports.
func (t *hostTelemetry) current() bool {
	snapshot := t.fencer.Current()
	if !snapshot.CanMutate() {
		t.load.Reset()
		t.epoch = 0
		return false
	}
	if t.epoch != snapshot.Epoch {
		t.load.Reset()
		t.epoch = snapshot.Epoch
	}
	return true
}

func (t *hostTelemetry) record(origin hostload.Origin, report hostload.Report) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.current() {
		return authority.ErrFenced
	}
	return t.load.Record(origin, report)
}

func (t *hostTelemetry) samples() []observability.Sample {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.current() {
		return nil
	}
	return hostLoadSamples(t.load)
}
