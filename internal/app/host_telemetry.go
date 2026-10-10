package app

import (
	"context"
	"maps"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

// hostTelemetry owns collection freshness even when no scaling policy uses it.
type hostTelemetry struct {
	mu       sync.Mutex
	fencer   authority.Fencer
	load     *hostload.Aggregator
	epoch    uint64
	requests map[string]hostload.Request
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

// Utilization windows cannot mix samples normalized against different requests.
func (t *hostTelemetry) setResources(resources map[string]placement.Resources) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.setRequests(loadRequests(resources))
}

// setRequests is called with mu held, including throughout usage recording.
func (t *hostTelemetry) setRequests(requests map[string]hostload.Request) {
	if maps.Equal(t.requests, requests) {
		return
	}
	t.requests = requests
	t.load.Reset()
	t.load.SetRequests(requests)
}

func (t *hostTelemetry) recordCommitted(ctx context.Context, history *nativeHistory, usage *runtimeObservability,
	origin hostload.Origin, report hostload.Report,
) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	desired, err := history.hosts.ListDesired(ctx, "")
	if err != nil {
		return err
	}
	resources, err := history.resources(ctx, desired, profileResources(history.services.profiles()))
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.current() {
		return authority.ErrFenced
	}
	t.setRequests(loadRequests(resources))
	return usage.recordHostLoad(t.load.Record, origin, report, t.requests)
}
