package app

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/hostload"
)

type metricTestFence struct{ switchingFencer }

func (f *metricTestFence) Guard(_ context.Context, epoch uint64) error {
	snapshot := f.Current()
	if !snapshot.CanMutate() || snapshot.Epoch != epoch {
		return authority.ErrFenced
	}
	return nil
}

func overflowingHostMetricLoad(t *testing.T, epoch uint64, at time.Time) *hostTelemetry {
	t.Helper()

	fence := &metricTestFence{}
	fence.set(authority.Snapshot{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Ready: true, Leader: true, Epoch: epoch, Revision: 1, ExpiresAt: time.Now().Add(time.Hour)})
	load := &hostTelemetry{fencer: fence, load: hostload.NewAggregator(hostload.AggregatorConfig{
		Now: func() time.Time { return at },
	})}
	cpu, cores, memory := 0.4, 0.125, uint64(1024)
	report := hostload.Report{SchemaVersion: hostload.SchemaVersion,
		Host: hostload.HostUsage{CPU: &cpu, Memory: &cpu, Disk: &cpu}}
	for role := range hostload.MaxRoles {
		report.Roles = append(report.Roles, hostload.RoleUsage{Role: fmt.Sprintf("role-%02d", role), CPUCores: &cores, MemoryBytes: &memory})
	}
	// Changing report and node arrival order cannot change capacity selection.
	for node := 61; node >= 0; node-- {
		copy := report
		copy.Roles = slices.Clone(report.Roles)
		if node%2 == 0 {
			slices.Reverse(copy.Roles)
		}
		if err := load.record(hostload.Origin{Cell: "gru", Environment: "production", Node: fmt.Sprintf("host-%03d", node)}, copy); err != nil {
			t.Fatal(err)
		}
	}
	return load
}
