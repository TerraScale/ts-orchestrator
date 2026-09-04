package vmqual

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

func TestResourceSamplerRecordsKernelHighWaterAndPeriodicCPU(t *testing.T) {
	t.Parallel()
	stack := &Stack{
		guests:   []Guest{{ID: "gru-member-1", Region: vmnet.GRU, MemoryMiB: 512}},
		resource: make(map[string]VMResourceReport),
		journal: &Journal{VMs: []JournalVM{{
			ID: "gru-member-1", Region: string(vmnet.GRU), CgroupPath: "/owned/gru-member-1",
		}}},
	}
	sampler, err := newStackResourceSampler(stack, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	sampler.now = func() time.Time { return now }
	samples := []kernelCgroupSample{
		{CurrentMemoryBytes: 100, PeakMemoryBytes: 175, CPUUsageUsec: 1_000},
		{CurrentMemoryBytes: 125, PeakMemoryBytes: 250, CPUUsageUsec: 251_000},
	}
	sampler.read = func(path string) (kernelCgroupSample, error) {
		if path != "/owned/gru-member-1" {
			t.Fatalf("sampled path = %q", path)
		}
		sample := samples[0]
		samples = samples[1:]
		return sample, nil
	}
	if err := sampler.sample(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(500 * time.Millisecond)
	if err := sampler.sample(context.Background()); err != nil {
		t.Fatal(err)
	}
	report := stack.ResourceReport()
	if report.PeakRSSBytes != 250 || len(report.VMs) != 1 || report.VMs[0].PeakRSSBytes != 250 {
		t.Fatalf("kernel memory high-water report = %+v", report)
	}
	if report.VMs[0].ConfiguredMemoryMiB != 512 || report.VMs[0].Region != vmnet.GRU {
		t.Fatalf("VM identity report = %+v", report.VMs[0])
	}
	if math.Abs(report.PeakIdleCPU-0.5) > 0.000001 || math.Abs(report.VMs[0].PeakIdleCPU-0.5) > 0.000001 {
		t.Fatalf("periodic CPU high-water = stack %g VM %g", report.PeakIdleCPU, report.VMs[0].PeakIdleCPU)
	}
	sampler.finished = now.Add(time.Millisecond)
	sampling := sampler.Report()
	if err := sampling.Validate(stack.guests); err != nil {
		t.Fatal(err)
	}
	if len(sampling.VMs) != 1 || sampling.VMs[0].MemorySamples != 2 || sampling.VMs[0].CPUSamples != 1 {
		t.Fatalf("sampling provenance = %+v", sampling)
	}
}

func TestResourceSamplerUsesConservativeAggregateKernelHighWater(t *testing.T) {
	t.Parallel()
	stack := &Stack{
		guests: []Guest{
			{ID: "gru-member-1", Region: vmnet.GRU, MemoryMiB: 256},
			{ID: "sfo-member-1", Region: vmnet.SFO, MemoryMiB: 256},
		},
		resource: make(map[string]VMResourceReport),
		journal: &Journal{VMs: []JournalVM{
			{ID: "gru-member-1", Region: string(vmnet.GRU), CgroupPath: "/owned/gru"},
			{ID: "sfo-member-1", Region: string(vmnet.SFO), CgroupPath: "/owned/sfo"},
		}},
	}
	sampler, err := newStackResourceSampler(stack, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sampler.now = func() time.Time { return time.Unix(1, 0) }
	sampler.read = func(path string) (kernelCgroupSample, error) {
		switch path {
		case "/owned/gru":
			return kernelCgroupSample{CurrentMemoryBytes: 80, PeakMemoryBytes: 120, CPUUsageUsec: 1}, nil
		case "/owned/sfo":
			return kernelCgroupSample{CurrentMemoryBytes: 90, PeakMemoryBytes: 140, CPUUsageUsec: 1}, nil
		default:
			return kernelCgroupSample{}, errors.New("unexpected path")
		}
	}
	if err := sampler.sample(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := stack.ResourceReport().PeakRSSBytes; got != 260 {
		t.Fatalf("aggregate kernel high-water = %d, want 260", got)
	}
}

func TestReadKernelCgroupSampleStrictAndBounded(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeCgroupEvidence(t, root, "memory.current", "1024\n")
	writeCgroupEvidence(t, root, "memory.peak", "2048\n")
	writeCgroupEvidence(t, root, "cpu.stat", "usage_usec 300\nuser_usec 200\nsystem_usec 100\n")
	sample, err := readKernelCgroupSample(root)
	if err != nil {
		t.Fatal(err)
	}
	if sample.CurrentMemoryBytes != 1024 || sample.PeakMemoryBytes != 2048 || sample.CPUUsageUsec != 300 {
		t.Fatalf("sample = %+v", sample)
	}

	writeCgroupEvidence(t, root, "cpu.stat", "usage_usec 300\nusage_usec 301\n")
	if _, err := readKernelCgroupSample(root); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate usage error = %v", err)
	}
	writeCgroupEvidence(t, root, "cpu.stat", strings.Repeat("x", maximumCgroupEvidenceBytes+1))
	if _, err := readKernelCgroupSample(root); err == nil || !strings.Contains(err.Error(), "bound") {
		t.Fatalf("oversized cpu.stat error = %v", err)
	}
}

func TestReadKernelCgroupSampleRejectsSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("1024\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "memory.current")); err != nil {
		t.Fatal(err)
	}
	writeCgroupEvidence(t, root, "memory.peak", "2048\n")
	writeCgroupEvidence(t, root, "cpu.stat", "usage_usec 1\n")
	if _, err := readKernelCgroupSample(root); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("symlink error = %v", err)
	}
}

func TestResourceSamplingReportRejectsMissingCPUAndUnknownVM(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	guests := []Guest{{ID: "gru-member-1"}}
	report := ResourceSamplingReport{
		Source: "cgroup-v2:memory.current,memory.peak,cpu.stat", Interval: time.Millisecond,
		StartedAt: now, FinishedAt: now.Add(time.Second),
		VMs: []ResourceSamplingVM{{ID: "gru-member-1", MemorySamples: 1}},
	}
	if err := report.Validate(guests); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("missing CPU validation error = %v", err)
	}
	report.VMs[0].CPUSamples = 1
	report.VMs = append(report.VMs, ResourceSamplingVM{ID: "unknown", MemorySamples: 1, CPUSamples: 1})
	if err := report.Validate(guests); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown VM validation error = %v", err)
	}
}

func writeCgroupEvidence(t *testing.T, root, name, payload string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(payload), 0600); err != nil {
		t.Fatal(err)
	}
}
