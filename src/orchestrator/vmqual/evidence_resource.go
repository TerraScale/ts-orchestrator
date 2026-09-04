package vmqual

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

const (
	defaultStackResourceSampleInterval = 100 * time.Millisecond
	maximumCgroupEvidenceBytes         = 4096
)

// stackResourceSampler records kernel-maintained cgroup memory high-water
// marks and periodic aggregate memory/CPU observations while the suite is
// running. It deliberately does not call VM.Inspect: doing that in the
// background would reset the provider's CPU delta and could make the explicit
// idle-budget sample depend on scheduler timing.
type stackResourceSampler struct {
	stack    *Stack
	interval time.Duration
	now      func() time.Time
	read     func(string) (kernelCgroupSample, error)

	mu       sync.Mutex
	previous map[string]kernelCPUPoint
	counts   map[string]ResourceSamplingVM
	started  time.Time
	finished time.Time
	err      error
	cancel   context.CancelFunc
	done     chan struct{}
	stopOnce sync.Once
}

type kernelCgroupSample struct {
	CurrentMemoryBytes uint64
	PeakMemoryBytes    uint64
	CPUUsageUsec       uint64
}

type kernelCPUPoint struct {
	path      string
	usageUsec uint64
	at        time.Time
}

type cgroupEvidenceTarget struct {
	id        string
	region    vmnet.RegionCode
	memoryMiB int64
	path      string
}

// ResourceSamplingReport proves where the peak figures came from and how
// often every VM was observed. A successful full suite requires both kernel
// memory high-water and periodic CPU samples for all six guests.
type ResourceSamplingReport struct {
	Source     string               `json:"source"`
	Interval   time.Duration        `json:"interval"`
	StartedAt  time.Time            `json:"startedAt"`
	FinishedAt time.Time            `json:"finishedAt"`
	VMs        []ResourceSamplingVM `json:"vms"`
}

type ResourceSamplingVM struct {
	ID            string `json:"id"`
	MemorySamples uint64 `json:"memorySamples"`
	CPUSamples    uint64 `json:"cpuSamples"`
}

func newStackResourceSampler(stack *Stack, interval time.Duration) (*stackResourceSampler, error) {
	if stack == nil {
		return nil, errors.New("vmqual: resource sampler stack is nil")
	}
	if interval <= 0 {
		interval = defaultStackResourceSampleInterval
	}
	return &stackResourceSampler{
		stack:    stack,
		interval: interval,
		now:      time.Now,
		read:     readKernelCgroupSample,
		previous: make(map[string]kernelCPUPoint),
		counts:   make(map[string]ResourceSamplingVM),
	}, nil
}

// startStackResourceSampler begins suite-lifetime resource observation. Stop
// must run before Stack.Cleanup removes the owned cgroups.
func startStackResourceSampler(ctx context.Context, stack *Stack) (*stackResourceSampler, error) {
	if ctx == nil {
		return nil, errors.New("vmqual: resource sampler context is nil")
	}
	sampler, err := newStackResourceSampler(stack, defaultStackResourceSampleInterval)
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	sampler.cancel = cancel
	sampler.done = make(chan struct{})
	go sampler.run(runCtx)
	return sampler, nil
}

func (s *stackResourceSampler) run(ctx context.Context) {
	defer close(s.done)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.sample(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				s.recordError(err)
			}
		}
	}
}

// Stop is idempotent. It takes one last kernel sample after stopping the
// ticker so a scenario-ending high-water mark is captured before cleanup.
func (s *stackResourceSampler) Stop() error {
	if s == nil {
		return nil
	}
	s.stopOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		if s.done != nil {
			<-s.done
		}
		finalCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := s.sample(finalCtx); err != nil {
			s.recordError(err)
		}
		s.mu.Lock()
		s.finished = time.Now().UTC()
		s.mu.Unlock()
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *stackResourceSampler) Report() ResourceSamplingReport {
	if s == nil {
		return ResourceSamplingReport{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	report := ResourceSamplingReport{
		Source:     "cgroup-v2:memory.current,memory.peak,cpu.stat",
		Interval:   s.interval,
		StartedAt:  s.started,
		FinishedAt: s.finished,
		VMs:        make([]ResourceSamplingVM, 0, len(s.counts)),
	}
	for _, observation := range s.counts {
		report.VMs = append(report.VMs, observation)
	}
	sort.Slice(report.VMs, func(i, j int) bool { return report.VMs[i].ID < report.VMs[j].ID })
	return report
}

func (r ResourceSamplingReport) Validate(guests []Guest) error {
	if r.Source != "cgroup-v2:memory.current,memory.peak,cpu.stat" || r.Interval <= 0 || r.StartedAt.IsZero() || r.FinishedAt.Before(r.StartedAt) {
		return errors.New("vmqual: kernel resource sampling evidence is incomplete")
	}
	observed := make(map[string]ResourceSamplingVM, len(r.VMs))
	for _, sample := range r.VMs {
		if sample.ID == "" || sample.MemorySamples == 0 || sample.CPUSamples == 0 || observed[sample.ID].ID != "" {
			return errors.New("vmqual: per-VM resource sampling evidence is incomplete")
		}
		observed[sample.ID] = sample
	}
	for _, guest := range guests {
		if observed[guest.ID].ID == "" {
			return fmt.Errorf("vmqual: VM %s has no kernel resource sampling evidence", guest.ID)
		}
	}
	if len(observed) != len(guests) {
		return errors.New("vmqual: resource sampling contains an unknown VM")
	}
	return nil
}

func (s *stackResourceSampler) recordError(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	s.err = errors.Join(s.err, err)
	s.mu.Unlock()
}

func (s *stackResourceSampler) sample(ctx context.Context) error {
	if s == nil || s.stack == nil {
		return errors.New("vmqual: resource sampler is not configured")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	targets := s.stack.cgroupEvidenceTargets()
	if len(targets) == 0 {
		return nil
	}
	now := s.now()
	observations := make([]sampledCgroupEvidence, 0, len(targets))
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		sample, err := s.read(target.path)
		if errors.Is(err, os.ErrNotExist) {
			// A planned VM has no cgroup before its VMM starts, and a crashed VM
			// may lose it before the recovery scenario finishes.
			continue
		}
		if err != nil {
			return fmt.Errorf("vmqual: sample owned cgroup %s: %w", target.id, err)
		}
		observation := sampledCgroupEvidence{target: target, sample: sample}
		s.mu.Lock()
		previous, ok := s.previous[target.id]
		if ok && previous.path == target.path && now.After(previous.at) && sample.CPUUsageUsec >= previous.usageUsec {
			elapsedUsec := float64(now.Sub(previous.at)) / float64(time.Microsecond)
			if elapsedUsec > 0 {
				observation.cpuCores = float64(sample.CPUUsageUsec-previous.usageUsec) / elapsedUsec
				observation.cpuSampled = true
			}
		}
		s.previous[target.id] = kernelCPUPoint{path: target.path, usageUsec: sample.CPUUsageUsec, at: now}
		s.mu.Unlock()
		observations = append(observations, observation)
	}
	if len(observations) != 0 {
		s.mu.Lock()
		if s.started.IsZero() {
			s.started = now.UTC()
		}
		for _, observation := range observations {
			count := s.counts[observation.target.id]
			count.ID = observation.target.id
			count.MemorySamples++
			if observation.cpuSampled {
				count.CPUSamples++
			}
			s.counts[observation.target.id] = count
		}
		s.mu.Unlock()
	}
	s.stack.recordKernelResourceSamples(observations)
	return nil
}

type sampledCgroupEvidence struct {
	target     cgroupEvidenceTarget
	sample     kernelCgroupSample
	cpuCores   float64
	cpuSampled bool
}

func (s *Stack) cgroupEvidenceTargets() []cgroupEvidenceTarget {
	if s == nil {
		return nil
	}
	memoryByID := make(map[string]int64, len(s.guests))
	for _, guest := range s.guests {
		memoryByID[guest.ID] = guest.MemoryMiB
	}
	s.journalMu.Lock()
	defer s.journalMu.Unlock()
	if s.journal == nil {
		return nil
	}
	targets := make([]cgroupEvidenceTarget, 0, len(s.journal.VMs))
	for _, resource := range s.journal.VMs {
		if resource.ID == "" || resource.CgroupPath == "" || resource.Cleaned {
			continue
		}
		targets = append(targets, cgroupEvidenceTarget{
			id:        resource.ID,
			region:    vmnet.RegionCode(resource.Region),
			memoryMiB: memoryByID[resource.ID],
			path:      resource.CgroupPath,
		})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].id < targets[j].id })
	return targets
}

func (s *Stack) recordKernelResourceSamples(samples []sampledCgroupEvidence) {
	if s == nil || len(samples) == 0 {
		return
	}
	var aggregateCurrent uint64
	var aggregateKernelHighWater uint64
	var aggregateCPU float64
	for _, observation := range samples {
		aggregateCurrent = saturatingAddUint64(aggregateCurrent, observation.sample.CurrentMemoryBytes)
		aggregateKernelHighWater = saturatingAddUint64(aggregateKernelHighWater, observation.sample.PeakMemoryBytes)
		if observation.cpuSampled {
			aggregateCPU += observation.cpuCores
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, observation := range samples {
		measurement := s.resource[observation.target.id]
		measurement.ID = observation.target.id
		measurement.Region = observation.target.region
		if measurement.ConfiguredMemoryMiB == 0 {
			measurement.ConfiguredMemoryMiB = observation.target.memoryMiB
		}
		if observation.sample.PeakMemoryBytes > measurement.PeakRSSBytes {
			measurement.PeakRSSBytes = observation.sample.PeakMemoryBytes
		}
		if observation.cpuSampled && observation.cpuCores > measurement.PeakIdleCPU {
			measurement.PeakIdleCPU = observation.cpuCores
		}
		s.resource[observation.target.id] = measurement
	}
	// memory.peak is maintained by the kernel and cannot miss a short-lived
	// allocation between controller samples. Summing the per-VM marks is a
	// conservative stack high-water; aggregateCurrent retains simultaneous
	// observations when that is larger.
	peak := aggregateKernelHighWater
	if aggregateCurrent > peak {
		peak = aggregateCurrent
	}
	if peak > s.peakRSSBytes {
		s.peakRSSBytes = peak
	}
	if aggregateCPU > s.peakIdleCPU {
		s.peakIdleCPU = aggregateCPU
	}
}

func saturatingAddUint64(left, right uint64) uint64 {
	if ^uint64(0)-left < right {
		return ^uint64(0)
	}
	return left + right
}

func readKernelCgroupSample(cgroupPath string) (kernelCgroupSample, error) {
	if !filepath.IsAbs(cgroupPath) || filepath.Clean(cgroupPath) == string(filepath.Separator) {
		return kernelCgroupSample{}, errors.New("invalid cgroup evidence path")
	}
	current, err := readBoundedUintFile(filepath.Join(cgroupPath, "memory.current"))
	if err != nil {
		return kernelCgroupSample{}, err
	}
	peak, err := readBoundedUintFile(filepath.Join(cgroupPath, "memory.peak"))
	if err != nil {
		return kernelCgroupSample{}, err
	}
	cpu, err := readCPUUsageUsec(filepath.Join(cgroupPath, "cpu.stat"))
	if err != nil {
		return kernelCgroupSample{}, err
	}
	if peak < current {
		return kernelCgroupSample{}, errors.New("kernel memory peak is below current usage")
	}
	return kernelCgroupSample{CurrentMemoryBytes: current, PeakMemoryBytes: peak, CPUUsageUsec: cpu}, nil
}

func readBoundedUintFile(path string) (uint64, error) {
	payload, err := readBoundedEvidenceFile(path, maximumCgroupEvidenceBytes)
	if err != nil {
		return 0, err
	}
	value := strings.TrimSpace(string(payload))
	if value == "" || strings.ContainsAny(value, " \t\r\n") {
		return 0, errors.New("invalid numeric cgroup evidence")
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, errors.New("invalid numeric cgroup evidence")
	}
	return parsed, nil
}

func readCPUUsageUsec(path string) (uint64, error) {
	payload, err := readBoundedEvidenceFile(path, maximumCgroupEvidenceBytes)
	if err != nil {
		return 0, err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(payload)))
	found := false
	var usage uint64
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			return 0, errors.New("invalid cpu.stat evidence")
		}
		if fields[0] != "usage_usec" {
			continue
		}
		if found {
			return 0, errors.New("duplicate cpu.stat usage evidence")
		}
		usage, err = strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, errors.New("invalid cpu.stat usage evidence")
		}
		found = true
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	if !found {
		return 0, errors.New("cpu.stat has no usage_usec evidence")
	}
	return usage, nil
}

func readBoundedEvidenceFile(path string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("invalid evidence read limit")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("evidence source is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(before, info) {
		return nil, errors.New("evidence source changed while opening")
	}
	payload, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > limit {
		return nil, errors.New("evidence source exceeds its read bound")
	}
	return payload, nil
}
