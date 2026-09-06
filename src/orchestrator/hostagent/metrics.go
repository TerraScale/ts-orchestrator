package hostagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HostMetrics is measured by the host agent and travels inside its signed
// status report. Queue fields are optional; CPU and memory are required by
// autoscale admission when configured there.
type HostMetrics struct {
	ObservationSequence int64   `json:"observationSequence"`
	BootGeneration      string  `json:"bootGeneration"`
	ObservedAtUnixMS    int64   `json:"observedAtUnixMs"`
	CPUPercent          float64 `json:"cpuPercent"`
	MemoryPercent       float64 `json:"memoryPercent"`
	QueueDepth          int     `json:"queueDepth,omitempty"`
	QueueCapacity       int     `json:"queueCapacity,omitempty"`
}

// OSHostMetrics samples /proc and persists its sequence atomically. The first
// CPU sample is intentionally unavailable because a delta needs two reads.
type OSHostMetrics struct {
	statePath string
	mu        sync.Mutex
	previous  cpuSample
}

type cpuSample struct{ total, idle uint64 }

func NewOSHostMetrics(statePath string) (*OSHostMetrics, error) {
	if statePath == "" || !filepath.IsAbs(statePath) || filepath.Clean(statePath) != statePath {
		return nil, errors.New("host metrics state path is invalid")
	}
	return &OSHostMetrics{statePath: statePath}, nil
}

func (s *OSHostMetrics) Sample(ctx context.Context) (HostMetrics, error) {
	if s == nil || ctx == nil {
		return HostMetrics{}, errors.New("host metrics source is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return HostMetrics{}, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) == "" {
		return HostMetrics{}, errors.New("host boot generation is unavailable")
	}
	total, idle, err := readCPU()
	if err != nil {
		return HostMetrics{}, err
	}
	totalMemory, availableMemory, err := readMemory()
	if err != nil || totalMemory == 0 || availableMemory > totalMemory {
		return HostMetrics{}, errors.New("host memory metrics are unavailable")
	}
	s.mu.Lock()
	previous := s.previous
	s.previous = cpuSample{total: total, idle: idle}
	s.mu.Unlock()
	if previous.total == 0 || total <= previous.total || idle < previous.idle {
		return HostMetrics{}, nil
	}
	sequence, err := s.nextSequence(strings.TrimSpace(string(boot)))
	if err != nil {
		return HostMetrics{}, err
	}
	busy := float64((total-previous.total)-(idle-previous.idle)) / float64(total-previous.total) * 100
	memory := float64(totalMemory-availableMemory) / float64(totalMemory) * 100
	return HostMetrics{ObservationSequence: sequence, BootGeneration: strings.TrimSpace(string(boot)), ObservedAtUnixMS: time.Now().UnixMilli(), CPUPercent: busy, MemoryPercent: memory}, nil
}

func readCPU() (uint64, uint64, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		var total, idle uint64
		for _, value := range fields[1:] {
			n, parseErr := strconv.ParseUint(value, 10, 64)
			if parseErr != nil {
				return 0, 0, parseErr
			}
			total += n
		}
		idle, err = strconv.ParseUint(fields[4], 10, 64)
		return total, idle, err
	}
	return 0, 0, errors.New("cpu metrics are unavailable")
}

func readMemory() (uint64, uint64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	var total, available uint64
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		n, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			return 0, 0, parseErr
		}
		switch fields[0] {
		case "MemTotal:":
			total = n
		case "MemAvailable:":
			available = n
		}
	}
	return total, available, nil
}

func (s *OSHostMetrics) nextSequence(boot string) (int64, error) {
	raw, _ := os.ReadFile(s.statePath)
	parts := strings.SplitN(strings.TrimSpace(string(raw)), ":", 2)
	sequence := int64(0)
	if len(parts) == 2 && parts[0] == boot {
		sequence, _ = strconv.ParseInt(parts[1], 10, 64)
	}
	sequence++
	tmp := s.statePath + ".tmp"
	if err := os.WriteFile(tmp, []byte(boot+":"+strconv.FormatInt(sequence, 10)), 0600); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, s.statePath); err != nil {
		return 0, err
	}
	return sequence, nil
}
