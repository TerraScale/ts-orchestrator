// This file implements the node metrics source of the host agent: the
// MetricsSource seam and the SystemMetricsSource that maps /proc/meminfo and
// /proc/loadavg data into the validated NodeMetricsSample of contracts.go.
package hostagent

import (
	"context"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
)

// MetricsSource produces one validated node metric sample on demand; the
// heartbeat publisher is its only consumer.
type MetricsSource interface {
	// Sample reads the node's current metric dimensions.
	Sample(ctx context.Context) (NodeMetricsSample, error)
}

// PendingAllocationCounter reports how many accepted allocations have not been
// observed running yet; WorkloadExecutor implements it.
type PendingAllocationCounter interface {
	PendingAllocations() int
}

// RunningAllocationCounter reports how many of the node's own tracked
// allocations are running; WorkloadExecutor implements it. The heartbeat's
// running-task gauge must come from here, not from the kernel's host-wide
// running-entity count: the autoscaler's retire gate reads the gauge as "the
// node's own running allocations", and a shared development host always has
// host-wide runnable entities even when the node hosts none.
type RunningAllocationCounter interface {
	RunningAllocations() int
}

// ProcFileReader reads one /proc file by its exact path; injectable for tests.
type ProcFileReader interface {
	ReadFile(path string) ([]byte, error)
}

// The two exact proc paths the metrics source reads; no other path is admitted.
const (
	procMeminfoPath = "/proc/meminfo"
	procLoadavgPath = "/proc/loadavg"
)

// OsProcFileReader reads real /proc files. It refuses every path other than
// the two the metrics source needs, so it cannot be misused as a generic file
// reader.
type OsProcFileReader struct{}

// ReadFile reads one admitted /proc file from the local filesystem.
func (OsProcFileReader) ReadFile(path string) ([]byte, error) {
	if path != procMeminfoPath && path != procLoadavgPath {
		return nil, &ArgumentError{
			Param:   "path",
			Message: "Only the meminfo and loadavg proc files are read.",
		}
	}
	return os.ReadFile(path)
}

// SystemMetricsSourceConfig is the fully explicit configuration of one system
// metrics source; the CPU envelope, task ceiling, and CPU count come from the
// node profile, never from ambient environment reads.
type SystemMetricsSourceConfig struct {
	// ProcReader reads the proc files; OsProcFileReader is the live spelling.
	ProcReader ProcFileReader
	// CpuQuotaPercent is the node's CPU envelope in percent (1..10000).
	CpuQuotaPercent int
	// TasksMax is the node's task ceiling.
	TasksMax int
	// LogicalCpuCount scales the load average into a CPU percent.
	LogicalCpuCount int
	// Pending optionally reports the node's pending allocation count; nil
	// reports zero.
	Pending PendingAllocationCounter
	// Running optionally reports the node's running allocation count, the
	// heartbeat's task gauge; nil falls back to the kernel's running
	// scheduling entities from /proc/loadavg, a host-wide figure that is not
	// the node's own allocation count.
	Running RunningAllocationCounter
}

// SystemMetricsSource maps /proc/meminfo and /proc/loadavg data into one
// validated NodeMetricsSample. Saturated dimensions report the full envelope
// rather than failing the sample, so heartbeats keep flowing exactly when the
// autoscaler needs them most.
type SystemMetricsSource struct {
	procReader      ProcFileReader
	cpuQuotaPercent int
	tasksMax        int
	logicalCpuCount int
	pending         PendingAllocationCounter
	running         RunningAllocationCounter
}

// NewSystemMetricsSource validates the configuration and composes the source.
func NewSystemMetricsSource(config SystemMetricsSourceConfig) (*SystemMetricsSource, error) {
	if config.ProcReader == nil {
		return nil, &ArgumentError{Param: "ProcReader", Message: "A proc file reader is required."}
	}
	if config.CpuQuotaPercent < 1 || config.CpuQuotaPercent > hostAgentMaximumCpuPercent {
		return nil, &ArgumentOutOfRangeError{
			Param:   "CpuQuotaPercent",
			Message: fmt.Sprintf("CPU quota must be between 1 and %d percent.", hostAgentMaximumCpuPercent),
		}
	}
	if config.TasksMax < 0 {
		return nil, &ArgumentOutOfRangeError{
			Param:   "TasksMax",
			Message: "Task ceiling must be non-negative.",
		}
	}
	if config.LogicalCpuCount < 1 {
		return nil, &ArgumentOutOfRangeError{
			Param:   "LogicalCpuCount",
			Message: "At least one logical CPU is required.",
		}
	}
	return &SystemMetricsSource{
		procReader:      config.ProcReader,
		cpuQuotaPercent: config.CpuQuotaPercent,
		tasksMax:        config.TasksMax,
		logicalCpuCount: config.LogicalCpuCount,
		pending:         config.Pending,
		running:         config.Running,
	}, nil
}

// Sample reads both proc files and maps them into one validated sample.
// Memory usage is total minus available; CPU usage is the one-minute load
// scaled by the logical CPU count; running tasks are the node's own running
// allocations when a RunningAllocationCounter is wired, and otherwise the
// kernel's currently running scheduling entities.
func (s *SystemMetricsSource) Sample(ctx context.Context) (NodeMetricsSample, error) {
	if ctx == nil {
		return NodeMetricsSample{}, &ArgumentError{Param: "ctx", Message: "The metrics context must not be nil."}
	}
	meminfo, err := s.procReader.ReadFile(procMeminfoPath)
	if err != nil {
		return NodeMetricsSample{}, &InvalidDataError{Message: fmt.Sprintf(
			"The node meminfo could not be read: %s.", err.Error())}
	}
	memoryTotalBytes, memoryAvailableBytes, err := parseProcMeminfo(string(meminfo))
	if err != nil {
		return NodeMetricsSample{}, err
	}
	loadavg, err := s.procReader.ReadFile(procLoadavgPath)
	if err != nil {
		return NodeMetricsSample{}, &InvalidDataError{Message: fmt.Sprintf(
			"The node loadavg could not be read: %s.", err.Error())}
	}
	load1, runningEntities, err := parseProcLoadavg(string(loadavg))
	if err != nil {
		return NodeMetricsSample{}, err
	}

	cpuUsedPercent := int(math.Round(load1 * 100 / float64(s.logicalCpuCount)))
	if cpuUsedPercent < 0 {
		cpuUsedPercent = 0
	}
	if cpuUsedPercent > s.cpuQuotaPercent {
		cpuUsedPercent = s.cpuQuotaPercent
	}
	tasksRunning := runningEntities
	if s.running != nil {
		tasksRunning = s.running.RunningAllocations()
	}
	if tasksRunning < 0 {
		tasksRunning = 0
	}
	if tasksRunning > s.tasksMax {
		tasksRunning = s.tasksMax
	}
	pending := 0
	if s.pending != nil {
		pending = s.pending.PendingAllocations()
		if pending < 0 {
			pending = 0
		}
	}
	return NewNodeMetricsSample(
		memoryTotalBytes,
		memoryTotalBytes-memoryAvailableBytes,
		s.cpuQuotaPercent,
		cpuUsedPercent,
		s.tasksMax,
		tasksRunning,
		pending,
	)
}

// parseProcMeminfo extracts MemTotal and MemAvailable in bytes. The available
// figure may not exceed the total, because a sample claiming more free memory
// than exists is malformed, not merely unusual.
func parseProcMeminfo(content string) (int64, int64, error) {
	var memoryTotal, memoryAvailable int64
	var haveTotal, haveAvailable bool
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || value < 0 {
			return 0, 0, &InvalidDataError{Message: fmt.Sprintf(
				"The meminfo line %q is malformed.", line)}
		}
		switch fields[0] {
		case "MemTotal:":
			memoryTotal = value * 1024
			haveTotal = true
		case "MemAvailable:":
			memoryAvailable = value * 1024
			haveAvailable = true
		}
	}
	if !haveTotal || !haveAvailable {
		return 0, 0, &InvalidDataError{
			Message: "The meminfo payload must carry MemTotal and MemAvailable.",
		}
	}
	if memoryAvailable > memoryTotal {
		return 0, 0, &InvalidDataError{
			Message: "The meminfo available memory may not exceed the total.",
		}
	}
	return memoryTotal, memoryAvailable, nil
}

// parseProcLoadavg extracts the one-minute load average and the count of
// currently running kernel scheduling entities from the running/total field.
func parseProcLoadavg(content string) (float64, int, error) {
	fields := strings.Fields(content)
	if len(fields) < 4 {
		return 0, 0, &InvalidDataError{
			Message: "The loadavg payload must carry its load averages and entity counts.",
		}
	}
	load1, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || load1 < 0 {
		return 0, 0, &InvalidDataError{
			Message: "The loadavg one-minute average is malformed.",
		}
	}
	entities := strings.Split(fields[3], "/")
	if len(entities) != 2 {
		return 0, 0, &InvalidDataError{
			Message: "The loadavg entity counts are malformed.",
		}
	}
	running, err := strconv.Atoi(entities[0])
	if err != nil || running < 0 {
		return 0, 0, &InvalidDataError{
			Message: "The loadavg running entity count is malformed.",
		}
	}
	return load1, running, nil
}
