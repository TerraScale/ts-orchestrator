// Runs a child process while sampling its whole process tree for
// memory/process budget violations.
package main

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ProcessObservation records the peaks sampled during one child-process run.
type ProcessObservation struct {
	ProcessId            int
	PeakMemoryBytes      int64
	PeakProcessCount     int
	DurationMilliseconds int64
}

// ObservedProcessResult is the outcome of a bounded run plus its observation.
type ObservedProcessResult struct {
	ExitCode       int
	StandardOutput string
	StandardError  string
	Observation    ProcessObservation
}

type boundedProcessRunner struct{}

// BoundedProcessRunner runs child processes under memory, process-count, and
// time budgets.
var BoundedProcessRunner = boundedProcessRunner{}

func (boundedProcessRunner) Run(
	fileName string,
	arguments []string,
	workingDirectory string,
	timeout time.Duration,
	memoryLimitBytes int64,
	processLimit int,
) (ObservedProcessResult, error) {
	command := exec.Command(fileName, arguments...)
	command.Dir = workingDirectory
	command.Env = append(filteredEnvironment(os.Environ()),
		"DOTNET_CLI_USE_MSBUILD_SERVER=0",
		"MSBUILDDISABLENODEREUSE=1",
		"UseSharedCompilation=false",
	)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return ObservedProcessResult{}, err
	}
	processId := command.Process.Pid
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()

	started := time.Now()
	var peakMemoryBytes int64
	peakProcessCount := 0
	violation := ""
	var waitErr error
	exited := false
	for !exited && violation == "" {
		sample := sampleTree(processId)
		if sample.MemoryBytes > peakMemoryBytes {
			peakMemoryBytes = sample.MemoryBytes
		}
		if sample.ProcessCount > peakProcessCount {
			peakProcessCount = sample.ProcessCount
		}
		if sample.MemoryBytes > memoryLimitBytes {
			violation = fmt.Sprintf("used %d bytes, above the %d-byte validation limit", sample.MemoryBytes, memoryLimitBytes)
			break
		}
		if sample.ProcessCount > processLimit {
			violation = fmt.Sprintf("used %d processes, above the %d-process validation limit", sample.ProcessCount, processLimit)
			break
		}
		if time.Since(started) > timeout {
			violation = fmt.Sprintf("exceeded %.0f seconds", timeout.Seconds())
			break
		}
		select {
		case waitErr = <-done:
			exited = true
		case <-time.After(100 * time.Millisecond):
		}
	}

	finalSample := sampleTree(processId)
	if finalSample.MemoryBytes > peakMemoryBytes {
		peakMemoryBytes = finalSample.MemoryBytes
	}
	if finalSample.ProcessCount > peakProcessCount {
		peakProcessCount = finalSample.ProcessCount
	}
	if violation != "" {
		killProcessTree(processId)
	}
	if !exited {
		waitErr = <-done
	}
	if peakMemoryBytes == 0 && command.ProcessState != nil {
		if usage, ok := command.ProcessState.SysUsage().(*syscall.Rusage); ok && usage.Maxrss > 0 {
			// Linux reports ru_maxrss in KiB.
			peakMemoryBytes = usage.Maxrss * 1024
		}
	}
	if violation != "" {
		return ObservedProcessResult{}, newToolValidationException([]string{fileName + " " + violation})
	}

	if peakProcessCount < 1 {
		peakProcessCount = 1
	}
	return ObservedProcessResult{
		ExitCode:       exitCodeOf(waitErr),
		StandardOutput: stdout.String(),
		StandardError:  stderr.String(),
		Observation: ProcessObservation{
			ProcessId:            processId,
			PeakMemoryBytes:      peakMemoryBytes,
			PeakProcessCount:     peakProcessCount,
			DurationMilliseconds: time.Since(started).Milliseconds(),
		},
	}, nil
}

type processStat struct {
	ParentProcessId int
	ResidentBytes   int64
}

type processTreeSample struct {
	MemoryBytes  int64
	ProcessCount int
}

func sampleTree(rootProcessId int) processTreeSample {
	if runtime.GOOS != "linux" {
		// Sampling reads /proc, so non-Linux hosts report no usage; the
		// repository validation targets Linux.
		return processTreeSample{}
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return processTreeSample{}
	}
	processes := make(map[int]processStat, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		processId, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		stat, ok := readProcStat(filepath.Join("/proc", entry.Name()))
		if !ok {
			continue
		}
		processes[processId] = stat
	}

	tree := map[int]bool{rootProcessId: true}
	for changed := true; changed; {
		changed = false
		ids := make([]int, 0, len(processes))
		for processId := range processes {
			ids = append(ids, processId)
		}
		sort.Ints(ids)
		for _, processId := range ids {
			stat := processes[processId]
			if !tree[processId] && tree[stat.ParentProcessId] {
				tree[processId] = true
				changed = true
			}
		}
	}
	var memoryBytes int64
	processCount := 0
	for processId := range tree {
		if stat, present := processes[processId]; present {
			memoryBytes += stat.ResidentBytes
			processCount++
		}
	}
	return processTreeSample{MemoryBytes: memoryBytes, ProcessCount: processCount}
}

func readProcStat(directory string) (processStat, bool) {
	value, err := os.ReadFile(filepath.Join(directory, "stat"))
	if err != nil {
		return processStat{}, false
	}
	close := bytes.LastIndexByte(value, ')')
	if close < 0 || close+2 > len(value) {
		return processStat{}, false
	}
	fields := strings.Fields(string(value[close+2:]))
	if len(fields) < 22 {
		return processStat{}, false
	}
	parentProcessId, err := strconv.Atoi(fields[1])
	if err != nil {
		return processStat{}, false
	}
	residentPages, err := strconv.ParseInt(fields[21], 10, 64)
	if err != nil {
		return processStat{}, false
	}
	pageSize := int64(os.Getpagesize())
	if residentPages != 0 && residentPages > math.MaxInt64/pageSize {
		return processStat{}, false
	}
	return processStat{ParentProcessId: parentProcessId, ResidentBytes: residentPages * pageSize}, true
}
