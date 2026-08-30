// This file tests the system metrics source: proc parsing, saturation
// clamping, pending counter composition, and configuration validation.
package hostagent

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeProcReader serves fixed proc file contents.
type fakeProcReader struct {
	files      map[string]string
	misses     []string
	missingErr error
}

func (f *fakeProcReader) ReadFile(path string) ([]byte, error) {
	if content, present := f.files[path]; present {
		return []byte(content), nil
	}
	f.misses = append(f.misses, path)
	if f.missingErr != nil {
		return nil, f.missingErr
	}
	return nil, errors.New("no such proc file")
}

// fakePendingCounter serves a fixed pending count.
type fakePendingCounter struct {
	pending int
}

func (f fakePendingCounter) PendingAllocations() int { return f.pending }

const metricsMeminfo = "MemTotal:       16326460 kB\n" +
	"MemFree:          524288 kB\n" +
	"MemAvailable:   12163448 kB\n" +
	"Buffers:          262144 kB\n"

const metricsLoadavg = "0.52 0.58 0.59 3/941 24567\n"

func TestSystemMetricsSourceMapsProcData(t *testing.T) {
	source := newSystemMetricsSourceForTest(t, &fakeProcReader{
		files: map[string]string{procMeminfoPath: metricsMeminfo, procLoadavgPath: metricsLoadavg},
	}, 800, 2048, 8, fakePendingCounter{pending: 2})

	sample, err := source.Sample(context.Background())
	if err != nil {
		t.Fatalf("sample: %v", err)
	}

	// MemTotal 16326460 kB minus MemAvailable 12163448 kB, in bytes.
	if sample.MemoryTotalBytes != 16326460*1024 {
		t.Fatalf("memory total = %d", sample.MemoryTotalBytes)
	}
	if sample.MemoryUsedBytes != (16326460-12163448)*1024 {
		t.Fatalf("memory used = %d", sample.MemoryUsedBytes)
	}
	// 0.52 load over 8 CPUs rounds to 7 percent.
	if sample.CpuUsedPercent != 7 {
		t.Fatalf("cpu used = %d", sample.CpuUsedPercent)
	}
	if sample.TasksRunning != 3 {
		t.Fatalf("tasks running = %d", sample.TasksRunning)
	}
	if sample.PendingAllocations != 2 {
		t.Fatalf("pending = %d", sample.PendingAllocations)
	}
	if sample.CpuQuotaPercent != 800 || sample.TasksMax != 2048 {
		t.Fatalf("envelope = %+v", sample)
	}
}

func TestSystemMetricsSourceClampsSaturatedDimensions(t *testing.T) {
	source := newSystemMetricsSourceForTest(t, &fakeProcReader{
		files: map[string]string{
			procMeminfoPath: metricsMeminfo,
			procLoadavgPath: "42.00 42.00 42.00 9999/10000 1\n",
		},
	}, 400, 128, 4, nil)

	sample, err := source.Sample(context.Background())
	if err != nil {
		t.Fatalf("sample: %v", err)
	}

	if sample.CpuUsedPercent != 400 {
		t.Fatalf("a saturated CPU must report the full envelope, got %d", sample.CpuUsedPercent)
	}
	if sample.TasksRunning != 128 {
		t.Fatalf("a saturated task count must report the ceiling, got %d", sample.TasksRunning)
	}
	if sample.PendingAllocations != 0 {
		t.Fatalf("a nil counter reports zero pending, got %d", sample.PendingAllocations)
	}
}

func TestSystemMetricsSourceRejectsMalformedProcData(t *testing.T) {
	tests := []struct {
		name     string
		meminfo  string
		loadavg  string
		missFile bool
	}{
		{
			name:    "meminfo without MemAvailable",
			meminfo: "MemTotal:       16326460 kB\n",
			loadavg: metricsLoadavg,
		},
		{
			name:    "meminfo without MemTotal",
			meminfo: "MemAvailable:   12163448 kB\n",
			loadavg: metricsLoadavg,
		},
		{
			name:    "meminfo value is not a number",
			meminfo: "MemTotal:       lots kB\nMemAvailable:   12163448 kB\n",
			loadavg: metricsLoadavg,
		},
		{
			name:    "meminfo available exceeds total",
			meminfo: "MemTotal:       100 kB\nMemAvailable:   200 kB\n",
			loadavg: metricsLoadavg,
		},
		{
			name:    "loadavg is empty",
			meminfo: metricsMeminfo,
			loadavg: "",
		},
		{
			name:    "loadavg average is not a number",
			meminfo: metricsMeminfo,
			loadavg: "busy busy busy 1/2 3\n",
		},
		{
			name:    "loadavg entity field is malformed",
			meminfo: metricsMeminfo,
			loadavg: "0.52 0.58 0.59 nine-of-them 1\n",
		},
		{
			name:     "meminfo file is missing",
			meminfo:  "",
			loadavg:  metricsLoadavg,
			missFile: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			files := map[string]string{procLoadavgPath: test.loadavg}
			if !test.missFile {
				files[procMeminfoPath] = test.meminfo
			}
			source := newSystemMetricsSourceForTest(t, &fakeProcReader{files: files}, 800, 2048, 8, nil)

			sample, err := source.Sample(context.Background())

			if err == nil {
				t.Fatalf("expected a malformed-data error, got %+v", sample)
			}
			var invalidData *InvalidDataError
			if !errors.As(err, &invalidData) {
				t.Fatalf("error %v is not an InvalidDataError", err)
			}
		})
	}
}

func TestSystemMetricsSourceRejectsNilContext(t *testing.T) {
	source := newSystemMetricsSourceForTest(t, &fakeProcReader{files: map[string]string{
		procMeminfoPath: metricsMeminfo, procLoadavgPath: metricsLoadavg,
	}}, 800, 2048, 8, nil)

	if _, err := source.Sample(nil); err == nil {
		t.Fatal("a nil context must be rejected")
	}
}

func TestNewSystemMetricsSourceValidatesConfiguration(t *testing.T) {
	valid := SystemMetricsSourceConfig{
		ProcReader:      &fakeProcReader{},
		CpuQuotaPercent: 800,
		TasksMax:        2048,
		LogicalCpuCount: 8,
	}
	tests := []struct {
		name      string
		mutate    func(config *SystemMetricsSourceConfig)
		wantParam string
	}{
		{name: "missing proc reader", mutate: func(c *SystemMetricsSourceConfig) { c.ProcReader = nil }, wantParam: "ProcReader"},
		{name: "zero cpu quota", mutate: func(c *SystemMetricsSourceConfig) { c.CpuQuotaPercent = 0 }, wantParam: "CpuQuotaPercent"},
		{name: "cpu quota above the bound", mutate: func(c *SystemMetricsSourceConfig) { c.CpuQuotaPercent = 10001 }, wantParam: "CpuQuotaPercent"},
		{name: "negative task ceiling", mutate: func(c *SystemMetricsSourceConfig) { c.TasksMax = -1 }, wantParam: "TasksMax"},
		{name: "zero cpu count", mutate: func(c *SystemMetricsSourceConfig) { c.LogicalCpuCount = 0 }, wantParam: "LogicalCpuCount"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if _, err := NewSystemMetricsSource(config); err == nil {
				t.Fatal("expected a configuration error")
			} else if !errorsAsParam(err, test.wantParam) {
				t.Fatalf("error %v does not reference param %s", err, test.wantParam)
			}
		})
	}
}

func TestOsProcFileReaderAdmitsOnlyTheTwoProcPaths(t *testing.T) {
	reader := OsProcFileReader{}
	for _, path := range []string{"/etc/passwd", "/proc/self/status", "../proc/meminfo", ""} {
		if _, err := reader.ReadFile(path); err == nil {
			t.Fatalf("path %q must be refused", path)
		} else if !errorsAsParam(err, "path") {
			t.Fatalf("error %v does not reference param path", err)
		} else if !strings.Contains(err.Error(), "meminfo and loadavg") {
			t.Fatalf("unexpected message %v", err)
		}
	}
}

func newSystemMetricsSourceForTest(
	t *testing.T,
	reader ProcFileReader,
	cpuQuotaPercent int,
	tasksMax int,
	logicalCpuCount int,
	pending PendingAllocationCounter,
) *SystemMetricsSource {
	t.Helper()
	source, err := NewSystemMetricsSource(SystemMetricsSourceConfig{
		ProcReader:      reader,
		CpuQuotaPercent: cpuQuotaPercent,
		TasksMax:        tasksMax,
		LogicalCpuCount: logicalCpuCount,
		Pending:         pending,
	})
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	return source
}
