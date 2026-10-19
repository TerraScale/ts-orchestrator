package observability

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testProcStat = `cpu  1000 50 300 8000 20 5 7 3 0 0
cpu0 500 25 150 4000 10 2 3 1 0 0
cpu1 500 25 150 4000 10 3 4 2 0 0
intr 12345
ctxt 999
`

const testMeminfo = `MemTotal:        8000000 kB
MemFree:          100000 kB
MemAvailable:    4000000 kB
SwapTotal:             0 kB
SwapFree:              0 kB
HugePages_Total:       0
`

const testPressure = `some avg10=1.50 avg60=0.75 avg300=0.10 total=123456
full avg10=0.25 avg60=0.10 avg300=0.00 total=6543
`

const testNetDev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:     900      10    0    0    0     0          0         0      900      10    0    0    0     0       0          0
  eth0:    1000       5    0    0    0     0          0         0     2000       7    0    0    0     0       0          0
  wt0:     500       3    0    0    0     0          0         0      300       2    0    0    0     0       0          0
`

func writeProcFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"stat": testProcStat, "meminfo": testMeminfo, "loadavg": "0.50 0.40 0.30 1/200 3000\n",
		"uptime": "3600.25 7000.00\n", "self/status": "Name:\tts-orch\nVmRSS:\t   2048 kB\n",
		"pressure/cpu": "some avg10=0.10 avg60=0.20 avg300=0.30 total=10\n", "pressure/memory": testPressure,
		"net/dev": testNetDev,
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestReadSystemFromProcFixture(t *testing.T) {
	t.Parallel()
	root := writeProcFixture(t)
	stat := func(path string) (FilesystemView, error) {
		if path == "/missing" {
			return FilesystemView{SizeBytes: 99, AvailBytes: 40, Files: 10, FilesFree: 5}, errors.New("missing")
		}
		return FilesystemView{SizeBytes: 100, AvailBytes: 40, Files: 10, FilesFree: 5}, nil
	}
	view, err := readSystem(root, []FilesystemRole{{Role: "nats", Path: "/data"}, {Role: "store", Path: "/missing"}}, stat)
	if err != nil {
		t.Fatal(err)
	}
	if view.CPUCount != 2 || view.CPUSeconds.User != 10 || view.CPUSeconds.Idle != 80 || view.CPUSeconds.Steal != 0.03 {
		t.Fatalf("cpu = %d %+v", view.CPUCount, view.CPUSeconds)
	}
	if busy := view.CPUSeconds.Busy(); busy < 13.64 || busy > 13.66 {
		t.Fatalf("busy = %v", busy)
	}
	if view.MemTotalBytes != 8000000*1024 || view.MemAvailBytes != 4000000*1024 || view.ProcessRSSBytes != 2048*1024 {
		t.Fatalf("memory = %+v", view)
	}
	if view.Load1 != 0.5 || view.Load15 != 0.3 || view.UptimeSeconds != 3600.25 {
		t.Fatalf("load or uptime = %+v", view)
	}
	if view.NetRxBytes != 1500 || view.NetTxBytes != 2300 {
		t.Fatalf("network counters = %d/%d", view.NetRxBytes, view.NetTxBytes)
	}
	memory := view.Pressure["memory"]
	if !memory.HasFullRow || memory.SomeAvg10 != 1.5 || memory.FullTotal != 6543 {
		t.Fatalf("memory pressure = %+v", memory)
	}
	if _, present := view.Pressure["io"]; present {
		t.Fatal("absent io pressure file produced a reading")
	}
	if len(view.Filesystems) != 2 || view.Filesystems[0].AvailBytes != 40 || view.Filesystems[1].SizeBytes != 0 ||
		view.Filesystems[1] != (FilesystemView{Role: "store", Path: "/missing"}) {
		t.Fatalf("filesystems = %+v", view.Filesystems)
	}
	view.Clock = &ClockView{Synchronized: true, OffsetSeconds: -0.002, MaxErrorSeconds: 0.0235}
	var output bytes.Buffer
	WriteSystemMetrics(&output, view)
	text := output.String()
	for _, want := range []string{`ts_orch_host_clock_synchronized 1`, `ts_orch_host_clock_offset_seconds -0.002`,
		`ts_orch_host_clock_max_error_seconds 0.0235`, `ts_orch_host_cpu_seconds_total{mode="user"} 10`, `ts_orch_host_memory_total_bytes 8192000000`,
		`ts_orch_host_pressure_avg10{resource="memory",kind="full"} 0.25`, `ts_orch_host_filesystem_avail_bytes{role="nats"} 40`} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics lack %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, `role="store"`) {
		t.Fatalf("unavailable filesystem produced gauges:\n%s", text)
	}
}

func TestReadNetDevSumsNonLoopbackInterfaces(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cases := map[string]struct {
		content string
		rx, tx  uint64
		ok      bool
	}{
		"fixture":   {content: testNetDev, rx: 1500, tx: 2300, ok: true},
		"malformed": {content: "eth0: nope 5 0 0 0 0 0 0 2000\neth1: 1 2\nno colon here\n"},
		"mixed":     {content: "eth0: 10 0 0 0 0 0 0 0 20\neth1: x 0 0 0 0 0 0 0 1\n", rx: 10, tx: 20, ok: true},
	}
	for name, tc := range cases {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
			t.Fatal(err)
		}
		if rx, tx, ok := readNetDev(path); rx != tc.rx || tx != tc.tx || ok != tc.ok {
			t.Errorf("%s: readNetDev = %d, %d, %v", name, rx, tx, ok)
		}
	}
	if rx, tx, ok := readNetDev(filepath.Join(dir, "absent")); rx != 0 || tx != 0 || ok {
		t.Errorf("missing file: readNetDev = %d, %d, %v", rx, tx, ok)
	}
}

func TestReadSystemWithoutNetDevKeepsReadings(t *testing.T) {
	t.Parallel()
	root := writeProcFixture(t)
	if err := os.Remove(filepath.Join(root, "net", "dev")); err != nil {
		t.Fatal(err)
	}
	view, err := readSystem(root, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if view.NetRxBytes != 0 || view.NetTxBytes != 0 || view.CPUCount != 2 || view.MemTotalBytes == 0 {
		t.Fatalf("view without net/dev = %+v", view)
	}
}

func TestSystemMalformedProcFilesAreReportedBySnapshotAPI(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, path, data string
		unavailable      bool
	}{
		{"missing cpu", "stat", "intr 1\n", true},
		{"malformed cpu", "stat", "cpu 1 x 3 4\n", true},
		{"missing memory", "meminfo", "MemFree: 1 kB\n", true},
		{"malformed pressure", "pressure/memory", "some avg10=abc\n", false},
		{"short load", "loadavg", "1.0\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := writeProcFixture(t)
			if err := os.WriteFile(filepath.Join(root, tc.path), []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}
			collector, _ := testCollector(t, "proc", nil)
			collector.config.System = func() (SystemView, error) { return readSystem(root, nil, nil) }
			snapshot, err := snapshotOverHTTP(t, collector, true)
			if err != nil {
				t.Fatal(err)
			}
			if tc.unavailable {
				if snapshot.System != nil || snapshot.Errors["system"] != "unavailable" || !strings.Contains(snapshot.Metrics, `ts_orch_collect_ok{section="system"} 0`) {
					t.Fatalf("invalid proc was hidden: %+v", snapshot)
				}
			} else if snapshot.System == nil || tc.path == "loadavg" && snapshot.System.Load1 != 0 || tc.path == "pressure/memory" && snapshot.System.Pressure["memory"].SomeAvg10 != 0 {
				t.Fatalf("optional malformed proc polluted snapshot: %+v", snapshot)
			}
		})
	}
	t.Run("missing net/dev", func(t *testing.T) {
		root := writeProcFixture(t)
		if err := os.Remove(filepath.Join(root, "net", "dev")); err != nil {
			t.Fatal(err)
		}
		collector, _ := testCollector(t, "proc-without-network", nil)
		collector.config.System = func() (SystemView, error) { return readSystem(root, nil, nil) }
		snapshot, err := snapshotOverHTTP(t, collector, true)
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.System == nil {
			t.Fatalf("missing net/dev omitted system: %+v", snapshot)
		}
		if _, present := snapshot.Errors["system"]; present {
			t.Fatalf("missing net/dev reported a system error: %+v", snapshot)
		}
		view := snapshot.System
		if view.NetRxBytes != 0 || view.NetTxBytes != 0 || view.CPUCount != 2 || view.MemTotalBytes == 0 {
			t.Fatalf("view without net/dev = %+v", view)
		}
	})
}

func TestReadSystemOnThisHost(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("system statistics require Linux")
	}
	view, err := ReadSystem([]FilesystemRole{{Role: "tmp", Path: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	if view.CPUCount < 1 || view.MemTotalBytes == 0 || len(view.Filesystems) != 1 || view.Filesystems[0].SizeBytes == 0 ||
		view.Clock == nil {
		t.Fatalf("host view = %+v", view)
	}
}
