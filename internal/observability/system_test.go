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

func writeProcFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"stat": testProcStat, "meminfo": testMeminfo, "loadavg": "0.50 0.40 0.30 1/200 3000\n",
		"uptime": "3600.25 7000.00\n", "self/status": "Name:\tts-orch\nVmRSS:\t   2048 kB\n",
		"pressure/cpu": "some avg10=0.10 avg60=0.20 avg300=0.30 total=10\n", "pressure/memory": testPressure,
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
			return FilesystemView{}, errors.New("missing")
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
	memory := view.Pressure["memory"]
	if !memory.HasFullRow || memory.SomeAvg10 != 1.5 || memory.FullTotal != 6543 {
		t.Fatalf("memory pressure = %+v", memory)
	}
	if _, present := view.Pressure["io"]; present {
		t.Fatal("absent io pressure file produced a reading")
	}
	if len(view.Filesystems) != 2 || view.Filesystems[0].AvailBytes != 40 || view.Filesystems[1].SizeBytes != 0 ||
		view.Filesystems[1].Role != "store" {
		t.Fatalf("filesystems = %+v", view.Filesystems)
	}
	var output bytes.Buffer
	WriteSystemMetrics(&output, view)
	text := output.String()
	for _, want := range []string{`ts_orch_host_cpu_seconds_total{mode="user"} 10`, `ts_orch_host_memory_total_bytes 8192000000`,
		`ts_orch_host_pressure_avg10{resource="memory",kind="full"} 0.25`, `ts_orch_host_filesystem_avail_bytes{role="nats"} 40`} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics lack %q:\n%s", want, text)
		}
	}
}

func TestSystemParsersRejectMalformedInput(t *testing.T) {
	t.Parallel()
	if _, _, err := parseProcStat([]byte("intr 1\n")); err == nil {
		t.Error("proc stat without cpu line was accepted")
	}
	if _, _, err := parseProcStat([]byte("cpu 1 x 3 4\n")); err == nil {
		t.Error("malformed cpu line was accepted")
	}
	if _, err := parseMeminfo([]byte("MemFree: 1 kB\n")); err == nil {
		t.Error("meminfo without MemTotal was accepted")
	}
	if _, err := parsePressure([]byte("some avg10=abc\n")); err == nil {
		t.Error("malformed pressure was accepted")
	}
	if _, _, _, err := parseLoadavg([]byte("1.0\n")); err == nil {
		t.Error("short loadavg was accepted")
	}
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
	if view.CPUCount < 1 || view.MemTotalBytes == 0 || len(view.Filesystems) != 1 || view.Filesystems[0].SizeBytes == 0 {
		t.Fatalf("host view = %+v", view)
	}
}
