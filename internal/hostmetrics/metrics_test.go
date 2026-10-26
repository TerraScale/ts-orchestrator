package hostmetrics

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func TestDiskstatsUnitsAndDeviceBoundary(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "sda"), 0700); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	data := "8 0 sda 10 0 100 20 30 0 200 40 2 50 60\n8 1 sda1 999 0 999 0 0 0 0 0 0 0 0\n7 0 loop0 999 0 999 0 0 0 0 0 0 0 0"
	if err := writeDisks(&out, data, root); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`ts_host_disk_bytes_total{device="sda",operation="read"} 51200`,
		`ts_host_disk_operation_seconds_total{device="sda",operation="write"} 0.04`,
		`ts_host_disk_weighted_seconds_total{device="sda"} 0.06`,
		`ts_host_disk_inflight{device="sda"} 2`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %s in %s", want, &out)
		}
	}
	if strings.Contains(out.String(), "sda1") || strings.Contains(out.String(), "loop0") {
		t.Fatal("partition or loop device leaked")
	}
	if err := writeDisks(&out, "8 0 sda invalid 0 100 20 30 0 200 40 2 50 60", root); err == nil {
		t.Fatal("malformed telemetry accepted")
	}
	if err := writeDisks(&out, "", root); err == nil {
		t.Fatal("missing telemetry accepted")
	}
}

func TestIdleIsObservedAndMissingIsRejected(t *testing.T) {
	view := observability.SystemView{Pressure: map[string]observability.PSI{"io": {HasFullRow: true}},
		Filesystems: []observability.FilesystemView{{Role: "data", SizeBytes: 100, AvailBytes: 90}}}
	var out bytes.Buffer
	if err := writeHost(&out, view); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `ts_host_io_psi_ratio{scope="some"} 0`) {
		t.Fatal(out.String())
	}
	delete(view.Pressure, "io")
	if err := writeHost(&out, view); err == nil {
		t.Fatal("missing PSI accepted as idle")
	}
}
