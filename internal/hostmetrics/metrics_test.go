package hostmetrics

import (
	"bytes"

	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

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
