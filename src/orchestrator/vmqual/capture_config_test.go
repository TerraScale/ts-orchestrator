package vmqual

import (
	"os"
	"testing"
)

func TestPreliminaryCaptureEnvironmentRequiresExplicitPairedBounds(t *testing.T) {
	for _, test := range []struct {
		snapshot, total string
		valid           bool
	}{{"1024", "4096", true}, {"0", "0", false}, {"1024", "0", false}, {"2048", "1024", false}, {"-1", "4096", false}, {" 1024", "4096", false}, {"1024", "9223372036854775807", false}} {
		t.Run(test.snapshot+"-"+test.total, func(t *testing.T) {
			t.Setenv("TS_VM_PRELIMINARY_CAPTURE_MAX_SNAPSHOT_BYTES", test.snapshot)
			t.Setenv("TS_VM_PRELIMINARY_CAPTURE_MAX_TOTAL_BYTES", test.total)
			config := defaultConfigForArchitecture("amd64")
			if (config.configurationError == "") != test.valid {
				t.Fatalf("capture configuration error: %q", config.configurationError)
			}
			if test.valid && (config.PreliminaryCaptureMaxSnapshotBytes != 1024 || config.PreliminaryCaptureMaxTotalBytes != 4096) {
				t.Fatal("declared capture capacities not retained")
			}
		})
	}
}

func TestPreliminaryCaptureEnvironmentDefaultsOffAndRejectsOneSidedEnable(t *testing.T) {
	for _, name := range []string{"TS_VM_PRELIMINARY_CAPTURE_MAX_SNAPSHOT_BYTES", "TS_VM_PRELIMINARY_CAPTURE_MAX_TOTAL_BYTES"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	c := defaultConfigForArchitecture("amd64")
	if c.PreliminaryCaptureMaxSnapshotBytes != 0 || c.PreliminaryCaptureMaxTotalBytes != 0 || c.configurationError != "" {
		t.Fatal("capture enabled without declaration")
	}
	t.Setenv("TS_VM_PRELIMINARY_CAPTURE_MAX_SNAPSHOT_BYTES", "1024")
	if c := defaultConfigForArchitecture("amd64"); c.configurationError == "" {
		t.Fatal("one-sided capture environment accepted")
	}
	c.PreliminaryCaptureMaxSnapshotBytes = 1024
	if err := c.Validate(); err == nil {
		t.Fatal("one-sided programmatic capture config accepted")
	}
}
