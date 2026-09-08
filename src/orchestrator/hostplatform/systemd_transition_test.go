package hostplatform

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnitStoppedRequiresCompleteKnownState(t *testing.T) {
	for _, test := range []struct {
		name, output string
		stopped      bool
		failed       bool
	}{
		{"stopped", "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlGroup=", true, false},
		{"unknown-cgroup", "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0", false, true},
		{"surviving-process", "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=42\nControlGroup=", false, false},
		{"failed-unit", "LoadState=loaded\nActiveState=failed\nSubState=failed\nMainPID=0\nControlGroup=", false, false},
		{"missing-unit", "LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlGroup=", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "systemctl")
			script := "#!/bin/sh\ncat <<'STATE'\n" + test.output + "\nSTATE\n"
			if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			c := SystemctlController{SystemctlBinary: binary, Timeout: time.Second}
			stopped, err := c.UnitStopped(t.Context(), "terrascale-orchestrator.service")
			if stopped != test.stopped || (err != nil) != test.failed {
				t.Fatalf("stopped=%v err=%v", stopped, err)
			}
		})
	}
}
