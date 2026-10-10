package selfupdate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallWatchdogLoggingDropinWritesOnceBesideTheUnit(t *testing.T) {
	dir := t.TempDir()
	if changed, err := InstallWatchdogLoggingDropin(dir); err != nil || changed {
		t.Fatalf("install without the unit = %v %v, want no change", changed, err)
	}
	if err := os.WriteFile(filepath.Join(dir, WatchdogUnit), []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if changed, err := InstallWatchdogLoggingDropin(dir); err != nil || !changed {
		t.Fatalf("first install = %v %v, want a change", changed, err)
	}
	path := filepath.Join(dir, WatchdogUnit+".d", "10-logging.conf")
	if data, err := os.ReadFile(path); err != nil || string(data) != WatchdogLoggingDropin {
		t.Fatalf("%s = %q %v", path, data, err)
	}
	if changed, err := InstallWatchdogLoggingDropin(dir); err != nil || changed {
		t.Fatalf("second install = %v %v, want no change", changed, err)
	}
}
