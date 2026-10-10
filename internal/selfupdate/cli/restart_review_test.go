package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A restart owed after a rollback is retried by later watchdog runs until it
// succeeds (#127 12039), and an unusable proof key disables confirmation but
// never the watchdog itself (#127 12040).
func TestWatchdogRetriesAnOwedRestartAndToleratesAnUnusableProofKey(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	owner := fmt.Sprint(os.Getuid())
	baked := filepath.Join(dir, "baked")
	if err := os.WriteFile(baked, []byte("baked build"), 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	unit := "terrascale-orchestrator-host.service"
	var restarted []string
	failRestart := true
	invoke := func(args ...string) (string, error) {
		var output bytes.Buffer
		err := run(t.Context(), args, &output, func() time.Time { return now }, func(_ context.Context, unit string) error {
			if failRestart {
				return errors.New("systemctl: bus unavailable")
			}
			restarted = append(restarted, unit)
			return nil
		})
		return output.String(), err
	}
	if _, err := invoke("prepare", "--root", root, "--owner", owner, "--unit", unit, "--baked-binary", baked); err != nil {
		t.Fatal(err)
	}
	// The proof key file is missing: the flag pair stays strict, the key
	// error only disables confirmation.
	proof := []string{"--proof-file", filepath.Join(dir, "proof.json"), "--proof-key-file", filepath.Join(dir, "missing.key")}
	watchdog := append([]string{"watchdog", "--root", root, "--owner", owner, "--unit", unit}, proof...)
	if output, err := invoke(watchdog...); err != nil || output != "" || len(restarted) != 0 {
		t.Fatalf("watchdog with an unusable key = %q %v", output, err)
	}
	// A rollback committed but its restart failed: the obligation remains.
	marker := filepath.Join(root, "restart-pending-"+unit)
	if err := os.WriteFile(marker, []byte(unit+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke(watchdog...); err == nil || !strings.Contains(err.Error(), "bus unavailable") {
		t.Fatalf("failed restart = %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("failed restart dropped the obligation: %v", err)
	}
	failRestart = false
	if _, err := invoke(watchdog...); err != nil || len(restarted) != 1 || restarted[0] != unit {
		t.Fatalf("owed restart not retried: %v %v", err, restarted)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("obligation kept after a successful restart: %v", err)
	}
	if _, err := invoke(watchdog...); err != nil || len(restarted) != 1 {
		t.Fatalf("restarted again without an obligation: %v %v", err, restarted)
	}
}
