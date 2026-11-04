package membership

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testRefoundGuard(t *testing.T, now *time.Time) RefoundGuard {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "membership")
	return RefoundGuard{PendingPath: filepath.Join(dir, "refound-pending.json"),
		HealthPath: filepath.Join(dir, "cluster-health.json"), Now: func() time.Time { return *now }}
}

func completeLedger() map[string]LedgerSlot {
	return map[string]LedgerSlot{
		"controller-a": {Attempt: 1, InstanceOCID: instanceA, Complete: true},
		"controller-b": {Attempt: 1, InstanceOCID: instanceB, Complete: true},
		"controller-c": {Attempt: 1, InstanceOCID: instanceC, Complete: true},
	}
}

func TestRefoundGuardRecoversPendingIdentityAcrossRestart(t *testing.T) {
	now := time.Now().UTC()
	guard := testRefoundGuard(t, &now)
	pending := RefoundPending{Cell: "gru", Slot: "controller-b", ServerName: "gru-1-ctl-2", Attempt: 2, StartedAt: now}
	if err := guard.Begin(pending); err != nil {
		t.Fatal(err)
	}
	// Reopen only the durable paths; no process memory or serving roster survives.
	restarted := RefoundGuard{PendingPath: guard.PendingPath, HealthPath: guard.HealthPath, Now: guard.Now}
	if err := restarted.Admit("gru", "controller-c", completeLedger()); err == nil {
		t.Fatal("missing health after restart admitted a second refound")
	}
	if err := restarted.Admit("sjc", "controller-c", completeLedger()); err == nil {
		t.Fatal("a pending record of another region was discarded")
	}
	invalid := pending
	invalid.Attempt = 0
	if err := restarted.Begin(invalid); err == nil {
		t.Fatal("an invalid retry overwrote the durable pending identity")
	}
	stored, err := restarted.readPending()
	if err != nil || stored != pending {
		t.Fatalf("pending identity after invalid retry = %+v, %v", stored, err)
	}
	if err := os.Chmod(guard.PendingPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Admit("gru", "controller-b", completeLedger()); err == nil {
		t.Fatal("a writable pending identity admitted a retry")
	}
	if err := os.Chmod(guard.PendingPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(guard.PendingPath, guard.PendingPath+".record"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(guard.PendingPath+".record", guard.PendingPath); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Admit("gru", "controller-b", completeLedger()); err == nil {
		t.Fatal("a linked pending identity admitted a retry")
	}
}
