package membership

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/membership/clusterhealth"
)

func testRefoundGuard(t *testing.T, now *time.Time) RefoundGuard {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "membership")
	return RefoundGuard{PendingPath: filepath.Join(dir, "refound-pending.json"),
		HealthPath: filepath.Join(dir, "cluster-health.json"), Now: func() time.Time { return *now }}
}

func writeHealth(t *testing.T, guard RefoundGuard, status clusterhealth.Status) {
	t.Helper()
	if err := clusterhealth.WriteStatusFile(guard.HealthPath, status); err != nil {
		t.Fatal(err)
	}
}

func completeLedger() map[string]LedgerSlot {
	return map[string]LedgerSlot{
		"controller-a": {Attempt: 1, InstanceOCID: instanceA, Complete: true},
		"controller-b": {Attempt: 1, InstanceOCID: instanceB, Complete: true},
		"controller-c": {Attempt: 1, InstanceOCID: instanceC, Complete: true},
	}
}

func TestRefoundGuardReFoundsOneSlotAtATime(t *testing.T) {
	now := time.Now().UTC()
	guard := testRefoundGuard(t, &now)
	if err := guard.Admit("gru", "controller-b", completeLedger()); err != nil {
		t.Fatalf("first refound refused: %v", err)
	}
	if err := guard.Begin(RefoundPending{Cell: "gru", Slot: "controller-b", ServerName: "gru-1-ctl-2",
		Attempt: 2, StartedAt: now}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(guard.PendingPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("pending record = %v, %v; want an owner-only file", info, err)
	}
	// The ledger alone blocks a second slot while b's successor is open.
	ledger := completeLedger()
	ledger["controller-b"] = LedgerSlot{Attempt: 2, Retirement: evidenceID}
	if err := guard.Admit("gru", "controller-c", ledger); err == nil ||
		!strings.Contains(err.Error(), "controller-b has an incomplete re-founded attempt 2") {
		t.Fatalf("second slot while b is incomplete: %v", err)
	}
	// Retrying the same slot is allowed.
	if err := guard.Admit("gru", "controller-b", ledger); err != nil {
		t.Fatalf("retrying b refused: %v", err)
	}
	// b completed in the ledger but has not caught up: still refused.
	ledger["controller-b"] = LedgerSlot{Attempt: 2, Complete: true, Retirement: evidenceID}
	if err := guard.Admit("gru", "controller-c", ledger); err == nil || !strings.Contains(err.Error(), "not current yet") {
		t.Fatalf("second slot without health: %v", err)
	}
	writeHealth(t, guard, clusterhealth.Status{ObservedAt: now, MetaLeader: "gru-1-ctl-1",
		Online:  []string{"gru-1-ctl-1", "gru-1-ctl-2"},
		Lagging: []clusterhealth.LaggingPeer{{Name: "gru-1-ctl-2", Lag: 900}}})
	if err := guard.Admit("gru", "controller-c", ledger); err == nil || !strings.Contains(err.Error(), "catching up") {
		t.Fatalf("second slot while b lags: %v", err)
	}
	stale := now.Add(-2 * RefoundHealthFreshness)
	writeHealth(t, guard, clusterhealth.Status{ObservedAt: stale, MetaLeader: "gru-1-ctl-1",
		Online: []string{"gru-1-ctl-1", "gru-1-ctl-2"}})
	if err := guard.Admit("gru", "controller-c", ledger); err == nil || !strings.Contains(err.Error(), "last observed") {
		t.Fatalf("second slot on stale health: %v", err)
	}
	// Online and not lagging is not caught up without positive evidence.
	writeHealth(t, guard, clusterhealth.Status{ObservedAt: now, MetaLeader: "gru-1-ctl-1",
		Online: []string{"gru-1-ctl-1", "gru-1-ctl-2"}, Missing: []string{"gru-1-ctl-3"}})
	if err := guard.Admit("gru", "controller-c", ledger); err == nil || !strings.Contains(err.Error(), "zero lag") {
		t.Fatalf("second slot without positive catch-up evidence: %v", err)
	}
	// A fresh view observed before b's relaunch began says nothing about
	// the successor that reuses its server name.
	writeHealth(t, guard, clusterhealth.Status{ObservedAt: now.Add(-time.Second), MetaLeader: "gru-1-ctl-1",
		Online: []string{"gru-1-ctl-1", "gru-1-ctl-2"}, CaughtUp: []string{"gru-1-ctl-2"}})
	if err := guard.Admit("gru", "controller-c", ledger); err == nil || !strings.Contains(err.Error(), "last observed") {
		t.Fatalf("second slot on a view from before the relaunch: %v", err)
	}
	writeHealth(t, guard, clusterhealth.Status{ObservedAt: now, MetaLeader: "gru-1-ctl-1",
		Online: []string{"gru-1-ctl-1", "gru-1-ctl-2"}, CaughtUp: []string{"gru-1-ctl-2"},
		Missing: []string{"gru-1-ctl-3"}})
	if err := guard.Admit("gru", "controller-c", ledger); err != nil {
		t.Fatalf("second slot after b is current: %v", err)
	}
	if _, err := os.Stat(guard.PendingPath); !os.IsNotExist(err) {
		t.Fatalf("pending record survived a current slot: %v", err)
	}
}

func TestRefoundGuardWaitsUntilTheSlotIsCurrent(t *testing.T) {
	now := time.Now().UTC()
	guard := testRefoundGuard(t, &now)
	pending := RefoundPending{Cell: "gru", Slot: "controller-b", ServerName: "gru-1-ctl-2",
		Attempt: 2, StartedAt: now}
	if err := guard.Begin(pending); err != nil {
		t.Fatal(err)
	}
	writeHealth(t, guard, clusterhealth.Status{ObservedAt: now, MetaLeader: "gru-1-ctl-1",
		Online: []string{"gru-1-ctl-1"}, Missing: []string{"gru-1-ctl-2"}})
	var out bytes.Buffer
	if err := guard.WaitCurrent(t.Context(), pending, time.Millisecond, 0, &out); err == nil ||
		!strings.Contains(err.Error(), "has not joined") {
		t.Fatalf("timed-out wait = %v", err)
	}
	if _, err := os.Stat(guard.PendingPath); err != nil {
		t.Fatalf("a timed-out wait dropped the pending record: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- guard.WaitCurrent(context.Background(), pending, time.Millisecond, time.Hour, &out)
	}()
	time.Sleep(20 * time.Millisecond)
	writeHealth(t, guard, clusterhealth.Status{ObservedAt: now, MetaLeader: "gru-1-ctl-1",
		Online: []string{"gru-1-ctl-1", "gru-1-ctl-2"}, CaughtUp: []string{"gru-1-ctl-2"}})
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("wait never saw the slot report current")
	}
	if _, err := os.Stat(guard.PendingPath); !os.IsNotExist(err) {
		t.Fatalf("pending record survived: %v", err)
	}
	if !strings.Contains(out.String(), "waiting for gru-1-ctl-2") {
		t.Fatalf("progress = %q", out.String())
	}
}

func TestRefoundGuardFailsClosedOnAMalformedRecord(t *testing.T) {
	now := time.Now().UTC()
	guard := testRefoundGuard(t, &now)
	if err := os.MkdirAll(filepath.Dir(guard.PendingPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(guard.PendingPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := guard.Admit("gru", "controller-c", completeLedger()); err == nil {
		t.Fatal("a malformed pending record admitted a refound")
	}
}

// Two refound commands never interleave: the host lock refuses the second
// until the first releases it.
func TestRefoundGuardLockAdmitsOneRefoundAtATime(t *testing.T) {
	now := time.Now().UTC()
	guard := testRefoundGuard(t, &now)
	release, err := guard.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.Lock(); err == nil || !strings.Contains(err.Error(), "another break-glass refound") {
		t.Fatalf("second lock while held = %v", err)
	}
	release()
	reacquired, err := guard.Lock()
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	reacquired()
}
