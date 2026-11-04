package alertdelivery

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEmailLedgerSurvivesRestartAndHonorsRollingWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.json")
	now := time.Now().UTC()
	reserve := func(key string, at time.Time, want string) {
		t.Helper()
		// A fresh relay on every attempt also exercises independent processes'
		// shared ledger, rather than relying on process-local deduplication.
		r := relay{ledgerPath: path}
		if got := r.reserveEmail(t.Context(), key, emailRepeatInterval, at); got != want {
			t.Fatalf("reserve %s at %v: %q, want %q", key, at.Sub(now), got, want)
		}
	}
	for i := range emailHourlyLimit {
		reserve(fmt.Sprint(i), now.Add(time.Duration(i)*time.Minute), "")
	}
	reserve("overflow", now.Add(59*time.Minute), "hourly cap")
	reserve("overflow", now.Add(time.Hour-time.Nanosecond), "hourly cap")
	reserve("overflow", now.Add(time.Hour), "")
	reserve("0", now.Add(emailRepeatInterval-time.Nanosecond), "duplicate")
	reserve("0", now.Add(emailRepeatInterval), "")
	digest := func(at time.Time, want string) {
		t.Helper()
		if got := (relay{ledgerPath: path}).reserveEmail(t.Context(), digestKey, digestInterval, at); got != want {
			t.Fatalf("digest at %v: %q, want %q", at.Sub(now), got, want)
		}
	}
	digest(now.Add(2*time.Hour), "")
	digest(now.Add(2*time.Hour+digestInterval-time.Nanosecond), "duplicate")
	digest(now.Add(2*time.Hour+digestInterval), "")
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	reserve("corrupt must not reset the budget", now.Add(5*time.Hour), "ledger unavailable")
}
