package host

import (
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
)

func TestLoadOperationIsRefusedUntilASinkIsSet(t *testing.T) {
	c, hostKey, s, _ := reportedTestHost(t)
	report := hostload.Report{SchemaVersion: hostload.SchemaVersion}
	if _, err := c.handleAuthorized(t.Context(), signedHostRequest(t, hostKey, "load", s.SessionID, s.Epoch, report)); err == nil ||
		!strings.Contains(err.Error(), errLoadDisabled.Error()) {
		t.Fatalf("load accepted without a sink: %v", err)
	}
}

func TestLoadOperationFiltersRolesAndUsesRegistrationOrigin(t *testing.T) {
	c, hostKey, s, _ := reportedTestHost(t)
	var gotOrigin hostload.Origin
	var gotReport hostload.Report
	calls := 0
	c.SetLoadSink(func(origin hostload.Origin, report hostload.Report) error {
		calls++
		gotOrigin, gotReport = origin, report
		return nil
	})
	cores, memory := 0.5, uint64(1<<20)
	report := hostload.Report{SchemaVersion: hostload.SchemaVersion, Roles: []hostload.RoleUsage{
		{Role: "terrabase", CPUCores: &cores, MemoryBytes: &memory, TerraBase: &memberstatus.Load{Connections: 3}},
		// Not registered for this host: dropped before the sink sees it.
		{Role: "api", CPUCores: &cores},
	}}
	payload, err := c.handleAuthorized(t.Context(), signedHostRequest(t, hostKey, "load", s.SessionID, s.Epoch, report))
	if err != nil {
		t.Fatal(err)
	}
	if ack, ok := payload.(loadAck); !ok || !ack.Accepted {
		t.Fatalf("load not acknowledged: %#v", payload)
	}
	if calls != 1 || gotOrigin != (hostload.Origin{Cell: "gru", Environment: "production", Node: "node-a"}) ||
		len(gotReport.Roles) != 1 || gotReport.Roles[0].Role != "terrabase" {
		t.Fatalf("sink got origin %+v report %+v after %d calls", gotOrigin, gotReport, calls)
	}

	// A withdrawn allocation no longer contributes load.
	desired, _, _, err := c.readDesired(t.Context(), "node-a", "terrabase")
	if err != nil {
		t.Fatal(err)
	}
	withdrawal := Desired{Cell: desired.Cell, Node: desired.Node, Environment: desired.Environment, Role: desired.Role,
		Generation: desired.Generation + 1, AuthorityEpoch: desired.AuthorityEpoch, Withdrawn: true}
	if _, err := c.ApplyDesired(t.Context(), withdrawal); err != nil {
		t.Fatal(err)
	}
	if _, err := c.handleAuthorized(t.Context(), signedHostRequest(t, hostKey, "load", s.SessionID, s.Epoch, report)); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(gotReport.Roles) != 0 {
		t.Fatalf("withdrawn role still reported: %+v", gotReport)
	}

	// Throttled reports are answered, not failed, so the agent keeps its
	// interval instead of backing off.
	c.SetLoadSink(func(hostload.Origin, hostload.Report) error { return hostload.ErrTooFrequent })
	payload, err = c.handleAuthorized(t.Context(), signedHostRequest(t, hostKey, "load", s.SessionID, s.Epoch, report))
	if err != nil {
		t.Fatal(err)
	}
	if ack := payload.(loadAck); ack.Accepted {
		t.Fatal("throttled report acknowledged as accepted")
	}

	invalid := hostload.Report{SchemaVersion: 9}
	if _, err := c.handleAuthorized(t.Context(), signedHostRequest(t, hostKey, "load", s.SessionID, s.Epoch, invalid)); err == nil {
		t.Fatal("invalid load report accepted")
	}
}

func TestTerraBaseLoadExpires(t *testing.T) {
	var a Agent
	a.noteTerraBaseLoad("terrabase", &memberstatus.Load{Connections: 7})
	if got := a.currentTerraBaseLoads(); got["terrabase"].Connections != 7 {
		t.Fatalf("fresh load missing: %+v", got)
	}
	a.loadMu.Lock()
	entry := a.terraBaseLoads["terrabase"]
	entry.at = time.Now().Add(-terraBaseLoadTTL - time.Second)
	a.terraBaseLoads["terrabase"] = entry
	a.loadMu.Unlock()
	if got := a.currentTerraBaseLoads(); len(got) != 0 {
		t.Fatalf("stale load kept: %+v", got)
	}
	a.noteTerraBaseLoad("terrabase", &memberstatus.Load{})
	a.noteTerraBaseLoad("terrabase", nil)
	if got := a.currentTerraBaseLoads(); len(got) != 0 {
		t.Fatalf("cleared load kept: %+v", got)
	}
}

// Backoff doubles up to its cap but never publishes more often than the
// configured interval.
func TestLoadBackoffNeverShortensTheInterval(t *testing.T) {
	for _, tc := range []struct{ wait, interval, want time.Duration }{
		{15 * time.Second, 15 * time.Second, 30 * time.Second},
		{8 * time.Minute, 15 * time.Second, maxLoadBackoff},
		{time.Hour, time.Hour, time.Hour},
		{30 * time.Minute, 30 * time.Minute, 30 * time.Minute},
	} {
		if got := nextLoadWait(tc.wait, tc.interval); got != tc.want {
			t.Errorf("nextLoadWait(%v, %v) = %v, want %v", tc.wait, tc.interval, got, tc.want)
		}
	}
}
