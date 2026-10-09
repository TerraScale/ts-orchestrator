package host

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/memberstatus"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

func TestLoadOperationIsRefusedUntilASinkIsSet(t *testing.T) {
	c, hostKey, s, _ := reportedTestHost(t)
	report := hostload.Report{SchemaVersion: hostload.SchemaVersion}
	if _, err := c.handleAuthorized(t.Context(), signedHostRequest(t, hostKey, "load", s.SessionID, s.Epoch, report)); err == nil ||
		!strings.Contains(err.Error(), errLoadDisabled.Error()) {
		t.Fatalf("load accepted without a sink: %v", err)
	}
}

func TestLoadOperationRejectsMalformedFilesystemsBeforeSink(t *testing.T) {
	c, hostKey, session, _ := reportedTestHost(t)
	calls := 0
	c.SetLoadSink(func(hostload.Origin, hostload.Report) error { calls++; return nil })
	valid := observability.FilesystemView{Role: "terrabase_data", Path: "/terrabase/data", SizeBytes: 100, AvailBytes: 40, FreeBytes: 50}
	for name, filesystems := range map[string][]observability.FilesystemView{
		"duplicate roles": {valid, valid},
		"invalid size":    {{Role: valid.Role, Path: valid.Path, SizeBytes: 10, AvailBytes: 40, FreeBytes: 50}},
		"invalid role":    {{Role: "data.*", Path: valid.Path, SizeBytes: 100}},
		"invalid path":    {{Role: valid.Role, Path: "data", SizeBytes: 100}},
	} {
		t.Run(name, func(t *testing.T) {
			report := hostload.Report{SchemaVersion: hostload.SchemaVersion, Host: hostload.HostUsage{Filesystems: filesystems}}
			if _, err := c.handleAuthorized(t.Context(), signedHostRequest(t, hostKey, "load", session.SessionID, session.Epoch, report)); !errors.Is(err, hostload.ErrInvalidReport) {
				t.Fatalf("malformed filesystem reached sink: %v", err)
			}
		})
	}
	if calls != 0 {
		t.Fatalf("invalid filesystems reached sink %d times", calls)
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
	report := hostload.Report{SchemaVersion: hostload.SchemaVersion,
		Host: hostload.HostUsage{CPUCores: 8, MemoryBytes: 16 << 30, Filesystems: []observability.FilesystemView{
			{Role: "terrabase_data", Path: "/terrabase/data", SizeBytes: 100, AvailBytes: 40, FreeBytes: 50, Device: 3},
		}}, Roles: []hostload.RoleUsage{
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
		!sameJSON(gotReport.Host, report.Host) || len(gotReport.Roles) != 1 || gotReport.Roles[0].Role != "terrabase" {
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

	// Throttled reports return a negative acknowledgement, which the
	// agent treats as a rejection and backs off.
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

func replaceLoadTestDesired(t *testing.T, c *Controller, desired Desired) {
	t.Helper()
	_, revision, _, err := c.readDesired(t.Context(), desired.Node, desired.Role)
	if err != nil {
		t.Fatal(err)
	}
	payload, operation, err := mutationPayload(desired)
	if err != nil {
		t.Fatal(err)
	}
	// Bypass admission to exercise validation of current stored desired state.
	if _, err := c.mutations.CommitHostMutation(t.Context(), desired.AuthorityEpoch, authority.MutationDesired,
		desiredSubjectKey(c.cell, desired.Node, desired.Role), operation, revision, payload); err != nil {
		t.Fatal(err)
	}
}

func TestLoadOperationFiltersInvalidDesiredAndKeepsOtherUsage(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Desired)
	}{
		{"wrong environment", func(d *Desired) { d.Environment = "staging" }},
		{"managed desired on generic host", func(d *Desired) { d.ManagedMember = &ManagedMemberLaunch{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, hostKey, s, _ := reportedTestHost(t)
			r, _, _, err := c.readRegistration(t.Context(), "node-a")
			if err != nil {
				t.Fatal(err)
			}
			r.Roles = append(r.Roles, "api")
			r.Generation++
			if _, err := c.Register(t.Context(), r); err != nil {
				t.Fatal(err)
			}
			key := sessionKey(c.cell, r.Node)
			old, revision, _, err := c.sessionSnapshot(t.Context(), key)
			if err != nil {
				t.Fatal(err)
			}
			old.ExpiresAt = time.Now().Add(-time.Second)
			if _, err := c.cas(t.Context(), key, old, revision); err != nil {
				t.Fatal(err)
			}
			result, err := c.handleSession(t.Context(), signedHostRequest(t, hostKey, "session", s.SessionID, 0,
				struct {
					Kind string `json:"kind"`
				}{"acquire"}))
			if err != nil {
				t.Fatal(err)
			}
			s = result.(session)
			desired, _, _, err := c.readDesired(t.Context(), "node-a", "terrabase")
			if err != nil {
				t.Fatal(err)
			}
			valid := desired
			valid.Role = "api"
			if _, err := c.ApplyDesired(t.Context(), valid); err != nil {
				t.Fatal(err)
			}
			tc.change(&desired)
			replaceLoadTestDesired(t, c, desired)
			cpu, memory, disk, cores := 0.5, 0.6, 0.7, 0.125
			report := hostload.Report{SchemaVersion: hostload.SchemaVersion,
				Host:  hostload.HostUsage{CPU: &cpu, Memory: &memory, Disk: &disk},
				Roles: []hostload.RoleUsage{{Role: "terrabase"}, {Role: "api", CPUCores: &cores}}}
			calls := 0
			c.SetLoadSink(func(origin hostload.Origin, got hostload.Report) error {
				calls++
				if origin != (hostload.Origin{Cell: r.Cell, Environment: r.Environment, Node: r.Node}) ||
					!sameJSON(got.Host, report.Host) || len(got.Roles) != 1 || !sameJSON(got.Roles[0], report.Roles[1]) {
					t.Fatalf("sink got origin %+v report %+v", origin, got)
				}
				return nil
			})
			payload, err := c.handleAuthorized(t.Context(), signedHostRequest(t, hostKey, "load", s.SessionID, s.Epoch, report))
			if err != nil || calls != 1 {
				t.Fatalf("filtered load error = %v, sink calls = %d", err, calls)
			}
			if ack, ok := payload.(loadAck); !ok || !ack.Accepted || loadOutcome(nil, ack) != nil {
				t.Fatalf("filtered load not acknowledged: %#v", payload)
			}
		})
	}
}

func TestLoadOperationRejectsInvalidAuthorizationBeforeSink(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *Controller, *request, ed25519.PrivateKey)
		want   string
	}{
		{"wrong session", func(t *testing.T, _ *Controller, req *request, key ed25519.PrivateKey) {
			req.SessionID = "0000000000M44BFMMJRNPNN6BB"
			if err := signRequest(req, key, "gru"); err != nil {
				t.Fatal(err)
			}
		}, "host session is not current"},
		{"wrong epoch", func(t *testing.T, _ *Controller, req *request, key ed25519.PrivateKey) {
			req.Epoch++
			if err := signRequest(req, key, "gru"); err != nil {
				t.Fatal(err)
			}
		}, "host session is not current"},
		{"expired session", func(t *testing.T, c *Controller, _ *request, _ ed25519.PrivateKey) {
			key := sessionKey(c.cell, "node-a")
			s, revision, _, err := c.sessionSnapshot(t.Context(), key)
			if err != nil {
				t.Fatal(err)
			}
			s.ExpiresAt = time.Now().Add(-time.Second)
			if _, err := c.cas(t.Context(), key, s, revision); err != nil {
				t.Fatal(err)
			}
		}, "host session is not current"},
		{"invalid signature", func(_ *testing.T, _ *Controller, req *request, _ ed25519.PrivateKey) {
			req.Envelope.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		}, "signature"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, hostKey, s, _ := reportedTestHost(t)
			calls := 0
			c.SetLoadSink(func(hostload.Origin, hostload.Report) error {
				calls++
				return nil
			})
			report := hostload.Report{SchemaVersion: hostload.SchemaVersion, Roles: []hostload.RoleUsage{{Role: "terrabase"}}}
			req := signedHostRequest(t, hostKey, "load", s.SessionID, s.Epoch, report)
			tc.change(t, c, &req, hostKey)
			if _, err := c.handleAuthorized(t.Context(), req); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("invalid authorization load error = %v, want %q", err, tc.want)
			}
			if calls != 0 {
				t.Fatalf("invalid authorization reached sink %d times", calls)
			}
		})
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
	// A block not refreshed for three polls (at least 5s) is dropped long
	// before the absolute cap.
	a.cfg.PollInterval = time.Second
	a.noteTerraBaseLoad("terrabase", &memberstatus.Load{Connections: 3})
	a.loadMu.Lock()
	entry = a.terraBaseLoads["terrabase"]
	entry.at = time.Now().Add(-6 * time.Second)
	a.terraBaseLoads["terrabase"] = entry
	a.loadMu.Unlock()
	if got := a.currentTerraBaseLoads(); len(got) != 0 {
		t.Fatalf("load missing several polls kept: %+v", got)
	}
	a.noteTerraBaseLoad("terrabase", &memberstatus.Load{})
	a.noteTerraBaseLoad("terrabase", nil)
	if got := a.currentTerraBaseLoads(); len(got) != 0 {
		t.Fatalf("cleared load kept: %+v", got)
	}
}

func TestLoadOperationKeepsAllocatedRolesWithUnknownUsage(t *testing.T) {
	c, hostKey, session, _ := reportedTestHost(t)
	var got hostload.Report
	c.SetLoadSink(func(_ hostload.Origin, report hostload.Report) error { got = report; return nil })
	report := hostload.Report{SchemaVersion: hostload.SchemaVersion}
	if _, err := c.handleAuthorized(t.Context(), signedHostRequest(t, hostKey, "load", session.SessionID, session.Epoch, report)); err != nil {
		t.Fatal(err)
	}
	if len(got.Roles) != 1 || got.Roles[0].Role != "terrabase" || got.Roles[0].CPUCores != nil || got.Roles[0].MemoryBytes != nil || got.Roles[0].LimitsRead {
		t.Fatalf("allocated role lost or unknown usage invented: %+v", got)
	}
	desired, _, _, err := c.readDesired(t.Context(), "node-a", "terrabase")
	if err != nil {
		t.Fatal(err)
	}
	withdrawal := Desired{Cell: desired.Cell, Node: desired.Node, Environment: desired.Environment, Role: desired.Role, Generation: desired.Generation + 1, AuthorityEpoch: desired.AuthorityEpoch, Withdrawn: true}
	if _, err := c.ApplyDesired(t.Context(), withdrawal); err != nil {
		t.Fatal(err)
	}
	if _, err := c.handleAuthorized(t.Context(), signedHostRequest(t, hostKey, "load", session.SessionID, session.Epoch, report)); err != nil {
		t.Fatal(err)
	}
	if len(got.Roles) != 0 {
		t.Fatalf("withdrawn role still reserved resources: %+v", got)
	}
}

// A discarded (throttled) sample is a rejection that backs off.
func TestLoadOutcomeTreatsDiscardedSampleAsRejection(t *testing.T) {
	if err := loadOutcome(nil, loadAck{Accepted: true}); err != nil {
		t.Fatal(err)
	}
	if err := loadOutcome(nil, loadAck{}); err != errLoadThrottled || loadErrorClass(err) != "throttled" {
		t.Fatalf("discarded sample outcome = %v", err)
	}
	if err := loadOutcome(errLoadDisabled, loadAck{}); err != errLoadDisabled {
		t.Fatalf("request error replaced: %v", err)
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
