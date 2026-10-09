//go:build linux

package host

import (
	"context"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostload"
)

func TestLoadOperationValidatesCurrentManagedBinding(t *testing.T) {
	for _, tc := range []struct {
		name     string
		change   func(*Desired)
		filtered bool
	}{
		{name: "exact binding"},
		{"wrong environment", func(d *Desired) { d.Environment = "staging" }, true},
		{"generic desired on managed host", func(d *Desired) { d.ManagedMember = nil }, true},
		{"wrong instance", func(d *Desired) { d.ManagedMember.OCI.InstanceID += "-other" }, true},
		{"wrong member attempt", func(d *Desired) { d.ManagedMember.Member.HostAttempt++ }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registration, desired, hostKey := managedContractFixture()
			registration.ManagedPlacement = &ManagedPlacementBinding{
				DatabaseID: "01000000000000000000000001", PartitionID: "01000000000000000000000002",
				SeatID: "01000000000000000000000003", IntentGeneration: 1,
				IntentPayloadDigest: strings.Repeat("1", 64), CanonicalRosterDigest: strings.Repeat("2", 64),
				ManagedHostProfileDigest: strings.Repeat("3", 64),
			}
			c, _, _, _, _ := testControllerWithVerifier(t,
				managedRegistrationVerifierFunc(func(context.Context, Registration) error { return nil }))
			if _, err := c.Register(t.Context(), registration); err != nil {
				t.Fatal(err)
			}
			result, err := c.handleSession(t.Context(), signedHostRequest(t, hostKey, "session", strings.Repeat("1", 32), 0,
				struct {
					Kind string `json:"kind"`
				}{"acquire"}))
			if err != nil {
				t.Fatal(err)
			}
			s := result.(session)
			if tc.change != nil {
				tc.change(&desired)
			}
			replaceLoadTestDesired(t, c, desired)
			cpu := 0.5
			calls := 0
			c.SetLoadSink(func(origin hostload.Origin, report hostload.Report) error {
				calls++
				wantRoles := 1
				if tc.filtered {
					wantRoles = 0
				}
				if origin != (hostload.Origin{Cell: registration.Cell, Environment: registration.Environment, Node: registration.Node}) ||
					report.Host.CPU == nil || *report.Host.CPU != cpu || len(report.Roles) != wantRoles ||
					(wantRoles == 1 && report.Roles[0].Role != desired.Role) {
					t.Fatalf("sink got origin %+v report %+v", origin, report)
				}
				return nil
			})
			report := hostload.Report{SchemaVersion: hostload.SchemaVersion, Host: hostload.HostUsage{CPU: &cpu}, Roles: []hostload.RoleUsage{{Role: desired.Role}}}
			payload, err := c.handleAuthorized(t.Context(), signedHostRequest(t, hostKey, "load", s.SessionID, s.Epoch, report))
			if err != nil || calls != 1 {
				t.Fatalf("valid managed load error = %v, sink calls = %d", err, calls)
			}
			if ack, ok := payload.(loadAck); !ok || !ack.Accepted {
				t.Fatalf("valid managed load not acknowledged: %#v", payload)
			}
		})
	}
}
