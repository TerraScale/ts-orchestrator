package serviceidentityrotation

import (
	"context"
	"slices"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
	"testing"
	"time"
)

type memoryStore struct{ j Journal }

func (s *memoryStore) Load(context.Context) (Journal, error)   { return s.j, nil }
func (s *memoryStore) Save(_ context.Context, j Journal) error { s.j = j; return nil }

type fakeIssuer struct{}

func rotationTestReference(name string, generation uint64) hostsecrets.IdentitySecretReference {
	return hostsecrets.IdentitySecretReference{SecretID: "ocid1.vaultsecret.oc1." + name, VersionNumber: 1, Generation: generation, OperationID: "rotation-" + name}
}

func (fakeIssuer) Generate(_ context.Context, r hostsecrets.IdentitySecretRequest) (hostsecrets.IdentitySecretReference, error) {
	return hostsecrets.IdentitySecretReference{SecretID: "ocid1.vaultsecret.oc1.new", Generation: r.Generation, VersionNumber: 1, OperationID: r.OperationID}, nil
}
func (fakeIssuer) Fetch(context.Context, hostsecrets.IdentitySecretReference) (*hostsecrets.IdentitySecret, error) {
	return &hostsecrets.IdentitySecret{}, nil
}

type effects struct {
	calls              []string
	fail               bool
	failDelivery       bool
	targets            [][]RemoteMemberEndpoint
	validateEnrollment func(context.Context, RemoteMemberEndpoint) error
}

func (e *effects) ValidateEnrollment(ctx context.Context, member RemoteMemberEndpoint) error {
	if e.validateEnrollment != nil {
		return e.validateEnrollment(ctx, member)
	}
	return nil
}

func (e *effects) SetIdentityServiceKeys(_ context.Context, _ string, _, _ []byte, deadline time.Time) error {
	if deadline.IsZero() {
		e.calls = append(e.calls, "single")
	} else {
		e.calls = append(e.calls, "overlap")
	}
	return nil
}
func (e *effects) DeliverTo(_ context.Context, targets []RemoteMemberEndpoint, _ hostsecrets.IdentitySecretReference, revision uint64, _ []byte) error {
	e.targets = append(e.targets, slices.Clone(targets))
	if e.failDelivery {
		return ErrRotation
	}
	if revision%2 == 0 {
		e.calls = append(e.calls, "adopt")
		if e.fail {
			return ErrRotation
		}
	} else {
		e.calls = append(e.calls, "rollback")
	}
	return nil
}
func TestAdoptionFailureRestoresDashboardBeforeMember(t *testing.T) {
	s := &memoryStore{Journal{Generation: 1, RosterRevision: 1, Members: []RemoteMemberEndpoint{{NodeID: "first", URL: "https://first.internal"}}, Active: rotationTestReference("old", 1), NextRotation: time.Now().Add(-time.Hour)}}
	e := &effects{fail: true}
	c, err := New(Config{BootstrapMembers: []RemoteMemberEndpoint{{NodeID: "first", URL: "https://first.internal"}}, Issuer: fakeIssuer{}, Store: s, Dashboard: e, Members: e, Script: "dashboard", Period: time.Hour, Overlap: 300 * time.Second, Authority: func(context.Context) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	want := []string{"overlap", "adopt", "single", "rollback"}
	if len(e.calls) != len(want) {
		t.Fatal(e.calls)
	}
	for i := range want {
		if e.calls[i] != want[i] {
			t.Fatal(e.calls)
		}
	}
	if s.j.Active.SecretID != "ocid1.vaultsecret.oc1.old" || s.j.Phase != "" {
		t.Fatal("failed adoption promoted pending key")
	}
}
func TestExpiredRecoveryNeverRestagesPrevious(t *testing.T) {
	s := &memoryStore{Journal{Generation: 2, RosterRevision: 1, Members: []RemoteMemberEndpoint{{NodeID: "first", URL: "https://first.internal"}}, Active: rotationTestReference("old", 2), Pending: rotationTestReference("new", 2), Phase: "stage", Deadline: time.Now().Add(-time.Second)}}
	e := &effects{}
	c, _ := New(Config{BootstrapMembers: []RemoteMemberEndpoint{{NodeID: "first", URL: "https://first.internal"}}, Issuer: fakeIssuer{}, Store: s, Dashboard: e, Members: e, Script: "dashboard", Period: time.Hour, Overlap: 300 * time.Second, Authority: func(context.Context) error { return nil }})
	if c.Run(t.Context()) != nil {
		t.Fatal("recovery failed")
	}
	if len(e.calls) != 2 || e.calls[0] != "single" || e.calls[1] != "rollback" {
		t.Fatal(e.calls)
	}
}
func TestEmptyJournalBootstrapsIssuedReference(t *testing.T) {
	s := &memoryStore{}
	e := &effects{}
	c, _ := New(Config{BootstrapMembers: []RemoteMemberEndpoint{{NodeID: "first", URL: "https://first.internal"}}, Issuer: fakeIssuer{}, Store: s, Dashboard: e, Members: e, Script: "dashboard", Period: time.Hour, Overlap: 300 * time.Second, Authority: func(context.Context) error { return nil }})
	if c.Run(t.Context()) != nil || s.j.Active.SecretID != "ocid1.vaultsecret.oc1.new" || s.j.Generation != 1 {
		t.Fatal("bootstrap failed")
	}
	if len(e.calls) != 2 || e.calls[0] != "single" || e.calls[1] != "adopt" {
		t.Fatal(e.calls)
	}
}

func TestRunRejectsInvalidLoadedJournal(t *testing.T) {
	s := &memoryStore{j: Journal{Generation: 1, Active: hostsecrets.IdentitySecretReference{SecretID: "plaintext"}}}
	e := &effects{}
	c, err := New(Config{BootstrapMembers: []RemoteMemberEndpoint{{NodeID: "first", URL: "https://first.internal"}}, Issuer: fakeIssuer{}, Store: s, Dashboard: e, Members: e, Script: "dashboard", Period: time.Hour, Overlap: 300 * time.Second, Authority: func(context.Context) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Run(t.Context()); err != ErrRotation {
		t.Fatalf("invalid journal was admitted: %v", err)
	}
	if len(e.calls) != 0 {
		t.Fatalf("invalid journal triggered effects: %v", e.calls)
	}
}

func TestAdoptedRecoveryOnlyRemovesPrevious(t *testing.T) {
	s := &memoryStore{Journal{Generation: 2, RosterRevision: 1, Members: []RemoteMemberEndpoint{{NodeID: "first", URL: "https://first.internal"}}, Active: rotationTestReference("old", 2), Pending: rotationTestReference("new", 2), Phase: "commit", Deadline: time.Now().Add(-time.Minute)}}
	e := &effects{}
	c, _ := New(Config{BootstrapMembers: []RemoteMemberEndpoint{{NodeID: "first", URL: "https://first.internal"}}, Issuer: fakeIssuer{}, Store: s, Dashboard: e, Members: e, Script: "dashboard", Period: time.Hour, Overlap: 300 * time.Second, Authority: func(context.Context) error { return nil }})
	if c.Run(t.Context()) != nil {
		t.Fatal("commit recovery failed")
	}
	if len(e.calls) != 1 || e.calls[0] != "single" || s.j.Active.SecretID != "ocid1.vaultsecret.oc1.new" {
		t.Fatal("adopted recovery restaged or rolled back", e.calls)
	}
}

func rosterCoordinator(t *testing.T) (*Coordinator, *memoryStore, *effects) {
	t.Helper()
	s := &memoryStore{}
	e := &effects{}
	c, err := New(Config{BootstrapMembers: []RemoteMemberEndpoint{{NodeID: "first", URL: "https://first.internal"}}, Issuer: fakeIssuer{}, Store: s, Dashboard: e, Members: e, Script: "dashboard", Period: time.Hour, Overlap: 300 * time.Second, Authority: func(context.Context) error { return nil }})
	if err != nil || c.Run(t.Context()) != nil {
		t.Fatal("bootstrap failed", err)
	}
	return c, s, e
}
func TestEnrolledMemberParticipatesInNextRotation(t *testing.T) {
	c, s, e := rosterCoordinator(t)
	second := RemoteMemberEndpoint{NodeID: "second", URL: "https://second.internal"}
	if c.Enroll(t.Context(), second) != nil {
		t.Fatal("enrollment failed")
	}
	if s.j.RosterRevision != 2 || len(s.j.Members) != 2 {
		t.Fatal("roster was not persisted")
	}
	if last := e.targets[len(e.targets)-1]; len(last) != 2 || last[0].NodeID != "first" || last[1] != second {
		t.Fatal("enrollment did not prove complete roster", last)
	}
	s.j.NextRotation = time.Now().Add(-time.Second)
	if c.Run(t.Context()) != nil {
		t.Fatal("rotation failed")
	}
	if last := e.targets[len(e.targets)-1]; len(last) != 2 || last[1] != second {
		t.Fatal("rotation omitted enrolled member", last)
	}
	if c.config.BootstrapMembers[0].NodeID != "first" || len(c.config.BootstrapMembers) != 1 {
		t.Fatal("roster modified bootstrap config")
	}
}
func TestFailedEnrollmentCannotAdmitAndRetryProvesAgain(t *testing.T) {
	c, s, e := rosterCoordinator(t)
	second := RemoteMemberEndpoint{NodeID: "second", URL: "https://second.internal"}
	e.failDelivery = true
	if c.Enroll(t.Context(), second) == nil {
		t.Fatal("failed adoption was admitted")
	}
	if len(s.j.Members) != 2 || s.j.RosterRevision != 2 {
		t.Fatal("failed enrollment lost durable roster")
	}
	e.failDelivery = false
	if c.Enroll(t.Context(), second) != nil || s.j.RosterRevision != 2 {
		t.Fatal("retry failed or changed roster revision")
	}
	if c.Enroll(t.Context(), RemoteMemberEndpoint{NodeID: "second", URL: "https://changed.internal"}) == nil {
		t.Fatal("changed endpoint adopted")
	}
	if c.Enroll(t.Context(), RemoteMemberEndpoint{NodeID: "third", URL: "https://second.internal/"}) == nil {
		t.Fatal("duplicate endpoint adopted")
	}
}

func TestUnauthorizedEnrollmentIsRejectedBeforeJournalSave(t *testing.T) {
	c, s, e := rosterCoordinator(t)
	prior := s.j
	priorDeliveries := len(e.targets)
	e.validateEnrollment = func(context.Context, RemoteMemberEndpoint) error { return ErrRotation }
	if c.Enroll(t.Context(), RemoteMemberEndpoint{NodeID: "untrusted", URL: "https://untrusted.internal"}) == nil {
		t.Fatal("unauthorized enrollment succeeded")
	}
	if !sameJournal(s.j, prior) {
		t.Fatalf("unauthorized enrollment changed journal: before=%+v after=%+v", prior, s.j)
	}
	if len(e.targets) != priorDeliveries {
		t.Fatalf("unauthorized enrollment delivered after save: %d deliveries", len(e.targets))
	}
}
func TestRosterChangesRejectBusyRotationAndRetainLastHost(t *testing.T) {
	c, s, _ := rosterCoordinator(t)
	second := RemoteMemberEndpoint{NodeID: "second", URL: "https://second.internal"}
	s.j.Phase = "stage"
	deadline := time.Now().Add(time.Minute)
	s.j.Deadline = deadline
	if c.Enroll(t.Context(), second) == nil || s.j.RosterRevision != 1 || !s.j.Deadline.Equal(deadline) {
		t.Fatal("busy enrollment changed operation")
	}
	if c.RetireMember(t.Context(), s.j.Members[0]) == nil {
		t.Fatal("busy retirement succeeded")
	}
	s.j.Phase = ""
	s.j.Deadline = time.Time{}
	if c.RetireMember(t.Context(), s.j.Members[0]) == nil {
		t.Fatal("retired final host")
	}
	if c.Enroll(t.Context(), second) != nil {
		t.Fatal("enrollment failed")
	}
	if c.RetireMember(t.Context(), second) != nil || len(s.j.Members) != 1 || s.j.RosterRevision != 3 {
		t.Fatal("retirement failed")
	}
}
