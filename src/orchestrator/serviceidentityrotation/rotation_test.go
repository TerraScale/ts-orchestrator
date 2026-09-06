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

func (fakeIssuer) Generate(_ context.Context, r hostsecrets.IdentitySecretRequest) (hostsecrets.IdentitySecretReference, error) {
	return hostsecrets.IdentitySecretReference{SecretID: "new", Generation: r.Generation, VersionNumber: 1, OperationID: r.OperationID}, nil
}
func (fakeIssuer) Fetch(context.Context, hostsecrets.IdentitySecretReference) (*hostsecrets.IdentitySecret, error) {
	return &hostsecrets.IdentitySecret{}, nil
}

type effects struct {
	calls        []string
	fail         bool
	failDelivery bool
	targets      [][]RemoteMemberEndpoint
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
	s := &memoryStore{Journal{Generation: 1, Active: hostsecrets.IdentitySecretReference{SecretID: "old"}}}
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
	if s.j.Active.SecretID != "old" || s.j.Phase != "" {
		t.Fatal("failed adoption promoted pending key")
	}
}
func TestExpiredRecoveryNeverRestagesPrevious(t *testing.T) {
	s := &memoryStore{Journal{Generation: 2, Active: hostsecrets.IdentitySecretReference{SecretID: "old"}, Pending: hostsecrets.IdentitySecretReference{SecretID: "new"}, Phase: "stage", Deadline: time.Now().Add(-time.Second)}}
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
	if c.Run(t.Context()) != nil || s.j.Active.SecretID != "new" || s.j.Generation != 1 {
		t.Fatal("bootstrap failed")
	}
	if len(e.calls) != 2 || e.calls[0] != "single" || e.calls[1] != "adopt" {
		t.Fatal(e.calls)
	}
}

func TestAdoptedRecoveryOnlyRemovesPrevious(t *testing.T) {
	s := &memoryStore{Journal{Generation: 2, Active: hostsecrets.IdentitySecretReference{SecretID: "old"}, Pending: hostsecrets.IdentitySecretReference{SecretID: "new"}, Phase: "commit", Deadline: time.Now().Add(-time.Minute)}}
	e := &effects{}
	c, _ := New(Config{BootstrapMembers: []RemoteMemberEndpoint{{NodeID: "first", URL: "https://first.internal"}}, Issuer: fakeIssuer{}, Store: s, Dashboard: e, Members: e, Script: "dashboard", Period: time.Hour, Overlap: 300 * time.Second, Authority: func(context.Context) error { return nil }})
	if c.Run(t.Context()) != nil {
		t.Fatal("commit recovery failed")
	}
	if len(e.calls) != 1 || e.calls[0] != "single" || s.j.Active.SecretID != "new" {
		t.Fatal("adopted recovery restaged or rolled back", e.calls)
	}
}
