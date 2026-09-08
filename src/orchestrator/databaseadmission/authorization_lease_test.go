package databaseadmission

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func authorizationLeaseFixture(t *testing.T) (AuthorizationLeaseRequest, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	return AuthorizationLeaseRequest{OperationID: "request-1", TenantID: "tenant-1", Scope: "production/tenant-1/project-1/database-1", CredentialGeneration: 7, PermissionSetGeneration: 11, Audience: "https://api.terrascale.tech", Region: "GRU", IssuedAt: now, ValidUntil: now.Add(30 * time.Second)}, public, private
}

func TestAuthorizationLeaseSignsExactScopeAndRejectsContractDrift(t *testing.T) {
	request, public, private := authorizationLeaseFixture(t)
	lease, err := SignAuthorizationLease(request, "auth-key-1", private)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Verify(public, request.IssuedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	changed := lease
	changed.Scope = "production/tenant-1/project-2/database-1"
	if err := changed.Verify(public, request.IssuedAt.Add(time.Second)); err == nil {
		t.Fatal("changed scope retained authorization")
	}
	for name, mutate := range map[string]func(*AuthorizationLeaseRequest){
		"long lifetime":      func(r *AuthorizationLeaseRequest) { r.ValidUntil = r.IssuedAt.Add(31 * time.Second) },
		"wrong region":       func(r *AuthorizationLeaseRequest) { r.Region = "IAD" },
		"wrong audience":     func(r *AuthorizationLeaseRequest) { r.Audience = "http://api.terrascale.tech" },
		"missing generation": func(r *AuthorizationLeaseRequest) { r.CredentialGeneration = 0 },
	} {
		bad := request
		mutate(&bad)
		if _, err := SignAuthorizationLease(bad, "auth-key-1", private); !errors.Is(err, ErrAuthorizationLeaseInvalid) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
}

func TestAuthorizationLeasePublicationReplaysAfterRestart(t *testing.T) {
	cluster := newAdmissionJournalCluster(t)
	ctx := t.Context()
	connection := cluster.connect(t)
	store := openAdmissionLeaseStore(t, ctx, connection, true)
	putAdmissionLease(t, ctx, store, admissionLease(1, "global-controller-gru-one"))
	request, _, private := authorizationLeaseFixture(t)
	config := AuthorizationLeasePublisherConfig{Connection: connection, CandidateID: "global-controller-gru-one", AuthorityEpoch: 1, LeaseID: "lease-1", KeyID: "auth-key-1", PrivateKey: private, Audience: request.Audience}
	first, err := NewAuthorizationLeasePublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := first.Issue(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	cluster.restart(t)
	connection = cluster.connect(t)
	store = openAdmissionLeaseStore(t, ctx, connection, false)
	putAdmissionLease(t, ctx, store, admissionLease(2, "global-controller-gru-two"))
	config.Connection, config.CandidateID, config.AuthorityEpoch, config.LeaseID = connection, "global-controller-gru-two", 2, "lease-2"
	second, err := NewAuthorizationLeasePublisher(config)
	if err != nil {
		t.Fatal(err)
	}
	// The old operation is immutable; a changed generation cannot overwrite it.
	if replay, err := second.Issue(ctx, request); err == nil || replay != issued {
		t.Fatalf("changed authority replay diverged: %+v %v", replay, err)
	}
	changed := request
	changed.OperationID = "request-2"
	changed.PermissionSetGeneration++
	if _, err := second.Issue(ctx, changed); err != nil {
		t.Fatal(err)
	}
	cluster.servers[1].Shutdown()
	cluster.servers[2].Shutdown()
	cluster.servers[1].WaitForShutdown()
	cluster.servers[2].WaitForShutdown()
	if _, err := second.Issue(ctx, request); err == nil {
		t.Fatal("minority published authorization lease")
	}
}
