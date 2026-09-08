package databaseadmission

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func authorizationLeaseFixture(t *testing.T) (AuthorizationLeaseRequest, []byte, []byte) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	return AuthorizationLeaseRequest{OperationID: "request-1", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAA", Scope: `{"database_ids":["db-a","db-b"],"project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAB"}`, CredentialGeneration: 7, PermissionSetGeneration: 11, Audience: "https://api.terrascale.tech", Region: "GRU", IssuedAt: now, ValidUntil: now.Add(30 * time.Second)}, key, key
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
	changed.CredentialGeneration++
	if err := changed.Verify(public, request.IssuedAt.Add(time.Second)); err == nil {
		t.Fatal("changed generation retained authorization")
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

func TestAuthorizationLeaseKeepsInternalScopeOutOfWireSignature(t *testing.T) {
	request, public, private := authorizationLeaseFixture(t)
	lease, err := SignAuthorizationLease(request, "auth-key-1", private)
	if err != nil {
		t.Fatal(err)
	}
	if lease.Scope != `{"database_ids":["db-a","db-b"],"project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAB"}` {
		t.Fatalf("scope = %q, want canonical scope", lease.Scope)
	}
	changed := lease
	changed.Scope = `{"database_ids":["db-a","db-c"],"project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAB"}`
	if err := changed.Verify(public, request.IssuedAt.Add(time.Second)); err != nil {
		t.Fatalf("internal scope changed published lease signature: %v", err)
	}
}

func TestAuthorizationLeaseMatchesSharedContractVector(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locating test source")
	}
	fixturePath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", "..", "ts-dashboard", "tests", "fixtures", "authorization-lease-v1.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read shared lease fixture: %v", err)
	}
	var fixture struct {
		Key       string             `json:"key"`
		Canonical string             `json:"canonical"`
		Lease     AuthorizationLease `json:"lease"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("decode shared lease fixture: %v", err)
	}
	keyBytes, err := hex.DecodeString(fixture.Key)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(authorizationLeasePayload(fixture.Lease)); got != fixture.Canonical {
		t.Fatalf("canonical lease body = %q, want %q", got, fixture.Canonical)
	}
	if err := fixture.Lease.Verify(keyBytes, time.Unix(1001, 0)); err != nil {
		t.Fatalf("shared lease vector did not verify: %v", err)
	}
	encoded, err := json.Marshal(fixture.Lease)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"scope"`)) {
		t.Fatalf("shared lease vector exposed internal scope: %s", encoded)
	}
}

func TestAuthorizationLeaseRejectsExpiredAndFutureRequests(t *testing.T) {
	request, _, private := authorizationLeaseFixture(t)
	request.IssuedAt = time.Now().UTC().Add(-31 * time.Second).Truncate(time.Second)
	request.ValidUntil = request.IssuedAt.Add(30 * time.Second)
	if _, err := SignAuthorizationLease(request, "auth-key-1", private); !errors.Is(err, ErrAuthorizationLeaseInvalid) {
		t.Fatalf("expired request accepted: %v", err)
	}
	request.IssuedAt = time.Now().UTC().Add(10 * time.Second).Truncate(time.Second)
	request.ValidUntil = request.IssuedAt.Add(30 * time.Second)
	if _, err := SignAuthorizationLease(request, "auth-key-1", private); !errors.Is(err, ErrAuthorizationLeaseInvalid) {
		t.Fatalf("future request accepted: %v", err)
	}
}

func TestAuthorizationLeaseJSONRoundTripPreservesScope(t *testing.T) {
	request, public, private := authorizationLeaseFixture(t)
	lease, err := SignAuthorizationLease(request, "auth-key-1", private)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(lease)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || bytes.Contains(encoded, []byte(`"scope"`)) {
		t.Fatalf("public lease exposed internal admission scope: %s", encoded)
	}
	var decoded AuthorizationLease
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Scope != "" || decoded.Verify(public, request.IssuedAt.Add(time.Second)) != nil {
		t.Fatalf("round trip changed wire lease or signature: %#v", decoded)
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
	// The old operation is immutable and replays the exact signed bytes.
	if replay, err := second.Issue(ctx, request); err != nil || replay != issued {
		t.Fatalf("authority replay diverged: %+v %v", replay, err)
	}
	changedScope := request
	changedScope.Scope = `{"database_ids":["db-other"],"project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAB"}`
	if _, err := second.Issue(ctx, changedScope); !errors.Is(err, ErrAuthorizationLeaseConflict) {
		t.Fatalf("changed admission scope replay was accepted: %v", err)
	}
	if err := second.Revoke(ctx, request.TenantID, request.CredentialGeneration, request.PermissionSetGeneration); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Issue(ctx, request); !errors.Is(err, ErrAuthorizationLeaseRevoked) {
		t.Fatalf("revoked lease replayed: %v", err)
	}
	changed := request
	changed.PermissionSetGeneration++
	if _, err := second.Issue(ctx, changed); !errors.Is(err, ErrAuthorizationLeaseRevoked) {
		t.Fatalf("revoked generation was accepted: %v", err)
	}
	cluster.servers[1].Shutdown()
	cluster.servers[2].Shutdown()
	cluster.servers[1].WaitForShutdown()
	cluster.servers[2].WaitForShutdown()
	if _, err := second.Issue(ctx, request); err == nil {
		t.Fatal("minority published authorization lease")
	}
}
