package keyrotation

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func TestMemberGatewaySelectsOnlyTargetIdentityAndChecksDispatchAuthority(t *testing.T) {
	clientPEM, clientTrust := receiverIdentity(t)
	pair, err := tls.X509KeyPair(clientPEM, clientPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(clientTrust)
	var seen MemberRotationRequest
	calls := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if len(r.TLS.VerifiedChains) == 0 {
			t.Error("missing authenticated caller")
		}
		if err := json.UnmarshalRead(r.Body, &seen); err != nil {
			t.Error(err)
		}
		reply, _ := json.Marshal(MemberRotationResponse{OperationID: seen.OperationID, Generation: seen.Generation, ValidUntil: time.Now().Add(time.Hour).Unix(), State: "staged"})
		w.Write(reply)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(server.Certificate())
	allowed := true
	gateway, err := NewMemberGateway(MemberGatewayConfig{AuthorityEpoch: 1, AuthorityLeaseID: "lease1", Members: []MemberEndpoint{{ID: "gru-1", Region: "gru", URL: server.URL}}, TLS: &tls.Config{RootCAs: serverRoots, Certificates: []tls.Certificate{pair}}, CheckAuthority: func(context.Context) error {
		if !allowed {
			return errors.New("fenced")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	envelope, _ := json.Marshal(map[string][]byte{"gru-1": []byte("only-this-member"), "fra-1": []byte("other-member-private-key")})
	credentials := security.CredentialSet{Identity: security.IdentityMaterial{Version: 1, ExpiresAt: time.Now().Add(time.Hour), WorkloadTLS: envelope, TrustBundle: []byte("ca")}, Capability: security.CapabilityMaterial{ID: "key-1", Version: 1, Key: make([]byte, 32), ExpiresAt: time.Now().Add(time.Hour)}}
	credentials.OriginProof = security.OriginProofMaterial{ID: "origin-1", Reference: "origin-ref-1", Version: 1, Secret: bytes.Repeat([]byte{7}, 32), ExpiresAt: time.Now().Add(time.Hour)}
	if err := gateway.Distribute(t.Context(), "gru-1", credentials, "operation/stage"); err != nil {
		t.Fatal(err)
	}
	if string(seen.WorkloadTLS) != "only-this-member" || len(seen.ControlTLS) != 0 {
		t.Fatal("cross-member identity disclosure")
	}
	if seen.CurrentKeyID != "key-1" || !bytes.Equal(seen.CurrentKey, credentials.Capability.Key) || seen.OriginCurrentKeyID != "origin-1" || !bytes.Equal(seen.OriginCurrentKey, credentials.OriginProof.Secret) || bytes.Equal(seen.OriginCurrentKey, seen.CurrentKey) {
		t.Fatal("member received capability material instead of origin proof")
	}
	missing := credentials
	missing.OriginProof = security.OriginProofMaterial{}
	if _, err := memberCredentialRequest("gru-1", "member", "stage", missing, "missing"); err == nil {
		t.Fatal("capability substituted for missing origin proof")
	}
	shared := credentials
	shared.OriginProof.Secret = bytes.Clone(credentials.Capability.Key)
	if _, err := memberCredentialRequest("gru-1", "member", "stage", shared, "shared"); err == nil {
		t.Fatal("shared material accepted")
	}
	allowed = false
	if err := gateway.Activate(t.Context(), "gru-1", 1, "operation/activate"); !errors.Is(err, ErrMemberRotation) {
		t.Fatalf("unfenced dispatch: %v", err)
	}
	if calls != 1 {
		t.Fatal("fenced request reached host")
	}
}
func TestMemberGatewayRejectsUnknownIdentityAndInsecureTransport(t *testing.T) {
	encoded, _ := json.Marshal(map[string][]byte{"other": []byte("private")})
	if _, err := selectMemberIdentity(encoded, "gru-1"); err == nil {
		t.Fatal("missing identity accepted")
	}
	if _, err := NewMemberGateway(MemberGatewayConfig{AuthorityEpoch: 1, AuthorityLeaseID: "lease1", Members: []MemberEndpoint{{ID: "gru-1", Region: "gru", URL: "http://127.0.0.1"}}, TLS: &tls.Config{InsecureSkipVerify: true}, CheckAuthority: func(context.Context) error { return nil }}); err == nil {
		t.Fatal("insecure transport accepted")
	}
}

func TestMemberCredentialRequestKeepsIndependentOverlap(t *testing.T) {
	now := time.Now().UTC()
	envelope, err := json.Marshal(map[string][]byte{"node": []byte("workload")})
	if err != nil {
		t.Fatal(err)
	}
	credentials := security.CredentialSet{
		Identity:            security.IdentityMaterial{Version: 3, ExpiresAt: now.Add(time.Hour), WorkloadTLS: envelope},
		Capability:          security.CapabilityMaterial{ID: "c3", Reference: "c3", Version: 3, ExpiresAt: now.Add(time.Hour), Key: bytes.Repeat([]byte{3}, 32)},
		PreviousCapability:  security.CapabilityMaterial{ID: "c2", Reference: "c2", Version: 2, ExpiresAt: now.Add(5 * time.Minute), Key: bytes.Repeat([]byte{2}, 32)},
		OriginProof:         security.OriginProofMaterial{ID: "o3", Reference: "o3", Version: 3, ExpiresAt: now.Add(30 * time.Minute), Secret: bytes.Repeat([]byte{13}, 32)},
		PreviousOriginProof: security.OriginProofMaterial{ID: "o1", Reference: "o1", Version: 1, ExpiresAt: now.Add(2 * time.Minute), Secret: bytes.Repeat([]byte{11}, 32)},
	}
	request, err := memberCredentialRequest("node", "member", "stage", credentials, "stage")
	if err != nil {
		t.Fatal(err)
	}
	if request.PreviousGeneration != 2 || request.OriginPreviousGeneration != 1 || request.PreviousExpiresAt != credentials.PreviousCapability.ExpiresAt.Unix() || request.OriginPreviousExpiresAt != credentials.PreviousOriginProof.ExpiresAt.Unix() || request.OriginExpiresAt != credentials.OriginProof.ExpiresAt.Unix() || !bytes.Equal(request.OriginPreviousKey, credentials.PreviousOriginProof.Secret) {
		t.Fatal("independent overlap lost")
	}
	clearMemberRequest(&request)
	if !bytes.Equal(request.OriginCurrentKey, make([]byte, 32)) || !bytes.Equal(request.OriginPreviousKey, make([]byte, 32)) || bytes.Equal(credentials.OriginProof.Secret, make([]byte, 32)) {
		t.Fatal("origin transient wipe or input isolation failed")
	}
}

func TestMemberCredentialRequestRejectsCrossDomainCollisionWithoutOriginOverlap(t *testing.T) {
	now := time.Now().UTC()
	envelope, err := json.Marshal(map[string][]byte{"node": []byte("workload")})
	if err != nil {
		t.Fatal(err)
	}
	previous := bytes.Repeat([]byte{2}, 32)
	credentials := security.CredentialSet{
		Identity:           security.IdentityMaterial{Version: 3, ExpiresAt: now.Add(time.Hour), WorkloadTLS: envelope},
		Capability:         security.CapabilityMaterial{ID: "c3", Reference: "c3", Version: 3, ExpiresAt: now.Add(time.Hour), Key: bytes.Repeat([]byte{3}, 32)},
		PreviousCapability: security.CapabilityMaterial{ID: "c2", Reference: "c2", Version: 2, ExpiresAt: now.Add(5 * time.Minute), Key: previous},
		OriginProof:        security.OriginProofMaterial{ID: "o3", Reference: "o3", Version: 3, ExpiresAt: now.Add(30 * time.Minute), Secret: bytes.Clone(previous)},
	}
	if _, err := memberCredentialRequest("node", "member", "stage", credentials, "stage"); err == nil {
		t.Fatal("accepted origin proof equal to previous capability without previous origin")
	}
}
