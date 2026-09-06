package keyrotation

import (
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
	if err := gateway.Distribute(t.Context(), "gru-1", credentials, "operation/stage"); err != nil {
		t.Fatal(err)
	}
	if string(seen.WorkloadTLS) != "only-this-member" || len(seen.ControlTLS) != 0 {
		t.Fatal("cross-member identity disclosure")
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
