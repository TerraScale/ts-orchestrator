//go:build linux

package serviceidentityrotation

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBridgeRejectsUnauthenticatedAndStaleAuthority(t *testing.T) {
	peer := &x509.Certificate{RawSubjectPublicKeyInfo: []byte("controller"), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	digest := sha256.Sum256(peer.RawSubjectPublicKeyInfo)
	calls := 0
	handler, err := NewMemberBridge(MemberBridgeConfig{NodeID: "member", SocketPath: "/run/terrascale/admission.sock", ControllerSPKI: []string{hex.EncodeToString(digest[:])}, CheckPeerAuthority: func(context.Context, string, uint64, string) error { calls++; return ErrRotation }})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"node_id":"member","authority_epoch":1,"authority_lease_id":"lease","version":"oci-1","generation":2,"secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`
	for _, tc := range []struct {
		name   string
		tls    *tls.ConnectionState
		body   string
		status int
	}{
		{"missing TLS", nil, body, 401},
		{"unverified TLS", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}, body, 401},
		{"unknown field", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}, VerifiedChains: [][]*x509.Certificate{{peer}}}, strings.TrimSuffix(body, "}") + `,"destination":"/tmp/leak"}`, 400},
		{"stale authority", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}, VerifiedChains: [][]*x509.Certificate{{peer}}}, body, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", HandlerPath, strings.NewReader(tc.body))
			r.TLS = tc.tls
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d", w.Code, tc.status)
			}
			if strings.Contains(w.Body.String(), "AAAA") {
				t.Fatal("secret reflected")
			}
		})
	}
	if calls != 1 {
		t.Fatalf("authority calls %d", calls)
	}
}
