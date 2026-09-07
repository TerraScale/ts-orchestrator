package keyrotation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReceiverRejectsUnverifiedTLS(t *testing.T) {
	r := &memberReceiver{}
	req := httptest.NewRequest(http.MethodPost, memberRotationPath, nil)
	req.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}
func TestReceiverForwardsOnlyKeyFields(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "consumer.sock")
	tokenFile := filepath.Join(dir, "token")
	token := strings.Repeat("t", 32)
	if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan bool, 4)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("missing token")
		}
		var fields map[string]any
		if err := json.UnmarshalRead(r.Body, &fields); err != nil {
			t.Error(err)
		}
		for _, forbidden := range []string{"node_id", "consumer", "control_tls"} {
			if _, ok := fields[forbidden]; ok {
				t.Errorf("forwarded %s", forbidden)
			}
		}
		if fields["current_key_id"] != "key" || fields["origin_current_key_id"] != "origin" || fields["origin_current_key"] != base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)) || fields["current_key"] == fields["origin_current_key"] || fields["origin_expires_at"] != fields["expires_at"] {
			t.Error("bridge lost independent origin ring")
		}
		seen <- true
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"operation_id":"stage","generation":1,"valid_until":4102444800,"state":"staged"}`))
	})}
	go server.Serve(listener)
	defer server.Close()
	cert, ca := receiverIdentity(t)
	dynamic, err := NewDynamicTLS(cert, ca)
	if err != nil {
		t.Fatal(err)
	}
	pair, _ := tls.X509KeyPair(cert, cert)
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	pin := hex.EncodeToString(sum[:])
	calls := 0
	handler, err := NewMemberReceiver(MemberReceiverConfig{NodeID: "node", SocketPath: socket, TokenFile: tokenFile, StateDir: dir, ControllerSPKI: []string{pin}, ControlTLS: dynamic, CheckPeerAuthority: func(_ context.Context, got string, epoch uint64, lease string) error {
		calls++
		if got != pin {
			t.Error("wrong peer")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer handler.(interface{ Close() error }).Close()
	if second, err := NewMemberReceiver(handler.(*memberReceiver).config); err == nil {
		second.(interface{ Close() error }).Close()
		t.Fatal("duplicate receiver acquired state lock")
	}
	q := MemberRotationRequest{AuthorityEpoch: 1, AuthorityLeaseID: "lease1", OperationID: "stage", NodeID: "node", Consumer: "member", Action: "stage", Generation: 1, ExpiresAt: time.Now().Add(time.Minute).Unix(), CurrentKeyID: "key", CurrentKey: bytes.Repeat([]byte{1}, 32), OriginCurrentKeyID: "origin", OriginCurrentKey: bytes.Repeat([]byte{2}, 32), OriginExpiresAt: time.Now().Add(time.Minute).Unix(), WorkloadTLS: cert, TrustBundle: ca}
	q.OriginExpiresAt = q.ExpiresAt
	body, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, memberRotationPath, bytes.NewReader(body))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	if calls < 2 {
		t.Fatal("authority not checked at effects")
	}
	for _, test := range []struct {
		action     string
		generation uint64
		status     int
	}{{"stage", 2, http.StatusBadGateway}, {"fence", 0, http.StatusOK}} {
		q.Action = test.action
		q.Generation = test.generation
		payload, err := json.Marshal(q)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, memberRotationPath, bytes.NewReader(payload))
		req.TLS = request.TLS
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, req)
		if result.Code != test.status {
			t.Fatalf("%s generation %d status %d", test.action, test.generation, result.Code)
		}
	}
	select {
	case <-seen:
	default:
		t.Fatal("consumer was not called")
	}
}
