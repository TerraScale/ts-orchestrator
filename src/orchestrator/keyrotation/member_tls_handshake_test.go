package keyrotation

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDynamicTLSActualListenerChangesCertificateAndFences(t *testing.T) {
	initial, trust := receiverIdentity(t)
	dynamic, err := NewDynamicTLS(initial, trust)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	server.TLS = dynamic.TLSConfig()
	server.StartTLS()
	defer server.Close()
	firstPair, _ := tls.X509KeyPair(initial, initial)
	// Test transport inspects exact leaf bytes below; generated fixture leaves
	// deliberately have no DNS SAN. Production gateway always verifies hostnames.
	dial := func(pair tls.Certificate) (*tls.Conn, error) {
		return tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, Certificates: []tls.Certificate{pair}})
	}
	first, err := dial(firstPair)
	if err != nil {
		t.Fatal(err)
	}
	old := string(first.ConnectionState().PeerCertificates[0].Raw)
	first.Close()
	replacement, roots := receiverIdentity(t)
	secondPair, _ := tls.X509KeyPair(replacement, replacement)
	request := MemberRotationRequest{OperationID: "reload-live", Consumer: "control", Action: "reload", Generation: 1, ControlTLS: replacement, TrustBundle: roots, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	if _, err := dynamic.apply(request); err != nil {
		t.Fatal(err)
	}
	second, err := dial(secondPair)
	if err != nil {
		t.Fatal(err)
	}
	if string(second.ConnectionState().PeerCertificates[0].Raw) == old {
		t.Fatal("listener retained old certificate")
	}
	second.Close()
	if _, err := dynamic.apply(MemberRotationRequest{OperationID: "fence-live", Consumer: "control", Action: "fence"}); err != nil {
		t.Fatal(err)
	}
	fenced, err := dial(secondPair)
	if err == nil {
		fenced.Close()
		t.Fatal("fenced listener accepted handshake")
	}
}
