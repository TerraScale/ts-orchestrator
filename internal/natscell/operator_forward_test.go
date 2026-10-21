package natscell

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json/v2"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestOperatorForwardSelectsOnlyConfiguredPrivateControllers(t *testing.T) {
	config := Config{Cell: "gru", Instance: "operator", Replicas: 3, ClientRole: "operator",
		URL:             "tls://10.251.0.11:4222,tls://10.251.0.12:4222,tls://10.251.0.13:4222",
		CredentialsFile: "operator.creds", TLS: TLSFiles{CAFile: "ca", CertFile: "cert", KeyFile: "key"},
		OperatorForward: map[string]string{"10.251.0.12:4222": "127.0.0.1:14222"}}
	selected, destinations, err := operatorForwarding(config)
	if err != nil || selected != "tls://10.251.0.12:4222" || destinations["10.251.0.12:4222"] != "127.0.0.1:14222" {
		t.Fatalf("selected forwarding = %q, %v, %v", selected, destinations, err)
	}
	if err := config.validate(); err != nil {
		t.Fatalf("valid operator forward rejected: %v", err)
	}
	t.Run("lab", func(t *testing.T) {
		var removed Config
		if err := json.Unmarshal([]byte(`{"lab":true}`), &removed, json.RejectUnknownMembers(true)); err == nil {
			t.Fatal("removed lab configuration was accepted")
		}
	})
	for _, test := range []struct {
		name   string
		change func(*Config)
	}{
		{"controller role", func(c *Config) { c.ClientRole = "controller" }},
		{"host role", func(c *Config) { c.ClientRole = "host" }},
		{"embedded", func(c *Config) { c.Embedded = &Embedded{} }},
		{"unknown controller", func(c *Config) { c.OperatorForward = map[string]string{"10.251.0.99:4222": "127.0.0.1:14222"} }},
		{"public controller", func(c *Config) { c.URL = "tls://8.8.8.8:4222" }},
		{"wrong controller port", func(c *Config) { c.URL = "tls://10.251.0.12:4223" }},
		{"loopback controller", func(c *Config) { c.URL = "tls://127.0.0.1:4222" }},
		{"nonloopback destination", func(c *Config) { c.OperatorForward["10.251.0.12:4222"] = "10.251.0.99:14222" }},
		{"hostname destination", func(c *Config) { c.OperatorForward["10.251.0.12:4222"] = "localhost:14222" }},
		{"invalid destination port", func(c *Config) { c.OperatorForward["10.251.0.12:4222"] = "127.0.0.1:0" }},
		{"duplicate configured URL", func(c *Config) { c.URL = "tls://10.251.0.12:4222,tls://10.251.0.12:4222" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := config
			changed.OperatorForward = map[string]string{"10.251.0.12:4222": "127.0.0.1:14222"}
			test.change(&changed)
			if err := changed.validate(); err == nil {
				t.Fatal("invalid operator forwarding accepted")
			}
		})
	}
}

func TestOperatorForwardTLSVerifiesOriginalControllerIPAndClientCert(t *testing.T) {
	const controller = "10.251.0.11:4222"
	for _, test := range []struct {
		name      string
		serverIP  string
		wantError bool
	}{
		{name: "matching controller", serverIP: "10.251.0.11"},
		{name: "wrong certificate identity", serverIP: "10.251.0.12", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverTLS, clientTLS := forwardTLSFixture(t, test.serverIP)
			listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			serverResult := make(chan error, 1)
			go func() {
				connection, err := listener.Accept()
				if err == nil {
					err = connection.(*tls.Conn).Handshake()
					_ = connection.Close()
				}
				serverResult <- err
			}()
			dialer := &tlsFirstDialer{config: clientTLS, timeout: time.Second,
				forward: map[string]string{controller: listener.Addr().String()}}
			connection, err := dialer.Dial("tcp", controller)
			if test.wantError {
				if err == nil || !strings.Contains(err.Error(), "certificate") {
					if connection != nil {
						_ = connection.Close()
					}
					t.Fatalf("wrong controller certificate accepted: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("forwarded mutual TLS failed: %v", err)
				}
				state := connection.(*tls.Conn).ConnectionState()
				if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 ||
					state.PeerCertificates[0].VerifyHostname("10.251.0.11") != nil {
					t.Fatal("forwarded TLS connection did not verify the original controller IP")
				}
				_ = connection.Close()
				if err := <-serverResult; err != nil {
					t.Fatalf("server rejected client certificate: %v", err)
				}
			}
			if connection, err := dialer.Dial("tcp", "10.251.0.99:4222"); err == nil || connection != nil {
				if connection != nil {
					_ = connection.Close()
				}
				t.Fatal("unmapped discovered controller was dialed")
			}
			if _, err := dialer.Dial("udp", controller); err == nil {
				t.Fatal("non-TCP forward was accepted")
			}
		})
	}
}

func forwardTLSFixture(t *testing.T, serverIP string) (*tls.Config, *tls.Config) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "forward test root"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(serial int64, usage x509.ExtKeyUsage, ip net.IP) tls.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute),
			NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if ip != nil {
			leaf.IPAddresses = []net.IP{ip}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	server := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{
		issue(2, x509.ExtKeyUsageServerAuth, net.ParseIP(serverIP))},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	client := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{
		issue(3, x509.ExtKeyUsageClientAuth, nil)}, RootCAs: roots}
	return server, client
}
