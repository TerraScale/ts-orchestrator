package messaging

import (
	"crypto/tls"
	"testing"

	"github.com/nats-io/nats.go"
)

func TestNatsTLSOptionsRequireTLS13(t *testing.T) {
	options := nats.GetDefaultOptions()
	tlsOptions := (&NatsTlsFiles{CaFile: "ca", CertificateFile: "cert", KeyFile: "key"}).Options()
	if len(tlsOptions) == 0 {
		t.Fatal("TLS options are empty")
	}
	if err := tlsOptions[0](&options); err != nil {
		t.Fatal(err)
	}
	if options.TLSConfig == nil || options.TLSConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("TLS minimum version = %v, want TLS 1.3", options.TLSConfig.MinVersion)
	}
}
