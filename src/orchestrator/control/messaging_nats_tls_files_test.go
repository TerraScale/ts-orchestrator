package control

import (
	"crypto/tls"
	"testing"

	"github.com/nats-io/nats.go"
)

func TestNatsTlsFilesOptionsRequireTLS13(t *testing.T) {
	files := &NatsTlsFiles{CaFile: "ca.pem", CertificateFile: "client.pem", KeyFile: "client-key.pem"}
	options := files.Options()
	if len(options) == 0 {
		t.Fatal("expected TLS options")
	}
	var natsOptions nats.Options
	if err := options[0](&natsOptions); err != nil {
		t.Fatalf("apply secure option: %v", err)
	}
	if natsOptions.TLSConfig == nil || natsOptions.TLSConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("TLS minimum version = %#v, want TLS 1.3", natsOptions.TLSConfig)
	}
}
