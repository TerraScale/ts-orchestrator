package hostenroll

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestParseCSRRejectsCallerChosenIdentityAndNonP256Keys(t *testing.T) {
	for _, test := range []struct {
		name    string
		curve   elliptic.Curve
		dnsName string
		wantErr bool
	}{
		{name: "empty P-256 scope", curve: elliptic.P256()},
		{name: "caller DNS name", curve: elliptic.P256(), dnsName: "operator.terrascale.internal", wantErr: true},
		{name: "P-384 key", curve: elliptic.P384(), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(test.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			request := &x509.CertificateRequest{}
			if test.dnsName != "" {
				request.DNSNames = []string{test.dnsName}
			}
			csrDER, err := x509.CreateCertificateRequest(rand.Reader, request, key)
			if err != nil {
				t.Fatal(err)
			}
			wire := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
			_, err = ParseCSR(wire)
			if (err != nil) != test.wantErr {
				t.Fatalf("ParseCSR error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}
