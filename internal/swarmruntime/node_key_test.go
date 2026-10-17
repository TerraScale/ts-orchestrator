package swarmruntime

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestParseNodeSigningKeyCapsEveryVerifiedCertificate(t *testing.T) {
	for _, limiting := range []string{"root", "intermediate", "leaf"} {
		t.Run(limiting, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			expected := now.Add(time.Hour)
			keys := make([]*ecdsa.PrivateKey, 3)
			certificates := make([]*x509.Certificate, 3)
			wire := make([][]byte, 3)
			for i, role := range []string{"root", "intermediate", "leaf"} {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				keys[i] = key
				expiry := now.Add(2 * time.Hour)
				if role == limiting {
					expiry = expected
				}
				template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)),
					Subject: pkix.Name{CommonName: role}, NotBefore: now.Add(-time.Hour), NotAfter: expiry,
					BasicConstraintsValid: true, IsCA: i < 2, KeyUsage: x509.KeyUsageDigitalSignature}
				if template.IsCA {
					template.KeyUsage |= x509.KeyUsageCertSign
				} else {
					template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
				}
				parent, signer := template, key
				if i > 0 {
					parent, signer = certificates[i-1], keys[i-1]
				}
				der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
				if err != nil {
					t.Fatal(err)
				}
				certificates[i], err = x509.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}
				wire[i] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			}
			keyDER, err := x509.MarshalECPrivateKey(keys[2])
			if err != nil {
				t.Fatal(err)
			}
			keyWire := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
			key, chain, deadline, err := parseNodeSigningKey("leaf", keyWire, append(wire[2], wire[1]...), wire[0])
			if err != nil {
				t.Fatal(err)
			}
			if key == nil || len(chain) != 2 || !deadline.Equal(expected) {
				t.Fatalf("verified %s expiry not retained: chain=%d deadline=%s want=%s", limiting, len(chain), deadline, expected)
			}
			verified, leaf, certificateExpiry, err := verifyNodeCertificateChain("leaf", append(wire[2], wire[1]...), wire[0])
			if err != nil || len(verified) != 2 || leaf == nil || leaf.Subject.CommonName != "leaf" || !certificateExpiry.Equal(expected) {
				t.Fatalf("actual native member %s expiry not retained: deadline=%s want=%s error=%v", limiting, certificateExpiry, expected, err)
			}
			if _, _, _, err := verifyNodeCertificateChain("other-member", append(wire[2], wire[1]...), wire[0]); err == nil {
				t.Fatal("another native member's certificate supplied an expiry cap")
			}
		})
	}
}
