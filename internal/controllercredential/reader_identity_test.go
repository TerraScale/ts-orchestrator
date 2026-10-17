package controllercredential

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
)

// These inputs check descriptive identity retention, not credential authority.
func TestControllerReaderSourceIdentityPinsOriginalMaterial(t *testing.T) {
	expires := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	fixture := func() (controllerReaderSnapshot, []controllerReaderMaterial) {
		return controllerReaderSnapshot{
			accepted: bootstrapstart.AcceptedIdentity{Cell: "gru", Slot: "controller-a", ConfigSHA256: map[string]string{"b": "two", "a": "one"}},
			chain:    []byte("retained-signed-chain"), config: []byte("retained-exact-config"),
		}, []controllerReaderMaterial{{Reference: bootstrap.SecretReference{
			SecretOCID: "original-secret", VersionNumber: 7, SHA256: "original-signed-digest", TargetFile: "controller.creds",
		}, SHA256: "original-verified-bytes-digest", ExpiresAt: expires}}
	}
	snapshot, material := fixture()
	original, err := controllerReaderSourceIdentity(snapshot, material, expires)
	if err != nil || len(original) != 64 {
		t.Fatalf("original identity = %q, %v", original, err)
	}
	snapshot.accepted.ConfigSHA256 = map[string]string{"a": "one", "b": "two"}
	stable, err := controllerReaderSourceIdentity(snapshot, material, expires)
	if err != nil || stable != original {
		t.Fatalf("map insertion order changed original identity: %q, %v", stable, err)
	}
	for name, change := range map[string]func(*controllerReaderSnapshot, []controllerReaderMaterial, *time.Time){
		"accepted scope": func(s *controllerReaderSnapshot, _ []controllerReaderMaterial, _ *time.Time) {
			s.accepted.Slot = "controller-b"
		},
		"signed chain": func(s *controllerReaderSnapshot, _ []controllerReaderMaterial, _ *time.Time) { s.chain[0]++ },
		"exact config": func(s *controllerReaderSnapshot, _ []controllerReaderMaterial, _ *time.Time) { s.config[0]++ },
		"secret version": func(_ *controllerReaderSnapshot, m []controllerReaderMaterial, _ *time.Time) {
			m[0].Reference.VersionNumber++
		},
		"actual bytes": func(_ *controllerReaderSnapshot, m []controllerReaderMaterial, _ *time.Time) {
			m[0].SHA256 = "different-bytes"
		},
		"bundle cap": func(_ *controllerReaderSnapshot, m []controllerReaderMaterial, _ *time.Time) {
			m[0].ExpiresAt = expires.Add(time.Second)
		},
		"source cap": func(_ *controllerReaderSnapshot, _ []controllerReaderMaterial, cap *time.Time) {
			*cap = cap.Add(time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			snapshot, material := fixture()
			cap := expires
			change(&snapshot, material, &cap)
			changed, err := controllerReaderSourceIdentity(snapshot, material, cap)
			if err != nil || changed == original {
				t.Fatalf("changed original material retained identity: %q, %v", changed, err)
			}
		})
	}
}

func TestControllerReaderSourceIdentityRejectsUnopenedReader(t *testing.T) {
	for _, reader := range []*ControllerReader{nil, {}} {
		identity, expires, err := reader.SourceIdentity(t.Context())
		if !errors.Is(err, ErrDelivery) || identity != "" || !expires.IsZero() {
			t.Fatalf("unopened reader returned source identity %q, %s, %v", identity, expires, err)
		}
	}
}

func TestControllerReaderCertificateExpiryIncludesVerifiedRoot(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, public, private)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, public, private)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	expires, err := controllerReaderCertificateExpiry(leafPEM, rootPEM)
	if err != nil || !expires.Equal(root.NotAfter) {
		t.Fatalf("source cap must include verified root: %s, %v", expires, err)
	}
	for _, bad := range [][]byte{nil, []byte("invalid certificate")} {
		if _, err := controllerReaderCertificateExpiry(bad, rootPEM); !errors.Is(err, ErrDelivery) {
			t.Fatalf("invalid certificate accepted: %v", err)
		}
	}
}
