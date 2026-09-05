package security

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

func TestParseCommandSignatureSignerPEMRetainsIndependentKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(pkcs8)
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(sec1)
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewCommandSignatureVerifierFromKeys([]CommandSignatureTrustKey{{Algorithm: CommandSignatureAlgorithm, PublicKeySPKI: spki}})
	if err != nil {
		t.Fatal(err)
	}
	for name, der := range map[string][]byte{"PRIVATE KEY": pkcs8, "EC PRIVATE KEY": sec1} {
		t.Run(name, func(t *testing.T) {
			data := pem.EncodeToMemory(&pem.Block{Type: name, Bytes: der})
			signer, err := ParseCommandSignatureSignerPEM(data)
			if err != nil {
				t.Fatal(err)
			}
			defer signer.Close()
			clear(data)
			material := commandTestMaterial("captured-key")
			signature, err := signer.Sign(material)
			if err != nil || verifier.Verify(material, signature) != protocol.VerificationOutcomeValid {
				t.Fatalf("clearing captured PEM damaged signer: %v", err)
			}
			if err = signer.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = signer.Sign(material); err == nil {
				t.Fatal("closed signer still signs")
			}
		})
	}
}

func TestParseCommandSignatureSignerPEMRejectsHostileData(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	valid := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	defer clear(valid)
	wrongCurve, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongDER, err := x509.MarshalPKCS8PrivateKey(wrongCurve)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wrongDER)
	cases := map[string][]byte{
		"malformed leading block": append([]byte("-----BEGIN EC PRIVATE KEY-----\ninvalid\n-----END EC PRIVATE KEY-----\n"), valid...),
		"empty":                   nil,
		"oversized":               bytes.Repeat([]byte{'x'}, maximumCommandKeyBytes+1),
		"multiple blocks":         append(append([]byte{}, valid...), valid...),
		"prefix":                  append([]byte("unexpected prefix\n"), valid...),
		"suffix":                  append(append([]byte{}, valid...), []byte("suffix")...),
		"wrong label":             pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}),
		"headers":                 pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: der}),
		"wrong curve":             pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: wrongDER}),
		"malformed DER":           pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("invalid")}),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			defer clear(data)
			if signer, err := ParseCommandSignatureSignerPEM(data); err == nil {
				signer.Close()
				t.Fatal("invalid credential accepted")
			}
		})
	}
}

func TestLoadCommandSignatureSignerPEMBoundsAndPermissions(t *testing.T) {
	if !runtimeIsLinux() {
		t.Skip("credential file handling requires Linux")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(der)
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer clear(data)
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	signer, err := LoadCommandSignatureSignerPEM(path)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	if _, err = signer.Sign(commandTestMaterial("loaded-key")); err != nil {
		t.Fatalf("loader clearing its PEM damaged signer: %v", err)
	}
	if runtimeIsLinux() {
		if err = os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if signer, err = LoadCommandSignatureSignerPEM(path); err == nil {
			signer.Close()
			t.Fatal("publicly readable private key accepted")
		}
		if err = os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.WriteFile(path, bytes.Repeat([]byte{'x'}, maximumCommandKeyBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if signer, err = LoadCommandSignatureSignerPEM(path); err == nil {
		signer.Close()
		t.Fatal("oversized credential accepted")
	}
}
