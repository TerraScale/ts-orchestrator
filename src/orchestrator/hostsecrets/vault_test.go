package hostsecrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestVaultDecryptUsesFederatedIdentityExactKEKAndAAD(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "opc-tenant:ocid1.tenancy.oc1..fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	payload := fmt.Sprintf(`{"exp":%d,"iat":%d}`, time.Now().Add(time.Hour).Unix(), time.Now().Unix())
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".fixture"
	kek := "ocid1.key.oc1.sa-saopaulo-1.fixture"
	version := "ocid1.keyversion.oc1.sa-saopaulo-1.fixture"
	endpoint := "https://fixture-crypto.kms.sa-saopaulo-1.oraclecloud.com"
	associated := map[string]string{"database_id": "database-fixture", "purpose": "data"}
	calls := 0
	transport := roundTrip(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "169.254.169.254" {
			if request.Header.Get("Authorization") != "Bearer Oracle" {
				t.Error("unsigned metadata")
			}
			switch {
			case strings.HasSuffix(request.URL.Path, "/region"):
				return response(200, "sa-saopaulo-1"), nil
			case strings.HasSuffix(request.URL.Path, "/key.pem"):
				return response(200, keyPEM), nil
			default:
				return response(200, certPEM), nil
			}
		}
		if request.URL.Host == "auth.sa-saopaulo-1.oraclecloud.com" {
			body, _ := json.Marshal(map[string]string{"token": token})
			return response(200, string(body)), nil
		}
		calls++
		if (request.URL.String() != endpoint+"/20180608/decrypt" && request.URL.String() != endpoint+"/20180608/encrypt") || request.Method != "POST" || !strings.Contains(request.Header.Get("Authorization"), "ST$") {
			t.Error("wrong Vault request or unsigned principal")
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}
		digest := sha256.Sum256(body)
		if request.Header.Get("x-content-sha256") != base64.StdEncoding.EncodeToString(digest[:]) || !strings.Contains(request.Header.Get("Authorization"), "x-content-sha256") {
			t.Error("body digest absent from signature")
		}
		var data struct {
			Plaintext           string            `json:"plaintext"`
			KeyID               string            `json:"keyId"`
			KeyVersionID        string            `json:"keyVersionId"`
			Ciphertext          string            `json:"ciphertext"`
			AssociatedData      map[string]string `json:"associatedData"`
			EncryptionAlgorithm string            `json:"encryptionAlgorithm"`
		}
		if json.Unmarshal(body, &data) != nil || data.KeyID != kek || data.KeyVersionID != version || data.AssociatedData["database_id"] != "database-fixture" || data.AssociatedData["purpose"] != "data" || data.EncryptionAlgorithm != "AES_256_GCM" {
			t.Error("scope or version not bound")
		}
		if strings.HasSuffix(request.URL.Path, "/encrypt") {
			if data.Plaintext != base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) || data.Ciphertext != "" {
				t.Error("wrong wrapped plaintext")
			}
			return response(200, `{"ciphertext":"wrapped-by-vault"}`), nil
		}
		if data.Ciphertext != "wrapped-fixture" || data.Plaintext != "" {
			t.Error("wrong ciphertext")
		}
		return response(200, `{"plaintext":"`+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))+`","plaintextChecksum":"fixture-checksum","keyId":"`+kek+`","keyVersionId":"`+version+`","encryptionAlgorithm":"AES_256_GCM"}`), nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	// This internal helper is called under the shared identity gate in production.
	leased, err := unwrapDataKey(ctx, "sa-saopaulo-1", endpoint, kek, version, "wrapped-fixture", associated, transport)
	if err != nil {
		t.Fatal(err)
	}
	defer ReleaseDataKey(leased)
	if calls != 1 || !bytes.Equal(leased.Bytes(), bytes.Repeat([]byte{7}, 32)) {
		t.Fatal("wrong leased key")
	}
	wrapped, err := wrapDataKey(ctx, "sa-saopaulo-1", endpoint, kek, version, leased, associated, transport)
	if err != nil || wrapped != "wrapped-by-vault" || calls != 2 {
		t.Fatalf("wrapped key request failed: %v", err)
	}
}
func TestVaultCryptoRejectsUntrustedEndpointsBeforeIdentity(t *testing.T) {
	for _, endpoint := range []string{"https://evil.example", "https://fixture-crypto.kms.sa-saopaulo-1.oraclecloud.com:443", "https://fixture-crypto.kms.eu-frankfurt-1.oraclecloud.com", "https://fixture-crypto.kms.sa-saopaulo-1.oraclecloud.com/path"} {
		if ValidVaultCryptoEndpoint("sa-saopaulo-1", endpoint) {
			t.Fatal("untrusted endpoint accepted")
		}
	}
}

func TestLockedDecryptParserRejectsAmbiguity(t *testing.T) {
	for _, body := range []string{`{"plaintext":"AAAA","plaintext":"BBBB"}`, `{"plaintext":"AAAA","extra":1}`, `{"plaintext":"AA\u0041A"}`, `{"plaintext":"AAAA"} trailing`, `{"other":"AAAA"}`} {
		if _, err := decryptFields([]byte(body), "key", "version"); err == nil {
			t.Fatal("ambiguous response accepted")
		}
	}
	body := []byte(` { "plaintext" : "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "plaintextChecksum":"checksum" } `)
	encoded, err := decryptFields(body, "key", "version")
	if err != nil || len(encoded) != 44 {
		t.Fatal("valid response rejected")
	}

}
func TestClosedLockedRequestBodyCannotReadUnmappedStorage(t *testing.T) {
	key, err := NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	body := &lockedRequestBody{reader: bytes.NewReader(key.Bytes())}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	ReleaseDataKey(key)
	var destination [32]byte
	if _, err := body.Read(destination[:]); err != io.ErrClosedPipe {
		t.Fatal("read allowed after mapping ownership ended")
	}
}
