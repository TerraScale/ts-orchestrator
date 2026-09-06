package hostsecrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
)

func TestIdentitySecretDurableGenerationAndLockedFetch(t *testing.T) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	provider := common.NewRawConfigurationProvider("tenant", "user", "sa-saopaulo-1", "fingerprint", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	i, e := NewIdentitySecretIssuer(IdentitySecretIssuerConfig{Provider: provider, Region: "sa-saopaulo-1", CompartmentID: "ocid1.compartment.oc1..fixture", VaultID: "ocid1.vault.oc1.sa-saopaulo-1.fixture", KeyID: "ocid1.key.oc1.sa-saopaulo-1.fixture", Authority: func(_ context.Context) error { return nil }})
	if e != nil {
		t.Fatal(e)
	}
	r := IdentitySecretRequest{"test-operation", 7}
	id := "ocid1.vaultsecret.oc1.sa-saopaulo-1.fixture"
	metadata := identitySecretMetadata{ID: id, SecretName: identitySecretName(r), CompartmentID: i.config.CompartmentID, VaultID: i.config.VaultID, KeyID: i.config.KeyID, LifecycleState: "ACTIVE", CurrentVersionNumber: 1, FreeformTags: map[string]string{"purpose": "identity-service-auth", "operation": r.OperationID, "generation": "7"}}
	exists := false
	creates := 0
	var secret string
	i.transport = roundTrip(func(req *http.Request) (*http.Response, error) {
		if !strings.HasPrefix(req.Header.Get("Authorization"), "Signature ") {
			t.Error("unsigned OCI request")
		}
		switch {
		case req.Method == http.MethodPost:
			creates++
			body, _ := io.ReadAll(req.Body)
			hash := sha256.Sum256(body)
			if req.Header.Get("x-content-sha256") != base64.StdEncoding.EncodeToString(hash[:]) {
				t.Error("unsigned body")
			}
			var payload struct {
				SecretContent struct {
					Content     string `json:"content"`
					ContentType string `json:"contentType"`
				} `json:"secretContent"`
			}
			if json.Unmarshal(body, &payload) != nil || payload.SecretContent.ContentType != "BASE64" {
				t.Error("bad provider body")
			}
			raw, e := base64.StdEncoding.Strict().DecodeString(payload.SecretContent.Content)
			if e != nil || len(raw) != 43 {
				t.Error("invalid secret format")
			}
			entropy, e := base64.RawURLEncoding.Strict().DecodeString(string(raw))
			if e != nil || len(entropy) != 32 || bytes.Equal(entropy, make([]byte, 32)) {
				t.Error("weak entropy")
			}
			secret = payload.SecretContent.Content
			exists = true
			// A lost create acknowledgement must recover by the immutable provider name.
			return nil, io.ErrUnexpectedEOF
		case strings.Contains(req.URL.Path, "secretbundles"):
			if req.URL.Query().Get("versionNumber") != "1" {
				t.Error("unpinned secret")
			}
			return response(200, `{"secretId":"`+id+`","versionNumber":1,"secretBundleContent":{"contentType":"BASE64","content":"`+secret+`"}}`), nil
		case req.URL.RawQuery != "":
			if !exists {
				return response(200, "[]"), nil
			}
			b, _ := json.Marshal([]identitySecretMetadata{metadata})
			return response(200, string(b)), nil
		default:
			b, _ := json.Marshal(metadata)
			return response(200, string(b)), nil
		}
	})
	ref, e := i.Generate(t.Context(), r)
	if e != nil {
		t.Fatal(e)
	}
	again, e := i.Generate(t.Context(), r)
	if e != nil || ref != again || creates != 1 {
		t.Fatal("durable generation not reused")
	}
	credential, e := i.Fetch(t.Context(), ref)
	if e != nil {
		t.Fatal(e)
	}
	defer credential.Close()
	want, _ := base64.StdEncoding.DecodeString(secret)
	if !bytes.Equal(credential.Bytes(), want) {
		t.Fatal("wrong credential")
	}
	for _, f := range []string{"%v", "%+v", "%#v", "%x"} {
		if fmt.Sprintf(f, credential) != "[redacted identity service credential]" {
			t.Fatal("credential formatting leaked")
		}
	}
	metadata.FreeformTags["purpose"] = "ts-capability"
	if s, e := i.Fetch(t.Context(), ref); e == nil {
		s.Close()
		t.Fatal("accepted another key purpose")
	}
}

func TestIdentityBundleParserRejectsAmbiguity(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("A", 43)))
	good := `{"secretId":"secret","versionNumber":1,"secretBundleContent":{"contentType":"BASE64","content":"` + encoded + `"}}`
	value, e := identityBundleContent([]byte(good), "secret")
	if e != nil || string(value) != encoded {
		t.Fatal("valid bundle rejected")
	}
	for _, bad := range []string{
		strings.Replace(good, `"versionNumber":1`, `"versionNumber":1,"versionNumber":1`, 1),
		strings.Replace(good, `"secretId":"secret"`, `"secretId":"wrong"`, 1),
		strings.Replace(good, `"versionNumber":1`, `"versionNumber":2`, 1),
		strings.Replace(good, `"contentType":"BASE64"`, `"contentType":"TEXT"`, 1),
		strings.Replace(good, `"content":"`, `"content":"AA\\`, 1),
		good + `{}`, strings.Replace(good, `"versionNumber":1`, `"versionNumber":01`, 1),
		strings.Replace(good, `"versionNumber":1`, `"versionNumber":1,"timeOfDeletion":"2030-01-01T00:00:00Z"`, 1),
	} {
		if _, e := identityBundleContent([]byte(bad), "secret"); e == nil {
			t.Fatal("ambiguous bundle accepted")
		}
	}
}
