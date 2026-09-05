package hostsecrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func testEntry() Entry {
	return Entry{SecretID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.testsecret", VersionNumber: 3, SHA256: digest([]byte("private-canary")), Destination: "/etc/terrascale/ts-node-bootstrap/client.key"}
}
func testSeed() Seed {
	return Seed{Region: "sa-saopaulo-1", OperationID: "bootstrap-host-1", Entries: []Entry{testEntry()}}
}
func clientFixture(t *testing.T, transport http.RoundTripper) *secretFetcher {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	config := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "sa-saopaulo-1", "aa:bb", private, nil)
	client, err := secrets.NewSecretsClientWithConfigurationProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTPClient = boundedDispatcher{client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, ctx: context.Background(), region: "sa-saopaulo-1"}
	return &secretFetcher{client: client}
}
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}
func bundle(entry Entry, content []byte) string {
	body, _ := json.Marshal(map[string]any{"secretId": entry.SecretID, "versionNumber": entry.VersionNumber, "secretBundleContent": map[string]string{"contentType": "BASE64", "content": base64.StdEncoding.EncodeToString(content)}})
	return string(body)
}
func TestSignedPinnedVaultGET(t *testing.T) {
	entry := testEntry()
	calls := 0
	fetcher := clientFixture(t, roundTrip(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method != "GET" || request.URL.Path != "/20190301/secretbundles/"+entry.SecretID || request.URL.Query().Get("versionNumber") != "3" || request.URL.Query().Get("stage") != "" || !strings.Contains(request.Header.Get("Authorization"), "Signature version=") {
			t.Errorf("request did not carry exact signed version binding")
		}
		return response(200, bundle(entry, []byte("private-canary"))), nil
	}))
	body, err := fetcher.fetch(context.Background(), entry)
	if err != nil || string(body) != "private-canary" || calls != 1 {
		t.Fatalf("fetch failed: %v, calls %d", err, calls)
	}
	erase(body)
}
func TestVaultFailuresAreBoundedAndSanitized(t *testing.T) {
	entry := testEntry()
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"wrong-bytes", bundle(entry, []byte("secret-contents-must-not-escape")), 200},
		{"wrong-version", strings.Replace(bundle(entry, []byte("private-canary")), `"versionNumber":3`, `"versionNumber":4`, 1), 200},
		{"error-body", `{"code":"Denied","message":"secret-contents-must-not-escape"}`, 403},
		{"oversized", strings.Repeat("secret-contents-must-not-escape", 20000), 200},
		{"invalid-base64", strings.Replace(bundle(entry, []byte("private-canary")), base64.StdEncoding.EncodeToString([]byte("private-canary")), "%%%", 1), 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			fetcher := clientFixture(t, roundTrip(func(*http.Request) (*http.Response, error) { calls++; return response(tc.status, tc.body), nil }))
			body, err := fetcher.fetch(context.Background(), entry)
			if err == nil || len(body) != 0 || strings.Contains(err.Error(), "secret-contents") || calls != 1 {
				t.Fatalf("unsafe failure: %v, calls %d", err, calls)
			}
		})
	}
}
func TestDispatcherCancellationAndScope(t *testing.T) {
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	d := boundedDispatcher{ctx: ctx, region: "sa-saopaulo-1", client: &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) { calls.Add(1); return response(200, "ok"), nil })}}
	request, _ := http.NewRequest("GET", "https://attacker.invalid/secret", nil)
	if _, err := d.Do(request); err == nil {
		t.Fatal("accepted unrelated endpoint")
	}
	cancel()
	request, _ = http.NewRequest("GET", "http://169.254.169.254/opc/v2/identity/region", nil)
	if _, err := d.Do(request); err == nil {
		t.Fatal("ignored cancellation")
	}
	if calls.Load() != 0 {
		t.Fatal("sent denied request")
	}
}
func TestOfficialMetadataDeadlineStopsFurtherNetwork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	transport := roundTrip(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		if request.URL.Host != "169.254.169.254" {
			t.Error("unexpected metadata host")
		}
		cancel()
		return response(200, "sa-saopaulo-1"), nil
	})
	start := time.Now()
	fetcher, err := instanceFetcherWithTransport(ctx, "sa-saopaulo-1", transport)
	if err != ErrIdentity || fetcher != nil || time.Since(start) > time.Second {
		t.Fatal("metadata cancellation did not return promptly")
	}
	// The official SDK next requests the leaf certificate. Cancellation must
	// prevent that request even though region discovery returned valid bytes.
	select {
	case identityWorker <- struct{}{}:
	case <-time.After(time.Second):
		t.Fatal("canceled SDK worker did not exit")
	}
	defer func() { <-identityWorker }()
	if calls.Load() != 1 {
		t.Fatalf("post-cancel metadata requests: %d", calls.Load())
	}
	queued, cancelQueued := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelQueued()
	if f, e := instanceFetcherWithTransport(queued, "sa-saopaulo-1", transport); f != nil || e != ErrIdentity {
		t.Fatal("canceled waiter created another identity")
	}
	if calls.Load() != 1 {
		t.Fatal("queued retry reached network")
	}
}
func TestSeedAdmission(t *testing.T) {
	seed := testSeed()
	body, _ := json.Marshal(seed)
	if _, err := ParseSeed(body); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Seed){func(s *Seed) { s.Entries[0].Destination = "/etc/terrascale/ts-node.json" }, func(s *Seed) { s.Entries[0].VersionNumber = 0 }, func(s *Seed) { s.Entries[0].SHA256 = "sha256:" + s.Entries[0].SHA256 }, func(s *Seed) { s.Entries = append(s.Entries, s.Entries[0]) }} {
		copy := testSeed()
		change(&copy)
		if ValidateSeed(copy) == nil {
			t.Fatal("invalid seed accepted")
		}
	}
	if _, err := ParseSeed(bytes.Repeat([]byte("x"), MaxSeedBytes+1)); err == nil {
		t.Fatal("oversized seed accepted")
	}
}

func TestOfficialInstanceFederationThenPinnedSecret(t *testing.T) {
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
	var federation, gets atomic.Int32
	entry := testEntry()
	transport := roundTrip(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "169.254.169.254" {
			if request.Header.Get("Authorization") != "Bearer Oracle" {
				t.Error("metadata authorization absent")
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
			federation.Add(1)
			if request.Method != "POST" || request.Header.Get("Authorization") == "" {
				t.Error("official federation signature absent")
			}
			body, _ := json.Marshal(map[string]string{"token": token})
			return response(200, string(body)), nil
		}
		gets.Add(1)
		if !strings.Contains(request.Header.Get("Authorization"), "ST$") || request.URL.Query().Get("versionNumber") != "3" {
			t.Error("Vault request lacks federated identity or pinned version")
		}
		return response(200, bundle(entry, []byte("private-canary"))), nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fetcher, err := instanceFetcherWithTransport(ctx, "sa-saopaulo-1", transport)
	if err != nil {
		t.Fatal(err)
	}
	body, err := fetcher.fetch(ctx, entry)
	if err != nil {
		t.Fatal(err)
	}
	erase(body)
	if federation.Load() != 1 || gets.Load() != 1 {
		t.Fatalf("federation=%d secret GET=%d", federation.Load(), gets.Load())
	}
}
