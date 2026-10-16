package netbird

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/secrets"
)

func vaultBundle(id, key string) map[string]any {
	return map[string]any{"secretId": id, "versionNumber": 7, "secretBundleContent": map[string]any{"contentType": "BASE64", "content": base64.StdEncoding.EncodeToString([]byte(key))}}
}

func vaultHTTPClient(t *testing.T, respond func(int) (int, map[string]any)) (secrets.SecretsClient, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := int(requests.Add(1))
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/20190301/secretbundles/") || r.URL.Query().Get("stage") != "CURRENT" || r.URL.Query().Has("versionNumber") || r.Header.Get("Authorization") == "" {
			t.Errorf("unexpected Vault request %s %s", r.Method, r.URL)
		}
		status, body := respond(attempt)
		if status == 0 {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			connection.Close()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		wire, err := json.Marshal(body)
		if err != nil {
			t.Error(err)
			return
		}
		w.Write(wire)
	}))
	t.Cleanup(server.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..integration", "ocid1.user.oc1..integration", DefaultRegion, "integration", string(privateKey), nil)
	client, err := secrets.NewSecretsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	client.Host = server.URL
	client.HTTPClient = server.Client()
	return client, &requests
}

func TestVaultIntegrationRetriesOnlyTransientHTTPFailures(t *testing.T) {
	for _, status := range []int{0, 429, 503, 401, 404} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			client, requests := vaultHTTPClient(t, func(attempt int) (int, map[string]any) {
				if attempt < 3 {
					return status, map[string]any{"code": "Failure", "message": testSetupKey}
				}
				return 200, vaultBundle(testConfig().SetupKeySecretID, "\n"+testSetupKey+"\n")
			})
			key, err := readCurrentSetupKey(t.Context(), testConfig().SetupKeySecretID, client)
			if status == 0 || status == 429 || status == 503 {
				if err != nil || string(key) != testSetupKey || requests.Load() != 3 {
					t.Fatalf("transient requests=%d bytes=%d error=%v", requests.Load(), len(key), err)
				}
			} else if err == nil || key != nil || requests.Load() != 1 || strings.Contains(err.Error(), testSetupKey) {
				t.Fatalf("final requests=%d error=%v", requests.Load(), err)
			}
			clear(key)
		})
	}
}

func TestVaultIntegrationRejectsUntrustedBundlesWithoutLeaking(t *testing.T) {
	for _, scenario := range []string{"wrong-id", "missing-version", "oversized", "malformed-key", "malformed-base64", "missing-content", "zero-key"} {
		t.Run(scenario, func(t *testing.T) {
			client, requests := vaultHTTPClient(t, func(int) (int, map[string]any) {
				response := vaultBundle(testConfig().SetupKeySecretID, testSetupKey)
				switch scenario {
				case "wrong-id":
					response["secretId"] = "ocid1.vaultsecret.oc1.sa-saopaulo-1.other"
				case "missing-version":
					delete(response, "versionNumber")
				case "oversized":
					response = vaultBundle(testConfig().SetupKeySecretID, strings.Repeat("x", 129))
				case "malformed-key":
					response = vaultBundle(testConfig().SetupKeySecretID, testSetupKey+" injected")
				case "malformed-base64":
					response["secretBundleContent"] = map[string]any{"contentType": "BASE64", "content": "not base64"}
				case "missing-content":
					delete(response, "secretBundleContent")
				case "zero-key":
					response = vaultBundle(testConfig().SetupKeySecretID, "00000000-0000-0000-0000-000000000000")
				}
				return 200, response
			})
			key, err := readCurrentSetupKey(t.Context(), testConfig().SetupKeySecretID, client)
			if err == nil || key != nil || requests.Load() != 1 || strings.Contains(err.Error(), testSetupKey) {
				t.Fatalf("untrusted bundle bytes=%d requests=%d error=%v", len(key), requests.Load(), err)
			}
		})
	}
}

func TestVaultIntegrationReadsOnlyBoundedAdminPATs(t *testing.T) {
	id := "ocid1.vaultsecret.oc1.sa-saopaulo-1.adminpat"
	const pat = "nbp_abcdefghijklmnopqrstuvwxyzABCD012345"
	for value, valid := range map[string]bool{
		pat + "\n": true, "nbp_" + strings.Repeat("Z", 196): true, "nbp_" + strings.Repeat("Z", 252): true,
		"nbp_" + strings.Repeat("Z", 253): false, "nbp_short": false, testSetupKey: false,
		"nbp_abcdefghijklmnopqrstuvwxyzABCD01234-": false, "nbx_" + pat[4:]: false, "NBP_" + pat[4:]: false,
		strings.Repeat("a", 40): false, pat[:39] + "\x00": false, pat[:39] + "é": false, "Token " + pat: false,
	} {
		t.Run(strings.TrimSpace(value[:min(12, len(value))])+"-"+strconv.Itoa(len(value)), func(t *testing.T) {
			client, _ := vaultHTTPClient(t, func(int) (int, map[string]any) { return 200, vaultBundle(id, value) })
			token, err := readCurrentSecret(t.Context(), id, "admin PAT", maxAdminPATBytes, client, validAdminPAT)
			if valid != (err == nil) || valid && string(token) != strings.TrimSpace(value) {
				t.Fatalf("PAT bytes=%d error=%v", len(token), err)
			}
			if err != nil && strings.Contains(err.Error(), value) {
				t.Fatal("PAT leaked")
			}
			clear(token)
		})
	}
}

func TestVaultIntegrationDispatcherRejectsRedirectProxyAndOversizedResponse(t *testing.T) {
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetRequests.Add(1) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, target.URL, http.StatusFound)
			return
		}
		io.WriteString(w, strings.Repeat("x", (1<<20)+100))
	}))
	defer source.Close()
	var proxyRequests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyRequests.Add(1); w.WriteHeader(502) }))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := boundedInstancePrincipalDispatcher(&http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, source.URL+"/redirect", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := dispatcher.Do(request); err == nil {
		response.Body.Close()
		t.Fatal("redirect accepted")
	}
	if targetRequests.Load() != 0 || proxyRequests.Load() != 0 {
		t.Fatal("redirect or proxy received OCI request")
	}
	request, err = http.NewRequestWithContext(t.Context(), http.MethodGet, source.URL+"/large", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := dispatcher.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	wire, err := io.ReadAll(response.Body)
	if err != nil || len(wire) != 1<<20 {
		t.Fatalf("response bytes=%d error=%v", len(wire), err)
	}
}

func TestVaultIntegrationCanceledHTTPReadDoesNotRetry(t *testing.T) {
	started := make(chan struct{})
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			close(started)
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	client, _ := vaultHTTPClient(t, func(int) (int, map[string]any) { return 200, nil })
	client.Host = server.URL
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	go func() { <-started; cancel() }()
	key, err := readCurrentSetupKey(ctx, testConfig().SetupKeySecretID, client)
	if err == nil || key != nil || requests.Load() != 1 {
		t.Fatalf("canceled read bytes=%d error=%v", len(key), err)
	}
}

func TestVaultIntegrationBoundsPersistentHTTPFailures(t *testing.T) {
	for _, status := range []int{0, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			client, requests := vaultHTTPClient(t, func(int) (int, map[string]any) {
				return status, map[string]any{"code": "Unavailable", "message": testSetupKey}
			})
			key, err := readCurrentSetupKey(t.Context(), testConfig().SetupKeySecretID, client)
			if err == nil || key != nil || requests.Load() != int32(len(vaultBackoff)+1) || strings.Contains(err.Error(), testSetupKey) {
				t.Fatalf("persistent requests=%d bytes=%d error=%v", requests.Load(), len(key), err)
			}
		})
	}
}
