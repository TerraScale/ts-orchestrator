package netbird

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/secrets"
)

type fakeBundleClient func(context.Context, secrets.GetSecretBundleRequest) (secrets.GetSecretBundleResponse, error)

func (client fakeBundleClient) GetSecretBundle(ctx context.Context, request secrets.GetSecretBundleRequest) (secrets.GetSecretBundleResponse, error) {
	return client(ctx, request)
}

func setupKeyBundle(id, key string) secrets.GetSecretBundleResponse {
	encoded := base64.StdEncoding.EncodeToString([]byte(key))
	return secrets.GetSecretBundleResponse{SecretBundle: secrets.SecretBundle{
		SecretId: new(id), VersionNumber: new(int64(7)),
		SecretBundleContent: secrets.Base64SecretBundleContentDetails{Content: new(encoded)},
	}}
}

func TestVaultReadsCurrentSecretWithNoSDKRetriesAndBoundedContext(t *testing.T) {
	id := testConfig().SetupKeySecretID
	client := fakeBundleClient(func(ctx context.Context, request secrets.GetSecretBundleRequest) (secrets.GetSecretBundleResponse, error) {
		if request.SecretId == nil || *request.SecretId != id || request.Stage != secrets.GetSecretBundleStageCurrent ||
			request.VersionNumber != nil || request.SecretVersionName != nil || request.RequestMetadata.RetryPolicy == nil {
			t.Fatalf("wrong secret request: %+v", request)
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 15*time.Second {
			t.Fatal("Vault request is not bounded")
		}
		return setupKeyBundle(id, "\n"+testSetupKey+"\n"), nil
	})
	key, err := readCurrentSetupKey(t.Context(), id, client)
	if err != nil || string(key) != testSetupKey {
		t.Fatalf("unexpected key bytes or error: length=%d error=%v", len(key), err)
	}
}

type fakeServiceError int

func (status fakeServiceError) Error() string           { return "OCI service error" }
func (status fakeServiceError) GetHTTPStatusCode() int  { return int(status) }
func (status fakeServiceError) GetMessage() string      { return "OCI service error" }
func (status fakeServiceError) GetCode() string         { return "Error" }
func (status fakeServiceError) GetOpcRequestID() string { return "request" }

func shortVaultBackoff(t *testing.T) {
	t.Helper()
	previous := vaultBackoff
	vaultBackoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { vaultBackoff = previous })
}

func TestVaultRetriesTransientFailuresWithinOneDeadline(t *testing.T) {
	shortVaultBackoff(t)
	id := testConfig().SetupKeySecretID
	for name, failure := range map[string]error{
		"transport": errors.New("connection reset"),
		"throttled": fakeServiceError(http.StatusTooManyRequests),
		"server":    fakeServiceError(http.StatusServiceUnavailable),
	} {
		t.Run(name, func(t *testing.T) {
			attempts := 0
			var deadline time.Time
			client := fakeBundleClient(func(ctx context.Context, _ secrets.GetSecretBundleRequest) (secrets.GetSecretBundleResponse, error) {
				attempts++
				current, ok := ctx.Deadline()
				if !ok || attempts > 1 && !current.Equal(deadline) {
					t.Fatal("retries did not share one bounded deadline")
				}
				deadline = current
				if attempts < 3 {
					return secrets.GetSecretBundleResponse{}, failure
				}
				return setupKeyBundle(id, testSetupKey), nil
			})
			key, err := readCurrentSetupKey(t.Context(), id, client)
			if err != nil || string(key) != testSetupKey || attempts != 3 {
				t.Fatalf("transient failure was not retried: attempts=%d error=%v", attempts, err)
			}
		})
	}
}

func TestVaultDoesNotRetryFinalOrPersistentFailures(t *testing.T) {
	shortVaultBackoff(t)
	id := testConfig().SetupKeySecretID
	for name, tc := range map[string]struct {
		failure  error
		attempts int
	}{
		"unauthorized": {fakeServiceError(http.StatusUnauthorized), 1},
		"not found":    {fakeServiceError(http.StatusNotFound), 1},
		"canceled":     {context.Canceled, 1},
		"persistent":   {errors.New("connection reset"), len(vaultBackoff) + 1},
	} {
		t.Run(name, func(t *testing.T) {
			attempts := 0
			client := fakeBundleClient(func(context.Context, secrets.GetSecretBundleRequest) (secrets.GetSecretBundleResponse, error) {
				attempts++
				return secrets.GetSecretBundleResponse{}, tc.failure
			})
			if key, err := readCurrentSetupKey(t.Context(), id, client); err == nil || key != nil || attempts != tc.attempts {
				t.Fatalf("attempts=%d want %d error=%v", attempts, tc.attempts, err)
			}
		})
	}
}

func TestVaultRejectsMismatchedMalformedAndOversizedSecretsWithoutLeaking(t *testing.T) {
	shortVaultBackoff(t)
	id := testConfig().SetupKeySecretID
	for _, scenario := range []string{"error", "wrong-id", "missing-version", "oversized", "malformed-key", "malformed-base64", "missing-content"} {
		t.Run(scenario, func(t *testing.T) {
			client := fakeBundleClient(func(context.Context, secrets.GetSecretBundleRequest) (secrets.GetSecretBundleResponse, error) {
				response := setupKeyBundle(id, testSetupKey)
				switch scenario {
				case "error":
					return secrets.GetSecretBundleResponse{}, errors.New("OCI returned sensitive body: " + testSetupKey)
				case "wrong-id":
					response.SecretId = new("ocid1.vaultsecret.oc1.sa-saopaulo-1.another")
				case "missing-version":
					response.VersionNumber = nil
				case "oversized":
					response = setupKeyBundle(id, strings.Repeat("x", 129))
				case "malformed-key":
					response = setupKeyBundle(id, testSetupKey+" injected")
				case "malformed-base64":
					response.SecretBundleContent = secrets.Base64SecretBundleContentDetails{Content: new("not base64")}
				case "missing-content":
					response.SecretBundleContent = nil
				}
				return response, nil
			})
			key, err := readCurrentSetupKey(t.Context(), id, client)
			if err == nil || key != nil || strings.Contains(err.Error(), testSetupKey) {
				t.Fatalf("untrusted secret response accepted or exposed: bytes=%d error=%v", len(key), err)
			}
		})
	}
}

func TestInstancePrincipalDispatcherClonesNoProxyTransportAndRejectsRedirects(t *testing.T) {
	sourceTransport := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		return url.Parse("http://proxy.invalid")
	}}
	source := &http.Client{Transport: sourceTransport}
	dispatcher, err := boundedInstancePrincipalDispatcher(source)
	if err != nil {
		t.Fatal(err)
	}
	client, ok := dispatcher.(*http.Client)
	if !ok || client == source || client.Timeout <= 0 || client.Timeout > 15*time.Second {
		t.Fatal("instance-principal dispatcher was not cloned and bounded")
	}
	limited, ok := client.Transport.(responseLimitTransport)
	if !ok || limited.limit != 1<<20 {
		t.Fatal("metadata response size is not bounded")
	}
	transport, ok := limited.transport.(*http.Transport)
	if !ok || transport == sourceTransport || transport.Proxy != nil || sourceTransport.Proxy == nil {
		t.Fatal("transport was not cloned with only the clone's proxy disabled")
	}
	if client.CheckRedirect == nil || client.CheckRedirect(&http.Request{}, nil) == nil {
		t.Fatal("OCI redirects were allowed")
	}
}

type fakeTransport func(*http.Request) (*http.Response, error)

func (transport fakeTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func TestOCIResponseBodyIsBounded(t *testing.T) {
	transport := responseLimitTransport{limit: 100, transport: fakeTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 1000)))}, nil
	})}
	response, err := transport.RoundTrip(&http.Request{})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || len(body) != 100 {
		t.Fatalf("unbounded response length=%d error=%v", len(body), err)
	}
}

func TestOCIOverridesAndVerboseLoggingAreRejectedBeforeMetadataAccess(t *testing.T) {
	for _, name := range []string{"OCI_GO_SDK_DEBUG", "OCI_METADATA_BASE_URL", "OCI_SDK_AUTH_CLIENT_REGION_URL", "OCI_DEFAULT_CERTS_PATH", "OCI_DEFAULT_CLIENT_CERTS_PATH", "OCI_DEFAULT_CLIENT_CERTS_PRIVATE_KEY_PATH"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "forbidden")
			_, err := readOCISetupKey(t.Context(), testConfig())
			if err == nil || !strings.Contains(err.Error(), "does not permit") {
				t.Fatalf("OCI override was not rejected before network access: %v", err)
			}
		})
	}
}

func TestAdminPATShapeIsSharedAndBounded(t *testing.T) {
	const pat = "nbp_abcdefghijklmnopqrstuvwxyzABCD012345"
	for value, ok := range map[string]bool{
		pat:                               true,
		"nbp_" + strings.Repeat("a", 252): true,
		"nbp_" + strings.Repeat("a", 253): false,
		pat[:39]:                          false,
		"nbx_" + pat[4:]:                  false,
		"NBP_" + pat[4:]:                  false,
		strings.Repeat("a", 40):           false,
		pat[:39] + " ":                    false,
		pat[:39] + "\x00":                 false,
		pat[:39] + "é":                    false,
		"Token " + pat:                    false,
	} {
		if ValidAdminPAT([]byte(value)) != ok {
			t.Fatalf("ValidAdminPAT(len %d) != %v", len(value), ok)
		}
	}
}

func TestVaultReadsOnlyWellFormedAdminPAT(t *testing.T) {
	id := "ocid1.vaultsecret.oc1.sa-saopaulo-1.adminpat"
	const pat = "nbp_abcdefghijklmnopqrstuvwxyzABCD012345"
	for value, ok := range map[string]bool{
		pat + "\n": true, "nbp_short": false, testSetupKey: false,
		"nbp_abcdefghijklmnopqrstuvwxyzABCD01234-": false,
		"nbp_" + strings.Repeat("Z", 196):          true,
		"nbp_" + strings.Repeat("Z", 252):          true,
		"nbp_" + strings.Repeat("Z", 253):          false,
	} {
		client := fakeBundleClient(func(context.Context, secrets.GetSecretBundleRequest) (secrets.GetSecretBundleResponse, error) {
			return setupKeyBundle(id, value), nil
		})
		token, err := readCurrentSecret(t.Context(), id, "admin PAT", maxAdminPATBytes, client, validAdminPAT)
		if ok != (err == nil) || ok && string(token) != strings.TrimSpace(value) {
			t.Fatalf("PAT shape of length %d: ok=%v error=%v", len(value), ok, err)
		}
		if err != nil && strings.Contains(err.Error(), value) {
			t.Fatal("PAT read error leaked secret content")
		}
	}
}
