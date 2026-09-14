package provider

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type instancePrincipalFixture struct {
	leafPEM, keyPEM, intermediatePEM []byte
	leaf, intermediate               *x509.Certificate
	leafKey                          *rsa.PrivateKey
}

func newInstancePrincipalFixture(t *testing.T, now time.Time, tenancy string) instancePrincipalFixture {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "OCI instance identity intermediate"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:         "OCI instance identity",
			OrganizationalUnit: []string{"opc-tenant:" + tenancy},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return instancePrincipalFixture{
		leafPEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		keyPEM:          pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)}),
		intermediatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		leaf:            leaf,
		intermediate:    intermediate,
		leafKey:         leafKey,
	}
}

func testSecurityToken(expiresAt time.Time, sequence int) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d,"seq":%d}`, expiresAt.Unix(), sequence)))
	signature := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("signature-%d", sequence)))
	return header + "." + payload + "." + signature
}

func authorizationField(value, name string) string {
	prefix := name + `="`
	start := strings.Index(value, prefix)
	if start < 0 {
		return ""
	}
	start += len(prefix)
	end := strings.Index(value[start:], `"`)
	if end < 0 {
		return ""
	}
	return value[start : start+end]
}

func verifySignedGet(t *testing.T, request *http.Request, publicKey *rsa.PublicKey) {
	t.Helper()
	authorization := request.Header.Get("Authorization")
	encodedSignature := authorizationField(authorization, "signature")
	signature, err := base64.StdEncoding.DecodeString(encodedSignature)
	if err != nil {
		t.Fatalf("invalid request signature: %v", err)
	}
	canonical := "date: " + request.Header.Get("Date") + "\n(request-target): " + strings.ToLower(request.Method) + " " + request.URL.RequestURI() + "\nhost: " + request.Host
	hash := sha256.Sum256([]byte(canonical))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature); err != nil {
		t.Fatalf("request was not signed by the federated session key: %v", err)
	}
}

func TestInstancePrincipalFederationCachesRefreshesAndSignsWithSecurityToken(t *testing.T) {
	tenancy := "ocid1.tenancy.oc1..aaaaaaaafederation"
	region := "sa-saopaulo-1"
	clock := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	fixture := newInstancePrincipalFixture(t, clock, tenancy)
	metadataCalls := 0
	metadataClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		metadataCalls++
		if request.URL.Scheme != "http" || request.URL.Host != "169.254.169.254" || !strings.HasPrefix(request.URL.Path, "/opc/v2/") || request.Header.Get("Authorization") != "Bearer Oracle" {
			t.Fatalf("metadata request escaped fixed authority: %s, headers=%v", request.URL.String(), request.Header)
		}
		var body []byte
		switch request.URL.Path {
		case "/opc/v2/instance/region":
			body = []byte(region)
		case "/opc/v2/identity/cert.pem":
			body = fixture.leafPEM
		case "/opc/v2/identity/key.pem":
			body = fixture.keyPEM
		case "/opc/v2/identity/intermediate.pem":
			body = fixture.intermediatePEM
		default:
			t.Fatalf("unexpected metadata path %s", request.URL.Path)
		}
		return testHTTPResponse(http.StatusOK, string(body), nil), nil
	})}
	authCalls := 0
	failAuth := false
	var sessionPublicKey *rsa.PublicKey
	authClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		authCalls++
		if request.Method != http.MethodPost || request.URL.String() != "https://auth.sa-saopaulo-1.oraclecloud.com/v1/x509" {
			t.Fatalf("unexpected federation request %s %s", request.Method, request.URL.String())
		}
		fingerprint := colonSeparatedFingerprint(sha256.Sum256(fixture.leaf.Raw))
		if authorizationField(request.Header.Get("Authorization"), "keyId") != tenancy+"/fed-x509-sha256/"+fingerprint {
			t.Fatalf("federation request key ID = %s", request.Header.Get("Authorization"))
		}
		if failAuth {
			return testHTTPResponse(http.StatusInternalServerError, `{"code":"InternalError"}`, nil), nil
		}
		var details struct {
			Certificate              string   `json:"certificate"`
			PublicKey                string   `json:"publicKey"`
			IntermediateCertificates []string `json:"intermediateCertificates"`
			FingerprintAlgorithm     string   `json:"fingerprintAlgorithm"`
		}
		if json.NewDecoder(request.Body).Decode(&details) != nil || details.Certificate != base64.StdEncoding.EncodeToString(fixture.leaf.Raw) ||
			len(details.IntermediateCertificates) != 1 || details.IntermediateCertificates[0] != base64.StdEncoding.EncodeToString(fixture.intermediate.Raw) || details.FingerprintAlgorithm != "SHA256" {
			t.Fatalf("invalid federation payload: %+v", details)
		}
		publicDER, err := base64.StdEncoding.DecodeString(details.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParsePKIXPublicKey(publicDER)
		var ok bool
		sessionPublicKey, ok = parsed.(*rsa.PublicKey)
		if err != nil || !ok || sessionPublicKey.N.BitLen() < 2048 {
			t.Fatalf("invalid session public key: %T, %v", parsed, err)
		}
		token := testSecurityToken(clock.Add(10*time.Minute), authCalls)
		return testHTTPResponse(http.StatusOK, `{"token":"`+token+`"}`, nil), nil
	})}
	federation, err := NewInstancePrincipalFederation(region, tenancy, metadataClient, authClient)
	if err != nil {
		t.Fatal(err)
	}
	federation.now = func() time.Time { return clock }
	federation.retryDelay = func(context.Context, int) error { return nil }
	signer, err := newFederatedInstancePrincipalSigner(federation)
	if err != nil {
		t.Fatal(err)
	}
	signer.Now = federation.now

	first, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://iaas.sa-saopaulo-1.oraclecloud.com/20160918/instances?limit=1000", nil)
	if err := signer.Sign(first); err != nil {
		t.Fatal(err)
	}
	firstToken := testSecurityToken(clock.Add(10*time.Minute), 1)
	if authorizationField(first.Header.Get("Authorization"), "keyId") != "ST$"+firstToken || metadataCalls != 4 || authCalls != 1 {
		t.Fatalf("first federation calls metadata=%d auth=%d authorization=%s", metadataCalls, authCalls, first.Header.Get("Authorization"))
	}
	verifySignedGet(t, first, sessionPublicKey)

	second, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://iaas.sa-saopaulo-1.oraclecloud.com/20160918/instances", nil)
	if err := signer.Sign(second); err != nil {
		t.Fatal(err)
	}
	if metadataCalls != 4 || authCalls != 1 {
		t.Fatalf("cached credential fetched metadata=%d auth=%d times", metadataCalls, authCalls)
	}

	clock = clock.Add(6 * time.Minute)
	refreshed, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://iaas.sa-saopaulo-1.oraclecloud.com/20160918/instances", nil)
	if err := signer.Sign(refreshed); err != nil {
		t.Fatal(err)
	}
	secondToken := testSecurityToken(clock.Add(10*time.Minute), 2)
	if authorizationField(refreshed.Header.Get("Authorization"), "keyId") != "ST$"+secondToken || metadataCalls != 8 || authCalls != 2 {
		t.Fatalf("refreshed federation calls metadata=%d auth=%d authorization=%s", metadataCalls, authCalls, refreshed.Header.Get("Authorization"))
	}
	verifySignedGet(t, refreshed, sessionPublicKey)

	clock = clock.Add(6 * time.Minute)
	failAuth = true
	fallback, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://iaas.sa-saopaulo-1.oraclecloud.com/20160918/instances", nil)
	if err := signer.Sign(fallback); err != nil {
		t.Fatalf("valid cached credential was not used after refresh failure: %v", err)
	}
	if authorizationField(fallback.Header.Get("Authorization"), "keyId") != "ST$"+secondToken {
		t.Fatalf("refresh failure changed cached credential: %s", fallback.Header.Get("Authorization"))
	}

	clock = clock.Add(5 * time.Minute)
	expired, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://iaas.sa-saopaulo-1.oraclecloud.com/20160918/instances", nil)
	if err := signer.Sign(expired); err == nil {
		t.Fatal("expired cached credential survived a failed refresh")
	}
}

func TestInstanceMetadataProductionClientBypassesEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:65534")
	t.Setenv("NO_PROXY", "")
	federation, err := NewInstancePrincipalFederation("sa-saopaulo-1", "ocid1.tenancy.oc1..aaaaaaaaproxy", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := federation.metadataClient.Transport.(*instanceMetadataTransport)
	if !ok || transport.base == nil || transport.base.Proxy != nil {
		t.Fatalf("production metadata transport is not direct: %T", federation.metadataClient.Transport)
	}
	defer transport.base.CloseIdleConnections()
	addresses := make([]string, 0, maximumMetadataAttempts)
	transport.base.DialContext = func(_ context.Context, _, address string) (net.Conn, error) {
		addresses = append(addresses, address)
		return nil, errors.New("dial trap")
	}
	federation.retryDelay = func(context.Context, int) error { return nil }
	if _, err := federation.readMetadata(context.Background(), "/identity/key.pem"); err == nil {
		t.Fatal("metadata dial trap unexpectedly succeeded")
	}
	if len(addresses) != maximumMetadataAttempts {
		t.Fatalf("metadata attempts = %d, want %d", len(addresses), maximumMetadataAttempts)
	}
	for _, address := range addresses {
		if address != "169.254.169.254:80" {
			t.Fatalf("metadata request dialed proxy or non-IMDS address %q", address)
		}
	}
}

func TestInstancePrincipalRetriesNon4xxAndNeverRetries4xx(t *testing.T) {
	tenancy := "ocid1.tenancy.oc1..aaaaaaaaretry"
	metadataCalls := 0
	metadataClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		metadataCalls++
		if metadataCalls < 3 {
			return testHTTPResponse(http.StatusServiceUnavailable, "", nil), nil
		}
		return testHTTPResponse(http.StatusOK, "sa-saopaulo-1", nil), nil
	})}
	federation, err := NewInstancePrincipalFederation("sa-saopaulo-1", tenancy, metadataClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	federation.retryDelay = func(context.Context, int) error { return nil }
	body, err := federation.readMetadata(context.Background(), "/instance/region")
	if err != nil || string(body) != "sa-saopaulo-1" || metadataCalls != 3 {
		t.Fatalf("metadata retry body=%q calls=%d err=%v", body, metadataCalls, err)
	}
	metadataCalls = 0
	federation.metadataClient = noRedirectHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		metadataCalls++
		return testHTTPResponse(http.StatusUnauthorized, "", nil), nil
	})}, 5*time.Second)
	if _, err := federation.readMetadata(context.Background(), "/instance/region"); err == nil || metadataCalls != 1 {
		t.Fatalf("metadata 4xx calls=%d err=%v", metadataCalls, err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewInstancePrincipalSigner("federation-test-key", key)
	if err != nil {
		t.Fatal(err)
	}
	signer.Now = func() time.Time { return time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC) }
	authCalls := 0
	federation.authClient = noRedirectHTTPClient(&http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		authCalls++
		var payload map[string]any
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil || payload["request"] != "bound" {
			t.Fatalf("federation retry body = %+v, %v", payload, err)
		}
		if authCalls < maximumFederationAttempts {
			return testHTTPResponse(http.StatusInternalServerError, "", nil), nil
		}
		return testHTTPResponse(http.StatusOK, `{"token":"token"}`, nil), nil
	})}, 15*time.Second)
	raw, err := federation.exchangeFederationToken(context.Background(), []byte(`{"request":"bound"}`), signer)
	if err != nil || string(raw) != `{"token":"token"}` || authCalls != maximumFederationAttempts {
		t.Fatalf("federation retry body=%q calls=%d err=%v", raw, authCalls, err)
	}
	authCalls = 0
	federation.authClient = noRedirectHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		authCalls++
		return testHTTPResponse(http.StatusBadRequest, "", nil), nil
	})}, 15*time.Second)
	if _, err := federation.exchangeFederationToken(context.Background(), []byte(`{}`), signer); err == nil || authCalls != 1 {
		t.Fatalf("federation 4xx calls=%d err=%v", authCalls, err)
	}
}

func TestInstancePrincipalCertificateValidationFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	tenancy := "ocid1.tenancy.oc1..aaaaaaaafederation"
	fixture := newInstancePrincipalFixture(t, now, tenancy)
	if err := validateInstanceCertificateChain(fixture.leaf, fixture.intermediate, fixture.leafKey, tenancy, now); err != nil {
		t.Fatalf("valid certificate chain rejected: %v", err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateInstanceCertificateChain(fixture.leaf, fixture.intermediate, otherKey, tenancy, now); err == nil {
		t.Fatal("mismatched instance key was accepted")
	}
	if err := validateInstanceCertificateChain(fixture.leaf, fixture.intermediate, fixture.leafKey, "ocid1.tenancy.oc1..aaaaaaaawrong", now); err == nil {
		t.Fatal("wrong certificate tenancy was accepted")
	}
	expired := *fixture.leaf
	expired.NotAfter = now.Add(-time.Second)
	if err := validateInstanceCertificateChain(&expired, fixture.intermediate, fixture.leafKey, tenancy, now); err == nil {
		t.Fatal("expired instance certificate was accepted")
	}
}

func TestOCICredentialTypesRedactEveryFormatterAndJSON(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewInstancePrincipalSigner("secret-key-id", key)
	if err != nil {
		t.Fatal(err)
	}
	federation, err := NewInstancePrincipalFederation("sa-saopaulo-1", "ocid1.tenancy.oc1..aaaaaaaasecret", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	federation.token = "secret-security-token"
	federation.sessionKey = key
	registry, err := NewOCIRegistryTokenSigner("secret-user", "secret-registry-token")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{signer, federation, registry} {
		for _, rendered := range []string{fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value)} {
			for _, secret := range []string{"secret-key-id", "secret-security-token", "secret-user", "secret-registry-token"} {
				if strings.Contains(rendered, secret) {
					t.Fatalf("formatter leaked %q in %q", secret, rendered)
				}
			}
		}
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != "{}" {
			t.Fatalf("credential JSON was not empty: %s", raw)
		}
	}
}

func TestBoundedJWTExpiryRejectsMalformedOrUnboundedClaims(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	if _, err := boundedJWTExpiry(testSecurityToken(now.Add(time.Hour), 1), now); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{
		"not-a-jwt",
		testSecurityToken(now.Add(30*time.Second), 1),
		testSecurityToken(now.Add(25*time.Hour), 1),
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, now.Add(time.Hour).Unix()))) + "." + base64.RawURLEncoding.EncodeToString([]byte("signature")),
	} {
		if _, err := boundedJWTExpiry(token, now); err == nil {
			t.Fatalf("invalid security token was accepted: %q", token)
		}
	}
}
