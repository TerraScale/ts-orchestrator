package production

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	json "encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const (
	testInstance = "ocid1.instance.oc1.sa-saopaulo-1.aaaa"
	testTenancy  = "ocid1.tenancy.oc1..aaaa"
	testURI      = "/20160918/instances/" + testInstance
)

type signingKey struct {
	key *rsa.PrivateKey
	id  string
}

func (key signingKey) PrivateRSAKey() (*rsa.PrivateKey, error) { return key.key, nil }
func (key signingKey) KeyID() (string, error)                  { return key.id, nil }

func testSimulator(t *testing.T) (*Simulator, *rsa.PrivateKey) {
	t.Helper()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "offline-only intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{
			CommonName: "offline-only instance",
			ExtraNames: []pkix.AttributeTypeAndValue{{Type: []int{2, 5, 4, 13}, Value: "opc-tenant:" + testTenancy}},
		},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})
	simulator, err := NewSimulator(Config{
		Region: "sa-saopaulo-1", InstanceID: testInstance, DescriptorSlot: "controller-a", TenancyID: testTenancy,
		PrimaryPrivateIP: "10.44.0.11",
		LeafCertificate:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		LeafPrivateKey:   keyPEM,
		Intermediate:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		Reads: []ReadResponse{{
			Host: "iaas.sa-saopaulo-1.oraclecloud.com", RequestURI: testURI,
			Body: []byte(`{"id":"` + testInstance + `"}`), ContentType: "application/json",
			ETag: `"fixture-etag"`, LastModified: now,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	simulator.now = func() time.Time { return now }
	return simulator, leafKey
}

func signedFederation(t *testing.T, simulator *Simulator, leafKey *rsa.PrivateKey,
	sessionKey *rsa.PrivateKey,
) *http.Request {
	t.Helper()
	publicDER, err := x509.MarshalPKIXPublicKey(&sessionKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(federationRequest{
		Certificate:              encodedPEM(simulator.config.LeafCertificate),
		PublicKey:                base64.StdEncoding.EncodeToString(publicDER),
		IntermediateCertificates: []string{encodedPEM(simulator.config.Intermediate)},
		FingerprintAlgorithm:     "SHA256",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://"+simulator.authHost+"/v1/x509", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Date", simulator.now().UTC().Format(http.TimeFormat))
	digest := sha256.Sum256(simulator.leaf.Raw)
	parts := make([]string, len(digest))
	for index, value := range digest {
		parts[index] = fmt.Sprintf("%02x", value)
	}
	keyID := testTenancy + "/fed-x509-sha256/" + strings.Join(parts, ":")
	signer := common.RequestSigner(signingKey{key: leafKey, id: keyID},
		[]string{"date", "(request-target)"},
		[]string{"content-length", "content-type", "x-content-sha256"})
	if err := signer.Sign(request); err != nil {
		t.Fatal(err)
	}
	if err := verifySignature(request, body, &leafKey.PublicKey, keyID,
		"date (request-target) content-length content-type x-content-sha256", false, simulator.now()); err != nil {
		t.Fatalf("SDK federation signature not accepted: %v; headers %#v", err, request.Header)
	}
	return request
}

func federate(t *testing.T, simulator *Simulator, leafKey, sessionKey *rsa.PrivateKey) string {
	t.Helper()
	response := httptest.NewRecorder()
	simulator.ServeHTTP(response, signedFederation(t, simulator, leafKey, sessionKey))
	if response.Code != http.StatusOK {
		t.Fatalf("federation status = %d, want 200", response.Code)
	}
	var token struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &token); err != nil || token.Token == "" {
		t.Fatalf("invalid federation token: %v", err)
	}
	return token.Token
}

func signedRead(t *testing.T, simulator *Simulator, key *rsa.PrivateKey, token, uri string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "https://"+simulator.computeHost+uri, nil)
	request.Header.Set("Date", simulator.now().UTC().Format(http.TimeFormat))
	if err := common.DefaultRequestSigner(signingKey{key: key, id: "ST$" + token}).Sign(request); err != nil {
		t.Fatal(err)
	}
	return request
}

func TestSimulatorRejectsTamperedFederationAndStaleServiceSignature(t *testing.T) {
	simulator, leafKey := testSimulator(t)
	sessionKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	request := signedFederation(t, simulator, leafKey, sessionKey)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, ' ')
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	response := httptest.NewRecorder()
	simulator.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("tampered federation status = %d", response.Code)
	}
	token := federate(t, simulator, leafKey, sessionKey)
	read := signedRead(t, simulator, sessionKey, token, testURI)
	simulator.now = func() time.Time { return time.Now().Add(10 * time.Minute) }
	response = httptest.NewRecorder()
	simulator.ServeHTTP(response, read)
	if response.Code != http.StatusForbidden {
		t.Fatalf("stale signed read status = %d", response.Code)
	}
}

func assertSimulatorIAMToken(t *testing.T, simulator *Simulator, keyID string, public *rsa.PublicKey) {
	t.Helper()
	token, ok := strings.CutPrefix(keyID, "ST$")
	parts := strings.Split(token, ".")
	if !ok || len(keyID) > maxRequest || len(parts) != 3 {
		t.Fatal("instance-principal key ID is not a bounded ST$ token")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || string(header) != `{"alg":"RS256","typ":"JWT"}` {
		t.Fatal("federation token does not name the simulator RSA signer")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal("federation token payload is not base64url")
	}
	var claims struct {
		Expires  int64  `json:"exp"`
		Subject  string `json:"sub"`
		Instance string `json:"opc-instance"`
		Type     string `json:"ptype"`
		Tenancy  string `json:"tenant"`
		ID       string `json:"jti"`
	}
	if json.Unmarshal(payload, &claims, json.RejectUnknownMembers(true)) != nil ||
		claims.Subject != testInstance || claims.Instance != testInstance || claims.Type != "instance" || claims.Tenancy != testTenancy ||
		claims.Expires != simulator.now().Add(tokenLifetime).Unix() || claims.Expires <= time.Now().Add(5*time.Minute).Unix() {
		t.Fatal("federation token claims differ from the authenticated fixture instance and tenancy")
	}
	if nonce, err := base64.RawURLEncoding.DecodeString(claims.ID); err != nil || len(nonce) != 16 {
		t.Fatal("federation token does not retain its random session ID")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err != nil || rsa.VerifyPKCS1v15(&simulator.tokenKey.PublicKey, crypto.SHA256, digest[:], signature) != nil {
		t.Fatal("federation token is not signed by this simulator")
	}
	simulator.mu.Lock()
	issued, exists := simulator.sessions[token]
	simulator.mu.Unlock()
	if !exists || issued.expires.Unix() != claims.Expires || !issued.public.Equal(public) {
		t.Fatal("federation token is not bound to its authenticated session key and expiry")
	}
}

type simulatorDispatcher struct {
	simulator *Simulator
}

func (dispatcher simulatorDispatcher) Do(request *http.Request) (*http.Response, error) {
	// The real SDK constructs and signs the original request. This in-memory
	// transport only replaces dialing. net/http normally writes URL.Host as
	// Host when Request.Host is empty; reproduce that wire-level behavior.
	request = request.Clone(request.Context())
	if request.Host == "" {
		request.Host = request.URL.Host
	}
	response := httptest.NewRecorder()
	dispatcher.simulator.ServeHTTP(response, request)
	result := response.Result()
	result.Request = request
	return result, nil
}

func TestSimulatorAcceptsRealInstancePrincipalSDKRequests(t *testing.T) {
	simulator, _ := testSimulator(t)
	objectURI := "/n/fixture-namespace/b/fixture-records/o/bootstrap/v1/record.json"
	missingURI := "/n/fixture-namespace/b/fixture-records/o/bootstrap/v1/missing.json"
	if err := simulator.addRead(ReadResponse{
		Host: simulator.storageHost, RequestURI: objectURI, Body: []byte("fixture-record"),
		ContentType: "application/json", ETag: `"record-etag"`, LastModified: simulator.now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := simulator.addMissing(MissingRead{Host: simulator.storageHost, RequestURI: missingURI}); err != nil {
		t.Fatal(err)
	}
	attachmentsURI := "/20160918/vnicAttachments?compartmentId=ocid1.compartment.oc1..aaaa&instanceId=" + testInstance + "&limit=50"
	if err := simulator.addRead(ReadResponse{
		Host: simulator.computeHost, RequestURI: attachmentsURI, Body: []byte(`[]`),
		ContentType: "application/json", ETag: `"vnic-list"`, LastModified: simulator.now(),
	}); err != nil {
		t.Fatal(err)
	}
	dispatcher := simulatorDispatcher{simulator: simulator}
	provider, err := auth.InstancePrincipalConfigurationForRegionWithCustomClient(
		common.Region("sa-saopaulo-1"),
		func(common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error) { return dispatcher, nil })
	if err != nil {
		t.Fatalf("real SDK provider IMDS sequence: %v", err)
	}
	keyID, err := provider.KeyID()
	if err != nil {
		t.Fatalf("real SDK federation: %v; routes=%#v", err, simulator.Requests())
	}
	kind, _ := provider.AuthType()
	if kind.AuthType != common.InstancePrincipal {
		t.Fatal("real SDK provider is not an instance principal")
	}
	if tenancy, err := provider.TenancyOCID(); err != nil || tenancy != testTenancy {
		t.Fatalf("real SDK authenticated tenancy differs from the fixture: %v", err)
	}
	private, err := provider.PrivateRSAKey()
	if err != nil {
		t.Fatalf("real SDK session key: %v", err)
	}
	assertSimulatorIAMToken(t, simulator, keyID, &private.PublicKey)
	compute, err := core.NewComputeClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	compute.HTTPClient = dispatcher
	instance, err := compute.GetInstance(t.Context(), core.GetInstanceRequest{InstanceId: new(testInstance)})
	if err != nil || *instance.Id != testInstance {
		t.Fatalf("real SDK Compute GetInstance decode: instance=%#v err=%v", instance.Instance, err)
	}
	_, err = compute.ListVnicAttachments(t.Context(), core.ListVnicAttachmentsRequest{
		CompartmentId: new("ocid1.compartment.oc1..aaaa"), InstanceId: new(testInstance), Limit: new(50),
	})
	if err != nil {
		t.Fatalf("real SDK signed exact-query VNIC list: %v", err)
	}
	storage, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	storage.HTTPClient = dispatcher
	read := func(name string) (objectstorage.GetObjectResponse, error) {
		return storage.GetObject(t.Context(), objectstorage.GetObjectRequest{
			NamespaceName: new("fixture-namespace"), BucketName: new("fixture-records"), ObjectName: new(name),
			RequestMetadata: common.RequestMetadata{RetryPolicy: new(common.NoRetryPolicy())},
		})
	}
	object, err := read("bootstrap/v1/record.json")
	if err != nil {
		t.Fatalf("real SDK Object Storage GET: %v", err)
	}
	wire, err := io.ReadAll(object.Content)
	if err != nil || string(wire) != "fixture-record" || object.ETag == nil || *object.ETag != `"record-etag"` {
		t.Fatalf("real SDK object decode: body=%q etag=%v err=%v", wire, object.ETag, err)
	}
	_ = object.Content.Close()
	_, err = read("bootstrap/v1/missing.json")
	if serviceErr, ok := common.IsServiceError(err); !ok || serviceErr.GetHTTPStatusCode() != http.StatusNotFound {
		t.Fatalf("expected missing exact object must decode as SDK 404, err=%v", err)
	}
	_, err = read("bootstrap/v1/unlisted.json")
	if serviceErr, ok := common.IsServiceError(err); !ok || serviceErr.GetHTTPStatusCode() != http.StatusMisdirectedRequest {
		t.Fatalf("unlisted object must be hard rejection, err=%v", err)
	}
	if got := simulator.Requests(); len(got) < 9 {
		t.Fatalf("actual SDK request inventory too short: %#v", got)
	} else {
		for _, record := range got[:len(got)-1] {
			if !record.Listed {
				t.Fatalf("real SDK expected path is unlisted: %#v", record)
			}
		}
		if got[len(got)-1].Listed || got[len(got)-1].Status != http.StatusMisdirectedRequest {
			t.Fatalf("unlisted SDK object was not audited as hard rejection: %#v", got[len(got)-1])
		}
	}
}
