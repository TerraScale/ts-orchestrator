package production

import (
	"bytes"
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
		LeafCertificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		LeafPrivateKey:  keyPEM,
		Intermediate:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
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

func TestSimulatorAuthenticatesFederationAndExactServiceRead(t *testing.T) {
	simulator, leafKey := testSimulator(t)
	sessionKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	token := federate(t, simulator, leafKey, sessionKey)
	response := httptest.NewRecorder()
	simulator.ServeHTTP(response, signedRead(t, simulator, sessionKey, token, testURI))
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"fixture-etag"` ||
		response.Header().Get("Date") == "" || response.Header().Get("Last-Modified") == "" ||
		response.Body.String() != `{"id":"`+testInstance+`"}` {
		t.Fatalf("exact GET response = %d, headers %v, body %q", response.Code, response.Header(), response.Body.String())
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		make func() *http.Request
		want int
	}{
		{"wrong RSA key for token", func() *http.Request { return signedRead(t, simulator, wrongKey, token, testURI) }, http.StatusForbidden},
		{"unknown exact key", func() *http.Request { return signedRead(t, simulator, sessionKey, token, testURI+"/other") }, http.StatusMisdirectedRequest},
		{"changed signed target", func() *http.Request {
			request := signedRead(t, simulator, sessionKey, token, testURI)
			request.URL.RawQuery = "page=other"
			return request
		}, http.StatusForbidden},
		{"OCI write", func() *http.Request {
			return httptest.NewRequest(http.MethodPut, "https://"+simulator.computeHost+testURI, nil)
		}, http.StatusMethodNotAllowed},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			simulator.ServeHTTP(response, test.make())
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
	if got := simulator.Requests(); len(got) != 6 || got[5].Status != http.StatusMethodNotAllowed {
		t.Fatalf("request audit = %#v", got)
	}
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

func TestSimulatorAcceptsSDKSignatureAcrossNetHTTPServer(t *testing.T) {
	simulator, leafKey := testSimulator(t)
	sessionKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(simulator)
	t.Cleanup(server.Close)
	request := signedFederation(t, simulator, leafKey, sessionKey)
	request.URL.Scheme = "http"
	request.URL.Host = strings.TrimPrefix(server.URL, "http://")
	request.Host = simulator.authHost
	request.RequestURI = ""
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("network federation status = %d", response.StatusCode)
	}
}

func TestSimulatorBindsDistinctFederationSessionsAndSignedQuery(t *testing.T) {
	simulator, leafKey := testSimulator(t)
	uriA := "/20160918/vnicAttachments?compartmentId=ocid1.compartment.oc1..aaaa&instanceId=" + testInstance + "&limit=50"
	uriB := uriA + "&page=next"
	for _, uri := range []string{uriA, uriB} {
		if err := simulator.addRead(ReadResponse{
			Host: simulator.computeHost, RequestURI: uri, Body: []byte("[]"),
			ContentType: "application/json", ETag: `"fixture-list"`, LastModified: simulator.now(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tokenA := federate(t, simulator, leafKey, keyA)
	tokenB := federate(t, simulator, leafKey, keyB)
	if tokenA == tokenB {
		t.Fatal("separate federation sessions reused one token")
	}
	request := signedRead(t, simulator, keyA, tokenA, uriA)
	response := httptest.NewRecorder()
	simulator.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("exact query status = %d", response.Code)
	}
	request = signedRead(t, simulator, keyA, tokenA, uriA)
	request.URL.RawQuery += "&page=next"
	response = httptest.NewRecorder()
	simulator.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("changed but allowlisted signed query status = %d", response.Code)
	}
	response = httptest.NewRecorder()
	simulator.ServeHTTP(response, signedRead(t, simulator, keyB, tokenB, uriB))
	if response.Code != http.StatusOK {
		t.Fatalf("second signed session status = %d", response.Code)
	}
}

func TestSimulatorPinsIMDSAndRejectsUnlistedRoutes(t *testing.T) {
	simulator, _ := testSimulator(t)
	for _, test := range []struct {
		path, want string
	}{
		{"/opc/v2/instance/id", testInstance},
		{"/opc/v2/instance/region", "sa-saopaulo-1"},
		{"/opc/v2/instance/metadata/terrascale-bootstrap", `{"schemaVersion":1,"slot":"controller-a"}`},
		{"/opc/v2/identity/cert.pem", string(simulator.config.LeafCertificate)},
		{"/opc/v2/identity/key.pem", string(simulator.config.LeafPrivateKey)},
		{"/opc/v2/identity/intermediate.pem", string(simulator.config.Intermediate)},
	} {
		request := httptest.NewRequest(http.MethodGet, "http://"+imdsHost+test.path, nil)
		request.Header.Set("Authorization", "Bearer Oracle")
		response := httptest.NewRecorder()
		simulator.ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Body.String() != test.want {
			t.Fatalf("IMDS %s = %d %q", test.path, response.Code, response.Body.String())
		}
	}
	for _, uri := range []string{"/opc/v2/instance/other", "/opc/v2/instance/id?other=1"} {
		request := httptest.NewRequest(http.MethodGet, "http://"+imdsHost+uri, nil)
		request.Header.Set("Authorization", "Bearer Oracle")
		response := httptest.NewRecorder()
		simulator.ServeHTTP(response, request)
		if response.Code != http.StatusMisdirectedRequest {
			t.Fatalf("unlisted IMDS %s = %d", uri, response.Code)
		}
	}
	response := httptest.NewRecorder()
	simulator.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		"https://iaas.us-ashburn-1.oraclecloud.com"+testURI, nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("unlisted OCI host status = %d", response.Code)
	}
	if err := simulator.addRead(ReadResponse{
		Host:       simulator.computeHost,
		RequestURI: "/20160918/subnets/ocid1.subnet.oc1.sa-saopaulo-1.subnet-a",
		Body:       []byte("{}"), ETag: "fixture", LastModified: simulator.now(),
	}); err != nil {
		t.Fatalf("regional GetSubnet route was rejected: %v", err)
	}
	for _, uri := range []string{
		"/20160918/instances/ocid1.instance.oc1.sa-saopaulo-1.other",
		"/20160918/instances/" + testInstance + "?unexpected=1",
		"/20160918/bootVolumes/ocid1.bootvolume.oc1..other",
		"/20160918/subnets/ocid1.subnet.oc1.us-ashburn-1.other",
		"/20160918/subnets/ocid1.subnet.oc1.sa-saopaulo-1.subnet-a?unexpected=1",
		"/20160918/vnicAttachments?instanceId=" + testInstance + "&limit=50",
	} {
		if err := simulator.addRead(ReadResponse{Host: simulator.computeHost, RequestURI: uri,
			Body: []byte("{}"), ETag: "fixture", LastModified: simulator.now()}); err == nil {
			t.Fatalf("unlisted Compute route was accepted: %s", uri)
		}
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
	if _, err := provider.KeyID(); err != nil {
		t.Fatalf("real SDK federation: %v; routes=%#v", err, simulator.Requests())
	}
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

func TestSimulatorExpectedMissingNeedsAuthentication(t *testing.T) {
	simulator, leafKey := testSimulator(t)
	uri := "/n/fixture-namespace/b/fixture-records/o/bootstrap/v1/missing.json"
	if err := simulator.addMissing(MissingRead{Host: simulator.storageHost, RequestURI: uri}); err != nil {
		t.Fatal(err)
	}
	unsigned := httptest.NewRequest(http.MethodGet, "https://"+simulator.storageHost+uri, nil)
	response := httptest.NewRecorder()
	simulator.ServeHTTP(response, unsigned)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unsigned expected-missing object = %d, want 403", response.Code)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	token := federate(t, simulator, leafKey, key)
	signed := httptest.NewRequest(http.MethodGet, "https://"+simulator.storageHost+uri, nil)
	signed.Header.Set("Date", simulator.now().UTC().Format(http.TimeFormat))
	if err := common.DefaultRequestSigner(signingKey{key: key, id: "ST$" + token}).Sign(signed); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	simulator.ServeHTTP(response, signed)
	if response.Code != http.StatusNotFound {
		t.Fatalf("signed expected-missing object = %d, want 404", response.Code)
	}
	got := simulator.Requests()
	if !got[0].Listed || !got[len(got)-1].Listed {
		t.Fatalf("expected-missing route was not explicitly listed: %#v", got)
	}
}

func TestSimulatorBoundsFixtureSessionsAndRequestAudit(t *testing.T) {
	simulator, leafKey := testSimulator(t)
	if err := simulator.addRead(ReadResponse{
		Host: simulator.storageHost, RequestURI: "/n/ns/b/bucket/o/oversized",
		Body: bytes.Repeat([]byte{'x'}, maxRouteBody+1),
		ETag: "fixture", LastModified: simulator.now(),
	}); err == nil {
		t.Fatal("oversized response body was accepted")
	}
	simulator.mu.Lock()
	for index := range maxSessions {
		simulator.sessions[fmt.Sprint(index)] = session{expires: simulator.now().Add(time.Hour)}
	}
	simulator.mu.Unlock()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	simulator.ServeHTTP(response, signedFederation(t, simulator, leafKey, key))
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("session capacity response = %d", response.Code)
	}
	simulator.mu.Lock()
	simulator.requests = make([]RequestRecord, maxRecordedRequests)
	simulator.mu.Unlock()
	response = httptest.NewRecorder()
	simulator.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		"https://"+simulator.computeHost+testURI+"?private=secret-value", nil))
	if response.Code != http.StatusTooManyRequests || simulator.OverflowCount() != 1 ||
		len(simulator.Requests()) != maxRecordedRequests {
		t.Fatalf("request audit overflow was not bounded and detectable")
	}
}

func TestSimulatorRedactsUnlistedQuery(t *testing.T) {
	simulator, _ := testSimulator(t)
	request := httptest.NewRequest(http.MethodGet,
		"https://"+simulator.computeHost+testURI+"/private-jwt-value?secret=private-token", nil)
	response := httptest.NewRecorder()
	simulator.ServeHTTP(response, request)
	got := simulator.Requests()[0]
	if got.Listed || got.Status != http.StatusForbidden || got.RequestURI != "[unlisted]" ||
		got.RouteSHA256 == "" {
		t.Fatalf("unlisted path/query audit = %#v", got)
	}
}
