//go:build linux

package execution_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/tests/firecracker/production"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"golang.org/x/sys/unix"
)

const (
	renewalFixtureChild    = "TS_SOURCE_RENEWAL_CHILD"
	renewalFixtureParent   = "TS_SOURCE_RENEWAL_PARENT_NETNS"
	renewalFixtureInstance = "ocid1.instance.oc1.sa-saopaulo-1.sourcerenewal"
	renewalFixtureTenancy  = "ocid1.tenancy.oc1..sourcerenewal"
	renewalFixtureAuth     = "auth.sa-saopaulo-1.oraclecloud.com"
	renewalFixtureSecrets  = "secrets.vaults.sa-saopaulo-1.oci.oraclecloud.com"
	renewalFixtureStorage  = "objectstorage.sa-saopaulo-1.oraclecloud.com"
)

// This prerequisite crosses production IMDS, federation, Vault and SDK CAS.
// Source admission, lease renewal and writer withdrawal require the full runtime scenario.
func TestSourceRenewalSDKFixtureIntegration(t *testing.T) {
	if !renewalIsolatedChild(t) {
		return
	}
	fixture := newRenewalCloud(t)
	instance, err := bootstrapstart.NewIMDSClient().FetchInstanceID(t.Context())
	if err != nil || instance != renewalFixtureInstance {
		t.Fatalf("production fixed-address IMDS: instance=%q error=%v", instance, err)
	}
	credential := oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.sourcerenewal", VersionNumber: 1}
	credentialPath := "/20190301/secretbundles/" + credential.SecretOCID + "?versionNumber=1"
	fixture.putJSON(t, renewalFixtureSecrets, credentialPath, map[string]any{
		"secretId": credential.SecretOCID, "versionNumber": credential.VersionNumber,
		"secretBundleContent": map[string]string{"contentType": "BASE64", "content": base64.StdEncoding.EncodeToString([]byte(`{"version":1,"access_key_id":"fixture-access","secret_access_key":"fixture-secret"}`))},
	})
	resolver, err := host.NewOCIS3CredentialResolver(oci.RegionGRU)
	if err != nil {
		t.Fatalf("production instance-principal Vault constructor: %v", err)
	}
	resolved, err := resolver.Resolve(t.Context(), credential)
	if err != nil || resolved.AccessKeyID != "fixture-access" || resolved.SecretAccessKey != "fixture-secret" {
		t.Fatalf("production exact Vault resolution: %v", err)
	}
	provider, err := ociclient.InstancePrincipalProvider(common.Region("sa-saopaulo-1"), bootstrap.BoundInstancePrincipalDispatcher)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	storage.HTTPClient, err = bootstrap.NewInstancePrincipalSDKHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	noRetry := common.NoRetryPolicy()
	storage.SetCustomClientConfiguration(common.CustomClientConfiguration{RetryPolicy: &noRetry})
	const allocationPath = "/n/fixture/b/gru-1-head/o/source-renewal-cas"
	fixture.allowCAS(renewalFixtureStorage, allocationPath)
	wire := []byte("first retained fixture allocation")
	_, err = storage.PutObject(t.Context(), objectstorage.PutObjectRequest{NamespaceName: new("fixture"), BucketName: new("gru-1-head"), ObjectName: new("source-renewal-cas"),
		IfNoneMatch: new("*"), ContentLength: new(int64(len(wire))), PutObjectBody: io.NopCloser(bytes.NewReader(wire))})
	if err != nil {
		t.Fatalf("signed SDK conditional creation: %v", err)
	}
	read, err := storage.GetObject(t.Context(), objectstorage.GetObjectRequest{NamespaceName: new("fixture"), BucketName: new("gru-1-head"), ObjectName: new("source-renewal-cas")})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(read.Content)
	closeErr := read.Content.Close()
	if err != nil || closeErr != nil || !bytes.Equal(actual, wire) || read.ETag == nil {
		t.Fatalf("signed SDK conditional read: read=%v close=%v", err, closeErr)
	}
	_, err = storage.PutObject(t.Context(), objectstorage.PutObjectRequest{NamespaceName: new("fixture"), BucketName: new("gru-1-head"), ObjectName: new("source-renewal-cas"),
		IfNoneMatch: new("*"), ContentLength: new(int64(len(wire))), PutObjectBody: io.NopCloser(bytes.NewReader(wire))})
	serviceErr, ok := common.IsServiceError(err)
	if !ok || serviceErr.GetHTTPStatusCode() != http.StatusPreconditionFailed {
		t.Fatal("occupied SDK allocation did not reject a second creator")
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.rejected != 0 || fixture.federations < 2 || fixture.reads != 2 || fixture.writes != 1 || fixture.conflicts != 1 {
		t.Fatalf("unexpected fixture boundary counts: federation=%d reads=%d writes=%d conflicts=%d rejected=%d", fixture.federations, fixture.reads, fixture.writes, fixture.conflicts, fixture.rejected)
	}
}

func renewalIsolatedChild(t *testing.T) bool {
	t.Helper()
	if os.Getenv(renewalFixtureChild) == t.Name() {
		if os.Geteuid() != 0 {
			t.Fatal("renewal fixture child requires root")
		}
		namespace, err := os.Readlink("/proc/self/ns/net")
		if err != nil || os.Getenv(renewalFixtureParent) == "" || namespace == os.Getenv(renewalFixtureParent) {
			t.Fatal("renewal fixture must have its own network namespace")
		}
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"link", "set", "lo", "up"}, {"address", "add", "169.254.169.254/32", "dev", "lo"}} {
			command := exec.CommandContext(t.Context(), "ip", args...)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("isolated IMDS address: %v: %s", err, output)
			}
		}
		return true
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), "sudo", "-n", "env", renewalFixtureChild+"="+t.Name(), renewalFixtureParent+"="+namespace, "GOMAXPROCS=2", "nice", "-n", "19", "unshare", "--mount", "--net", executable,
		"-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.timeout=90s", "-test.v")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated renewal fixture: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
	return false
}

type renewalCloudRoute struct {
	body []byte
	etag string
	cas  bool
}

type renewalCloud struct {
	simulator                                       *production.Simulator
	mu                                              sync.Mutex
	sessions                                        map[string]*rsa.PublicKey
	routes                                          map[string]renewalCloudRoute
	federations, reads, writes, conflicts, rejected int
}

func newRenewalCloud(t *testing.T) *renewalCloud {
	t.Helper()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Source renewal fixture CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Source renewal fixture instance",
		ExtraNames: []pkix.AttributeTypeAndValue{{Type: []int{2, 5, 4, 13}, Value: "opc-tenant:" + renewalFixtureTenancy}}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{renewalFixtureAuth, renewalFixtureSecrets, renewalFixtureStorage}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})
	simulator, err := production.NewSimulator(production.Config{Region: "sa-saopaulo-1", InstanceID: renewalFixtureInstance,
		DescriptorSlot: "source-renewal", PrimaryPrivateIP: "10.44.0.11", TenancyID: renewalFixtureTenancy,
		LeafCertificate: certificate, LeafPrivateKey: privateKey, Intermediate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &renewalCloud{simulator: simulator, sessions: make(map[string]*rsa.PublicKey), routes: make(map[string]renewalCloudRoute)}
	server := httptest.NewUnstartedServer(fixture)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey}}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	listener, err := net.Listen("tcp4", "169.254.169.254:80")
	if err != nil {
		t.Fatal(err)
	}
	imds := &http.Server{Handler: fixture, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := imds.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("isolated IMDS server: %v", err)
		}
	}()
	t.Cleanup(func() { _ = imds.Close() })
	trusted := x509.NewCertPool()
	trusted.AddCert(root)
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "169.254.169.254:80" {
				return nil, errors.New("renewal fixture refuses non-IMDS plain HTTP")
			}
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
		// OCI's default transport replaces DialContext and TLSClientConfig.
		// DialTLSContext survives its clone and still validates the original hostname.
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			hostname, port, err := net.SplitHostPort(address)
			if err != nil || network != "tcp" || port != "443" || hostname != renewalFixtureAuth && hostname != renewalFixtureSecrets && hostname != renewalFixtureStorage {
				return nil, errors.New("renewal fixture refuses unlisted TLS destination")
			}
			dialer := &tls.Dialer{Config: &tls.Config{RootCAs: trusted, ServerName: hostname, MinVersion: tls.VersionTLS12}}
			return dialer.DialContext(ctx, "tcp", server.Listener.Addr().String())
		}}
	original := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
	return fixture
}

func (fixture *renewalCloud) putJSON(t *testing.T, hostname, path string, value any) {
	t.Helper()
	wire, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.routes[hostname+path] = renewalCloudRoute{body: wire, etag: fmt.Sprintf(`"%x"`, sha256.Sum256(wire))}
}

func (fixture *renewalCloud) allowCAS(hostname, path string) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.routes[hostname+path] = renewalCloudRoute{cas: true}
}

var renewalSignature = regexp.MustCompile(`^Signature version="1",headers="([a-z0-9() -]+)",keyId="ST\$([^"]+)",algorithm="rsa-sha256",signature="([A-Za-z0-9+/=]+)"$`)

func (fixture *renewalCloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Host == "169.254.169.254" {
		fixture.simulator.ServeHTTP(w, r)
		return
	}
	if r.Host == renewalFixtureAuth && r.Method == http.MethodPost && r.URL.RequestURI() == "/v1/x509" {
		body, err := io.ReadAll(io.LimitReader(r.Body, (64<<10)+1))
		if err != nil || len(body) > 64<<10 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		recorder := httptest.NewRecorder()
		fixture.simulator.ServeHTTP(recorder, r)
		if recorder.Code == http.StatusOK {
			var submitted struct {
				PublicKey string `json:"publicKey"`
			}
			var response struct {
				Token string `json:"token"`
			}
			if json.Unmarshal(body, &submitted) != nil || json.Unmarshal(recorder.Body.Bytes(), &response) != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			der, err := base64.StdEncoding.DecodeString(submitted.PublicKey)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			parsed, err := x509.ParsePKIXPublicKey(der)
			public, ok := parsed.(*rsa.PublicKey)
			if err != nil || !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			fixture.mu.Lock()
			fixture.sessions[response.Token] = public
			fixture.federations++
			fixture.mu.Unlock()
		}
		for name, values := range recorder.Header() {
			w.Header()[name] = values
		}
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(recorder.Body.Bytes())
		return
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	route, exists := fixture.routes[r.Host+r.URL.RequestURI()]
	if !exists || r.Method != http.MethodGet && !(r.Method == http.MethodPut && route.cas) {
		fixture.rejected++
		w.WriteHeader(http.StatusMisdirectedRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, (64<<10)+1))
	if err != nil || len(body) > 64<<10 || fixture.verify(r) != nil || r.Method == http.MethodPut && r.ContentLength != int64(len(body)) {
		fixture.rejected++
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.Method == http.MethodPut {
		if r.Header.Get("If-None-Match") == "*" && route.body != nil || r.Header.Get("If-Match") != "" && (route.body == nil || r.Header.Get("If-Match") != route.etag) {
			fixture.conflicts++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = io.WriteString(w, `{"code":"PreconditionFailed","message":"fixture CAS conflict"}`)
			return
		}
		if r.Header.Get("If-None-Match") != "*" && r.Header.Get("If-Match") == "" {
			fixture.rejected++
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		route.body, route.etag = bytes.Clone(body), fmt.Sprintf(`"%x"`, sha256.Sum256(body))
		fixture.routes[r.Host+r.URL.RequestURI()] = route
		fixture.writes++
		w.Header().Set("ETag", route.etag)
		w.WriteHeader(http.StatusOK)
		return
	}
	if route.body == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"code":"ObjectNotFound","message":"fixture CAS object absent"}`)
		return
	}
	fixture.reads++
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", route.etag)
	w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	_, _ = w.Write(route.body)
}

func (fixture *renewalCloud) verify(r *http.Request) error {
	match := renewalSignature.FindStringSubmatch(r.Header.Get("Authorization"))
	if match == nil || fixture.sessions[match[2]] == nil {
		return errors.New("unknown fixture federation session")
	}
	date, err := http.ParseTime(r.Header.Get("Date"))
	if err != nil || time.Since(date).Abs() > 5*time.Minute {
		return errors.New("stale fixture request")
	}
	headers := "date (request-target) host"
	lines := []string{"date: " + r.Header.Get("Date"), "(request-target): " + strings.ToLower(r.Method) + " " + r.URL.RequestURI(), "host: " + r.Host}
	// The OCI SDK deliberately excludes PutObject bodies from HTTP signatures.
	if match[1] != headers {
		return errors.New("fixture request signed header set differs")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(match[3])
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return rsa.VerifyPKCS1v15(fixture.sessions[match[2]], crypto.SHA256, digest[:], signature)
}
