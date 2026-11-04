package ociclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/secrets"
)

func TestInstancePrincipalProtocolFreshSigningAndRotatingRefresh(t *testing.T) {
	fixture := newPrincipalProtocol(t)
	constructor, cancelConstructor := context.WithCancel(t.Context())
	defer cancelConstructor()
	factory, err := InstancePrincipalContext(constructor, "sa-saopaulo-1")
	if err != nil {
		t.Fatal(err)
	}
	client, err := factory.SecretsContext(constructor)
	if err != nil {
		t.Fatal(err)
	}
	if !client.IsRefreshableAuthType() {
		t.Fatal("provider view lost SDK refreshable authentication")
	}
	// The real generated constructor must release its private context view.
	configured := *client.ConfigurationProvider()
	view, ok := configured.(*constructionProvider)
	if !ok || view.ctx != nil {
		t.Fatal("constructor context retained after validation")
	}
	cancelConstructor()
	client.HTTPClient = readDispatcher{next: fixture}
	_, err = client.GetSecretBundle(RequestContext(t.Context()), secrets.GetSecretBundleRequest{SecretId: new("ocid1.vaultsecret.oc1.sa-saopaulo-1.protocol")})
	if err != nil {
		t.Fatalf("fresh request retained canceled constructor: %v", err)
	}
	fixture.mu.Lock()
	expiry := fixture.refreshAt
	fixture.mu.Unlock()
	timer := time.NewTimer(time.Until(expiry))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	fixture.rotate("ocid1.tenancy.oc1..protocol")
	fixture.setMode("federation:headers")
	fresh, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	request, err := http.NewRequestWithContext(RequestContext(fresh), http.MethodGet, client.Host+"/20190301/secretbundles/ocid1.vaultsecret.oc1.sa-saopaulo-1.protocol", nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() { done <- client.Signer.Sign(request) }()
	fixture.wait("federation")
	// A second real signing refresh must be cancellable while waiting for the first.
	queued, stop := context.WithCancel(t.Context())
	defer stop()
	queued, waiting := principalObserveQueuedWait(queued)
	queuedDone := make(chan error, 1)
	go func() {
		_, err := factory.Provider().(common.ContextKeyProvider).KeyIDContext(queued)
		queuedDone <- err
	}()
	principalWaitForQueuedSelect(t, waiting)
	stop()
	if err := principalJoined(t, queuedDone); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	cancel()
	if err := principalJoined(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	fixture.waitIdle(t)
	fixture.mu.Lock()
	serviceCalls := fixture.calls["service"]
	fixture.mu.Unlock()
	if serviceCalls != 1 {
		t.Fatalf("canceled refresh reached Secrets wire: %d calls", serviceCalls)
	}
	// A changed tenancy in the rotating metadata leaf remains forbidden.
	fixture.rotate("ocid1.tenancy.oc1..other")
	fixture.setMode("")
	_, err = factory.Provider().(common.ContextKeyProvider).KeyIDContext(t.Context())
	if err == nil || !strings.Contains(err.Error(), "unexpected update of tenancy") {
		t.Fatalf("changed tenancy accepted: %v", err)
	}
}

type principalProtocol struct {
	t                                    *testing.T
	metadata, federation                 *httptest.Server
	mu                                   sync.Mutex
	mode                                 string
	calls                                map[string]int
	hits                                 chan string
	idle                                 chan struct{}
	active                               int
	ca                                   *x509.Certificate
	issuer, leaf                         *rsa.PrivateKey
	leafPEM, leafKeyPEM, intermediatePEM []byte
	session                              *rsa.PublicKey
	token                                string
	refreshAt                            time.Time
}

func newPrincipalProtocol(t *testing.T) *principalProtocol {
	t.Helper()
	for _, name := range SecretUnsafeEnv {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	fixture := &principalProtocol{t: t, calls: map[string]int{}, hits: make(chan string, 100), idle: make(chan struct{})}
	close(fixture.idle)
	var err error
	fixture.issuer, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "protocol issuer"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &fixture.issuer.PublicKey, fixture.issuer)
	if err != nil {
		t.Fatal(err)
	}
	fixture.ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	fixture.intermediatePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	fixture.rotate("ocid1.tenancy.oc1..protocol")
	fixture.metadata = httptest.NewServer(http.HandlerFunc(fixture.serveMetadata))
	fixture.federation = httptest.NewTLSServer(http.HandlerFunc(fixture.serveTLS))
	fixture.metadata.Client().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	fixture.federation.Client().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	t.Cleanup(fixture.federation.Close)
	t.Cleanup(fixture.metadata.Close)
	original := newInstancePrincipalProvider
	sharedMu.Lock()
	saved := sharedPrincipal
	sharedPrincipal = map[string]*Factory{}
	sharedMu.Unlock()
	newInstancePrincipalProvider = func(ctx context.Context, region common.Region, modifier func(common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error)) (common.ConfigurationProvider, error) {
		return auth.InstancePrincipalConfigurationForRegionWithCustomClientContext(ctx, region, func(common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error) {
			if modifier != nil {
				return modifier(fixture)
			}
			return fixture, nil
		})
	}
	t.Cleanup(func() {
		newInstancePrincipalProvider = original
		sharedMu.Lock()
		sharedPrincipal = saved
		sharedMu.Unlock()
	})
	return fixture
}

func (f *principalProtocol) rotate(tenancy string) {
	f.t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "opc-tenant:" + tenancy}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, f.ca, &key.PublicKey, f.issuer)
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.leaf = key
	f.leafPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	f.leafKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func (f *principalProtocol) setMode(mode string) {
	f.mu.Lock()
	f.mode = mode
	f.mu.Unlock()
	for {
		select {
		case <-f.hits:
		default:
			return
		}
	}
}

func (f *principalProtocol) wait(kind string) {
	f.t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case hit := <-f.hits:
			if hit == kind {
				return
			}
		case <-deadline.C:
			f.t.Fatalf("no %s wire observed", kind)
		}
	}
}

func principalJoined(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("canceled SDK acquisition did not join")
		return nil
	}
}

func (f *principalProtocol) waitIdle(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	idle := f.idle
	f.mu.Unlock()
	select {
	case <-idle:
	case <-time.After(10 * time.Second):
		t.Fatal("metadata/federation handler continued after canceled acquisition")
	}
}

func (f *principalProtocol) begin(w http.ResponseWriter, r *http.Request, kind string) (bool, func()) {
	f.mu.Lock()
	if f.active == 0 {
		f.idle = make(chan struct{})
	}
	f.active++
	f.calls[kind]++
	mode := f.mode
	f.mu.Unlock()
	finish := func() {
		f.mu.Lock()
		f.active--
		if f.active == 0 {
			close(f.idle)
		}
		f.mu.Unlock()
	}
	if mode == kind+":body" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"`))
		w.(http.Flusher).Flush()
	}
	f.hits <- kind
	if mode == kind+":headers" || mode == kind+":body" {
		<-r.Context().Done()
		return true, finish
	}
	if mode == kind+":retry" {
		http.Error(w, "retry boundary", http.StatusServiceUnavailable)
		return true, finish
	}
	return false, finish
}

func (f *principalProtocol) serveMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer Oracle" || r.Method != http.MethodGet {
		f.t.Error("metadata authentication changed")
		http.Error(w, "denied", 403)
		return
	}
	if r.URL.Path == "/opc/v2/instance/region" {
		stopped, finish := f.begin(w, r, "metadata")
		defer finish()
		if stopped {
			return
		}
		_, _ = io.WriteString(w, "sa-saopaulo-1")
		return
	}
	kind := "certificate"
	if r.URL.Path == "/opc/v2/identity/key.pem" {
		kind = "privatekey"
	}
	stopped, finish := f.begin(w, r, kind)
	defer finish()
	if stopped {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/opc/v2/identity/cert.pem":
		_, _ = w.Write(f.leafPEM)
	case "/opc/v2/identity/key.pem":
		if f.mode == "certificate:mismatch" {
			_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.issuer)}))
		} else {
			_, _ = w.Write(f.leafKeyPEM)
		}
	case "/opc/v2/identity/intermediate.pem":
		_, _ = w.Write(f.intermediatePEM)
	default:
		f.t.Errorf("unexpected metadata path: %s", r.URL.Path)
		http.Error(w, "denied", 403)
	}
}

func (f *principalProtocol) Do(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	var target string
	switch request.URL.Scheme + "://" + request.URL.Host {
	case "http://169.254.169.254":
		target = f.metadata.URL
	case "https://auth.sa-saopaulo-1.oraclecloud.com", "https://secrets.vaults.sa-saopaulo-1.oci.oraclecloud.com":
		target = f.federation.URL
	default:
		return nil, fmt.Errorf("protocol simulator denied endpoint %s", request.URL.Host)
	}
	endpoint, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	clone.Host = request.URL.Host
	clone.URL.Scheme, clone.URL.Host = endpoint.Scheme, endpoint.Host
	if target == f.metadata.URL {
		return f.metadata.Client().Do(clone)
	}
	response, err := f.federation.Client().Do(clone)
	if err == nil && response.StatusCode == http.StatusUnauthorized && request.URL.Host == "secrets.vaults.sa-saopaulo-1.oci.oraclecloud.com" {
		response.Body = &principalProtocolEOFBody{ReadCloser: response.Body, observed: func() { f.hits <- "service-401-body" }}
	}
	return response, err
}

type principalProtocolEOFBody struct {
	io.ReadCloser
	once     sync.Once
	observed func()
}

func (body *principalProtocolEOFBody) Read(buffer []byte) (int, error) {
	count, err := body.ReadCloser.Read(buffer)
	if err == io.EOF {
		body.once.Do(body.observed)
	}
	return count, err
}

func (f *principalProtocol) serveTLS(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		f.t.Error(err)
		return
	}
	if r.Host == "auth.sa-saopaulo-1.oraclecloud.com" && r.URL.Path == "/v1/x509" && r.Method == http.MethodPost {
		var details auth.X509FederationDetails
		if err := json.Unmarshal(body, &details); err != nil {
			f.t.Error(err)
			http.Error(w, "denied", 400)
			return
		}
		certDER, err := base64.StdEncoding.DecodeString(details.Certificate)
		if err != nil {
			f.t.Error(err)
			http.Error(w, "denied", 400)
			return
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			f.t.Error(err)
			http.Error(w, "denied", 400)
			return
		}
		f.mu.Lock()
		expectedLeaf, _ := pem.Decode(f.leafPEM)
		f.mu.Unlock()
		if expectedLeaf == nil || !bytes.Equal(cert.Raw, expectedLeaf.Bytes) {
			f.t.Error("federation used stale metadata certificate")
			http.Error(w, "denied", 401)
			return
		}
		if err := cert.CheckSignatureFrom(f.ca); err != nil {
			f.t.Error(err)
			http.Error(w, "denied", 401)
			return
		}
		sum := sha256.Sum256(cert.Raw)
		fingerprint := strings.ReplaceAll(fmt.Sprintf("% x", sum), " ", ":")
		if err := verifyPrincipalSignature(r, body, cert.PublicKey.(*rsa.PublicKey), "ocid1.tenancy.oc1..protocol/fed-x509-sha256/"+fingerprint); err != nil {
			f.mu.Lock()
			f.calls["denied-signature"]++
			f.mu.Unlock()
			http.Error(w, "denied", 401)
			return
		}
		publicDER, err := base64.StdEncoding.DecodeString(details.PublicKey)
		if err != nil {
			f.t.Error(err)
			http.Error(w, "denied", 400)
			return
		}
		public, err := x509.ParsePKIXPublicKey(publicDER)
		if err != nil {
			f.t.Error(err)
			http.Error(w, "denied", 400)
			return
		}
		session, ok := public.(*rsa.PublicKey)
		if !ok || session.N.BitLen() < 2048 || details.FingerprintAlgorithm != "SHA256" || len(details.IntermediateCertificates) != 1 {
			f.t.Error("invalid genuine federation key or certificate request")
			http.Error(w, "denied", 400)
			return
		}
		intermediate, err := base64.StdEncoding.DecodeString(details.IntermediateCertificates[0])
		if err != nil || !bytes.Equal(intermediate, f.ca.Raw) {
			f.t.Error("intermediate certificate changed")
			http.Error(w, "denied", 400)
			return
		}
		stopped, finish := f.begin(w, r, "federation")
		defer finish()
		if stopped {
			return
		}
		expiry := time.Now().Add(5*time.Minute + 3*time.Second).Truncate(time.Second)
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
		claims, err := json.Marshal(map[string]any{"exp": expiry.Unix(), "opc-tenant": "ocid1.tenancy.oc1..protocol"})
		if err != nil {
			f.t.Error(err)
			return
		}
		unsigned := header + "." + base64.RawURLEncoding.EncodeToString(claims)
		hash := sha256.Sum256([]byte(unsigned))
		signature, err := rsa.SignPKCS1v15(rand.Reader, f.issuer, crypto.SHA256, hash[:])
		if err != nil {
			f.t.Error(err)
			return
		}
		token := unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
		f.mu.Lock()
		f.session, f.token, f.refreshAt = session, token, expiry.Add(-5*time.Minute)
		f.mu.Unlock()
		encoded, err := json.Marshal(map[string]string{"token": token})
		if err != nil {
			f.t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(encoded)
		return
	}
	if r.Host != "secrets.vaults.sa-saopaulo-1.oci.oraclecloud.com" || r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/20190301/secretbundles/") {
		f.t.Error("unexpected TLS endpoint")
		http.Error(w, "denied", 403)
		return
	}
	f.mu.Lock()
	session, token := f.session, f.token
	f.mu.Unlock()
	if session == nil {
		f.t.Error("no federation session")
		http.Error(w, "denied", 401)
		return
	}
	if err := verifyPrincipalSignature(r, body, session, "ST$"+token); err != nil {
		f.t.Error(err)
		http.Error(w, "denied", 401)
		return
	}
	stopped, finish := f.begin(w, r, "service")
	defer finish()
	if stopped {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	f.mu.Lock()
	unauthorized := f.mode == "service:unauthorized"
	f.mu.Unlock()
	if unauthorized {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"code":"NotAuthenticated","message":"protocol retry boundary"}`)
		return
	}
	_, _ = io.WriteString(w, `{"secretId":"ocid1.vaultsecret.oc1.sa-saopaulo-1.protocol","versionNumber":1,"secretBundleContent":{"contentType":"BASE64","content":"cHJvdG9jb2w="}}`)
}

func verifyPrincipalSignature(r *http.Request, body []byte, key *rsa.PublicKey, keyID string) error {
	fields := map[string]string{}
	for _, field := range strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Signature "), ",") {
		name, value, ok := strings.Cut(field, "=")
		if ok {
			fields[name] = strings.Trim(value, `"`)
		}
	}
	if fields["keyId"] != keyID || fields["algorithm"] != "rsa-sha256" {
		return errors.New("unexpected signing identity or algorithm")
	}
	var canonical []string
	for _, header := range strings.Fields(fields["headers"]) {
		value := r.Header.Get(header)
		switch header {
		case "(request-target)":
			value = strings.ToLower(r.Method) + " " + r.URL.RequestURI()
		case "host":
			value = r.Host
		case "content-length":
			value = strconv.FormatInt(r.ContentLength, 10)
		}
		canonical = append(canonical, header+": "+value)
	}
	if r.Method == http.MethodPost {
		hash := sha256.Sum256(body)
		if r.Header.Get("x-content-sha256") != base64.StdEncoding.EncodeToString(hash[:]) {
			return errors.New("federation body hash mismatch")
		}
	}
	signature, err := base64.StdEncoding.DecodeString(fields["signature"])
	if err != nil {
		return err
	}
	hash := sha256.Sum256([]byte(strings.Join(canonical, "\n")))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], signature)
}

// Done delegates real cancellation and signals evaluation of the held lock's select.
type principalQueuedContext struct {
	context.Context
	once    sync.Once
	waiting chan struct{}
}

func principalObserveQueuedWait(ctx context.Context) (context.Context, <-chan struct{}) {
	observed := &principalQueuedContext{Context: ctx, waiting: make(chan struct{})}
	return observed, observed.waiting
}
func (ctx *principalQueuedContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.waiting) })
	return ctx.Context.Done()
}
func principalWaitForQueuedSelect(t *testing.T, waiting <-chan struct{}) {
	t.Helper()
	select {
	case <-waiting:
	case <-time.After(10 * time.Second):
		t.Fatal("queued caller never reached the cancellable lock select")
	}
}
