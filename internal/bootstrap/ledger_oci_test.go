package bootstrap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func TestInstancePrincipalLedgerPinsCanonicalRegionAndBoundsSDKHTTP(t *testing.T) {
	privateKeyPEM := testLedgerSDKPrivateKey(t)
	tests := []struct {
		region oci.Region
		oci    string
		host   string
	}{
		{region: oci.RegionGRU, oci: "sa-saopaulo-1", host: "https://objectstorage.sa-saopaulo-1.{dualStack?ds.oci.:}oraclecloud.com"},
		{region: oci.RegionSJC, oci: "us-sanjose-1", host: "https://objectstorage.us-sanjose-1.{dualStack?ds.oci.:}oraclecloud.com"},
		{region: oci.RegionFRA, oci: "eu-frankfurt-1", host: "https://objectstorage.eu-frankfurt-1.{dualStack?ds.oci.:}oraclecloud.com"},
	}
	for _, test := range tests {
		t.Run(string(test.region), func(t *testing.T) {
			fixture := newLedgerFixture(t)
			config := ledgerConfigForRegion(t, fixture, test.region)
			providerCalls := 0
			providerFactory := func(region common.Region, modify func(common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error)) (common.ConfigurationProvider, error) {
				providerCalls++
				if region != common.Region(test.oci) {
					t.Fatalf("provider region = %q, want %q", region, test.oci)
				}
				dispatcher := &http.Client{}
				modified, err := modify(dispatcher)
				if err != nil {
					return nil, err
				}
				client, ok := modified.(*http.Client)
				if !ok || client == dispatcher || dispatcher.Timeout != 0 || client.Timeout != instancePrincipalRequestTimeout {
					t.Fatalf("Instance Principal dispatcher was not safely cloned and bounded: returned=%T source timeout=%s", modified, dispatcher.Timeout)
				}
				transport, ok := client.Transport.(*http.Transport)
				if !ok || transport == http.DefaultTransport || transport.Proxy != nil {
					t.Fatalf("Instance Principal dispatcher lacks a cloned no-proxy transport: %#v", client.Transport)
				}
				return common.NewRawConfigurationProvider(
					"ocid1.tenancy.oc1..test",
					"ocid1.user.oc1..test",
					string(region),
					"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
					privateKeyPEM,
					nil,
				), nil
			}

			ledger, err := newInstancePrincipalLedger(test.region, config, providerFactory)
			if err != nil {
				t.Fatalf("newInstancePrincipalLedger() error = %v", err)
			}
			if providerCalls != 1 {
				t.Fatalf("provider calls = %d, want 1", providerCalls)
			}
			client, ok := ledger.client.(*objectstorage.ObjectStorageClient)
			if !ok {
				t.Fatalf("ledger client has type %T, want *objectstorage.ObjectStorageClient", ledger.client)
			}
			if client.Host != test.host {
				t.Fatalf("Object Storage host = %q, want %q", client.Host, test.host)
			}
			serviceClient, ok := client.HTTPClient.(*http.Client)
			if !ok || serviceClient.Timeout != instancePrincipalRequestTimeout {
				t.Fatalf("Object Storage client has no bounded hardened HTTP client: %T", client.HTTPClient)
			}
			if transport, ok := serviceClient.Transport.(*http.Transport); !ok || transport.Proxy != nil {
				t.Fatalf("Object Storage client HTTP transport is not no-proxy: %#v", serviceClient.Transport)
			}
		})
	}
}

func testLedgerSDKPrivateKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return string(data)
}

func TestInstancePrincipalLedgerRejectsInvalidInputBeforeProvider(t *testing.T) {
	fixture := newLedgerFixture(t)
	missingDeployment := fixture.ledger.config
	missingDeployment.DeploymentID = ""
	missingCell := fixture.ledger.config
	missingCell.Cell = "LAX"
	missingCluster := fixture.ledger.config
	missingCluster.ClusterID = ""
	tests := []struct {
		name   string
		region oci.Region
		config LedgerConfig
	}{
		{name: "unsupported region", region: oci.Region("LAX"), config: fixture.ledger.config},
		{name: "invalid prefix", region: oci.RegionGRU, config: invalidLedgerPrefixConfig(fixture.ledger.config)},
		{name: "missing deployment anchor", region: oci.RegionGRU, config: missingDeployment},
		{name: "unsupported anchor cell", region: oci.RegionGRU, config: missingCell},
		{name: "missing cluster anchor", region: oci.RegionGRU, config: missingCluster},
		{name: "missing controller slot pin", region: oci.RegionGRU, config: func() LedgerConfig {
			config := fixture.ledger.config
			config.ControllerSlots = nil
			return config
		}()},
		{name: "region does not match anchor cell", region: oci.RegionSJC, config: fixture.ledger.config},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			providerCalled := false
			providerFactory := func(common.Region, func(common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error)) (common.ConfigurationProvider, error) {
				providerCalled = true
				return nil, nil
			}
			if _, err := newInstancePrincipalLedger(test.region, test.config, providerFactory); err == nil {
				t.Fatal("newInstancePrincipalLedger() succeeded with invalid input")
			}
			if providerCalled {
				t.Fatal("Instance Principal provider was created for invalid input")
			}
		})
	}
}

func TestInstancePrincipalLedgerRejectsSDKOverridesBeforeProvider(t *testing.T) {
	fixture := newLedgerFixture(t)
	for _, name := range []string{
		metadataBaseURLEnv,
		authClientRegionURLEnv,
		customCertBundleEnv,
		customClientCertEnv,
		customClientKeyEnv,
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "http://attacker.invalid/override")
			providerCalled := false
			providerFactory := func(common.Region, func(common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error)) (common.ConfigurationProvider, error) {
				providerCalled = true
				return nil, errors.New("provider must not be called")
			}
			if _, err := newInstancePrincipalLedger(oci.RegionGRU, fixture.ledger.config, providerFactory); err == nil {
				t.Fatalf("Instance Principal setup accepted %s override", name)
			}
			if providerCalled {
				t.Fatal("unsafe SDK override was rejected only after provider creation")
			}
		})
	}
}

func TestInstancePrincipalLedgerCanUseValidatedSharedProvider(t *testing.T) {
	fixture := newLedgerFixture(t)
	provider := common.NewRawConfigurationProvider(
		"ocid1.tenancy.oc1..test",
		"ocid1.user.oc1..test",
		"sa-saopaulo-1",
		"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
		testLedgerSDKPrivateKey(t),
		nil,
	)
	ledger, err := NewInstancePrincipalLedgerWithProvider(oci.RegionGRU, fixture.ledger.config, provider)
	if err != nil {
		t.Fatalf("NewInstancePrincipalLedgerWithProvider() error = %v", err)
	}
	if ledger.client == nil {
		t.Fatal("shared provider produced a ledger with no SDK client")
	}
	if _, err := NewInstancePrincipalLedgerWithProvider(oci.RegionGRU, fixture.ledger.config, common.NewRawConfigurationProvider(
		"ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "us-sanjose-1",
		"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00", testLedgerSDKPrivateKey(t), nil,
	)); err == nil {
		t.Fatal("shared provider with a mismatched region was accepted")
	}
}

func TestBoundInstancePrincipalDispatcherSupportsActualOCISDKTransportWrapper(t *testing.T) {
	provider := common.NewRawConfigurationProvider(
		"ocid1.tenancy.oc1..test",
		"ocid1.user.oc1..test",
		"sa-saopaulo-1",
		"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
		testLedgerSDKPrivateKey(t),
		nil,
	)
	sdkClient, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatalf("create offline OCI SDK client: %v", err)
	}
	source, ok := sdkClient.HTTPClient.(*http.Client)
	if !ok || source == nil {
		t.Fatalf("OCI SDK client HTTP dispatcher has type %T, want *http.Client", sdkClient.HTTPClient)
	}
	original, ok := source.Transport.(*common.OciHTTPTransportWrapper)
	if !ok || original == nil {
		t.Fatalf("OCI SDK client transport has type %T, want *common.OciHTTPTransportWrapper", source.Transport)
	}
	original.RefreshRate = instancePrincipalRequestTimeout
	refresh := &countingTLSConfigProvider{}
	original.TLSConfigProvider = refresh

	modified, err := BoundInstancePrincipalDispatcher(source)
	if err != nil {
		t.Fatalf("harden actual OCI SDK dispatcher: %v", err)
	}
	hardenedClient, ok := modified.(*http.Client)
	if !ok || hardenedClient == source || source.Timeout == instancePrincipalRequestTimeout ||
		hardenedClient.Timeout != instancePrincipalRequestTimeout || hardenedClient.CheckRedirect == nil {
		t.Fatalf("OCI dispatcher was not cloned and bounded: source timeout=%s modified=%#v", source.Timeout, modified)
	}
	hardened, ok := hardenedClient.Transport.(*common.OciHTTPTransportWrapper)
	if !ok || hardened == original || hardened.TLSConfigProvider != refresh || hardened.RefreshRate != original.RefreshRate {
		t.Fatalf("SDK TLS-refresh wrapper was not preserved: transport=%T, provider preserved=%t", hardenedClient.Transport, ok && hardened.TLSConfigProvider == refresh)
	}
	if err := hardened.Refresh(true); err != nil {
		t.Fatalf("initialize hardened SDK TLS transport: %v", err)
	}
	delegate, ok := hardened.Delegate().(*http.Transport)
	if !ok || delegate.Proxy != nil {
		t.Fatalf("refreshed SDK transport did not disable proxies: %#v", hardened.Delegate())
	}
	hardened.RefreshRate = time.Nanosecond
	refresh.changed = true
	time.Sleep(time.Millisecond)
	if err := hardened.Refresh(false); err != nil {
		t.Fatalf("refresh hardened SDK TLS transport: %v", err)
	}
	if refresh.calls != 2 {
		t.Fatalf("TLS configuration refresh calls = %d, want 2", refresh.calls)
	}
}

type countingTLSConfigProvider struct {
	calls   int
	changed bool
}

func (provider *countingTLSConfigProvider) NewOrDefault() (*tls.Config, error) {
	provider.calls++
	return &tls.Config{MinVersion: tls.VersionTLS12}, nil
}

func (provider *countingTLSConfigProvider) WatchedFilesModified() bool {
	return provider.changed
}

func TestInstancePrincipalHTTPClientClonesNoProxyTransportAndRejectsRedirects(t *testing.T) {
	proxyCalls := 0
	sourceTransport := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
		proxyCalls++
		return nil, nil
	}}
	source := &http.Client{Transport: sourceTransport}
	client, err := newInstancePrincipalHTTPClient(source)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport == sourceTransport || transport.Proxy != nil || sourceTransport.Proxy == nil {
		t.Fatalf("transport was not cloned with only the clone's proxy disabled: clone=%#v source=%#v", client.Transport, source.Transport)
	}
	if client.CheckRedirect == nil || client.Timeout != instancePrincipalRequestTimeout {
		t.Fatalf("redirect or timeout policy is missing: redirect configured=%t timeout=%s", client.CheckRedirect != nil, client.Timeout)
	}

	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected = true }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	response, err := client.Get(redirect.URL)
	if err == nil {
		if response != nil {
			response.Body.Close()
		}
		t.Fatal("HTTP client followed an OCI metadata or service redirect")
	}
	if redirected || proxyCalls != 0 {
		t.Fatalf("HTTP client crossed a redirect or proxy boundary: redirected=%t proxy calls=%d", redirected, proxyCalls)
	}
}

func invalidLedgerPrefixConfig(config LedgerConfig) LedgerConfig {
	config.Prefix = "../invalid"
	return config
}

func ledgerConfigForRegion(t *testing.T, fixture *ledgerFixture, region oci.Region) LedgerConfig {
	t.Helper()
	config := fixture.ledger.config
	config.Cell = region
	ociRegion, err := region.OCIRegion()
	if err != nil {
		t.Fatal(err)
	}
	config.KMSKeyID = "ocid1.key.oc1." + ociRegion + ".ledger"
	config.HeadKMSKeyID = "ocid1.key.oc1." + ociRegion + ".head"
	publicWire, err := trust.EncodeDelegatedPublicKey(fixture.authority.peerPublic)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := make([]trust.Capability, 0, 3)
	for _, domain := range []string{domainBootstrapHead, domainBootstrapIntent, domainBootstrapResult,
		domainBootstrapCandidate, domainBootstrapProgress} {
		capabilities = append(capabilities, trust.Capability{
			Domain: domain, DeploymentID: config.DeploymentID, Cell: string(region), Environment: config.Environment,
			Role: roleController, Slots: slices.Clone(config.ControllerSlots), Actions: []string{"sign"},
		})
	}
	delegation, err := trust.SignDelegation(trust.Delegation{
		SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID(t, fixture.authority.peerPublic),
		SubjectPublicKey: publicWire, Capabilities: capabilities,
	}, fixture.now, fixture.now.Add(fixture.maxLifetime), fixture.authority.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := trust.VerifyDelegationCurrent(delegation, config.TrustRoots, fixture.now, config.TrustPolicy)
	if err != nil {
		t.Fatal(err)
	}
	config.Delegations = []trust.VerifiedDelegation{verified}
	return config
}
