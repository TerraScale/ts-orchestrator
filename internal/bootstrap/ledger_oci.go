package bootstrap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const (
	instancePrincipalRequestTimeout = 10 * time.Second
	metadataBaseURLEnv              = "OCI_METADATA_BASE_URL"
	authClientRegionURLEnv          = "OCI_SDK_AUTH_CLIENT_REGION_URL"
	customCertBundleEnv             = "OCI_DEFAULT_CERTS_PATH"
	customClientCertEnv             = "OCI_DEFAULT_CLIENT_CERTS_PATH"
	customClientKeyEnv              = "OCI_DEFAULT_CLIENT_CERTS_PRIVATE_KEY_PATH"
)

type instancePrincipalProviderFactory func(
	common.Region,
	func(common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error),
) (common.ConfigurationProvider, error)

// NewInstancePrincipalLedger creates an Object Storage ledger client pinned to
// one supported TerraScale region. The caller must provision the immutable
// record bucket as private, KMS-encrypted, versioning-disabled storage with a
// locked retention rule, and provision a separate private, KMS-encrypted,
// versioned bucket for the mutable HEAD. This constructor neither creates nor
// verifies buckets; conditional writes alone do not provide WORM protection.
//
// The OCI SDK obtains Instance Principal material synchronously from instance
// metadata. Its HTTP requests are individually bounded, but its retry sleeps
// cannot be canceled through this constructor. With SDK v65.126.0, metadata
// region discovery makes eight attempts and sleeps after each failure, with a
// backoff capped at 30 seconds per failed attempt.
func NewInstancePrincipalLedger(region oci.Region, config LedgerConfig) (*Ledger, error) {
	return newInstancePrincipalLedger(
		region,
		config,
		auth.InstancePrincipalConfigurationForRegionWithCustomClient,
	)
}

// NewHistoricalInstancePrincipalLedger creates a read-only Object Storage
// reader for legacy schema-v2 anchors and their three-domain grant.
func NewHistoricalInstancePrincipalLedger(region oci.Region, config LedgerConfig) (*Ledger, error) {
	return newHistoricalInstancePrincipalLedger(
		region,
		config,
		auth.InstancePrincipalConfigurationForRegionWithCustomClient,
	)
}

// NewInstancePrincipalLedgerWithProvider builds a hardened Object Storage
// ledger client from an already-created OCI provider. The provider must be
// pinned to the OCI region corresponding to the anchor-bound config cell.
func NewInstancePrincipalLedgerWithProvider(region oci.Region, config LedgerConfig, provider common.ConfigurationProvider) (*Ledger, error) {
	return newInstancePrincipalLedgerWithProviderMode(region, config, provider, false)
}

// NewHistoricalInstancePrincipalLedgerWithProvider creates an evidence-only
// reader for legacy schema-v2 anchors and their three-domain grant.
func NewHistoricalInstancePrincipalLedgerWithProvider(region oci.Region, config LedgerConfig,
	provider common.ConfigurationProvider,
) (*Ledger, error) {
	return newInstancePrincipalLedgerWithProviderMode(region, config, provider, true)
}

// NewInstancePrincipalConfigurationProvider creates the hardened OCI
// Instance Principal provider shared by bootstrap observers. It validates the
// anchored ledger scope before SDK metadata access and bounds that access with
// a cloned no-proxy transport that rejects redirects. OCI endpoint, custom CA,
// and client-certificate overrides are rejected; system root certificates are
// used for federation TLS.
func NewInstancePrincipalConfigurationProvider(region oci.Region, config LedgerConfig) (common.ConfigurationProvider, error) {
	return newInstancePrincipalConfigurationProvider(
		region,
		config,
		auth.InstancePrincipalConfigurationForRegionWithCustomClient,
		false,
	)
}

// NewInstancePrincipalSDKHTTPClient returns the hardened HTTP client to assign
// to OCI service clients created from NewInstancePrincipalConfigurationProvider.
func NewInstancePrincipalSDKHTTPClient() (*http.Client, error) {
	return newInstancePrincipalHTTPClient(nil)
}

func newInstancePrincipalLedger(
	region oci.Region,
	config LedgerConfig,
	newProvider instancePrincipalProviderFactory,
) (*Ledger, error) {
	provider, err := newInstancePrincipalConfigurationProvider(region, config, newProvider, false)
	if err != nil {
		return nil, err
	}
	return newInstancePrincipalLedgerWithProviderMode(region, config, provider, false)
}

func newHistoricalInstancePrincipalLedger(
	region oci.Region,
	config LedgerConfig,
	newProvider instancePrincipalProviderFactory,
) (*Ledger, error) {
	provider, err := newInstancePrincipalConfigurationProvider(region, config, newProvider, true)
	if err != nil {
		return nil, err
	}
	return newInstancePrincipalLedgerWithProviderMode(region, config, provider, true)
}

func newInstancePrincipalLedgerWithProviderMode(
	region oci.Region,
	config LedgerConfig,
	provider common.ConfigurationProvider,
	historical bool,
) (*Ledger, error) {
	ociRegion, err := validateInstancePrincipalLedgerScope(region, config, historical)
	if err != nil {
		return nil, err
	}
	if provider == nil {
		return nil, errors.New("bootstrap ledger OCI configuration provider is nil")
	}
	providerRegion, err := provider.Region()
	if err != nil {
		return nil, fmt.Errorf("read bootstrap ledger OCI provider region: %w", err)
	}
	if providerRegion != ociRegion {
		return nil, fmt.Errorf("bootstrap ledger OCI provider region %q does not match anchored region %q", providerRegion, ociRegion)
	}
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("create OCI Object Storage client for bootstrap ledger: %w", err)
	}
	client.SetRegion(ociRegion)
	client.HTTPClient, err = NewInstancePrincipalSDKHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("configure OCI Object Storage HTTP transport: %w", err)
	}
	if historical {
		return NewHistoricalLedger(&client, config)
	}
	return NewLedger(&client, config)
}

func newInstancePrincipalConfigurationProvider(
	region oci.Region,
	config LedgerConfig,
	newProvider instancePrincipalProviderFactory,
	historical bool,
) (common.ConfigurationProvider, error) {
	ociRegion, err := validateInstancePrincipalLedgerScope(region, config, historical)
	if err != nil {
		return nil, err
	}
	if newProvider == nil {
		return nil, errors.New("bootstrap ledger Instance Principal provider factory is nil")
	}

	provider, err := newProvider(common.Region(ociRegion), boundInstancePrincipalDispatcher)
	if err != nil {
		return nil, fmt.Errorf("create OCI Instance Principal provider for bootstrap ledger: %w", err)
	}
	if provider == nil {
		return nil, errors.New("create OCI Instance Principal provider for bootstrap ledger: provider is nil")
	}
	return provider, nil
}

func validateInstancePrincipalLedgerScope(region oci.Region, config LedgerConfig, historical bool) (string, error) {
	ociRegion, err := region.OCIRegion()
	if err != nil {
		return "", err
	}
	if err := validateInstancePrincipalLedgerConfig(config, historical); err != nil {
		return "", err
	}
	if config.Cell != region {
		return "", fmt.Errorf("bootstrap ledger cell %q does not match requested OCI region %q", config.Cell, region)
	}
	if err := validateInstancePrincipalSDKOverrides(); err != nil {
		return "", err
	}
	return ociRegion, nil
}

func validateInstancePrincipalSDKOverrides() error {
	for _, name := range []string{
		metadataBaseURLEnv,
		authClientRegionURLEnv,
		customCertBundleEnv,
		customClientCertEnv,
		customClientKeyEnv,
	} {
		if _, overridden := os.LookupEnv(name); overridden {
			return fmt.Errorf("bootstrap ledger does not allow OCI SDK override %s", name)
		}
	}
	return nil
}

func validateInstancePrincipalLedgerConfig(config LedgerConfig, historical bool) error {
	// Keep this pre-authentication check aligned with NewLedger's config check.
	// NewLedger remains authoritative after the SDK client is constructed.
	if validateLedgerAnchor(config) != nil || !ledgerIDPattern.MatchString(config.Namespace) ||
		!ledgerNamePattern.MatchString(config.Bucket) || !strings.HasPrefix(config.KMSKeyID, "ocid1.key.") ||
		len(config.KMSKeyID) > 255 || strings.ContainsAny(config.KMSKeyID, " \t\r\n") || !validLedgerPrefix(config.Prefix) ||
		!ledgerNamePattern.MatchString(config.HeadBucket) || config.HeadBucket == config.Bucket ||
		!strings.HasPrefix(config.HeadKMSKeyID, "ocid1.key.") || len(config.HeadKMSKeyID) > 255 ||
		strings.ContainsAny(config.HeadKMSKeyID, " \t\r\n") || !ledgerIDPattern.MatchString(config.Environment) ||
		config.TrustPolicy.MaxLifetime <= 0 || config.TrustPolicy.ClockSkew < 0 ||
		len(config.ControllerSlots) == 0 || len(config.ControllerSlots) > 64 || hasDuplicate(config.ControllerSlots) ||
		len(config.TrustRoots) == 0 && len(config.Delegations) == 0 || validateLedgerDelegations(config, historical) != nil {
		return errors.New("bootstrap ledger configuration is invalid before Instance Principal setup")
	}
	for _, slot := range config.ControllerSlots {
		if !controllerSlotRE.MatchString(slot) {
			return errors.New("bootstrap ledger configuration has an invalid anchor-pinned controller slot set")
		}
	}
	return nil
}

func boundInstancePrincipalDispatcher(dispatcher common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error) {
	client, ok := dispatcher.(*http.Client)
	if !ok || client == nil {
		return nil, errors.New("OCI Instance Principal SDK supplied an unsupported HTTP dispatcher")
	}
	return newInstancePrincipalHTTPClient(client)
}

func newInstancePrincipalHTTPClient(source *http.Client) (*http.Client, error) {
	var client http.Client
	if source != nil {
		client = *source
	}
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("OCI SDK default HTTP transport has an unsupported type")
	}
	var transport http.RoundTripper = defaultTransport.Clone()
	if source != nil && source.Transport != nil {
		switch provided := source.Transport.(type) {
		case *http.Transport:
			transport = provided.Clone()
		case *common.OciHTTPTransportWrapper:
			if provided == nil || provided.TLSConfigProvider == nil {
				return nil, errors.New("OCI SDK supplied an incomplete HTTP transport wrapper")
			}
			transport = &common.OciHTTPTransportWrapper{
				RefreshRate:       provided.RefreshRate,
				TLSConfigProvider: provided.TLSConfigProvider,
				TransportTemplate: noProxyOCITransportTemplate(provided.TransportTemplate),
			}
		default:
			return nil, errors.New("OCI SDK supplied an unsupported HTTP transport")
		}
	}
	if pinned, ok := transport.(*http.Transport); ok {
		pinned.Proxy = nil
	}
	client.Transport = transport
	client.Timeout = instancePrincipalRequestTimeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("OCI Instance Principal HTTP redirects are not permitted")
	}
	return &client, nil
}

func noProxyOCITransportTemplate(template common.TransportTemplateProvider) common.TransportTemplateProvider {
	return func(tlsConfig *tls.Config) (http.RoundTripper, error) {
		provided, err := template.NewOrDefault(tlsConfig)
		if err != nil {
			return nil, err
		}
		transport, ok := provided.(*http.Transport)
		if !ok || transport == nil {
			return nil, errors.New("OCI SDK supplied an unsupported HTTP transport template")
		}
		pinned := transport.Clone()
		pinned.Proxy = nil
		return pinned, nil
	}
}
