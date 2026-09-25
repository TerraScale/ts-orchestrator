package bootstrap

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const instancePrincipalRequestTimeout = 10 * time.Second

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
// backoff capped at roughly 31 seconds per failed attempt.
func NewInstancePrincipalLedger(region oci.Region, config LedgerConfig) (*Ledger, error) {
	return newInstancePrincipalLedger(
		region,
		config,
		auth.InstancePrincipalConfigurationForRegionWithCustomClient,
	)
}

func newInstancePrincipalLedger(
	region oci.Region,
	config LedgerConfig,
	newProvider instancePrincipalProviderFactory,
) (*Ledger, error) {
	ociRegion, err := region.OCIRegion()
	if err != nil {
		return nil, err
	}
	if err := validateInstancePrincipalLedgerConfig(config); err != nil {
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
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("create OCI Object Storage client for bootstrap ledger: %w", err)
	}
	client.SetRegion(ociRegion)
	return NewLedger(&client, config)
}

func validateInstancePrincipalLedgerConfig(config LedgerConfig) error {
	// Keep this pre-authentication check aligned with NewLedger's config check.
	// NewLedger remains authoritative after the SDK client is constructed.
	if !ledgerIDPattern.MatchString(config.Namespace) ||
		!ledgerNamePattern.MatchString(config.Bucket) || !strings.HasPrefix(config.KMSKeyID, "ocid1.key.") ||
		len(config.KMSKeyID) > 255 || strings.ContainsAny(config.KMSKeyID, " \t\r\n") || !validLedgerPrefix(config.Prefix) ||
		!ledgerNamePattern.MatchString(config.HeadBucket) || config.HeadBucket == config.Bucket ||
		!strings.HasPrefix(config.HeadKMSKeyID, "ocid1.key.") || len(config.HeadKMSKeyID) > 255 ||
		strings.ContainsAny(config.HeadKMSKeyID, " \t\r\n") || !ledgerIDPattern.MatchString(config.Environment) ||
		config.TrustPolicy.MaxLifetime <= 0 || config.TrustPolicy.ClockSkew < 0 ||
		len(config.TrustRoots) == 0 && len(config.Delegations) == 0 {
		return errors.New("bootstrap ledger configuration is invalid before Instance Principal setup")
	}
	return nil
}

func boundInstancePrincipalDispatcher(dispatcher common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error) {
	client, ok := dispatcher.(*http.Client)
	if !ok || client == nil {
		return nil, errors.New("OCI Instance Principal SDK supplied an unsupported HTTP dispatcher")
	}
	client.Timeout = instancePrincipalRequestTimeout
	return client, nil
}
