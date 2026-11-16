package bootstrapstart

import (
	"errors"
	"fmt"
	"slices"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
)

var ErrLedgerGrant = errors.New("baked anchor ledger grant is unavailable")

// InstancePrincipalLedgerOpener builds only the exact anchor-pinned Object
// Storage reader. The baked public roots retain authority to verify the
// offline-signed seed records; one anchor-verified delegation authorizes the
// managed slot HEAD, intent, and result records.
type InstancePrincipalLedgerOpener struct {
	provider common.ConfigurationProvider
}

// currentLedgerConfig derives Object Storage scope only from a root-verified,
// currently valid baked anchor and its single verified ledger grant.
func currentLedgerConfig(verified bootstrap.VerifiedBootstrapAnchor, roots trust.Keyring) (bootstrap.LedgerConfig, error) {
	if !verified.IsVerified() || len(roots) == 0 {
		return bootstrap.LedgerConfig{}, ErrLedgerGrant
	}
	grant, err := verified.LedgerDelegation()
	if err != nil {
		return bootstrap.LedgerConfig{}, fmt.Errorf("read current anchor ledger grant: %w", err)
	}
	config := ledgerConfigFromAnchor(verified.Anchor(), roots, grant)
	config.AnchorExpiresAt = verified.ExpiresAt()
	return config, nil
}

func newOCIAdmissionProvider(config bootstrap.LedgerConfig) (common.ConfigurationProvider, error) {
	provider, err := bootstrap.NewInstancePrincipalConfigurationProvider(config.Cell, config)
	if err != nil {
		return nil, err
	}
	return provider, nil
}

// ledgerConfigFromAnchor is called only with a typed verified grant obtained
// from the current or historical anchor accessor. It carries no private root
// signer or unconstrained delegation list.
func ledgerConfigFromAnchor(anchor bootstrap.BootstrapAnchor, roots trust.Keyring,
	grant trust.VerifiedDelegation,
) bootstrap.LedgerConfig {
	domain := anchor.StorageDomain
	return bootstrap.LedgerConfig{
		DeploymentID: anchor.DeploymentID, Environment: anchor.Environment,
		ClusterID: anchor.ClusterID, Cell: anchor.Cell,
		InitialRegionIntentGeneration: anchor.InitialRegionIntentGeneration,
		InitialRegionIntentSHA256:     anchor.InitialRegionIntentSHA256,
		Namespace:                     domain.Namespace, Bucket: domain.LedgerBucket, KMSKeyID: domain.LedgerKMSKeyOCID,
		HeadBucket: domain.HeadBucket, HeadKMSKeyID: domain.HeadKMSKeyOCID, Prefix: domain.Prefix,
		ControllerSlots: slices.Clone(anchor.ControllerSlots),
		TrustRoots:      roots, Delegations: []trust.VerifiedDelegation{grant},
		TrustPolicy: bootstrap.ManifestTrustPolicy(),
	}
}
