package bootstrapstart

import (
	"context"
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

func (opener InstancePrincipalLedgerOpener) OpenCurrentLedger(ctx context.Context,
	verified bootstrap.VerifiedBootstrapAnchor, roots trust.Keyring,
) (AdmissionLedger, error) {
	config, err := currentLedgerConfig(verified, roots)
	if err != nil {
		return nil, err
	}
	return openInstancePrincipalLedger(ctx, config, opener.provider)
}

// OpenSelectedFounderLedger gives the admitted seed the launch-capable ledger
// for the currently selected anchor. A historical baked anchor cannot grant
// writes after selection changes.
func OpenSelectedFounderLedger(ctx context.Context, selected CurrentFounderAuthority,
	roots trust.Keyring,
) (*bootstrap.Ledger, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if selected.Derived != nil {
		return selected.Derived.SeedAuthority().OpenLedger(ctx, roots)
	}
	config, err := currentLedgerConfig(selected.Anchor, roots)
	if err != nil || selected.Plan == nil || !selected.Plan.IsVerified() ||
		selected.Plan.Plan().AnchorSHA256 != selected.Anchor.Digest() {
		return nil, ErrLedgerGrant
	}
	provider, err := newOCIAdmissionProvider(config)
	if err != nil {
		return nil, err
	}
	ledger, err := bootstrap.NewInstancePrincipalLedgerWithProvider(config.Cell, config, provider)
	if err != nil {
		return nil, fmt.Errorf("open selected founder ledger: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return ledger, nil
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

func (opener InstancePrincipalLedgerOpener) OpenHistoricalLedger(ctx context.Context,
	verified bootstrap.HistoricalBootstrapAnchor, roots trust.Keyring,
) (AdmissionLedger, error) {
	config, err := historicalLedgerConfig(verified, roots)
	if err != nil {
		return nil, err
	}
	return openHistoricalInstancePrincipalLedger(ctx, config, opener.provider)
}

// historicalLedgerConfig is only for historical ReadSlot evidence.
func historicalLedgerConfig(verified bootstrap.HistoricalBootstrapAnchor, roots trust.Keyring) (bootstrap.LedgerConfig, error) {
	if !verified.IsVerified() || len(roots) == 0 {
		return bootstrap.LedgerConfig{}, ErrLedgerGrant
	}
	grant, err := verified.HistoricalLedgerDelegation()
	if err != nil {
		return bootstrap.LedgerConfig{}, fmt.Errorf("read historical anchor ledger evidence: %w", err)
	}
	return ledgerConfigFromAnchor(verified.Anchor(), roots, grant), nil
}

// NewCurrentOCIAdmissionClients shares one hardened instance-principal
// provider across the current anchor-scoped ledger, instance observer, and
// Vault reader. The IMDS descriptor supplies no endpoint or account scope.
func NewCurrentOCIAdmissionClients(verified bootstrap.VerifiedBootstrapAnchor, roots trust.Keyring) (
	InstanceObserver, LedgerOpener, *bootstrap.Vault, error,
) {
	config, err := currentLedgerConfig(verified, roots)
	if err != nil {
		return nil, nil, nil, err
	}
	provider, err := newOCIAdmissionProvider(config)
	if err != nil {
		return nil, nil, nil, err
	}
	observer, err := NewOCIInstanceObserver(config.Cell, provider)
	if err != nil {
		return nil, nil, nil, err
	}
	vault, err := bootstrap.NewInstancePrincipalVault(config.Cell, provider)
	if err != nil {
		return nil, nil, nil, err
	}
	return observer, InstancePrincipalLedgerOpener{provider: provider}, vault, nil
}

// NewHistoricalOCIAdmissionClients is only for exact accepted-install restart
// comparison; its historical grant cannot authorize current effects or Vault.
func NewHistoricalOCIAdmissionClients(verified bootstrap.HistoricalBootstrapAnchor, roots trust.Keyring) (
	InstanceObserver, LedgerOpener, error,
) {
	config, err := historicalLedgerConfig(verified, roots)
	if err != nil {
		return nil, nil, err
	}
	provider, err := newOCIAdmissionProvider(config)
	if err != nil {
		return nil, nil, err
	}
	observer, err := NewOCIInstanceObserver(config.Cell, provider)
	if err != nil {
		return nil, nil, err
	}
	return observer, InstancePrincipalLedgerOpener{provider: provider}, nil
}

func newOCIAdmissionProvider(config bootstrap.LedgerConfig) (common.ConfigurationProvider, error) {
	provider, err := bootstrap.NewInstancePrincipalConfigurationProvider(config.Cell, config)
	if err != nil {
		return nil, err
	}
	return provider, nil
}

func openInstancePrincipalLedger(ctx context.Context, config bootstrap.LedgerConfig, provider common.ConfigurationProvider) (AdmissionLedger, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var ledger *bootstrap.Ledger
	var err error
	if provider == nil {
		ledger, err = bootstrap.NewInstancePrincipalLedger(config.Cell, config)
	} else {
		ledger, err = bootstrap.NewInstancePrincipalLedgerWithProvider(config.Cell, config, provider)
	}
	if err != nil {
		return nil, fmt.Errorf("open anchor-scoped OCI bootstrap ledger: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return admissionLedger{ledger: ledger}, nil
}

func openHistoricalInstancePrincipalLedger(ctx context.Context, config bootstrap.LedgerConfig,
	provider common.ConfigurationProvider,
) (AdmissionLedger, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var ledger *bootstrap.Ledger
	var err error
	if provider == nil {
		ledger, err = bootstrap.NewHistoricalInstancePrincipalLedger(config.Cell, config)
	} else {
		ledger, err = bootstrap.NewHistoricalInstancePrincipalLedgerWithProvider(config.Cell, config, provider)
	}
	if err != nil {
		return nil, fmt.Errorf("open historical anchor-scoped OCI bootstrap ledger: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return admissionLedger{ledger: ledger}, nil
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

// admissionLedger exposes only slot reads and the one object admission
// writes: its public accepted-install marker.
type admissionLedger struct{ ledger *bootstrap.Ledger }

func (reader admissionLedger) ReadSlot(ctx context.Context, scope bootstrap.BootstrapScope) (bootstrap.SlotState, error) {
	return reader.ledger.ReadSlot(ctx, scope)
}

func (reader admissionLedger) PublishAcceptedInstall(ctx context.Context, scope bootstrap.BootstrapScope,
	marker []byte,
) error {
	return reader.ledger.PublishAcceptedInstall(ctx, scope, marker)
}

var _ LedgerOpener = InstancePrincipalLedgerOpener{}
var _ AdmissionLedger = admissionLedger{}
