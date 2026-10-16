package bootstrapstart

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// WithDerivedStartupAuthority supplies genuine same-grant source provenance;
// AdmitInitial still performs every independent ledger, host and floor check.
func (gate Gate) WithDerivedStartupAuthority(authority bootstrap.DerivedStartupAuthority) (Gate, error) {
	manifest := authority.Manifest()
	if !authority.IsVerified() || authority.AnchorDigest() != digest(gate.AnchorWire) || manifest.ControllerConfigSHA256 != gate.LoadedControllerConfigSHA256 || manifest.DeploymentID != gate.Expected.DeploymentID || manifest.Cell != gate.Expected.Cell || manifest.Environment != gate.Expected.Environment {
		return Gate{}, ErrAdmission
	}
	gate.derivedStartup = new(authority)
	return gate, nil
}

// NewDerivedOCIAdmissionClients uses the sealed source capability for new
// registrations while retaining all original storage and instance boundaries.
func NewDerivedOCIAdmissionClients(ctx context.Context, authority bootstrap.DerivedStartupAuthority, roots trust.Keyring) (InstanceObserver, LedgerOpener, *bootstrap.Vault, error) {
	if err := authority.VerifyCurrent(ctx, time.Now()); err != nil {
		return nil, nil, nil, err
	}
	config, err := authority.LedgerConfig(roots)
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
	return observer, derivedLedgerOpener{authority: authority}, vault, nil
}

type derivedLedgerOpener struct {
	authority bootstrap.DerivedStartupAuthority
}

func (opener derivedLedgerOpener) OpenCurrentLedger(ctx context.Context, anchor bootstrap.VerifiedBootstrapAnchor, roots trust.Keyring) (AdmissionLedger, error) {
	if opener.authority.AnchorDigest() != anchor.Digest() {
		return nil, ErrLedgerGrant
	}
	ledger, err := opener.authority.OpenLedger(ctx, roots)
	if err != nil {
		return nil, err
	}
	return admissionLedger{ledger: ledger}, nil
}
