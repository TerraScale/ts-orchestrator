// Package hostbootstrap executes the owner's finite signed initial host grant
// before the embedded control broker is available.
package hostbootstrap

import (
	"context"
	"errors"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
)

type LocalBootstrapConfig struct {
	NodeID                    string
	PublicKeyPEM, SignedGrant []byte
	Lifecycle                 *hostagent.Lifecycle
	ManifestPath, InstallRoot string
	Timeout                   time.Duration
	CredentialHandoff         func(context.Context, string, string) error
}

func RunLocalBootstrap(ctx context.Context, config LocalBootstrapConfig) error {
	if ctx == nil || config.Timeout <= 0 || config.Timeout > 10*time.Minute {
		return errors.New("hostbootstrap: invalid execution deadline")
	}
	ctx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	if handled, err := hostagent.ResumeLocalCandidatePreparation(ctx, config.Lifecycle, config.NodeID, config.PublicKeyPEM, config.SignedGrant, config.ManifestPath); handled || err != nil {
		return err
	}
	session, err := hostagent.OpenLocalBootstrap(ctx, config.Lifecycle, config.NodeID, config.PublicKeyPEM, config.SignedGrant, config.ManifestPath, config.CredentialHandoff)
	if err != nil {
		return err
	}
	defer session.Close()
	if session.Retired {
		return nil
	}
	ctx, expiryCancel := context.WithDeadline(ctx, session.ExpiresAt)
	defer expiryCancel()
	for index, spec := range session.Manifest.Components {
		current, err := hostagent.CurrentVersion(config.InstallRoot, spec.Name)
		if err != nil {
			return err
		}
		if current == spec.Version {
			continue
		}
		if err = session.Execute(ctx, index*2); err != nil {
			return err
		}
		if err = session.Execute(ctx, index*2+1); err != nil {
			return err
		}
	}
	if err = session.Execute(ctx, len(session.Manifest.Components)*2); err != nil {
		return err
	}
	return nodebootstrap.WaitInitialServices(ctx, session.Ready)
}
