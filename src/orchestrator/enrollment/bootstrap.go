package enrollment

import (
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// PublicBootstrap is the public portion of an enrollment. Manifest and Grant
// are safe to place in cloud-init; private identity material is fetched by the
// host agent from the Vault references carried by the manifest configuration.
type PublicBootstrap struct {
	Manifest []byte
	Grant    []byte
}

func SignPublicBootstrap(signer *security.CommandSignatureSigner, record Record, manifest hostmanifest.HostManifest, now time.Time) (PublicBootstrap, error) {
	if signer == nil || record.MemberID == "" || record.OperationID == "" || record.IssuedAt.IsZero() || !record.ExpiresAt.After(record.IssuedAt) {
		return PublicBootstrap{}, ErrInvalid
	}
	canonical, err := hostmanifest.CanonicalHostManifestJSON(manifest)
	if err != nil {
		return PublicBootstrap{}, err
	}
	grant, err := nodebootstrap.SignBootstrapGrant(signer, nodebootstrap.BootstrapGrant{Version: 1, GrantID: record.OperationID, NodeID: record.MemberID, Manifest: canonical, IssuedAt: now, ExpiresAt: record.ExpiresAt})
	if err != nil {
		return PublicBootstrap{}, err
	}
	return PublicBootstrap{Manifest: canonical, Grant: grant}, nil
}
