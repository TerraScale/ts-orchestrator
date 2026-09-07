package enrollment

import (
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"time"
)

type PublicBootstrap struct {
	ArchitectureFiles map[string]map[string][]byte `json:"architecture_files"`
	Manifest          []byte                       `json:"manifest"`
	Grant             []byte                       `json:"grant"`
	Files             map[string][]byte            `json:"files"`
	Seed              hostsecrets.Seed             `json:"seed"`
	PublicKeys        map[string]string            `json:"public_keys"`
}

func SignPublicBootstrap(signer *security.CommandSignatureSigner, r Record, manifest hostmanifest.HostManifest, _ time.Time) (PublicBootstrap, error) {
	if signer == nil || r.NodeID == "" || r.OperationID == "" || r.IssuedAt.IsZero() || !r.ExpiresAt.After(r.IssuedAt) {
		return PublicBootstrap{}, ErrInvalid
	}
	canonical, e := hostmanifest.CanonicalHostManifestJSON(manifest)
	if e != nil {
		return PublicBootstrap{}, e
	}
	grant, e := nodebootstrap.SignBootstrapGrant(signer, nodebootstrap.BootstrapGrant{Version: 1, GrantID: r.OperationID, NodeID: r.NodeID, Manifest: canonical, IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt})
	if e != nil {
		return PublicBootstrap{}, e
	}
	return PublicBootstrap{Manifest: canonical, Grant: grant}, nil
}
