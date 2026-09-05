package hostagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// BootstrapGrant admits every setting of the initial host manifest.
type BootstrapGrant struct {
	Version   int                       `json:"version"`
	GrantID   string                    `json:"grantId"`
	NodeID    string                    `json:"nodeId"`
	Manifest  hostmanifest.HostManifest `json:"manifest"`
	IssuedAt  time.Time                 `json:"issuedAt"`
	ExpiresAt time.Time                 `json:"expiresAt"`
}
type BootstrapCommand = nodebootstrap.BootstrapCommand

// BootstrapAuthority composes independently signed initial host admission with
// real regional authority. The initial grant carries no runtime epoch or lease.
type BootstrapAuthority struct {
	initialProof           *initialgrant.Proof
	runtime                nodeauthority.CommandAuthorizer
	verifier               *nodebootstrap.BootstrapAuthority
	grant                  BootstrapGrant
	digest, manifestDigest string
}

func rawBootstrapGrant(grant BootstrapGrant) (nodebootstrap.BootstrapGrant, error) {
	manifest, err := hostmanifest.CanonicalHostManifestJSON(grant.Manifest)
	if err != nil {
		return nodebootstrap.BootstrapGrant{}, err
	}
	return nodebootstrap.BootstrapGrant{Version: grant.Version, GrantID: grant.GrantID, NodeID: grant.NodeID, Manifest: manifest, IssuedAt: grant.IssuedAt, ExpiresAt: grant.ExpiresAt}, nil
}
func SignBootstrapGrant(signer *security.CommandSignatureSigner, grant BootstrapGrant) ([]byte, error) {
	raw, err := rawBootstrapGrant(grant)
	if err != nil {
		return nil, err
	}
	return nodebootstrap.SignBootstrapGrant(signer, raw)
}
func BootstrapCommands(grant BootstrapGrant) ([]BootstrapCommand, error) {
	raw, err := rawBootstrapGrant(grant)
	if err != nil {
		return nil, err
	}
	return nodebootstrap.BootstrapCommands(raw)
}
func SignBootstrapCommand(signer *security.CommandSignatureSigner, grant []byte, subject string, command any, issued, expires time.Time) ([]byte, error) {
	return nodebootstrap.SignBootstrapCommand(signer, grant, subject, command, issued, expires)
}
func VerifyBootstrapGrant(node string, publicPEM, signedGrant []byte) (BootstrapGrant, error) {
	authority, err := parseBootstrapAuthority(node, publicPEM, signedGrant)
	if err != nil {
		return BootstrapGrant{}, err
	}
	return authority.grant, nil
}
func NewBootstrapAuthority(runtime nodeauthority.CommandAuthorizer, node string, publicPEM, signedGrant []byte) (*BootstrapAuthority, error) {
	if runtime == nil {
		return nil, errors.New("hostagent: runtime command verifier is required")
	}
	authority, err := parseBootstrapAuthority(node, publicPEM, signedGrant)
	if err != nil {
		return nil, err
	}
	authority.runtime = runtime
	return authority, nil
}
func parseBootstrapAuthority(node string, publicPEM, signedGrant []byte) (*BootstrapAuthority, error) {
	verifier, err := nodebootstrap.NewBootstrapAuthority(node, publicPEM, signedGrant)
	if err != nil {
		return nil, err
	}
	raw := verifier.Grant()
	manifest, err := hostmanifest.ParseHostManifest(raw.Manifest)
	if err != nil {
		return nil, err
	}
	canonical, err := hostmanifest.CanonicalHostManifestJSON(manifest)
	if err != nil || !bytes.Equal(canonical, raw.Manifest) {
		return nil, errors.New("hostagent: bootstrap manifest is not canonical")
	}
	digest, err := hostmanifest.HostManifestSha256(manifest)
	if err != nil {
		return nil, err
	}
	proof, err := initialgrant.VerifyProof(node, publicPEM, signedGrant)
	if err != nil {
		return nil, err
	}
	grant := BootstrapGrant{Version: raw.Version, GrantID: raw.GrantID, NodeID: raw.NodeID, Manifest: manifest, IssuedAt: raw.IssuedAt, ExpiresAt: raw.ExpiresAt}
	return &BootstrapAuthority{initialProof: proof, verifier: verifier, grant: grant, digest: verifier.Digest(), manifestDigest: digest}, nil
}
func (a *BootstrapAuthority) Authorize(ctx context.Context, subject string, wire []byte) (nodeauthority.CommandAuthorization, error) {
	if len(wire) > protocol.MaximumCommandEnvelopeBytes {
		return nodeauthority.CommandAuthorization{}, errors.New("hostagent: authority envelope exceeds bound")
	}
	var family map[string]json.RawMessage
	if json.Unmarshal(wire, &family) != nil {
		return nodeauthority.CommandAuthorization{}, errors.New("hostagent: invalid authority envelope")
	}
	// These wire families are disjoint; failed initial verification never falls
	// through to regional verification.
	if _, regional := family["protocolVersion"]; regional {
		return a.runtime.Authorize(ctx, subject, wire)
	}
	return a.verifier.Authorize(ctx, subject, wire)
}
