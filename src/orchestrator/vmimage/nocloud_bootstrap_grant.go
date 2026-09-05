package vmimage

import (
	"bytes"
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"

	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
)

const BootstrapGrantPath = "/etc/terrascale/ts-node-bootstrap/grant.json"
const BootstrapPublicKeyPath = "/etc/terrascale/ts-node-bootstrap/authority.pem"

// TSNodeInitialGrant contains only the provisioning owner's public admission.
// Its signing key remains outside the guest and is separate from runtime trust.
type TSNodeInitialGrant struct{ PublicKeyPEM, SignedGrant []byte }

func canonicalInitialGrant(input TSNodeBootstrap) ([]NoCloudRootFile, error) {
	if input.InitialGrant == nil || len(input.InitialGrant.PublicKeyPEM) > 1024 || len(input.InitialGrant.SignedGrant) > 128<<10 {
		return nil, errors.New("vmimage: initial host grant and public owner pin are required")
	}
	grant, err := hostagent.VerifyBootstrapGrant(input.Config.NodeID, input.InitialGrant.PublicKeyPEM, input.InitialGrant.SignedGrant)
	if err != nil {
		return nil, errors.New("vmimage: initial host grant failed owner verification")
	}
	canonical, err := hostmanifest.CanonicalHostManifestJSON(grant.Manifest)
	if err != nil || !bytes.Equal(canonical, input.DesiredHostManifest) {
		return nil, errors.New("vmimage: initial grant must admit the complete desired host manifest")
	}
	for _, trust := range input.Config.CommandTrustKeys {
		if bytes.Equal(bytes.TrimSpace(trust.PublicKeyPEM), bytes.TrimSpace(input.InitialGrant.PublicKeyPEM)) {
			return nil, errors.New("vmimage: bootstrap owner must be independent of regional command identities")
		}
	}
	return []NoCloudRootFile{
		{Path: BootstrapGrantPath, Mode: 0400, Content: append([]byte(nil), input.InitialGrant.SignedGrant...)},
		{Path: BootstrapPublicKeyPath, Mode: 0400, Content: append([]byte(nil), input.InitialGrant.PublicKeyPEM...)},
	}, nil
}
