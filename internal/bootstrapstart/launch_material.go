package bootstrapstart

import (
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// Deployment-specific public material arrives in OCI launch metadata. The
// image carries only the trust roots that authenticate it, so one qualified
// image serves every deployment and bootstrap attempt.
const (
	IdentityMetadataKey                   = "terrascale-bootstrap-identity-v1"
	AnchorMetadataKey                     = "terrascale-bootstrap-anchor-v1"
	ManagedHostImageReceiptMetadataKey    = "terrascale-managed-host-image-receipt-v1"
	ManagedHostImageDelegationMetadataKey = "terrascale-managed-host-image-delegation-v1"
	HostEnrollmentFilename                = "host-enrollment-public.json"
	identityFilename                      = "identity.json"
	anchorFilename                        = "anchor.json"
	// OperatorSSHKeyMetadataKey is OCI's standard launch metadata field.
	// cloud-init authorizes it for the image's default user, so every server
	// accepts the operator's OpenSSH key.
	OperatorSSHKeyMetadataKey = "ssh_authorized_keys"
	operatorSSHKeyFilename    = "operator-ssh-key.pub"
	maxOperatorSSHKey         = 512
)

var (
	ErrLaunchMaterial = errors.New("launch bootstrap material is invalid")
)

// LaunchMaterial is the exact public deployment material a controller
// receives at launch and forwards to the instances it launches.
type LaunchMaterial struct {
	Identity                   []byte
	Anchor                     []byte
	HostEnrollment             []byte
	OperatorSSHKey             []byte
	ManagedHostImageReceipt    []byte
	ManagedHostImageDelegation []byte
	OriginalOrigin             []byte
}

// ControllerMetadata returns the launch metadata entries a controller needs.
func (material LaunchMaterial) ControllerMetadata() map[string]string {
	metadata := map[string]string{
		IdentityMetadataKey:                   string(material.Identity),
		AnchorMetadataKey:                     string(material.Anchor),
		hostboot.EnrollmentMetadataKey:        string(material.HostEnrollment),
		OperatorSSHKeyMetadataKey:             string(material.OperatorSSHKey),
		ManagedHostImageReceiptMetadataKey:    string(material.ManagedHostImageReceipt),
		ManagedHostImageDelegationMetadataKey: string(material.ManagedHostImageDelegation),
	}
	if len(material.OriginalOrigin) != 0 {
		// Callers authenticate this companion before launching; transport
		// only the bounded locator, never the large origin grant.
		if origin, err := parseOriginalStartupOrigin(material.OriginalOrigin); err == nil {
			wire, err := protocol.EncodeJSON(origin.locator())
			if err == nil {
				metadata[OriginalStartupMetadataKey] = string(wire)
			}
		}
		delete(metadata, OperatorSSHKeyMetadataKey)
	}
	return metadata
}

// HostMetadata returns the launch metadata entries a managed host needs.
func (material LaunchMaterial) HostMetadata() map[string]string {
	metadata := map[string]string{hostboot.EnrollmentMetadataKey: string(material.HostEnrollment)}
	if len(material.OriginalOrigin) == 0 {
		metadata[OperatorSSHKeyMetadataKey] = string(material.OperatorSSHKey)
	}
	return metadata
}
