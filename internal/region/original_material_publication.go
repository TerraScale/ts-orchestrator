package region

import (
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
)

// OriginalMaterialPublicationScope is public DATA, never startup authority.
type OriginalMaterialPublicationScope struct {
	Target                 bootstrapmaterial.VaultTarget `json:"target"`
	PolicyID               string                        `json:"policyId"`
	PolicyETag             string                        `json:"policyEtag"`
	PolicySHA256           string                        `json:"policySha256"`
	ReadbackSHA256         string                        `json:"readbackSha256"`
	SecretNames            [8]string                     `json:"secretNames,omitzero"`
	OriginalLinkObject     string                        `json:"originalLinkObject,omitempty"`
	OriginalLinkSecretName string                        `json:"originalLinkSecretName,omitempty"`
	OriginalLinkEscrow     bootstrapmaterial.VaultTarget `json:"originalLinkEscrow,omitzero"`
}
