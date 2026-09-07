package keyrotation

import (
	"net/url"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

// OCIIdentityIssuerFileConfig contains references only. The authenticated
// provider and live lease guard are supplied when the runtime is activated.
type OCIIdentityIssuerFileConfig struct {
	Region                 string                 `json:"region"`
	CompartmentID          string                 `json:"compartment_id"`
	CertificateAuthorityID string                 `json:"certificate_authority_id"`
	Principals             []OCIIdentityPrincipal `json:"principals"`
}

// OCICapabilityVaultFileConfig contains OCI resource identifiers, never keys.
type OCICapabilityVaultFileConfig struct {
	Region        string `json:"region"`
	CompartmentID string `json:"compartment_id"`
	VaultID       string `json:"vault_id"`
	KeyID         string `json:"key_id"`
}

func validAuthorityOCID(value, resource string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 5 || parts[0] != "ocid1" || parts[1] != resource || parts[2] != "oc1" || parts[4] == "" || len(value) > 512 {
		return false
	}
	for _, part := range []string{parts[3], parts[4]} {
		for _, r := range part {
			if r < 'a' || r > 'z' {
				if r < '0' || r > '9' {
					if r != '-' && r != '_' {
						return false
					}
				}
			}
		}
	}
	return true
}
func (c OCIIdentityIssuerFileConfig) Validate() error {
	if !provider.ValidOCIRegion(c.Region) || !validAuthorityOCID(c.CompartmentID, "compartment") || !validAuthorityOCID(c.CertificateAuthorityID, "certificateauthority") || len(c.Principals) == 0 || len(c.Principals) > 1024 {
		return errOCIIdentity
	}
	seen := map[string]bool{}
	uris := map[string]bool{}
	for _, p := range c.Principals {
		u, e := url.Parse(p.SPIFFEID)
		if !validOperationKey(p.ID) || len(p.ID) > 128 || seen[p.ID] || uris[p.SPIFFEID] || e != nil || u.Scheme != "spiffe" || u.Host == "" || u.Port() != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path == "" || u.RawPath != "" {
			return errOCIIdentity
		}
		seen[p.ID] = true
		uris[p.SPIFFEID] = true
	}
	return nil
}
func (c OCICapabilityVaultFileConfig) Validate() error {
	if !provider.ValidOCIRegion(c.Region) || !validAuthorityOCID(c.CompartmentID, "compartment") || !validAuthorityOCID(c.VaultID, "vault") || !validAuthorityOCID(c.KeyID, "key") {
		return capabilityError()
	}
	return nil
}

// OCIOriginProofVaultFileConfig binds the independent origin-proof owner to OCI
// resources. Sharing a wrapping vault does not share the role's secret material.
type OCIOriginProofVaultFileConfig OCICapabilityVaultFileConfig

func (c OCIOriginProofVaultFileConfig) Validate() error {
	return OCICapabilityVaultFileConfig(c).Validate()
}
