package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"slices"
)

// ControllerConfigDerivationV1 identifies the house renderer authorized by the
// signed footprint. It is fixed in code, never a runtime configuration switch.
const ControllerConfigDerivationV1 = "terrascale.bootstrap.controller.v1"

// StartupTemplate is the public startup recipe carried by the same signed
// foundation grant that authorizes regional material generation. Dynamic Vault
// references and rendered configuration are bound by the source CAS before use.
type StartupTemplate struct {
	SeedSlot                   string                   `json:"seedSlot"`
	Profiles                   []LaunchProfile          `json:"profiles"`
	ImageOCID                  string                   `json:"imageOcid"`
	ImageArchitecture          string                   `json:"imageArchitecture"`
	ReleaseImageReceiptWire    []byte                   `json:"releaseImageReceiptWire"`
	ReleaseDelegationWire      []byte                   `json:"releaseDelegationWire"`
	TrustedSigners             jsontext.Value           `json:"trustedSigners"`
	ControllerConfigDerivation string                   `json:"controllerConfigDerivation"`
	ControllerFiles            []ControllerConfigFile   `json:"controllerFiles"`
	ManagedMaterial            *ManagedMaterialDomain   `json:"managedMaterial,omitempty"`
	FounderResources           *StartupFounderResources `json:"founderResources,omitempty"`
}

func (template StartupTemplate) Clone() StartupTemplate {
	template.ControllerFiles = slices.Clone(template.ControllerFiles)
	for index := range template.ControllerFiles {
		template.ControllerFiles[index].Bytes = bytes.Clone(template.ControllerFiles[index].Bytes)
	}
	if template.ManagedMaterial != nil {
		template.ManagedMaterial = new(*template.ManagedMaterial)
	}
	if template.FounderResources != nil {
		template.FounderResources = new(template.FounderResources.Clone())
	}
	template.Profiles = slices.Clone(template.Profiles)
	for index := range template.Profiles {
		template.Profiles[index] = cloneProfile(template.Profiles[index])
	}
	template.ReleaseImageReceiptWire = bytes.Clone(template.ReleaseImageReceiptWire)
	template.ReleaseDelegationWire = bytes.Clone(template.ReleaseDelegationWire)
	template.TrustedSigners = bytes.Clone(template.TrustedSigners)
	return template
}

func (template StartupTemplate) Validate() error {
	if !controllerSlotRE.MatchString(template.SeedSlot) || len(template.Profiles) == 0 || len(template.Profiles) > MaxBootstrapAnchorSlots ||
		!isOCID(template.ImageOCID, "image") || template.ImageArchitecture != "linux-amd64" && template.ImageArchitecture != "linux-arm64" ||
		len(template.ReleaseImageReceiptWire) == 0 || len(template.ReleaseImageReceiptWire) > MaxManifestBytes ||
		len(template.ReleaseDelegationWire) == 0 || len(template.ReleaseDelegationWire) > MaxManifestBytes ||
		template.ControllerConfigDerivation != ControllerConfigDerivationV1 {
		return ErrManifestInvalid
	}
	if len(template.ControllerFiles) != len(ControllerConfigFileNames) || template.ManagedMaterial != nil && template.ManagedMaterial.Validate() != nil {
		return ErrManifestInvalid
	}
	for index, file := range template.ControllerFiles {
		sum := sha256.Sum256(file.Bytes)
		var value map[string]any
		if file.Name != ControllerConfigFileNames[index] || len(file.Bytes) == 0 || len(file.Bytes) > MaxControllerSidecarBytes || file.SHA256 != hex.EncodeToString(sum[:]) || json.Unmarshal(file.Bytes, &value) != nil || value == nil {
			return ErrManifestInvalid
		}
	}
	seen := make(map[string]bool, len(template.Profiles))
	for _, profile := range template.Profiles {
		if profile.validate() != nil || seen[profile.Slot] {
			return ErrManifestInvalid
		}
		seen[profile.Slot] = true
	}
	if template.FounderResources != nil {
		slots := make([]string, len(template.Profiles))
		for index, profile := range template.Profiles {
			slots[index] = profile.Slot
		}
		if err := template.FounderResources.Validate(slots); err != nil {
			return err
		}
	}
	var signers []jsontext.Value
	if !seen[template.SeedSlot] || len(template.TrustedSigners) > MaxManifestBytes || json.Unmarshal(template.TrustedSigners, &signers) != nil || len(signers) == 0 {
		return ErrManifestInvalid
	}
	return nil
}
